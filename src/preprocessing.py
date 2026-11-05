"""Зареждане, почистване и предварителна обработка на CIC-IDS2017.

Правило на заданието: НИТО ЕДНА колона не се премахва от набора данни. Всички 78 характеристики
влизат в модела; редукцията на размерността се извършва чрез PCA (проекция на всички колони),
а не чрез изтриване на колони.
"""
import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

from action_log import num
from config import (ATTACKS, BENIGN_LABEL, LABEL_COL, PCA_VARIANCE, PROCESSED_DIR, RANDOM_STATE,
                    RAW_DIR, TEST_SIZE)

RATE_COLUMNS = {
    # колона със скорост : (числител, ...) – формулата на CICFlowMeter е числител / (Flow Duration [µs] / 1e6)
    "Flow Bytes/s": ("Total Length of Fwd Packets", "Total Length of Bwd Packets"),
    "Flow Packets/s": ("Total Fwd Packets", "Total Backward Packets"),
}
TIMER_RESOLUTION_US = 1.0  # минималната разделителна способност на часовника в CICFlowMeter – 1 µs


def class_counts(df):
    return {k: int(v) for k, v in df[LABEL_COL].value_counts().items()}


def load_raw(attack):
    return pd.read_csv(RAW_DIR / ATTACKS[attack]["file"], low_memory=False)


def clean(df, attack, log):
    """Почистване на един набор. Всяко действие се записва в дневника `log`."""
    n_cols = df.shape[1]

    # 1) Имена на колоните: в оригиналните CSV почти всички имена започват с интервал (" Flow Duration").
    stripped = {c: c.strip() for c in df.columns if c != c.strip()}
    df = df.rename(columns=lambda c: c.strip())
    log.record(attack, "Нормализиране на имената на колоните",
               f"Премахнати водещи/крайни интервали в {len(stripped)} имена на колони (преименуване, без премахване).",
               len(df), len(df), n_cols, df.shape[1],
               {"преименувани": len(stripped),
                "бележка": "Заглавието 'Fwd Header Length' се среща два пъти в оригиналния файл; "
                           "pandas автоматично именува второто копие 'Fwd Header Length.1'. И двете колони са запазени."})

    # 2) Проверка на типовете – 78 числови характеристики + текстов етикет.
    feats = feature_columns(df)
    non_numeric = [c for c in feats if not pd.api.types.is_numeric_dtype(df[c])]
    if non_numeric:
        raise ValueError(f"Нечислови характеристики: {non_numeric}")
    log.record(attack, "Проверка на типовете данни",
               f"{len(feats)} числови характеристики (int64/float64) и 1 текстова колона '{LABEL_COL}'.",
               len(df), len(df), n_cols, df.shape[1],
               {"int64": int((df[feats].dtypes == "int64").sum()), "float64": int((df[feats].dtypes == "float64").sum())})

    # 3) Невалидни стойности (NaN / ±Infinity) в скоростите. Те възникват само при Flow Duration = 0
    #    (деление на нула в CICFlowMeter). Вместо да изтриваме редовете, преизчисляваме скоростта
    #    по същата формула, като приемаме продължителност = 1 µs (разделителната способност на таймера).
    details = {}
    for col, parts in RATE_COLUMNS.items():
        bad = ~np.isfinite(df[col].to_numpy(dtype=float))
        if not bad.any():
            continue
        if (df.loc[bad, "Flow Duration"] != 0).any():
            raise ValueError(f"{col}: невалидни стойности при Flow Duration != 0")
        n_nan = int(df.loc[bad, col].isna().sum())
        numer = df.loc[bad, list(parts)].sum(axis=1).astype(float)
        df.loc[bad, col] = numer / (TIMER_RESOLUTION_US / 1e6)
        details[col] = {"NaN": n_nan, "Infinity": int(bad.sum()) - n_nan,
                        "по клас": {k: int(v) for k, v in df.loc[bad, LABEL_COL].value_counts().items()}}
    log.record(attack, "Коригиране на NaN/Infinity",
               "Стойностите NaN и Infinity във 'Flow Bytes/s' и 'Flow Packets/s' (при Flow Duration = 0) са "
               "преизчислени с продължителност 1 µs. Редове и колони не са премахвани.",
               len(df), len(df), n_cols, df.shape[1], details)

    # 4) Етикети извън изследваната атака (напр. Heartbleed в DoS файла) – отстраняват се редовете им.
    meta = ATTACKS[attack]
    if meta["exclude"]:
        before = len(df)
        mask = df[LABEL_COL].str.strip().isin(meta["exclude"])
        removed = {k: int(v) for k, v in df.loc[mask, LABEL_COL].value_counts().items()}
        df = df.loc[~mask].reset_index(drop=True)
        log.record(attack, "Отстраняване на неизследвани атаки",
                   f"Отстранени {num(before - len(df))} реда с етикети {', '.join(meta['exclude'])} – друг тип атака, "
                   "която не е обект на този детектор. Колони не са премахвани.",
                   before, len(df), n_cols, df.shape[1], {"премахнати": removed})
    df[LABEL_COL] = df[LABEL_COL].str.strip()
    unknown = set(df[LABEL_COL]) - {BENIGN_LABEL} - set(meta["positive"])
    if unknown:
        raise ValueError(f"Неочаквани етикети: {unknown}")

    # 5) Пълни дубликати – премахват се, за да няма еднакви записи едновременно в обучаващото и тестовото множество.
    before = len(df)
    dup_mask = df.duplicated(keep="first")
    dup_by_class = {k: int(v) for k, v in df.loc[dup_mask, LABEL_COL].value_counts().items()}
    df = df.loc[~dup_mask].reset_index(drop=True)
    log.record(attack, "Премахване на дублирани редове",
               f"Премахнати {num(before - len(df))} напълно идентични реда (запазено е първото срещане).",
               before, len(df), n_cols, df.shape[1], {"премахнати по клас": dup_by_class})

    # 6) Противоречиви записи – еднакъв вектор на характеристиките, но етикет и BENIGN, и атака.
    #    Такъв поток не може да бъде класифициран правилно и в двата случая; редовете се отстраняват.
    binary = (df[LABEL_COL] != BENIGN_LABEL).astype(int)
    row_hash = pd.util.hash_pandas_object(df[feats], index=False)   # отпечатък на вектора на характеристиките
    n_classes = binary.groupby(row_hash.values).transform("nunique")
    conflict_mask = (n_classes > 1).to_numpy()
    if conflict_mask.any():
        before = len(df)
        removed = {k: int(v) for k, v in df.loc[conflict_mask, LABEL_COL].value_counts().items()}
        df = df.loc[~conflict_mask].reset_index(drop=True)
        log.record(attack, "Отстраняване на противоречиви записи",
                   f"Отстранени {num(before - len(df))} реда, чийто вектор на характеристиките се среща и като "
                   "BENIGN, и като атака (неразрешима неяснота в етикетите).",
                   before, len(df), n_cols, df.shape[1], {"премахнати по етикет": removed})

    # 7) Контролни проверки след почистването.
    X = df[feats].to_numpy(dtype=float)
    if not np.isfinite(X).all():
        raise ValueError("Останали са невалидни стойности")
    log.record(attack, "Контролна проверка",
               "Няма NaN/Infinity; няма еднакви вектори на характеристиките с противоречиви етикети.",
               len(df), len(df), n_cols, df.shape[1],
               {"NaN/Inf": 0, "противоречиви записи": int(conflict_mask.sum()), "класове": class_counts(df)})
    return df


def binary_counts(df):
    """Брой нормални потоци и потоци на атаката (всички етикети на атаката заедно)."""
    attack = int((df[LABEL_COL].str.strip() != BENIGN_LABEL).sum())
    return {"BENIGN": int(len(df) - attack), "ATTACK": attack}


def feature_columns(df):
    return [c for c in df.columns if c != LABEL_COL]


def processed_path(attack):
    return PROCESSED_DIR / f"{attack}_clean.csv"


def load_processed(attack):
    return pd.read_csv(processed_path(attack), low_memory=False)


def to_xy(df):
    """X – всички 78 характеристики; y – 1 за атака, 0 за нормален трафик (BENIGN)."""
    X = df[feature_columns(df)].astype(float)
    y = (df[LABEL_COL] != BENIGN_LABEL).astype(int).to_numpy()
    return X, y


def get_split(attack):
    """Детерминирано стратифицирано разделяне 70/30 (едно и също за всички скриптове)."""
    X, y = to_xy(load_processed(attack))
    return train_test_split(X, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE)


def signed_log1p(X):
    """sign(x)·ln(1+|x|) – компресира тежките опашки (байтове/s до 10^9) и запазва знака."""
    X = np.asarray(X, dtype=float)
    return np.sign(X) * np.log1p(np.abs(X))


def make_classifier(alg, **params):
    if alg == "RF":
        return RandomForestClassifier(random_state=RANDOM_STATE, n_jobs=-1, **params)
    if alg == "KNN":
        return KNeighborsClassifier(n_jobs=-1, **params)
    if alg == "MLP":
        # Ранно спиране: 10 % от обучаващите данни се отделят за следене на загубата; до 200 епохи.
        defaults = {"hidden_layer_sizes": (64,), "activation": "relu", "solver": "adam", "batch_size": 512,
                    "learning_rate_init": 1e-3, "max_iter": 200, "early_stopping": True,
                    "validation_fraction": 0.1, "n_iter_no_change": 8, "random_state": RANDOM_STATE}
        defaults.update(params)
        return MLPClassifier(**defaults)
    if alg == "LR":
        defaults = {"solver": "lbfgs", "max_iter": 2000}
        defaults.update(params)
        return LogisticRegression(**defaults)
    raise ValueError(alg)


def build_pipeline(alg, n_components=PCA_VARIANCE, **params):
    """Логаритмична трансформация -> стандартизация -> PCA -> класификатор.

    Всички стъпки се обучават само върху обучаващите данни (в рамките на всеки fold при валидирането),
    така че няма изтичане на информация от тестовото множество.
    """
    return Pipeline([
        ("log", FunctionTransformer(signed_log1p, feature_names_out="one-to-one")),
        ("scaler", StandardScaler()),
        ("pca", PCA(n_components=n_components, svd_solver="full", random_state=RANDOM_STATE)),
        ("clf", make_classifier(alg, **params)),
    ])
