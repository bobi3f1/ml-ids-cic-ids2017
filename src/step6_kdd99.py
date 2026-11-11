"""Проверка на метода върху класическия набор KDD Cup 99 (ресурс към заданието).

KDD Cup 99 е извлечен от записите (tcpdump) на DARPA 1998 Intrusion Detection Evaluation (MIT Lincoln Laboratory).
Атаките в него се съпоставят с изследваните в CIC-IDS2017:
  DDoS       – smurf (ICMP наводнение чрез усилване: жертвата получава отговорите на много отразяващи хостове)
  PortScan   – Probe: portsweep, nmap, satan, ipsweep
  DoS        – neptune (SYN наводнение), back, teardrop, pod, land
  BruteForce – guess_passwd (отгатване на пароли за telnet)
За всяка атака се използват същите алгоритми, същите хиперпараметри (избрани върху CIC-IDS2017) и същата обработка:
премахване на дубликатите и противоречивите записи, one-hot кодиране на символните характеристики (protocol_type,
service, flag) и sign(x)·ln(1+|x|) → StandardScaler → PCA (99 % дисперсия) → класификатор.
Фаза на машинно обучение: стратифицирано 5-кратно кръстосано валидиране върху 70 %;
оперативна фаза: класификация на останалите 30 % (невиждани записи).

Данните се изтеглят чрез scikit-learn (fetch_kddcup99, проверка на SHA-256), защото оригиналният сървър на UCI
(kdd.ics.uci.edu) отказва изтеглянето на архивите (HTTP 403).

Изход: results/kdd99.json, results/tables/kdd99_metrics.csv, results/figures/p5_kdd99_metrics(_slide).png
"""
import json
import time

import numpy as np
import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.datasets import fetch_kddcup99
from sklearn.decomposition import PCA
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, StandardScaler

import plot_style as ps
from action_log import DataActionLog, get_logger, num
from config import (ATTACKS, CV_FOLDS, LABEL_COL, PCA_VARIANCE, RANDOM_STATE, RESULTS_DIR, ROOT, TABLES_DIR,
                    TEST_SIZE, ensure_dirs, experiments, setup_console)
from preprocessing import make_classifier, signed_log1p
from step3_train_evaluate import binary_metrics

log = get_logger()

KDD_DIR = ROOT / "data" / "external" / "KDD99"
KDD_SOURCE = "http://kdd.ics.uci.edu/databases/kddcup99/kddcup99.html"
NORMAL = "normal"
SYMBOLIC = ["protocol_type", "service", "flag"]
# атака в изследването -> етикети в KDD Cup 99
KDD_ATTACKS = {
    "DDoS": ["smurf"],
    "PortScan": ["portsweep", "nmap", "satan", "ipsweep"],
    "DoS": ["neptune", "back", "teardrop", "pod", "land"],
    "BruteForce": ["guess_passwd"],
}
ALG_LABEL = {"RF": "Random Forest", "KNN": "k-NN", "MLP": "MLP", "LR": "Лог. регресия"}
KDD_SHORT = {"DDoS": "smurf", "PortScan": "Probe", "DoS": "neptune…", "BruteForce": "guess_passwd"}
ALG_SHORT_LABEL = {"RF": "RF", "KNN": "k-NN", "MLP": "MLP", "LR": "LR"}


def load():
    """KDD Cup 99 (10 %) като DataFrame: 41 характеристики + Label (без точката в края на етикета)."""
    df = fetch_kddcup99(percent10=True, data_home=str(KDD_DIR), download_if_missing=True, as_frame=True).frame
    df = df.rename(columns={"labels": LABEL_COL})
    for c in SYMBOLIC + [LABEL_COL]:
        df[c] = df[c].map(lambda v: v.decode() if isinstance(v, bytes) else str(v))
    df[LABEL_COL] = df[LABEL_COL].str.rstrip(".")
    feats = [c for c in df.columns if c != LABEL_COL]
    numeric = [c for c in feats if c not in SYMBOLIC]
    df[numeric] = df[numeric].astype(float)
    return df, feats


def build_pipeline(alg, params):
    """Същият конвейер като за CIC-IDS2017, с one-hot кодиране на символните характеристики в началото.

    Кодирането се обучава само върху обучаващите данни (непознати стойности при теста се кодират с нули)."""
    encode = ColumnTransformer([("onehot", OneHotEncoder(handle_unknown="ignore", sparse_output=False), SYMBOLIC)],
                               remainder="passthrough")
    return Pipeline([
        ("encode", encode),
        ("log", FunctionTransformer(signed_log1p)),
        ("scaler", StandardScaler()),
        ("pca", PCA(n_components=PCA_VARIANCE, svd_solver="full", random_state=RANDOM_STATE)),
        ("clf", make_classifier(alg, **params)),
    ])


def binary_subset(df, feats, attack, dlog):
    """Нормален трафик + етикетите на атаката; отстраняват се векторите, които са и нормални, и атака."""
    labels = KDD_ATTACKS[attack]
    sub = df[df[LABEL_COL].isin([NORMAL] + labels)]
    y = sub[LABEL_COL].isin(labels).astype(int).to_numpy()
    h = pd.util.hash_pandas_object(sub[feats], index=False).to_numpy()
    keep = pd.Series(y).groupby(h).transform("nunique").to_numpy() == 1
    if (~keep).any():
        dlog.record("KDD99", f"Противоречиви записи ({attack})",
                    f"От подмножеството normal + {', '.join(labels)} са отстранени {num(int((~keep).sum()))} реда с "
                    "еднакъв вектор и двата етикета.", len(sub), int(keep.sum()), sub.shape[1], sub.shape[1])
    return sub.loc[keep], y[keep]


def evaluate(attack, alg, params, X, y):
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE)
    cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)
    t = time.perf_counter()
    cvr = cross_validate(build_pipeline(alg, params), X_tr, y_tr, cv=cv,
                         scoring=("accuracy", "precision", "recall", "f1"), n_jobs=1 if alg in ("RF", "KNN") else CV_FOLDS)
    cv_s = time.perf_counter() - t
    model = build_pipeline(alg, params)
    t = time.perf_counter()
    model.fit(X_tr, y_tr)
    fit_s = time.perf_counter() - t
    t = time.perf_counter()
    pred = model.predict(X_te)
    pred_s = time.perf_counter() - t
    test = binary_metrics(y_te, pred, model.predict_proba(X_te)[:, 1])
    return {
        "params": params,
        "train_size": int(len(X_tr)), "test_size": int(len(X_te)),
        "train_attack": int(y_tr.sum()), "test_attack": int(y_te.sum()),
        "encoded_features": int(model.named_steps["encode"].transform(X_tr.head(1)).shape[1]),
        "pca_components": int(model.named_steps["pca"].n_components_),
        "cv": {k: {"mean": float(cvr[f"test_{k}"].mean()), "std": float(cvr[f"test_{k}"].std())}
               for k in ("accuracy", "precision", "recall", "f1")},
        "test": test,
        "timing": {"cv_seconds": round(cv_s, 1), "fit_seconds": round(fit_s, 2),
                   "latency_us_per_flow": round(pred_s / len(X_te) * 1e6, 2)},
    }


def fig_metrics(res, keys=("accuracy", "precision", "sensitivity")):
    titles = {"accuracy": "Accuracy", "precision": "Precision",
              "sensitivity": "Sensitivity (дял открити атаки)"}
    models = experiments()
    labels = [f"{ATTACKS[a]['label']} · {ALG_SHORT_LABEL[g]}\nKDD: {KDD_SHORT[a]}" for a, g in models]
    x = np.arange(len(labels))
    fig, axes = ps.plt.subplots(len(keys), 1, figsize=(13, 3.3 * len(keys)), sharex=True, squeeze=False)
    axes = axes.ravel()
    series = (("cic", ps.BLUE, "CIC-IDS2017 (оперативен тест)"), ("kdd", ps.SERIES[6], "KDD Cup 99 (оперативен тест)"))
    lo = min(res[m][src][k] for m in models for src, _, _ in series for k in keys) * 100
    bottom = max(0, np.floor((lo - 2) / 5) * 5)
    for ax, key in zip(axes, keys):
        w = 0.36
        for k, (src, color, name) in enumerate(series):
            vals = [res[m][src][key] * 100 for m in models]
            bars = ax.bar(x + (k - 0.5) * (w + 0.03), vals, w, color=color, label=name)
            for b_, v in zip(bars, vals):
                ax.annotate(ps.fmt(v, 2), (b_.get_x() + b_.get_width() / 2, v), xytext=(0, 2),
                            textcoords="offset points", ha="center", va="bottom",
                            fontsize=7.5 if not ps.SUFFIX else 9, color=ps.INK_2)
        ax.set_ylim(bottom, 100.9)
        ax.set_yticks(np.arange(bottom, 100.01, 1 if 100 - bottom <= 6 else 2))
        ax.set_ylabel("%")
        ax.set_title(titles[key])
        ax.grid(axis="x", visible=False)
    axes[-1].set_xticks(x, labels, fontsize=9.5 if not ps.SUFFIX else 11)
    handles, names = axes[0].get_legend_handles_labels()
    fig.tight_layout(rect=(0, 0, 1, 0.95 if len(keys) > 2 else 0.92))
    fig.legend(handles, names, loc="upper center", ncols=2, bbox_to_anchor=(0.5, 1.0), frameon=False)
    return ps.save(fig, "p5_kdd99_metrics")


def main():
    setup_console()
    ensure_dirs()
    ps.apply()
    dlog = DataActionLog("step6_kdd99")
    log.info("=== ПРОВЕРКА НА МЕТОДА: KDD Cup 99 ===")
    df, feats = load()
    n_cols = df.shape[1]
    labels_raw = {k: int(v) for k, v in df[LABEL_COL].value_counts().items()}
    dlog.record("KDD99", "Получаване на набора данни",
                f"KDD Cup 99 (10 %): {num(len(df))} записа × {n_cols} колони (41 характеристики + етикет), изтеглен "
                "чрез scikit-learn (fetch_kddcup99) с проверка на SHA-256.", len(df), len(df), n_cols, n_cols,
                {"източник": KDD_SOURCE, "етикети": labels_raw})
    before = len(df)
    dup = df.duplicated(keep="first")
    removed = {k: int(v) for k, v in df.loc[dup, LABEL_COL].value_counts().items()}
    df = df.loc[~dup].reset_index(drop=True)
    dlog.record("KDD99", "Премахване на дублирани записи",
                f"Премахнати {num(before - len(df))} напълно идентични реда ({100 * (before - len(df)) / before:.1f} %).",
                before, len(df), n_cols, n_cols, {"премахнати по етикет": removed})
    dlog.record("KDD99", "Кодиране на символните характеристики (в конвейера)",
                "protocol_type, service и flag се кодират с one-hot вътре в конвейера (обучава се само върху "
                "обучаващите данни); колоните в набора остават непроменени.", len(df), len(df), n_cols, n_cols,
                {"брой стойности": {c: int(df[c].nunique()) for c in SYMBOLIC}})
    cic = {(m["attack"], m["algorithm"]): m for m in
           json.loads((RESULTS_DIR / "metrics.json").read_text(encoding="utf-8"))["models"]}
    res, rows, sizes = {}, [], {}
    for attack in ATTACKS:
        sub, y = binary_subset(df, feats, attack, dlog)
        X = sub[feats]
        sizes[attack] = {"kdd_labels": KDD_ATTACKS[attack], "total": int(len(y)), "attack": int(y.sum()),
                         "normal": int(len(y) - y.sum()),
                         "attack_raw": int(sum(labels_raw.get(lab, 0) for lab in KDD_ATTACKS[attack]))}
        log.info(f"[KDD99/{attack}] {len(y):,} записа ({int(y.sum()):,} атака: {', '.join(KDD_ATTACKS[attack])})")
        for alg in [g for a, g in experiments() if a == attack]:
            r = evaluate(attack, alg, cic[(attack, alg)]["best_params"], X, y)
            res[(attack, alg)] = {"cic": cic[(attack, alg)]["test"], "kdd": r["test"], **r}
            t = r["test"]
            log.info(f"[KDD99/{attack}_{alg}] CV acc={r['cv']['accuracy']['mean']:.5f}±{r['cv']['accuracy']['std']:.5f} | "
                     f"тест: TP={t['TP']} TN={t['TN']} FP={t['FP']} FN={t['FN']} acc={t['accuracy']:.5f} "
                     f"prec={t['precision']:.5f} sens={t['sensitivity']:.5f} (PCA {r['pca_components']})")
            rows.append({"attack": attack, "kdd_labels": "+".join(KDD_ATTACKS[attack]), "algorithm": alg,
                         **{k: t[k] for k in ("TP", "TN", "FP", "FN", "precision", "accuracy", "sensitivity",
                                              "specificity", "f1", "roc_auc")},
                         "cv_accuracy_mean": r["cv"]["accuracy"]["mean"], "cv_accuracy_std": r["cv"]["accuracy"]["std"],
                         "pca_components": r["pca_components"]})
    pd.DataFrame(rows).to_csv(TABLES_DIR / "kdd99_metrics.csv", index=False, encoding="utf-8-sig")
    out = {"dataset": "KDD Cup 1999 (10 %)", "source": KDD_SOURCE, "sklearn": sklearn.__version__,
           "raw_rows": before, "unique_rows": int(len(df)), "labels_raw": labels_raw,
           "labels_unique": {k: int(v) for k, v in df[LABEL_COL].value_counts().items()},
           "symbolic_values": {c: int(df[c].nunique()) for c in SYMBOLIC},
           "mapping": KDD_ATTACKS, "subsets": sizes,
           "models": [{"attack": a, "algorithm": g, **{k: v for k, v in r.items() if k != "kdd"}}
                      for (a, g), r in res.items()]}
    (RESULTS_DIR / "kdd99.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    fig_metrics(res)
    ps.slide_mode(True)
    fig_metrics(res, keys=("precision", "sensitivity"))
    ps.slide_mode(False)
    log.info("Проверката с KDD Cup 99 приключи")


if __name__ == "__main__":
    main()
