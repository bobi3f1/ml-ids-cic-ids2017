"""Кръстосана проверка на 8-те модела върху външния набор данни InSDN (друга организация, друга мрежа).

Експеримент А – пренос: моделите, обучени върху CIC-IDS2017, се прилагат БЕЗ промяна върху InSDN
                 (нормален трафик + потоците на съответната атака).
Експеримент Б – повторно обучение: същите алгоритми със същите (избрани върху CIC-IDS2017) хиперпараметри и
                 същата предварителна обработка се обучават върху 70 % от InSDN и се тестват върху 30 %.
                 Показва дали методът работи в новата мрежа, когато има обучаващи данни от нея.

Изход: data/processed/InSDN_clean.csv, results/external_insdn.json, results/tables/external_insdn.csv,
       results/figures/p4_*.png, записи в logs/data_actions_log.(md|json) и logs/experiment_log.txt
"""
import hashlib
import json
import sys
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

import plot_style as ps
from action_log import DataActionLog, get_logger, num
from config import (ATTACKS, LABEL_COL, MODELS_DIR, RANDOM_STATE, RESULTS_DIR, TABLES_DIR, TEST_SIZE, ensure_dirs,
                    experiments, setup_console)
from external_data import (INSDN_DIR, INSDN_FILES, INSDN_LABEL, INSDN_NORMAL, INSDN_PROCESSED, INSDN_SHA256,
                           INSDN_URL, binary_for, harmonize, load_insdn_raw)
from preprocessing import build_pipeline, feature_columns, get_split, load_processed
from step3_train_evaluate import binary_metrics

log = get_logger()
ALG_LABEL = {"RF": "Random Forest", "KNN": "k-NN", "MLP": "MLP", "LR": "Лог. регресия"}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def prepare(dlog, feats):
    zip_path = INSDN_DIR.parent / "InSDN_DatasetCSV.zip"
    digest = sha256(zip_path)
    if digest != INSDN_SHA256:
        raise RuntimeError(f"SHA-256 на InSDN не съвпада: {digest}")
    dlog.record("InSDN", "Получаване на външния набор данни",
                "Изтеглен InSDN_DatasetCSV.zip (19 302 607 B) от University College Dublin, проверена SHA-256 сума, "
                "разархивирани 3 CSV файла.", details={"източник": INSDN_URL, "sha256": digest, "файлове": INSDN_FILES})
    raw = load_insdn_raw()
    n_raw_cols = raw.shape[1] - 1          # без служебната колона Source File
    dlog.record("InSDN", "Зареждане", f"Заредени {num(len(raw))} потока × {n_raw_cols} колони (CICFlowMeter-V3), "
                "добавена служебна колона Source File (име на изходния файл).",
                len(raw), len(raw), n_raw_cols, raw.shape[1],
                {"етикети": {k: int(v) for k, v in raw["Label"].astype(str).str.strip().value_counts().items()}})
    df = harmonize(raw)
    dlog.record("InSDN", "Съпоставяне на колоните с CIC-IDS2017",
                "50 колони са преименувани към имената от CIC-IDS2017 (напр. Tot Fwd Pkts → Total Fwd Packets); "
                "добавена производна колона Fwd Header Length.1 = Fwd Header Length (в CIC-IDS2017 е точно копие). "
                "Колоните Flow ID, Src IP, Src Port, Dst IP, Protocol и Timestamp се запазват, но не се подават на "
                "моделите (не са използвани и при обучението).",
                len(df), len(df), raw.shape[1], df.shape[1], {"липсващи характеристики": [c for c in feats if c not in df]})
    X = df[feats].to_numpy(dtype=float)
    dlog.record("InSDN", "Проверка за NaN/Infinity", "Няма невалидни стойности – корекция не е нужна.",
                len(df), len(df), df.shape[1], df.shape[1], {"NaN": int(np.isnan(X).sum()), "Inf": int(np.isinf(X).sum())})
    before = len(df)
    dup = df.duplicated(subset=feats + [LABEL_COL], keep="first")
    removed = {k: int(v) for k, v in df.loc[dup, LABEL_COL].value_counts().items()}
    df = df.loc[~dup].reset_index(drop=True)
    dlog.record("InSDN", "Премахване на дублирани записи",
                f"Премахнати {num(before - len(df))} реда с идентичен вектор на 78-те характеристики и етикет "
                "(различават се само по IP адреси, портове на източника и време).",
                before, len(df), df.shape[1], df.shape[1], {"премахнати по етикет": removed})
    df.to_csv(INSDN_PROCESSED, index=False)
    dlog.record("InSDN", "Запис на обработения набор", f"Записан data/processed/{INSDN_PROCESSED.name} "
                f"({num(len(df))} реда × {df.shape[1]} колони).", len(df), len(df), df.shape[1], df.shape[1])
    return df


def subset(df, attack, feats, dlog):
    """Нормален трафик + атаката; отстраняват се векторите, които са и нормални, и атака."""
    sub, y = binary_for(df, attack)
    h = pd.util.hash_pandas_object(sub[feats], index=False).to_numpy()
    n_cls = pd.Series(y).groupby(h).transform("nunique").to_numpy()
    keep = n_cls == 1
    if (~keep).any():
        dlog.record("InSDN", f"Противоречиви записи ({attack})",
                    f"От подмножеството Normal + {INSDN_LABEL[attack]} са отстранени {num(int((~keep).sum()))} реда с "
                    "еднакъв вектор и двата етикета.", len(sub), int(keep.sum()), sub.shape[1], sub.shape[1])
    return sub.loc[keep], y[keep]


def transfer(attack, alg, X, y):
    model = joblib.load(MODELS_DIR / f"{attack}_{alg}.joblib")
    t = time.perf_counter()
    pred = model.predict(X)
    secs = time.perf_counter() - t
    score = model.predict_proba(X)[:, 1]
    m = binary_metrics(y, pred, score)
    m["latency_us_per_flow"] = round(secs / len(X) * 1e6, 2)
    m["pred_attack_share"] = float(pred.mean())
    m["score_attack_median"] = float(np.median(score[y == 1]))
    m["score_normal_p99"] = float(np.quantile(score[y == 0], 0.99))
    # диагностика: дял открити атаки / фалшиви тревоги при по-ниски прагове (илюстративно, не се използва за избор)
    m["thresholds"] = [{"thr": thr, "tpr": float((score[y == 1] >= thr).mean()),
                        "fpr": float((score[y == 0] >= thr).mean())} for thr in (0.5, 0.3, 0.2, 0.15, 0.1)]
    return m


def shift_stats(df, feats):
    """Систематични разлики между CIC-IDS2017 и InSDN (за анализа)."""
    out = {}
    for attack in ATTACKS:
        cic = load_processed(attack)
        sub, y = binary_for(df, attack)
        ca, ia = cic[cic[LABEL_COL] != "BENIGN"], sub[y == 1]
        out[attack] = {
            "median_flow_duration_us": {"cic": float(ca["Flow Duration"].median()), "insdn": float(ia["Flow Duration"].median())},
            "median_fwd_packets": {"cic": float(ca["Total Fwd Packets"].median()), "insdn": float(ia["Total Fwd Packets"].median())},
            "median_min_seg_size_forward": {"cic": float(ca["min_seg_size_forward"].median()),
                                            "insdn": float(ia["min_seg_size_forward"].median())},
            "median_init_win_fwd": {"cic": float(ca["Init_Win_bytes_forward"].median()),
                                    "insdn": float(ia["Init_Win_bytes_forward"].median())},
            "top_ports": {"cic": {int(k): int(v) for k, v in ca["Destination Port"].value_counts().head(3).items()},
                          "insdn": {int(k): int(v) for k, v in ia["Destination Port"].value_counts().head(3).items()}},
            "insdn_protocols": {int(k): int(v) for k, v in ia["Protocol"].value_counts().items()},
            # дял потоци без нито един пакет в права посока – при CICFlowMeter първият пакет определя посоката „напред“
            "fwd_zero_share": {"cic": float((ca["Total Fwd Packets"] == 0).mean()),
                               "insdn": float((ia["Total Fwd Packets"] == 0).mean())},
        }
    normal = df[df[LABEL_COL] == "Normal"]
    out["normal"] = {"dns_share": float((normal["Destination Port"] == 53).mean()),
                     "median_flow_duration_us": float(normal["Flow Duration"].median()),
                     "fwd_zero_share": float((normal["Total Fwd Packets"] == 0).mean())}
    cic_fwd = [load_processed(a)["Total Fwd Packets"] for a in ATTACKS]
    out["cic_fwd_zero"] = {"flows": int(sum((s == 0).sum() for s in cic_fwd)), "total": int(sum(len(s) for s in cic_fwd))}
    cic_all = load_processed("DDoS")
    out["psh_equals_syn"] = {"cic": float((cic_all["Fwd PSH Flags"] == cic_all["SYN Flag Count"]).mean()),
                             "insdn": float((df["Fwd PSH Flags"] == df["SYN Flag Count"]).mean())}
    return out


def retrain(attack, alg, X, y, params):
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE)
    model = build_pipeline(alg, **params)
    t = time.perf_counter()
    model.fit(X_tr, y_tr)
    fit_s = time.perf_counter() - t
    pred = model.predict(X_te)
    m = binary_metrics(y_te, pred, model.predict_proba(X_te)[:, 1])
    m["fit_seconds"] = round(fit_s, 2)
    m["train_size"], m["test_size"] = int(len(X_tr)), int(len(X_te))
    m["pca_components"] = int(model.named_steps["pca"].n_components_)
    return m


def shift_projection(df, feats):
    """Проекция на потоците от двата набора в пространството PC1–PC2 на модела, обучен върху CIC-IDS2017."""
    out = {}
    rng = np.random.default_rng(RANDOM_STATE)
    for attack in ATTACKS:
        X_tr, _, y_tr, _ = get_split(attack)
        model = joblib.load(MODELS_DIR / f"{attack}_{experiments_first(attack)}.joblib")
        pre = Pipeline(model.steps[:3])
        sub, y = binary_for(df, attack)

        def sample(X, mask, k=3000):
            idx = np.flatnonzero(mask)
            return X.iloc[rng.choice(idx, min(k, len(idx)), replace=False)]
        out[attack] = {
            "CIC-IDS2017 · BENIGN": pre.transform(sample(X_tr, y_tr == 0))[:, :2],
            "CIC-IDS2017 · атака": pre.transform(sample(X_tr, y_tr == 1))[:, :2],
            "InSDN · Normal": pre.transform(sample(sub[feats].astype(float), y == 0))[:, :2],
            "InSDN · атака": pre.transform(sample(sub[feats].astype(float), y == 1))[:, :2],
        }
    return out


def raw_labels():
    lab = pd.concat([pd.read_csv(INSDN_DIR / f, usecols=["Label"])["Label"] for f in INSDN_FILES])
    return {k: int(v) for k, v in lab.astype(str).str.strip().value_counts().items()}


def experiments_first(attack):
    return next(g for a, g in experiments() if a == attack)


# ------------------------------------------------------------------------------------------- фигури
def fig_transfer(res, keys=("accuracy", "precision", "sensitivity")):
    titles = {"accuracy": "Accuracy", "precision": "Precision", "sensitivity": "Sensitivity (дял открити атаки)"}
    models = experiments()
    labels = [f"{ATTACKS[a]['label']}\n{ALG_LABEL[g]}" for a, g in models]
    x = np.arange(len(labels))
    fig, axes = ps.plt.subplots(len(keys), 1, figsize=(13, 3.3 * len(keys)), sharex=True, squeeze=False)
    axes = axes.ravel()
    series = (("cic", ps.BLUE, "CIC-IDS2017 (оперативен тест)"),
              ("transfer", ps.ORANGE, "InSDN – пренос без обучение (А)"),
              ("retrain", ps.AQUA, "InSDN – обучение върху InSDN (Б)"))
    for ax, key in zip(axes, keys):
        w = 0.26
        for k, (src, color, name) in enumerate(series):
            vals = [res[m][src][key] * 100 for m in models]
            bars = ax.bar(x + (k - 1) * (w + 0.02), vals, w, color=color, label=name)
            for b_, v in zip(bars, vals):
                ax.annotate(ps.fmt(v, 1 if v < 99.95 or v == 100 else 2), (b_.get_x() + b_.get_width() / 2, v),
                            xytext=(0, 2), textcoords="offset points", ha="center", va="bottom",
                            fontsize=7.5 if not ps.SUFFIX else 9, color=ps.INK_2)
        ax.set_ylim(0, 112)
        ax.set_yticks([0, 25, 50, 75, 100])
        ax.set_ylabel("%")
        ax.set_title(titles[key])
        ax.grid(axis="x", visible=False)
    axes[-1].set_xticks(x, labels)
    handles, names = axes[0].get_legend_handles_labels()
    fig.tight_layout(rect=(0, 0, 1, 0.95 if len(keys) > 2 else 0.92))
    fig.legend(handles, names, loc="upper center", ncols=3, bbox_to_anchor=(0.5, 1.0), frameon=False)
    return ps.save(fig, "p4_insdn_metrics")


def fig_confusion(res, experiment="transfer", name="p4_insdn_confusion"):
    from step4_figures import _confusion_panel
    models = experiments()
    fig, axes = ps.grid(len(models), ncols=4, panel=(4.2, 3.7))
    for ax, (a, g) in zip(axes, models):
        _confusion_panel(ax, res[(a, g)][experiment], a, g, fontsize=9.5)
        ax.set_title(f"InSDN ({'А' if experiment == 'transfer' else 'Б'}) – {ATTACKS[a]['label']} · {ALG_LABEL[g]}",
                     fontsize=10.5)
    fig.tight_layout()
    return ps.save(fig, name)


def fig_classes(data):
    """Разпределение на етикетите в InSDN – суров набор и след премахване на дубликатите."""
    raw = data["labels_raw"]
    clean = data["labels_clean"]
    order = ["Normal", "DDoS", "Probe", "DoS", "BFA", "Web-Attack", "BOTNET", "U2R"]
    x = np.arange(len(order))
    fig, ax = ps.plt.subplots(figsize=(12, 4.6))
    w = 0.36
    b1 = ax.bar(x - w / 2 - 0.01, [raw.get(k, 0) for k in order], w, color=ps.BLUE, label="Суров набор")
    b2 = ax.bar(x + w / 2 + 0.01, [clean.get(k, 0) for k in order], w, color=ps.ORANGE, label="След премахване на дубликатите")
    ps.bar_labels(ax, b1, fontsize=8.5)
    ps.bar_labels(ax, b2, fontsize=8.5)
    ax.set_xticks(x, order)
    ax.set_yscale("log")
    ax.set_ylim(5, max(raw.values()) * 4)
    ax.yaxis.set_major_formatter(ps.THOUSANDS)
    ax.set_ylabel("Брой потоци (логаритмична скала)")
    ax.grid(axis="x", visible=False)
    ax.legend(loc="upper right")
    fig.tight_layout()
    return ps.save(fig, "p4_insdn_classes")


def fig_shift(proj):
    fig, axes = ps.grid(len(proj), panel=(6.0, 4.6))
    styles = {"CIC-IDS2017 · BENIGN": (ps.BLUE, 0.25), "CIC-IDS2017 · атака": (ps.ORANGE, 0.35),
              "InSDN · Normal": (ps.AQUA, 0.35), "InSDN · атака": (ps.SERIES[6], 0.45)}
    for ax, (attack, groups) in zip(axes, proj.items()):
        for name, Z in groups.items():
            c, a = styles[name]
            ax.scatter(Z[:, 0], Z[:, 1], s=5, alpha=a, color=c, linewidths=0, label=name, rasterized=True)
        ax.set_title(f"{ATTACKS[attack]['bg']} (PCA на модела от CIC-IDS2017)")
        ax.set_xlabel("PC1")
        ax.set_ylabel("PC2")
        leg = ax.legend(loc="best", markerscale=3, fontsize=8.5)
        for h in leg.legend_handles:
            h.set_alpha(1)
    fig.tight_layout()
    return ps.save(fig, "p4_insdn_shift")


def figures_only():
    path = RESULTS_DIR / "external_insdn.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if "labels_raw" not in data:      # допълване на по-стар файл с резултати (без повторно изчисление на моделите)
        data["labels_raw"] = raw_labels()
        data["files"] = {f: {k: int(v) for k, v in pd.read_csv(INSDN_DIR / f, usecols=["Label"])["Label"].astype(str)
                             .str.strip().value_counts().items()} for f in INSDN_FILES}
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    fig_classes(data)
    res = {(m["attack"], m["algorithm"]): m for m in data["models"]}
    fig_transfer(res)
    ps.slide_mode(True)
    fig_transfer(res, keys=("accuracy", "sensitivity"))
    ps.slide_mode(False)
    fig_confusion(res)
    fig_confusion(res, "retrain", "p4_insdn_confusion_retrain")


def main():
    setup_console()
    ensure_dirs()
    ps.apply()
    if "--figures-only" in sys.argv:
        figures_only()
        return
    if "--update-shift" in sys.argv:
        # преизчисляване само на статистиките за разликите между наборите (без повторно обучение)
        path = RESULTS_DIR / "external_insdn.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        df = pd.read_csv(INSDN_PROCESSED, low_memory=False)
        data["shift"] = json.loads(json.dumps(shift_stats(df, feature_columns(load_processed("DDoS").head(1)))))
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return
    dlog = DataActionLog("step5_external_test")
    log.info("=== КРЪСТОСАНА ПРОВЕРКА: външен набор InSDN ===")
    feats = feature_columns(load_processed("DDoS").head(1))
    df = prepare(dlog, feats)
    cic = {(m["attack"], m["algorithm"]): m for m in
           json.loads((RESULTS_DIR / "metrics.json").read_text(encoding="utf-8"))["models"]}
    res, rows, sizes = {}, [], {}
    for attack in ATTACKS:
        sub, y = subset(df, attack, feats, dlog)
        X = sub[feats].astype(float)
        sizes[attack] = {"total": int(len(y)), "attack": int(y.sum()), "normal": int(len(y) - y.sum()),
                         "insdn_label": INSDN_LABEL[attack]}
        log.info(f"[InSDN/{attack}] {len(y):,} потока ({int(y.sum()):,} {INSDN_LABEL[attack]})")
        for alg in [g for a, g in experiments() if a == attack]:
            a_res = transfer(attack, alg, X, y)
            b_res = retrain(attack, alg, X, y, cic[(attack, alg)]["best_params"])
            res[(attack, alg)] = {"cic": cic[(attack, alg)]["test"], "transfer": a_res, "retrain": b_res}
            log.info(f"[InSDN/{attack}_{alg}] пренос: TP={a_res['TP']} TN={a_res['TN']} FP={a_res['FP']} "
                     f"FN={a_res['FN']} acc={a_res['accuracy']:.4f} prec={a_res['precision']:.4f} "
                     f"sens={a_res['sensitivity']:.4f} | обучение върху InSDN: acc={b_res['accuracy']:.5f} "
                     f"FP={b_res['FP']} FN={b_res['FN']}")
            for phase, mm in (("transfer", a_res), ("retrain", b_res)):
                rows.append({"attack": attack, "algorithm": alg, "experiment": phase,
                             **{k: mm[k] for k in ("TP", "TN", "FP", "FN", "accuracy", "precision", "sensitivity",
                                                   "specificity", "f1", "roc_auc")}})
    pd.DataFrame(rows).to_csv(TABLES_DIR / "external_insdn.csv", index=False, encoding="utf-8-sig")
    out = {"dataset": "InSDN", "source": INSDN_URL, "rows_clean": int(len(df)),
           "labels_clean": {k: int(v) for k, v in df[LABEL_COL].value_counts().items()},
           "subsets": sizes, "shift": shift_stats(df, feats),
           "raw_rows": int(sum(pd.read_csv(INSDN_DIR / f, usecols=["Label"]).shape[0] for f in INSDN_FILES)),
           "labels_raw": raw_labels(),
           "files": {f: {k: int(v) for k, v in pd.read_csv(INSDN_DIR / f, usecols=["Label"])["Label"].astype(str)
                         .str.strip().value_counts().items()} for f in INSDN_FILES},
           "models": [{"attack": a, "algorithm": g, **v} for (a, g), v in res.items()]}
    (RESULTS_DIR / "external_insdn.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    fig_classes(out)
    fig_transfer(res)
    ps.slide_mode(True)
    fig_transfer(res, keys=("accuracy", "sensitivity"))
    ps.slide_mode(False)
    fig_confusion(res)
    fig_confusion(res, "retrain", "p4_insdn_confusion_retrain")
    fig_shift(shift_projection(df, feats))
    log.info("Кръстосаната проверка приключи")


if __name__ == "__main__":
    main()
