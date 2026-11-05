"""ФАЗА 1 – анализ на атаките и характеристиките, предварителна обработка на наборите данни.

Изход:
  data/processed/<атака>_clean.csv     – почистен набор (всички 79 колони запазени)
  results/phase1_summary.json          – статистики преди/след обработката
  results/tables/*.csv                 – описателни статистики, взаимна информация
  results/figures/p1_*.png             – фигури за фаза 1
  logs/data_actions_log.(md|json)      – дневник на действията върху данните
"""
import hashlib
import json
import sys
import time
import zipfile

import numpy as np
import pandas as pd
from sklearn.feature_selection import mutual_info_classif

import plot_style as ps
from action_log import DataActionLog, get_logger, num
from config import (ATTACKS, BENIGN_LABEL, DATASET_MIRROR_URL, DATASET_SHA256, LABEL_COL, RANDOM_STATE,
                    RAW_ZIP, RESULTS_DIR, TABLES_DIR, ensure_dirs, setup_console)
from preprocessing import (class_counts, clean, feature_columns, load_raw, processed_path, signed_log1p,
                           to_xy, binary_counts)

log = get_logger()


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def raw_profile(df):
    """Профил на суровия набор (нищо не се променя)."""
    df = df.rename(columns=lambda c: c.strip())
    feats = feature_columns(df)
    num = df[feats]
    arr = num.to_numpy(dtype=float)
    constant = [c for c in feats if num[c].nunique() == 1]
    identical = []
    for i, a in enumerate(feats):
        for b in feats[i + 1:]:
            if a not in constant and num[a].equals(num[b]):
                identical.append([a, b])
    return {
        "rows": int(len(df)),
        "cols": int(df.shape[1]),
        "features": len(feats),
        "classes": class_counts(df),
        "nan_cells": {c: int(v) for c, v in num.isna().sum().items() if v},
        "inf_cells": {c: int(v) for c, v in zip(feats, np.isinf(arr).sum(axis=0)) if v},
        "duplicate_rows": int(df.duplicated().sum()),
        "constant_columns": constant,
        "identical_column_pairs": identical,
        "negative_value_columns": {c: float(num[c].min()) for c in feats if num[c].min() < 0},
        "negative_duration_rows": int((num["Flow Duration"] < 0).sum()),
        "memory_mb": round(df.memory_usage(deep=True).sum() / 2**20, 1),
    }


def mutual_information(df, attack, n=60000):
    X, y = to_xy(df)
    idx = np.random.default_rng(RANDOM_STATE).choice(len(X), size=min(n, len(X)), replace=False)
    mi = mutual_info_classif(signed_log1p(X.iloc[idx]), y[idx], random_state=RANDOM_STATE)
    s = pd.Series(mi, index=X.columns, name="mutual_information").sort_values(ascending=False)
    s.to_csv(TABLES_DIR / f"{attack}_mutual_information.csv", encoding="utf-8-sig")
    return s


def describe_by_class(df, attack):
    feats = feature_columns(df)
    stats = df.groupby(LABEL_COL)[feats].agg(["mean", "std", "min", "max"]).T
    stats.to_csv(TABLES_DIR / f"{attack}_feature_stats_by_class.csv", encoding="utf-8-sig")


# ------------------------------------------------------------------------------------------- фигури
ATTACK_LIST = list(ATTACKS)


def fig_class_distribution(summary):
    fig, axes = ps.grid(len(ATTACK_LIST), panel=(5.6, 4.2))
    for ax, attack in zip(axes, ATTACK_LIST):
        raw, cln = summary[attack]["raw"]["binary"], summary[attack]["clean"]["binary"]
        x = np.arange(2)
        w = 0.34
        b1 = ax.bar(x - w / 2 - 0.01, [raw["BENIGN"], raw["ATTACK"]], w, color=ps.BLUE, label="Суров набор")
        b2 = ax.bar(x + w / 2 + 0.01, [cln["BENIGN"], cln["ATTACK"]], w, color=ps.ORANGE, label="След почистване")
        ps.bar_labels(ax, b1)
        ps.bar_labels(ax, b2)
        ax.set_xticks(x, ["Нормален (BENIGN)", f"Атака ({ATTACKS[attack]['label']})"])
        ax.set_title(f"{ATTACKS[attack]['bg']}")
        ax.set_ylabel("Брой мрежови потоци")
        ax.yaxis.set_major_formatter(ps.THOUSANDS)
        ax.grid(axis="x", visible=False)
        ax.set_ylim(0, max(raw.values()) * 1.15)
        ax.legend(loc="upper right" if raw["ATTACK"] < raw["BENIGN"] * 0.8 else "upper left", fontsize=9)
    fig.tight_layout()
    return ps.save(fig, "p1_class_distribution")


def fig_mutual_information(mi, top_n=15):
    fig, axes = ps.grid(len(ATTACK_LIST), panel=(6.2, 5.0))
    for ax, attack in zip(axes, ATTACK_LIST):
        top = mi[attack].head(top_n)[::-1]
        ax.barh(top.index, top.values, height=0.62, color=ps.BLUE)
        ax.set_title(ATTACKS[attack]["bg"])
        ax.set_xlabel("Взаимна информация с етикета (nats)")
        ax.grid(axis="y", visible=False)
        for y, v in enumerate(top.values):
            ax.annotate(ps.fmt(v, 3), (v, y), xytext=(3, 0), textcoords="offset points", va="center",
                        fontsize=8.5 if not ps.SUFFIX else 10.5, color=ps.INK_2)
        ax.set_xlim(0, top.max() * 1.18)
    fig.tight_layout()
    return ps.save(fig, "p1_mutual_information")


def fig_correlation(dfs):
    fig, axes = ps.grid(len(ATTACK_LIST), panel=(6.0, 5.2))
    stats = {}
    for ax, attack in zip(axes, ATTACK_LIST):
        X, _ = to_xy(dfs[attack])
        corr = pd.DataFrame(signed_log1p(X), columns=X.columns).corr().fillna(0)
        im = ax.imshow(corr.to_numpy(), cmap="RdBu_r", vmin=-1, vmax=1, interpolation="nearest")
        ax.set_title(f"{ATTACKS[attack]['bg']}")
        ax.set_xlabel("Индекс на характеристика (0–77)")
        ax.set_ylabel("Индекс на характеристика (0–77)")
        ax.grid(False)
        upper = corr.where(np.triu(np.ones(corr.shape, dtype=bool), k=1)).stack().dropna()
        stats[attack] = {"pairs_abs_r_gt_0_95": int((upper.abs() > 0.95).sum()),
                         "pairs_abs_r_gt_0_80": int((upper.abs() > 0.80).sum()),
                         "pairs_total": int(len(upper))}
    cb = fig.colorbar(im, ax=axes, shrink=0.6, pad=0.02)
    cb.set_label("Коефициент на корелация на Пиърсън")
    return ps.save(fig, "p1_correlation"), stats


def distinct_top(df, ranking, k=4, max_abs_r=0.98):
    """Първите k характеристики по взаимна информация, без почти идентични двойки (|r| > 0.98)."""
    chosen = []
    for feat in ranking.index:
        x = signed_log1p(df[feat])
        if all(abs(np.corrcoef(x, signed_log1p(df[c]))[0, 1]) <= max_abs_r for c in chosen):
            chosen.append(feat)
        if len(chosen) == k:
            break
    return chosen


def fig_boxplots(dfs, mi):
    fig, axes = ps.plt.subplots(len(ATTACK_LIST), 4, figsize=(13, 3.3 * len(ATTACK_LIST)))
    for row, attack in zip(axes, ATTACK_LIST):
        df = dfs[attack]
        for ax, feat in zip(row, distinct_top(df, mi[attack])):
            data = [signed_log1p(df.loc[df[LABEL_COL] == BENIGN_LABEL, feat]),
                    signed_log1p(df.loc[df[LABEL_COL] != BENIGN_LABEL, feat])]
            bp = ax.boxplot(data, widths=0.5, patch_artist=True, showfliers=False,
                            medianprops={"color": ps.INK, "linewidth": 1.5})
            for patch, c in zip(bp["boxes"], (ps.BLUE, ps.ORANGE)):
                patch.set_facecolor(c)
                patch.set_alpha(0.85)
                patch.set_edgecolor(ps.SURFACE)
            ax.set_xticks([1, 2], ["BENIGN", ATTACKS[attack]["label"]])
            ax.set_title(feat, fontsize=10)
            ax.grid(axis="x", visible=False)
        row[0].set_ylabel(f"{ATTACKS[attack]['bg']}\nsign(x)·ln(1+|x|)")
    fig.tight_layout()
    return ps.save(fig, "p1_feature_boxplots")


def slide_figures(summary=None, mi=None):
    """Варианти на фигурите за презентацията (от записаните резултати, без преизчисляване)."""
    if summary is None:
        summary = json.loads((RESULTS_DIR / "phase1_summary.json").read_text(encoding="utf-8"))
    if mi is None:
        mi = {a: pd.read_csv(TABLES_DIR / f"{a}_mutual_information.csv", index_col=0).iloc[:, 0] for a in ATTACK_LIST}
    ps.slide_mode(True)
    fig_class_distribution(summary)
    fig_mutual_information(mi, top_n=8)
    ps.slide_mode(False)


def main():
    setup_console()
    ensure_dirs()
    ps.apply()
    if "--slide-figures" in sys.argv:
        slide_figures()
        return
    dlog = DataActionLog("step1_prepare_data", reset=True)
    t0 = time.time()
    log.info("=== ФАЗА 1: предварителна обработка ===")

    digest = sha256(RAW_ZIP)
    if digest != DATASET_SHA256:
        raise RuntimeError(f"SHA-256 не съвпада: {digest}")
    with zipfile.ZipFile(RAW_ZIP) as z:
        members = [(i.filename, i.file_size) for i in z.infolist() if not i.is_dir()]
    dlog.record("CIC-IDS2017", "Получаване на набора данни",
                "Изтеглен MachineLearningCSV.zip (235 102 953 B), проверена SHA-256 сума, разархивирани 8 CSV файла.",
                details={"източник": DATASET_MIRROR_URL, "sha256": digest, "файлове": members})

    summary, dfs, mi = {}, {}, {}
    for attack, meta in ATTACKS.items():
        log.info(f"[{attack}] зареждане на {meta['file']}")
        df = load_raw(attack)
        prof = raw_profile(df)
        lab = df[df.columns[-1]].astype(str).str.strip()
        prof["binary"] = {"BENIGN": int((lab == BENIGN_LABEL).sum()), "ATTACK": int(lab.isin(meta["positive"]).sum())}
        dlog.record(attack, "Зареждане и профилиране",
                    f"Зареден файл {meta['file']}: {num(prof['rows'])} реда × {prof['cols']} колони "
                    f"({prof['features']} характеристики + етикет).",
                    prof["rows"], prof["rows"], prof["cols"], prof["cols"],
                    {k: prof[k] for k in ("classes", "nan_cells", "inf_cells", "duplicate_rows")})
        dlog.record(attack, "Анализ на излишни колони (без премахване)",
                    f"{len(prof['constant_columns'])} константни колони и {len(prof['identical_column_pairs'])} "
                    "двойки идентични колони. Колоните се запазват – PCA им дава нулево/общо тегло.",
                    prof["rows"], prof["rows"], prof["cols"], prof["cols"],
                    {"константни": prof["constant_columns"], "идентични двойки": prof["identical_column_pairs"],
                     "отрицателни стойности (минимум)": prof["negative_value_columns"],
                     "редове с отрицателна Flow Duration": prof["negative_duration_rows"]})

        df = clean(df, attack, dlog)
        out = processed_path(attack)
        df.to_csv(out, index=False)
        dlog.record(attack, "Запис на обработения набор",
                    f"Записан {out.relative_to(out.parents[2]).as_posix()} ({num(len(df))} реда × {df.shape[1]} колони).",
                    len(df), len(df), df.shape[1], df.shape[1],
                    {"размер_MB": round(out.stat().st_size / 2**20, 1)})

        describe_by_class(df, attack)
        mi[attack] = mutual_information(df, attack)
        summary[attack] = {"file": meta["file"], "raw": prof,
                           "clean": {"rows": int(len(df)), "cols": int(df.shape[1]), "classes": class_counts(df),
                                     "binary": binary_counts(df)},
                           "top_mutual_information": mi[attack].head(15).round(4).to_dict()}
        dfs[attack] = df
        log.info(f"[{attack}] {num(prof['rows'])} -> {num(len(df))} реда; колони {prof['cols']} -> {df.shape[1]}")

    fig_class_distribution(summary)
    fig_mutual_information(mi)
    _, corr_stats = fig_correlation(dfs)
    fig_boxplots(dfs, mi)
    for attack in ATTACK_LIST:
        summary[attack]["correlation"] = corr_stats[attack]
    (RESULTS_DIR / "phase1_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2),
                                                     encoding="utf-8")
    slide_figures(summary, mi)
    log.info(f"Фаза 1 приключи за {time.time() - t0:.1f} s")


if __name__ == "__main__":
    main()
