"""ФАЗА 2 – графично представяне на експерименталните резултати (results/figures/p3_*.png).

Фигурите са по членове на екипа (суфикс _m1, _m2 – двете атаки и двата алгоритъма на съответния член)
и обобщени за всички 8 модела.
"""
import json

import numpy as np
import pandas as pd

import plot_style as ps
from config import ATTACKS, RESULTS_DIR, TABLES_DIR, TEAM, experiments, setup_console

ALG_LABEL = {"RF": "Random Forest", "KNN": "k-NN", "MLP": "MLP", "LR": "Лог. регресия"}

# Оси на топлинните карти на кръстосаното валидиране: (параметър по редове, стойности, етикети,
#                                                      параметър по колони, стойности, етикети)
GRID_AXES = {
    "RF": ("max_depth", [10, 20, None], ["10", "20", "без ограничение"],
           "n_estimators", [50, 100, 200], ["50", "100", "200"], "max_depth", "n_estimators (брой дървета)"),
    "KNN": ("weights", ["uniform", "distance"], ["uniform", "distance"],
            "n_neighbors", [1, 3, 5, 7, 9], ["1", "3", "5", "7", "9"], "weights (тегла)", "k (брой съседи)"),
    "MLP": ("alpha", [1e-4, 1e-3], ["0,0001", "0,001"],
            "hidden_layer_sizes", [(32,), (64,), (64, 32)], ["32", "64", "64–32"], "alpha (L2 регуляризация)",
            "скрити слоеве (неврони)"),
    "LR": ("class_weight", [None, "balanced"], ["еднакви", "balanced"],
           "C", [0.01, 0.1, 1, 10, 100], ["0,01", "0,1", "1", "10", "100"], "тегла на класовете",
           "C (обратна сила на регуляризацията)"),
}


def model_label(attack, alg):
    return f"{ATTACKS[attack]['label']} · {ALG_LABEL[alg]}"


def load():
    data = json.loads((RESULTS_DIR / "metrics.json").read_text(encoding="utf-8"))
    return {(m["attack"], m["algorithm"]): m for m in data["models"]}


def member_models(member):
    return [(a, g) for a in member["attacks"] for g in member["algorithms"]]


def _norm(v):
    return tuple(v) if isinstance(v, list) else v


def fig_cv_heatmaps(res, member, suffix):
    models = member_models(member)
    fig, axes = ps.grid(len(models), panel=(6.0, 3.6))
    cmap = ps.matplotlib.colors.LinearSegmentedColormap.from_list("blues", ps.SEQ_BLUES)
    for ax, (attack, alg) in zip(axes, models):
        rp, rvals, rlabs, cp, cvals, clabs, ylab, xlab = GRID_AXES[alg]
        cvr = pd.read_csv(TABLES_DIR / f"{attack}_{alg}_cv_results.csv")
        params = cvr["params"].apply(eval)
        M = np.full((len(rvals), len(cvals)), np.nan)
        for p, f1 in zip(params, cvr["mean_test_f1"]):
            M[rvals.index(p[f"clf__{rp}"]), cvals.index(p[f"clf__{cp}"])] = f1 * 100
        im = ax.imshow(M, cmap=cmap, aspect="auto")
        best = res[(attack, alg)]["best_params"]
        bi, bj = rvals.index(_norm(best[rp])), cvals.index(_norm(best[cp]))
        decimals = 3 if np.nanmin(M) > 99 else 2
        for i in range(len(rvals)):
            for j in range(len(cvals)):
                v = M[i, j]
                lum = (v - np.nanmin(M)) / ((np.nanmax(M) - np.nanmin(M)) or 1)
                is_best = (i, j) == (bi, bj)
                ax.text(j, i, ps.fmt(v, decimals) + ("\n(най-добър)" if is_best else ""), ha="center", va="center",
                        fontsize=9, color="white" if lum > 0.55 else ps.INK, fontweight="bold" if is_best else "normal")
        ax.set_xticks(range(len(cvals)), clabs)
        ax.set_yticks(range(len(rvals)), rlabs)
        ax.set_xlabel(xlab)
        ax.set_ylabel(ylab)
        ax.grid(False)
        ax.set_title(f"{ATTACKS[attack]['bg']} – {ALG_LABEL[alg]}")
        cb = fig.colorbar(im, ax=ax, shrink=0.9, pad=0.02)
        cb.set_label("Средна F1 при CV (%)", fontsize=9)
    fig.tight_layout()
    return ps.save(fig, f"p3_cv_heatmaps{suffix}")


def _confusion_panel(ax, m, attack, alg, fontsize=11):
    cmap = ps.matplotlib.colors.LinearSegmentedColormap.from_list("blues", ["#f2f7fd"] + ps.SEQ_BLUES[2:])
    M = np.array([[m["TN"], m["FP"]], [m["FN"], m["TP"]]])
    pct = M / M.sum(axis=1, keepdims=True) * 100
    ax.imshow(np.log10(M + 1), cmap=cmap, vmin=0, vmax=np.log10(M.max() + 1))
    names = [["TN", "FP"], ["FN", "TP"]]
    for i in range(2):
        for j in range(2):
            dark = np.log10(M[i, j] + 1) > 0.6 * np.log10(M.max() + 1)
            ax.text(j, i, f"{names[i][j]}\n{ps.fmt(M[i, j])}\n({ps.fmt(pct[i, j], 3)} %)", ha="center", va="center",
                    fontsize=fontsize, color="white" if dark else ps.INK, fontweight="semibold")
    lab = ATTACKS[attack]["label"]
    ax.set_xticks([0, 1], ["BENIGN", lab])
    ax.set_yticks([0, 1], ["BENIGN", lab])
    ax.set_xlabel("Прогнозиран клас")
    ax.set_ylabel("Действителен клас")
    ax.grid(False)
    ax.set_title(f"{ATTACKS[attack]['bg']} – {ALG_LABEL[alg]}", fontsize=11)


def fig_confusion(res, models, name, phase="test", ncols=2, panel=(5.25, 4.5), fontsize=11):
    fig, axes = ps.grid(len(models), ncols=ncols, panel=panel)
    for ax, (attack, alg) in zip(axes, models):
        _confusion_panel(ax, res[(attack, alg)][phase], attack, alg, fontsize)
    fig.tight_layout()
    return ps.save(fig, name)


def fig_metrics_dotplot(res):
    metrics = [("accuracy", "Accuracy (точност)"), ("precision", "Precision (прецизност)"),
               ("sensitivity", "Sensitivity (чувствителност)"), ("specificity", "Specificity (специфичност)"),
               ("f1", "F1 мярка")]
    attacks = list(ATTACKS)
    fig, axes = ps.grid(len(attacks), panel=(6.3, 4.4))
    y = np.arange(len(metrics))[::-1]
    for idx, (ax, attack) in enumerate(zip(axes, attacks)):
        algs = [g for a, g in experiments() if a == attack]
        lo = 100
        for k, alg in enumerate(algs):
            vals = np.array([res[(attack, alg)]["test"][m] * 100 for m, _ in metrics])
            lo = min(lo, vals.min())
            off = 0.13 if k == 0 else -0.13
            ax.scatter(vals, y + off, s=70, color=ps.ALG_COLORS[alg], edgecolor=ps.SURFACE, linewidth=2, zorder=3,
                       label=ALG_LABEL[alg])
            for v, yy in zip(vals, y + off):
                ax.annotate(ps.fmt(v, 3), (v, yy), xytext=(0, 7 if k == 0 else -13),
                            textcoords="offset points", ha="center", fontsize=8.5, color=ps.INK_2)
        span = 100 - lo
        step = 0.01 if span < 0.08 else 0.02 if span < 0.15 else 0.05 if span < 0.4 else 0.2 if span < 1.5 else 1.0
        left = np.floor((lo - step) / step) * step
        ax.set_xlim(left, 100 + step / 2)
        ax.set_xticks(np.arange(left, 100 + 1e-9, step))
        dec = 2 if step < 0.1 else 1 if step < 1 else 0
        ax.xaxis.set_major_formatter(ps.matplotlib.ticker.FuncFormatter(lambda v, _, d=dec: ps.fmt(v, d)))
        ax.set_yticks(y, [lab for _, lab in metrics] if idx % 2 == 0 else [""] * len(metrics))
        ax.set_xlabel("Стойност върху тестовото множество (%)")
        ax.set_title(ATTACKS[attack]["bg"])
        ax.grid(axis="y", visible=False)
        if not ps.SUFFIX:
            ax.legend(loc="lower left")
    fig.tight_layout()
    if ps.SUFFIX:
        ps.top_legend(fig, [(ALG_LABEL[g], ps.ALG_COLORS[g]) for g in ("RF", "KNN", "MLP", "LR")])
    return ps.save(fig, "p3_metrics_comparison")


def fig_counts(res):
    models = experiments()
    labels = [model_label(a, g) for a, g in models]
    x = np.arange(len(labels))
    fig, axes = ps.plt.subplots(2, 1, figsize=(13, 9))
    for ax, pair, title in ((axes[0], ("TP", "TN"), "Верни решения (TP, TN)"),
                            (axes[1], ("FP", "FN"), "Фалшиви тревоги и пропуснати атаки (FP, FN)")):
        w = 0.36
        all_vals = []
        for k, (key, color) in enumerate(zip(pair, (ps.BLUE, ps.ORANGE))):
            vals = [res[m]["test"][key] for m in models]
            all_vals += vals
            bars = ax.bar(x + (k - 0.5) * (w + 0.02), vals, w, color=color, label=key)
            ps.bar_labels(ax, bars)
        ax.set_xticks(x, labels, rotation=10)
        ax.set_ylabel("Брой потоци (тестово множество)")
        ax.set_title(title)
        ax.grid(axis="x", visible=False)
        if pair == ("FP", "FN") and max(all_vals) > 40 * max(1, sorted(all_vals)[len(all_vals) // 2]):
            ax.set_yscale("symlog", linthresh=10)
            ax.set_ylim(0, max(all_vals) * 3)
            ax.set_ylabel("Брой потоци (симетрична логаритмична скала)")
        else:
            ax.set_ylim(0, max(all_vals) * 1.15)
        ax.yaxis.set_major_formatter(ps.THOUSANDS)
        ax.legend(loc="upper left")
    fig.tight_layout()
    return ps.save(fig, "p3_tp_tn_fp_fn")


def fig_fp_fn(res):
    """Само FP и FN (за презентацията) – логаритмична скала, защото стойностите са от 0 до стотици."""
    models = experiments()
    labels = [model_label(a, g) for a, g in models]
    x = np.arange(len(labels))
    fig, ax = ps.plt.subplots(figsize=(13, 5.2))
    w = 0.36
    vals_all = []
    for k, (key, color, name) in enumerate((("FP", ps.BLUE, "FP – фалшиви тревоги"),
                                            ("FN", ps.ORANGE, "FN – пропуснати атаки"))):
        vals = [res[m]["test"][key] for m in models]
        vals_all += vals
        heights = [v if v > 0 else np.nan for v in vals]   # нулата не се рисува като стълб, а само като надпис
        bars = ax.bar(x + (k - 0.5) * (w + 0.02), heights, w, color=color, label=name)
        for b, v in zip(bars, vals):
            ax.annotate(ps.fmt(v), (b.get_x() + b.get_width() / 2, max(v, 0.6)), xytext=(0, 3),
                        textcoords="offset points", ha="center", va="bottom", color=ps.INK_2, fontsize=10)
    ax.set_yscale("log")
    ax.set_ylim(0.5, max(vals_all) * 4)
    ax.yaxis.set_major_formatter(ps.THOUSANDS)
    ax.set_xticks(x, labels, rotation=10)
    ax.set_ylabel("Брой потоци (логаритмична скала)")
    ax.grid(axis="x", visible=False)
    ax.legend(loc="upper left")
    fig.tight_layout()
    return ps.save(fig, "p3_fp_fn")


def fig_roc(res):
    attacks = list(ATTACKS)
    fig, axes = ps.grid(len(attacks), panel=(6.0, 4.4))
    for ax, attack in zip(axes, attacks):
        lows = []
        for alg in [g for a, g in experiments() if a == attack]:
            r = res[(attack, alg)]
            fpr = np.maximum(np.array(r["roc"]["fpr"]), 1e-5)
            tpr = np.array(r["roc"]["tpr"]) * 100
            ax.plot(fpr * 100, tpr, color=ps.ALG_COLORS[alg], drawstyle="steps-post",
                    label=f"{ALG_LABEL[alg]} (AUC = {ps.fmt(r['test']['roc_auc'], 5)})")
            at = tpr[np.searchsorted(fpr, 1e-3, side="right") - 1] if (fpr <= 1e-3).any() else tpr.min()
            lows.append(at)
        lo = min(99.8, np.floor(min(lows) * 10) / 10 - 0.1)
        ax.set_xscale("log")
        ax.set_xlim(1e-3, 100)
        ax.set_ylim(max(0, lo), 100 + (100 - lo) * 0.05)
        ax.set_xlabel("Дял фалшиви тревоги FPR (%, лог. скала)")
        ax.set_ylabel("Чувствителност TPR (%)")
        ax.set_title(ATTACKS[attack]["bg"])
        ax.legend(loc="lower right", fontsize=9)
    fig.tight_layout()
    return ps.save(fig, "p3_roc_curves")


def fig_timing(res):
    models = experiments()
    labels = [model_label(a, g) for a, g in models]
    colors = [ps.ALG_COLORS[g] for _, g in models]
    fig, axes = ps.plt.subplots(2, 1, figsize=(13, 8.4))
    for ax, key, title, unit, suffix in (
            (axes[0], "refit_seconds", "Време за обучение на финалния модел", "Секунди", " s"),
            (axes[1], "latency_us_per_flow", "Време за класификация на един поток", "Микросекунди на поток", " µs")):
        vals = [res[m]["timing"][key] for m in models]
        bars = ax.bar(labels, vals, 0.55, color=colors)
        ps.bar_labels(ax, bars, decimals=1, suffix=suffix)
        ax.set_ylabel(unit)
        ax.set_title(title)
        ax.grid(axis="x", visible=False)
        ax.tick_params(axis="x", rotation=10)
        ax.set_ylim(0, max(vals) * 1.18)
    handles = [ps.matplotlib.patches.Patch(color=ps.ALG_COLORS[g], label=ALG_LABEL[g])
               for g in dict.fromkeys(g for _, g in models)]
    axes[0].legend(handles=handles, loc="upper right", ncols=4)
    fig.tight_layout()
    return ps.save(fig, "p3_timing")


def fig_validation_vs_test(res):
    models = experiments()
    labels = [model_label(a, g) for a, g in models]
    x = np.arange(len(labels))
    fig, axes = ps.plt.subplots(2, 1, figsize=(13, 8.4))
    for ax, key, title in ((axes[0], "fpr", "Дял фалшиви тревоги FPR"), (axes[1], "fnr", "Дял пропуснати атаки FNR")):
        w = 0.36
        for k, (phase, color, name) in enumerate((("validation", ps.BLUE, "Валидиране (5-fold CV)"),
                                                  ("test", ps.ORANGE, "Оперативен тест"))):
            vals = [res[m][phase][key] * 100 for m in models]
            bars = ax.bar(x + (k - 0.5) * (w + 0.02), vals, w, color=color, label=name)
            ps.bar_labels(ax, bars, decimals=3, fontsize=8)
        ax.set_xticks(x, labels, rotation=10)
        ax.set_ylabel("%")
        ax.set_title(title)
        ax.grid(axis="x", visible=False)
        ax.set_ylim(0, ax.get_ylim()[1] * 1.15)
        ax.legend(loc="upper left")
    fig.tight_layout()
    return ps.save(fig, "p3_validation_vs_test")


def fig_methodology():
    """Схема на методологията (две фази, последователни стъпки)."""
    from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
    dim = json.loads((RESULTS_DIR / "dimensionality_summary.json").read_text(encoding="utf-8"))
    ks = sorted({v["n_components_99"] for v in dim.values()})
    k_txt = f"{ks[0]}–{ks[-1]}" if len(ks) > 1 else str(ks[0])
    fig, ax = ps.plt.subplots(figsize=(13, 5.0))
    ax.set_xlim(0, 13)
    ax.axis("off")
    rows = [
        (3.55, "ФАЗА 1 · Данни и предварителна обработка", ps.BLUE, [
            "CIC-IDS2017\n4 атаки: DDoS, PortScan,\nDoS, Brute Force",
            "Почистване\nимена · NaN/Inf ·\nдубликати",
            "Разделяне\n70 % обучение\n30 % тест",
            "Трансформация\nsign·ln(1+|x|) +\nстандартизация",
            f"Редукция на\nразмерността\nPCA 78 → {k_txt}"]),
        (1.05, "ФАЗА 2 · Машинно обучение и оперативна фаза", ps.ORANGE, [
            "8 модела\nRF · k-NN\nMLP · Лог. регресия",
            "GridSearchCV\n5-кратно\nкръстосано вал.",
            "Финален модел\n(обучен върху\n70 %)",
            "Оперативен тест\n30 % невиждани\nпотоци",
            "Метрики\nTP TN FP FN\nPrec. Acc. Sens."]),
    ]
    w, h, gap, x0 = 2.18, 1.25, 0.42, 0.25
    for y, title, color, boxes in rows:
        ax.text(x0, y + h + 0.18, title, fontsize=11.5, fontweight="semibold", color=ps.INK)
        for i, label in enumerate(boxes):
            x = x0 + i * (w + gap)
            ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.12",
                                        facecolor=color, edgecolor="none", alpha=0.12))
            ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.12",
                                        facecolor="none", edgecolor=color, lw=1.4))
            ax.text(x + w / 2, y + h / 2, label, ha="center", va="center", fontsize=10, color=ps.INK,
                    linespacing=1.35)
            if i < len(boxes) - 1:
                ax.add_patch(FancyArrowPatch((x + w + 0.04, y + h / 2), (x + w + gap - 0.04, y + h / 2),
                                             arrowstyle="-|>", mutation_scale=14, color=ps.INK_2, lw=1.3))
    last_x = x0 + 4 * (w + gap) + w / 2
    y_mid, x_left = 3.12, 0.08
    ax.plot([last_x, last_x, x_left, x_left], [3.55 - 0.04, y_mid, y_mid, 1.05 + h / 2], color=ps.INK_2,
            lw=1.3, solid_joinstyle="round")
    ax.add_patch(FancyArrowPatch((x_left, 1.05 + h / 2), (x0 - 0.03, 1.05 + h / 2), arrowstyle="-|>",
                                 mutation_scale=14, color=ps.INK_2, lw=1.3))
    ax.set_ylim(0.75, 5.0)
    return ps.save(fig, "p0_methodology")


def main():
    setup_console()
    ps.apply()
    print("записана", fig_methodology())
    res = load()
    for i, member in enumerate(TEAM, 1):
        if all(m in res for m in member_models(member)):
            print("записана", fig_cv_heatmaps(res, member, f"_m{i}"))
            print("записана", fig_confusion(res, member_models(member), f"p3_confusion_matrices_m{i}"))
            print("записана", fig_confusion(res, member_models(member), f"p3_confusion_matrices_validation_m{i}",
                                            phase="validation"))
    if all(m in res for m in experiments()):
        print("записана", fig_confusion(res, experiments(), "p3_confusion_matrices_all", ncols=4,
                                        panel=(4.2, 3.7), fontsize=9.5))
        for f in (fig_metrics_dotplot, fig_counts, fig_fp_fn, fig_roc, fig_timing, fig_validation_vs_test):
            print("записана", f(res))
        ps.slide_mode(True)
        print("записана", fig_metrics_dotplot(res))
        print("записана", fig_confusion(res, experiments(), "p3_confusion_matrices_all", ncols=4,
                                        panel=(4.2, 3.7), fontsize=11.5))
        ps.slide_mode(False)


if __name__ == "__main__":
    main()
