"""Проверка за преобучение (overfitting) на 8-те модела – без повторно обучение.

За всеки модел се сравняват:
  * Accuracy върху обучаващото множество (финалният модел, обучен върху него);
  * средна Accuracy ± стандартно отклонение при 5-кратното кръстосано валидиране (от GridSearchCV);
  * Accuracy на out-of-fold прогнозите при валидирането;
  * Accuracy върху невижданото тестово множество (оперативна фаза).
Преобученият модел има висока точност при обучението и забележимо по-ниска при валидирането и теста.

Изход: results/overfitting_check.json, results/figures/p3_overfitting.png
"""
import json
import math
import time

import joblib
import numpy as np

import plot_style as ps
from action_log import get_logger
from config import ATTACKS, MODELS_DIR, RESULTS_DIR, experiments, setup_console
from preprocessing import get_split

log = get_logger()
ALG_LABEL = {"RF": "Random Forest", "KNN": "k-NN", "MLP": "MLP", "LR": "Лог. регресия"}


def compute():
    metrics = {(m["attack"], m["algorithm"]): m for m in
               json.loads((RESULTS_DIR / "metrics.json").read_text(encoding="utf-8"))["models"]}
    out, cache = [], {}
    for attack, alg in experiments():
        if attack not in cache:
            cache = {attack: get_split(attack)}
        X_tr, _, y_tr, _ = cache[attack]
        model = joblib.load(MODELS_DIR / f"{attack}_{alg}.joblib")
        t = time.perf_counter()
        train_acc = float((model.predict(X_tr) == y_tr).mean())
        r = metrics[(attack, alg)]
        row = {"attack": attack, "algorithm": alg,
               "train_accuracy": train_acc,
               "cv_accuracy_mean": r["cv"]["best_mean"]["accuracy"], "cv_accuracy_std": r["cv"]["best_std"]["accuracy"],
               "cv_f1_mean": r["cv"]["best_mean"]["f1"], "cv_f1_std": r["cv"]["best_std"]["f1"],
               "validation_accuracy": r["validation"]["accuracy"], "test_accuracy": r["test"]["accuracy"],
               "test_roc_auc": r["test"]["roc_auc"], "best_params": r["best_params"]}
        row["gap_train_test_pp"] = (row["train_accuracy"] - row["test_accuracy"]) * 100
        row["gap_val_test_pp"] = (row["validation_accuracy"] - row["test_accuracy"]) * 100
        sd = max(row["cv_accuracy_std"], 1e-9)
        row["test_vs_cv_sigma"] = (row["test_accuracy"] - row["cv_accuracy_mean"]) / sd
        out.append(row)
        log.info(f"[overfitting] {attack}_{alg}: train={train_acc:.5f} cv={row['cv_accuracy_mean']:.5f}±"
                 f"{row['cv_accuracy_std']:.5f} oof={row['validation_accuracy']:.5f} test={row['test_accuracy']:.5f} "
                 f"({time.perf_counter() - t:.0f} s)")
    (RESULTS_DIR / "overfitting_check.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def wilson(k, total, z=1.96):
    """95 % доверителен интервал на Уилсън за дял k / total."""
    p = k / total
    den = 1 + z ** 2 / total
    centre = (p + z ** 2 / (2 * total)) / den
    half = z * math.sqrt(p * (1 - p) / total + z ** 2 / (4 * total ** 2)) / den
    return centre - half, centre + half


def figure(rows):
    """Дял грешки (%) при обучение, кръстосано валидиране (± σ) и тест (95 % ДИ) – логаритмична скала."""
    metrics = {(m["attack"], m["algorithm"]): m for m in
               json.loads((RESULTS_DIR / "metrics.json").read_text(encoding="utf-8"))["models"]}
    fig, ax = ps.plt.subplots(figsize=(13, 5.4))
    x = np.arange(len(rows))
    floor = 2e-4
    tr = [(1 - r["train_accuracy"]) * 100 for r in rows]
    cv = [(1 - r["cv_accuracy_mean"]) * 100 for r in rows]
    cv_sd = [r["cv_accuracy_std"] * 100 for r in rows]
    te, te_lo, te_hi = [], [], []
    for r in rows:
        t = metrics[(r["attack"], r["algorithm"])]["test"]
        total = t["TP"] + t["TN"] + t["FP"] + t["FN"]
        lo, hi = wilson(t["TP"] + t["TN"], total)
        e = (1 - r["test_accuracy"]) * 100
        te.append(e)
        te_lo.append(e - (1 - hi) * 100)
        te_hi.append((1 - lo) * 100 - e)
    for xi, v in zip(x, tr):
        if v > 0:
            ax.scatter(xi - 0.2, v, s=70, color=ps.MUTED, edgecolor=ps.SURFACE, linewidth=2, zorder=3)
        else:
            ax.scatter(xi - 0.2, floor, s=70, facecolor="none", edgecolor=ps.MUTED, linewidth=1.8, zorder=3)
            ax.annotate("0 грешки", (xi - 0.2, floor), xytext=(0, 9), textcoords="offset points", ha="center",
                        fontsize=8.5, color=ps.INK_2)
    ax.scatter([], [], s=70, color=ps.MUTED, label="Обучаващо множество")
    lo_cv = [min(c * 0.95, s_) for c, s_ in zip(cv, cv_sd)]
    ax.errorbar(x, cv, yerr=[lo_cv, cv_sd], fmt="o", ms=8, color=ps.BLUE, ecolor=ps.BLUE, elinewidth=2, capsize=5,
                mec=ps.SURFACE, mew=2, zorder=4, label="Кръстосано валидиране (средно ± σ)")
    ax.errorbar(x + 0.2, te, yerr=[te_lo, te_hi], fmt="o", ms=8, color=ps.ORANGE, ecolor=ps.ORANGE, elinewidth=2,
                capsize=5, mec=ps.SURFACE, mew=2, zorder=5, label="Оперативен тест (95 % доверителен интервал)")
    for xi, v, h in zip(x, te, te_hi):
        ax.annotate(ps.fmt(v, 3) + " %", (xi + 0.2, v), xytext=(7, 0), textcoords="offset points", va="center",
                    fontsize=8.5, color=ps.INK_2)
    ax.set_yscale("log")
    ax.set_ylim(1e-4, 4)
    ax.yaxis.set_major_formatter(ps.matplotlib.ticker.FuncFormatter(
        lambda v, _: ps.fmt(v, 4 if v < 0.001 else 3 if v < 0.01 else 2 if v < 0.1 else 1 if v < 1 else 0) + " %"))
    ax.set_xticks(x, [ATTACKS[r["attack"]]["label"] + "\n" + ALG_LABEL[r["algorithm"]] for r in rows])
    ax.set_ylabel("Дял грешни класификации (лог. скала)")
    ax.grid(axis="x", visible=False)
    ax.legend(loc="upper left", ncols=3)
    fig.tight_layout()
    return ps.save(fig, "p3_overfitting")


def main():
    setup_console()
    ps.apply()
    path = RESULTS_DIR / "overfitting_check.json"
    import sys
    rows = json.loads(path.read_text(encoding="utf-8")) if "--figures-only" in sys.argv and path.exists() else compute()
    print("записана", figure(rows))


if __name__ == "__main__":
    main()
