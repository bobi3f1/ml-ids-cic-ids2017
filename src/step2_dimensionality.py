"""ФАЗА 1 (продължение) – редукция на размерността на вектора на характеристиките чрез PCA.

PCA се обучава само върху обучаващото множество (70 %). Колоните на набора данни не се премахват –
всички 78 характеристики участват в линейните комбинации (главните компоненти).

Експеримент „брой компоненти“: обучаващото множество се разделя 80/20 (подобучаващо/валидиращо)
и за n = 1 … 78 компоненти се измерва качеството на двата алгоритъма, избрани за съответната атака.

Изпълнение:
  python src/step2_dimensionality.py                     – всичко
  python src/step2_dimensionality.py --only DoS,BruteForce – експериментът с компонентите само за тези атаки
  python src/step2_dimensionality.py --figures-only      – само PCA и фигури (експериментът се чете от CSV)
  python src/step2_dimensionality.py --fill-k            – добавя само точката n = k (99 % дисперсия), ако липсва

Изход: results/dimensionality_summary.json, results/tables/*_pca_*.csv, results/figures/p2_*.png
"""
import json
import sys
import time

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

import plot_style as ps
from action_log import DataActionLog, get_logger, num
from config import (ALGORITHMS, ATTACKS, PCA_VARIANCE, RANDOM_STATE, RESULTS_DIR, TABLES_DIR, algorithms_for,
                    ensure_dirs, setup_console)
from preprocessing import build_pipeline, get_split

log = get_logger()
SWEEP = [1, 2, 3, 4, 6, 8, 10, 13, 16, 19, 22, 26, 30, 40, 55, 78]
# Фиксирани (неоптимизирани) параметри за експеримента с броя компоненти
SWEEP_PARAMS = {"RF": {"n_estimators": 100}, "KNN": {"n_neighbors": 5}, "MLP": {}, "LR": {}}
SWEEP_LABEL = {"RF": "Random Forest (100 дървета)", "KNN": "k-NN (k = 5)", "MLP": "MLP (64 неврона)",
               "LR": "Логистична регресия (C = 1)"}
ATTACK_LIST = list(ATTACKS)


def preprocessor(X_train):
    """Първите три стъпки на конвейера (log -> scaler -> PCA с всички компоненти)."""
    pipe = build_pipeline("RF", n_components=None)
    pre = Pipeline(pipe.steps[:3])
    return pre.fit(X_train)


def component_sweep(X_train, y_train, attack, ns=SWEEP):
    X_sub, X_val, y_sub, y_val = train_test_split(X_train, y_train, test_size=0.2, stratify=y_train,
                                                  random_state=RANDOM_STATE)
    rows = []
    for n in ns:
        for alg in algorithms_for(attack):
            model = build_pipeline(alg, n_components=n, **SWEEP_PARAMS[alg])
            t = time.perf_counter()
            model.fit(X_sub, y_sub)
            fit_s = time.perf_counter() - t
            t = time.perf_counter()
            pred = model.predict(X_val)
            pred_s = time.perf_counter() - t
            tn, fp, fn, tp = confusion_matrix(y_val, pred).ravel()
            rows.append({"attack": attack, "algorithm": alg, "n_components": n,
                         "accuracy": accuracy_score(y_val, pred), "f1": f1_score(y_val, pred),
                         "FP": int(fp), "FN": int(fn), "errors": int(fp + fn),
                         "fit_s": round(fit_s, 2), "predict_s": round(pred_s, 2)})
            log.info(f"[{attack}] sweep n={n:>2} {alg:<3} acc={rows[-1]['accuracy']:.5f} "
                     f"F1={rows[-1]['f1']:.5f} FP={fp} FN={fn} fit={fit_s:.1f}s pred={pred_s:.1f}s")
    return pd.DataFrame(rows), len(X_sub), len(X_val)


# ------------------------------------------------------------------------------------------- фигури
def fig_variance(info):
    fig, ax = ps.plt.subplots(figsize=(9, 4.6))
    for color, attack in zip(ps.SERIES, ATTACK_LIST):
        cum = np.array(info[attack]["cumulative_variance"])
        n = np.arange(1, len(cum) + 1)
        k = info[attack]["n_components_99"]
        ax.plot(n, cum * 100, color=color, label=f"{ATTACKS[attack]['bg']} ({k} компоненти)")
        ax.plot(k, cum[k - 1] * 100, "o", ms=8, color=color, mec=ps.SURFACE, mew=2, zorder=5)
    ax.axhline(PCA_VARIANCE * 100, color=ps.MUTED, lw=1)
    ax.annotate(f"праг {ps.fmt(PCA_VARIANCE * 100)} % обяснена дисперсия", (78, PCA_VARIANCE * 100), xytext=(0, -14),
                textcoords="offset points", ha="right", color=ps.INK_2, fontsize=9)
    ax.set_xlabel("Брой главни компоненти")
    ax.set_ylabel("Кумулативна обяснена дисперсия (%)")
    ax.set_xlim(0, 79)
    ax.set_ylim(0, 102)
    ax.legend(loc="lower right", title="Атака (компоненти за 99 %)", title_fontsize=9.5)
    return ps.save(fig, "p2_pca_variance")


def fig_scatter(scatter):
    fig, axes = ps.grid(len(ATTACK_LIST), panel=(6.0, 4.8))
    for ax, attack in zip(axes, ATTACK_LIST):
        Z, y = scatter[attack]
        for cls, color, name in ((0, ps.BLUE, "BENIGN"), (1, ps.ORANGE, ATTACKS[attack]["label"])):
            m = y == cls
            ax.scatter(Z[m, 0], Z[m, 1], s=5, alpha=0.35, color=color, label=name, linewidths=0, rasterized=True)
        ax.set_title(ATTACKS[attack]["bg"])
        ax.set_xlabel("Главна компонента PC1")
        ax.set_ylabel("Главна компонента PC2")
        leg = ax.legend(loc="upper right", markerscale=3)
        for h in leg.legend_handles:
            h.set_alpha(1)
    fig.tight_layout()
    return ps.save(fig, "p2_pca_scatter")


def fig_loadings(loadings):
    fig, axes = ps.grid(len(ATTACK_LIST), panel=(7.0, 5.6), gridspec_kw={"wspace": 0.62, "hspace": 0.3})
    for ax, attack in zip(axes, ATTACK_LIST):
        L = loadings[attack]
        top = L.abs().sum(axis=1).sort_values(ascending=False).head(14).index
        sub = L.loc[top]
        im = ax.imshow(sub.to_numpy(), cmap="RdBu_r", vmin=-0.35, vmax=0.35, aspect="auto")
        ax.set_yticks(range(len(top)), top, fontsize=9)
        ax.set_xticks(range(sub.shape[1]), sub.columns)
        ax.set_title(ATTACKS[attack]["bg"])
        ax.grid(False)
        for i in range(sub.shape[0]):
            for j in range(sub.shape[1]):
                v = sub.iat[i, j]
                ax.text(j, i, ("+" if v >= 0 else "−") + ps.fmt(abs(v), 2), ha="center", va="center", fontsize=7.5,
                        color="white" if abs(v) > 0.22 else ps.INK)
    cb = fig.colorbar(im, ax=axes, shrink=0.6, pad=0.02)
    cb.set_label("Тегло (натоварване) на характеристиката")
    return ps.save(fig, "p2_pca_loadings")


def fig_sweep(sweep, info):
    fig, axes = ps.grid(len(ATTACK_LIST), panel=(6.0, 4.4))
    for ax, attack in zip(axes, ATTACK_LIST):
        d = sweep[sweep.attack == attack]
        n_val = info[attack]["sweep_sizes"]["validation"]
        for alg in algorithms_for(attack):
            s_ = d[d.algorithm == alg]
            ax.plot(s_.n_components, np.maximum(s_.errors, 0.7), color=ps.ALG_COLORS[alg], marker="o", ms=5,
                    mec=ps.SURFACE, mew=1.5, label=SWEEP_LABEL[alg])
        k = info[attack]["n_components_99"]
        ax.axvline(k, color=ps.MUTED, lw=1)
        ax.set_xscale("log")
        ax.set_yscale("log")
        top = max(2e4, d.errors.max() * 2)
        ax.set_ylim(0.6, top)
        ax.annotate(f"99 % дисперсия\n{k} компонента", (k, top), xytext=(5, -6), textcoords="offset points",
                    va="top", fontsize=9, color=ps.INK_2)
        ax.set_xticks(SWEEP[::2] + [78], [str(v) for v in SWEEP[::2] + [78]])
        ax.minorticks_off()
        ax.yaxis.set_major_formatter(ps.THOUSANDS)
        ax.set_title(ATTACKS[attack]["bg"])
        ax.set_xlabel("Брой главни компоненти (логаритмична скала)")
        if ps.SUFFIX:
            ax.set_ylabel("Грешки FP + FN")
        else:
            ax.set_ylabel(f"Грешки FP + FN (от {ps.fmt(n_val)} потока)")
            ax.legend(loc="lower left", fontsize=9)
    fig.tight_layout()
    if ps.SUFFIX:
        ps.top_legend(fig, [(SWEEP_LABEL[g], ps.ALG_COLORS[g]) for g in ("RF", "KNN", "MLP", "LR")], line=True)
    return ps.save(fig, "p2_pca_sweep")


def main():
    setup_console()
    ensure_dirs()
    ps.apply()
    dlog = DataActionLog("step2_dimensionality")
    log.info("=== ФАЗА 1: редукция на размерността (PCA) ===")
    figures_only = "--figures-only" in sys.argv
    only = None
    if "--only" in sys.argv:
        only = sys.argv[sys.argv.index("--only") + 1].split(",")
    summary_path = RESULTS_DIR / "dimensionality_summary.json"
    previous = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.exists() else {}
    sweep_path = TABLES_DIR / "pca_component_sweep.csv"
    old_sweep = pd.read_csv(sweep_path) if sweep_path.exists() else pd.DataFrame(columns=["attack"])
    info, scatter, loadings, sweeps = {}, {}, {}, []
    for attack in ATTACK_LIST:
        X_train, X_test, y_train, y_test = get_split(attack)
        dlog.record(attack, "Разделяне на обучаващо/тестово множество",
                    f"Стратифицирано разделяне 70/30 (random_state={RANDOM_STATE}): "
                    f"{num(len(X_train))} за обучение и валидиране, {num(len(X_test))} за оперативен тест.",
                    len(X_train) + len(X_test), len(X_train) + len(X_test), X_train.shape[1] + 1, X_train.shape[1] + 1,
                    {"обучение": {"общо": len(X_train), "атака": int(y_train.sum())},
                     "тест": {"общо": len(X_test), "атака": int(y_test.sum())}})
        pre = preprocessor(X_train)
        pca = pre.named_steps["pca"]
        cum = np.cumsum(pca.explained_variance_ratio_)
        k99 = int(np.searchsorted(cum, PCA_VARIANCE) + 1)
        comps = pd.DataFrame(pca.components_[:5].T, index=X_train.columns,
                             columns=[f"PC{i}" for i in range(1, 6)])
        comps.to_csv(TABLES_DIR / f"{attack}_pca_loadings.csv", encoding="utf-8-sig")
        pd.DataFrame({"component": np.arange(1, len(cum) + 1), "explained_variance_ratio": pca.explained_variance_ratio_,
                      "cumulative": cum}).to_csv(TABLES_DIR / f"{attack}_pca_variance.csv", index=False)
        loadings[attack] = comps
        info[attack] = {"n_features": int(X_train.shape[1]), "n_components_99": k99,
                        "variance_pc1_pc2": float(cum[1]),
                        "n_components_90": int(np.searchsorted(cum, 0.90) + 1),
                        "n_components_95": int(np.searchsorted(cum, 0.95) + 1),
                        "cumulative_variance": cum.round(6).tolist(),
                        "zero_variance_components": int((pca.explained_variance_ratio_ < 1e-12).sum())}
        dlog.record(attack, "Редукция на размерността (PCA)",
                    f"Вектор на характеристиките 78 → {k99} главни компоненти ({ps.fmt(PCA_VARIANCE * 100)} % обяснена "
                    f"дисперсия, намаление {ps.fmt((1 - k99 / 78) * 100)} %). PCA е стъпка от конвейера, обучава се само "
                    "върху обучаващите данни; колоните в набора остават непроменени (79).",
                    details={"трансформации": ["sign(x)·ln(1+|x|)", "StandardScaler", f"PCA(n_components={PCA_VARIANCE})"],
                             "компоненти за 90/95/99 %": [info[attack]["n_components_90"],
                                                         info[attack]["n_components_95"], k99]})
        rng = np.random.default_rng(RANDOM_STATE)
        per_class = min(6000, int(min((y_train == 0).sum(), (y_train == 1).sum())))
        idx = np.concatenate([rng.choice(np.flatnonzero(y_train == c), per_class, replace=False) for c in (0, 1)])
        scatter[attack] = (pre.transform(X_train.iloc[idx])[:, :2], y_train[idx])
        log.info(f"[{attack}] PCA: 78 -> {k99} компоненти за 99 % дисперсия")
        if "--fill-k" in sys.argv:
            # само липсващата точка n = k (брой компоненти за 99 %), ако я няма в експеримента
            old = old_sweep[old_sweep.attack == attack]
            info[attack]["sweep_sizes"] = previous[attack]["sweep_sizes"]
            if k99 not in set(old.n_components):
                sw, _, _ = component_sweep(X_train, y_train, attack, ns=[k99])
                old = pd.concat([old, sw], ignore_index=True).sort_values(["n_components", "algorithm"])
            sweeps.append(old)
            continue
        if figures_only or (only is not None and attack not in only):
            info[attack]["sweep_sizes"] = previous[attack]["sweep_sizes"]
            sweeps.append(old_sweep[old_sweep.attack == attack])
            continue
        sw, n_sub, n_val = component_sweep(X_train, y_train, attack, ns=sorted(set(SWEEP) | {k99}))
        info[attack]["sweep_sizes"] = {"subtrain": n_sub, "validation": n_val}
        sweeps.append(sw)
    sweep = pd.concat(sweeps, ignore_index=True)
    sweep.to_csv(sweep_path, index=False)
    fig_variance(info)
    fig_scatter(scatter)
    fig_loadings(loadings)
    fig_sweep(sweep, info)
    ps.slide_mode(True)
    fig_scatter(scatter)
    fig_sweep(sweep, info)
    ps.slide_mode(False)
    summary_path.write_text(json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
