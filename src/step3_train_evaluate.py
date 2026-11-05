"""ФАЗА 2 – синтез, обучение, валидиране и оперативно тестване на 4 модела (2 атаки × 2 алгоритъма).

Фаза на машинно обучение (обучаващо множество, 70 %):
  * GridSearchCV със стратифицирано 5-кратно кръстосано валидиране – избор на хиперпараметри по F1;
  * out-of-fold прогнози с най-добрите параметри -> TP/TN/FP/FN при валидирането;
  * финално обучение на най-добрия конвейер върху цялото обучаващо множество.
Оперативна фаза (тестово множество, 30 %, невиждано по време на обучението):
  * класификация на всеки мрежов поток, време за детекция, TP/TN/FP/FN, Precision, Accuracy, Sensitivity …

Изход: models/*.joblib, results/metrics.json, results/tables/metrics_summary.csv,
       results/tables/*_cv_results.csv, results/predictions/*.csv.gz, logs/training_log.md
"""
import hashlib
import json
import platform
import sys
import time

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, matthews_corrcoef, precision_score,
                             recall_score, roc_auc_score, roc_curve)
from sklearn.model_selection import GridSearchCV, StratifiedKFold, cross_val_predict

from action_log import get_logger
from config import (ALGORITHMS, CV_FOLDS, LOGS_DIR, MODELS_DIR, PCA_VARIANCE, PRED_DIR, RANDOM_STATE,
                    RESULTS_DIR, TABLES_DIR, ensure_dirs, experiments, setup_console)
from preprocessing import build_pipeline, get_split

log = get_logger()

PARAM_GRIDS = {
    "RF": {"clf__n_estimators": [50, 100, 200], "clf__max_depth": [10, 20, None]},
    "KNN": {"clf__n_neighbors": [1, 3, 5, 7, 9], "clf__weights": ["uniform", "distance"]},
    "MLP": {"clf__hidden_layer_sizes": [(32,), (64,), (64, 32)], "clf__alpha": [1e-4, 1e-3]},
    "LR": {"clf__C": [0.01, 0.1, 1, 10, 100], "clf__class_weight": [None, "balanced"]},
}
# RF и k-NN се паралелизират вътрешно (n_jobs=-1); MLP и логистичната регресия – чрез паралелни fold-ове.
SEARCH_JOBS = {"RF": 1, "KNN": 1, "MLP": 5, "LR": 5}
SCORING = {"accuracy": "accuracy", "precision": "precision", "recall": "recall", "f1": "f1"}


def binary_metrics(y_true, y_pred, y_score=None):
    tn, fp, fn, tp = (int(v) for v in confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel())
    m = {
        "TP": tp, "TN": tn, "FP": fp, "FN": fn,
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "sensitivity": recall_score(y_true, y_pred),            # TPR, recall
        "specificity": tn / (tn + fp) if tn + fp else 0.0,      # TNR
        "f1": f1_score(y_true, y_pred),
        "fpr": fp / (fp + tn) if fp + tn else 0.0,              # дял фалшиви тревоги
        "fnr": fn / (fn + tp) if fn + tp else 0.0,              # дял пропуснати атаки
        "mcc": matthews_corrcoef(y_true, y_pred),
    }
    if y_score is not None:
        m["roc_auc"] = roc_auc_score(y_true, y_score)
    return m


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(attack, alg, X_train, X_test, y_train, y_test):
    tag = f"{attack}_{alg}"
    log.info(f"[{tag}] ---- фаза на машинно обучение: GridSearchCV {PARAM_GRIDS[alg]}")
    cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)
    search = GridSearchCV(build_pipeline(alg), PARAM_GRIDS[alg], scoring=SCORING, refit="f1", cv=cv,
                          n_jobs=SEARCH_JOBS[alg])
    t = time.perf_counter()
    search.fit(X_train, y_train)
    search_s = time.perf_counter() - t
    cvr = pd.DataFrame(search.cv_results_)
    keep = ["params"] + [c for c in cvr.columns if c.startswith(("mean_", "std_", "rank_"))]
    cvr[keep].to_csv(TABLES_DIR / f"{tag}_cv_results.csv", index=False, encoding="utf-8-sig")
    best_i = search.best_index_
    for _, r in cvr.iterrows():
        log.info(f"[{tag}] CV {r['params']}: F1={r['mean_test_f1']:.5f}±{r['std_test_f1']:.5f} "
                 f"acc={r['mean_test_accuracy']:.5f} fit={r['mean_fit_time']:.1f}s score={r['mean_score_time']:.1f}s")
    best_params = {k.replace("clf__", ""): v for k, v in search.best_params_.items()}
    log.info(f"[{tag}] най-добри параметри: {best_params} (търсене {search_s:.0f} s)")

    # Out-of-fold прогнози с най-добрите параметри -> матрица на грешките при валидирането.
    t = time.perf_counter()
    oof = cross_val_predict(build_pipeline(alg, **best_params), X_train, y_train, cv=cv,
                            n_jobs=SEARCH_JOBS[alg])
    val = binary_metrics(y_train, oof)
    log.info(f"[{tag}] валидиране (out-of-fold): TP={val['TP']} TN={val['TN']} FP={val['FP']} FN={val['FN']} "
             f"acc={val['accuracy']:.5f} ({time.perf_counter() - t:.0f} s)")

    # Финален модел (GridSearchCV вече го е преобучил върху цялото обучаващо множество).
    model = search.best_estimator_
    n_comp = int(model.named_steps["pca"].n_components_)
    path = MODELS_DIR / f"{tag}.joblib"
    joblib.dump(model, path, compress=3)

    log.info(f"[{tag}] ---- оперативна фаза: класификация на {len(X_test):,} невиждани потока")
    t = time.perf_counter()
    y_pred = model.predict(X_test)
    pred_s = time.perf_counter() - t
    y_score = model.predict_proba(X_test)[:, 1]
    test = binary_metrics(y_test, y_pred, y_score)
    log.info(f"[{tag}] тест: TP={test['TP']} TN={test['TN']} FP={test['FP']} FN={test['FN']} "
             f"acc={test['accuracy']:.5f} prec={test['precision']:.5f} sens={test['sensitivity']:.5f} "
             f"AUC={test['roc_auc']:.5f} predict={pred_s:.2f}s")

    pd.DataFrame({"y_true": y_test, "y_pred": y_pred, "score": y_score.round(6)}).to_csv(
        PRED_DIR / f"{tag}.csv.gz", index=False)
    fpr, tpr, _ = roc_curve(y_test, y_score)
    return {
        "attack": attack, "algorithm": alg,
        "best_params": best_params,
        "param_grid": {k.replace("clf__", ""): v for k, v in PARAM_GRIDS[alg].items()},
        "pca_components": n_comp,
        "train_size": int(len(X_train)), "test_size": int(len(X_test)),
        "cv": {"folds": CV_FOLDS, "combinations": int(len(cvr)), "search_seconds": round(search_s, 1),
               "best_mean": {k: float(cvr.loc[best_i, f"mean_test_{k}"]) for k in SCORING},
               "best_std": {k: float(cvr.loc[best_i, f"std_test_{k}"]) for k in SCORING}},
        "validation": val,
        "test": test,
        "timing": {"refit_seconds": round(float(search.refit_time_), 2),
                   "predict_seconds": round(pred_s, 3),
                   "latency_us_per_flow": round(pred_s / len(X_test) * 1e6, 2),
                   "throughput_flows_per_s": round(len(X_test) / pred_s)},
        "model_file": path.name, "model_size_mb": round(path.stat().st_size / 2**20, 2),
        "model_sha256": sha256(path),
        "roc": {"fpr": fpr.tolist(), "tpr": tpr.tolist()} if len(fpr) < 4000 else
               {"fpr": fpr[:: len(fpr) // 3000 + 1].tolist() + [1.0], "tpr": tpr[:: len(fpr) // 3000 + 1].tolist() + [1.0]},
    }


def write_training_log(results, env):
    lines = ["# Дневник на обучението на моделите", "",
             "Генерира се автоматично от `src/step3_train_evaluate.py`.", "",
             f"* Среда: Python {env['python']}, scikit-learn {env['sklearn']}, {env['platform']}",
             f"* Конвейер: sign(x)·ln(1+|x|) → StandardScaler → PCA(99 % дисперсия) → класификатор",
             f"* Валидиране: стратифицирано {CV_FOLDS}-кратно кръстосано валидиране, критерий F1, random_state={RANDOM_STATE}",
             ""]
    for r in results:
        t, v = r["test"], r["validation"]
        lines += [f"## {r['attack']} – {ALGORITHMS[r['algorithm']]['name']}", "",
                  f"* Мрежа от хиперпараметри: `{r['param_grid']}` ({r['cv']['combinations']} комбинации × "
                  f"{r['cv']['folds']} fold-а, {r['cv']['search_seconds']} s)",
                  f"* Избрани хиперпараметри: `{r['best_params']}`; PCA компоненти: {r['pca_components']}",
                  f"* Обучаващо множество: {r['train_size']:,} потока; тестово: {r['test_size']:,} потока",
                  f"* Валидиране (out-of-fold): TP={v['TP']:,}, TN={v['TN']:,}, FP={v['FP']:,}, FN={v['FN']:,}, "
                  f"Accuracy={v['accuracy']:.5f}",
                  f"* Оперативен тест: TP={t['TP']:,}, TN={t['TN']:,}, FP={t['FP']:,}, FN={t['FN']:,}, "
                  f"Accuracy={t['accuracy']:.5f}, Precision={t['precision']:.5f}, Sensitivity={t['sensitivity']:.5f}",
                  f"* Време: финално обучение {r['timing']['refit_seconds']} s; детекция "
                  f"{r['timing']['latency_us_per_flow']} µs/поток",
                  f"* Файл на модела: `models/{r['model_file']}` ({r['model_size_mb']} MB, SHA-256 `{r['model_sha256'][:16]}…`)",
                  ""]
    (LOGS_DIR / "training_log.md").write_text("\n".join(lines), encoding="utf-8")


def main():
    setup_console()
    ensure_dirs()
    env = {"python": platform.python_version(), "sklearn": sklearn.__version__, "numpy": np.__version__,
           "pandas": pd.__version__, "platform": platform.platform(), "processor": platform.processor()}
    log.info(f"=== ФАЗА 2: обучение и оценка; среда {env} ===")
    # --only DoS,BruteForce – обучават се само моделите на тези атаки; останалите резултати се запазват.
    only = sys.argv[sys.argv.index("--only") + 1].split(",") if "--only" in sys.argv else None
    path = RESULTS_DIR / "metrics.json"
    done = {}
    if only is not None and path.exists():
        done = {(m["attack"], m["algorithm"]): m for m in json.loads(path.read_text(encoding="utf-8"))["models"]}
    order = experiments()
    split_cache = {}
    for attack, alg in order:
        if only is not None and attack not in only:
            continue
        if attack not in split_cache:
            split_cache = {attack: get_split(attack)}
        X_train, X_test, y_train, y_test = split_cache[attack]
        done[(attack, alg)] = run(attack, alg, X_train, X_test, y_train, y_test)
        results = [done[k] for k in order if k in done]
        path.write_text(json.dumps({"environment": env, "models": results}, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    results = [done[k] for k in order if k in done]
    rows = []
    for r in results:
        for phase in ("validation", "test"):
            row = {"attack": r["attack"], "algorithm": r["algorithm"], "phase": phase}
            row.update({k: v for k, v in r[phase].items()})
            rows.append(row)
    pd.DataFrame(rows).to_csv(TABLES_DIR / "metrics_summary.csv", index=False, encoding="utf-8-sig")
    write_training_log(results, env)
    log.info("Фаза 2 приключи")


if __name__ == "__main__":
    main()
