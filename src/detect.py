"""Оперативна фаза – детекция на атаки в нов CSV файл с мрежови потоци (формат CICFlowMeter).

Пример:
    python src/detect.py --model models/DDoS_RF.joblib --input data/processed/DDoS_clean.csv --limit 20000

Входният файл трябва да съдържа 78-те характеристики на CIC-IDS2017 (колоната Label е по избор –
ако я има, се изчисляват и метриките). Към данните се прилага същото почистване на имената и на
NaN/Infinity стойностите, както при обучението (без премахване на редове или колони).
"""
import argparse
import time

import joblib
import numpy as np
import pandas as pd

from config import BENIGN_LABEL, LABEL_COL, setup_console
from preprocessing import RATE_COLUMNS, TIMER_RESOLUTION_US, signed_log1p  # noqa: F401 (нужно за joblib)


def prepare(df, expected):
    df = df.rename(columns=lambda c: c.strip())
    for col, parts in RATE_COLUMNS.items():
        bad = ~np.isfinite(df[col].to_numpy(dtype=float))
        df.loc[bad, col] = df.loc[bad, list(parts)].sum(axis=1) / (TIMER_RESOLUTION_US / 1e6)
    missing = [c for c in expected if c not in df.columns]
    if missing:
        raise ValueError(f"Липсват характеристики: {missing}")
    return df


def main():
    setup_console()
    ap = argparse.ArgumentParser(description="Детекция на мрежови атаки с обучен модел")
    ap.add_argument("--model", required=True)
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", default=None, help="CSV с прогнозите (по избор)")
    ap.add_argument("--limit", type=int, default=None, help="обработка само на първите N потока")
    args = ap.parse_args()

    model = joblib.load(args.model)
    expected = list(model.feature_names_in_)
    df = prepare(pd.read_csv(args.input, nrows=args.limit, low_memory=False), expected)

    t = time.perf_counter()
    pred = model.predict(df[expected].astype(float))
    score = model.predict_proba(df[expected].astype(float))[:, 1]
    elapsed = time.perf_counter() - t

    n_alarm = int(pred.sum())
    print(f"Модел: {args.model}")
    print(f"Обработени потоци: {len(df):,} за {elapsed:.2f} s ({elapsed / len(df) * 1e6:.1f} µs/поток)")
    print(f"Тревоги (атака): {n_alarm:,}  |  нормален трафик: {len(df) - n_alarm:,}")
    if LABEL_COL in df.columns:
        y = (df[LABEL_COL] != BENIGN_LABEL).astype(int).to_numpy()
        tp = int(((pred == 1) & (y == 1)).sum())
        tn = int(((pred == 0) & (y == 0)).sum())
        fp = int(((pred == 1) & (y == 0)).sum())
        fn = int(((pred == 0) & (y == 1)).sum())
        acc = (tp + tn) / len(y)
        prec = tp / (tp + fp) if tp + fp else 0.0
        sens = tp / (tp + fn) if tp + fn else 0.0
        print(f"TP={tp:,} TN={tn:,} FP={fp:,} FN={fn:,} | Accuracy={acc:.5f} Precision={prec:.5f} Sensitivity={sens:.5f}")
    if args.output:
        out = pd.DataFrame({"prediction": np.where(pred == 1, "ATTACK", BENIGN_LABEL), "attack_probability": score})
        out.to_csv(args.output, index=False)
        print(f"Прогнозите са записани в {args.output}")


if __name__ == "__main__":
    main()
