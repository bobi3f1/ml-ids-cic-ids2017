"""Външен набор данни InSDN (University College Dublin, 2020) – кръстосана проверка на обучените модели.

InSDN е извлечен с по-нова версия на CICFlowMeter, затова имената на колоните са съкратени
(„Tot Fwd Pkts“ вместо „Total Fwd Packets“). Колоните се преименуват към имената от CIC-IDS2017; нито една
колона не се премахва. Липсващата „Fwd Header Length.1“ (в CIC-IDS2017 – точно копие на „Fwd Header Length“)
се добавя като производна колона.

Elsayed, M. S., Le-Khac, N.-A., Jurcut, A. InSDN: A Novel SDN Intrusion Dataset. IEEE Access, 8, 2020.
Източник: https://aseados.ucd.ie/datasets/SDN/  (лиценз CC BY-NC 4.0)
"""
import numpy as np
import pandas as pd

from config import BENIGN_LABEL, LABEL_COL, ROOT

INSDN_URL = "https://aseados.ucd.ie/datasets/SDN/InSDN_DatasetCSV.zip"
INSDN_SHA256 = "ee89ec66705c529fef26b27dd18c6aa56d469006f7ade9cd92fd4a503e320d7d"
INSDN_DIR = ROOT / "data" / "external" / "InSDN" / "InSDN_DatasetCSV"
INSDN_FILES = ["Normal_data.csv", "OVS.csv", "metasploitable-2.csv"]
INSDN_PROCESSED = ROOT / "data" / "processed" / "InSDN_clean.csv"

# атака в нашето изследване -> етикет в InSDN
INSDN_LABEL = {"DDoS": "DDoS", "PortScan": "Probe", "DoS": "DoS", "BruteForce": "BFA"}
INSDN_NORMAL = "Normal"

# име в InSDN (CICFlowMeter-V3) -> име в CIC-IDS2017
RENAME = {
    "Dst Port": "Destination Port", "Tot Fwd Pkts": "Total Fwd Packets", "Tot Bwd Pkts": "Total Backward Packets",
    "TotLen Fwd Pkts": "Total Length of Fwd Packets", "TotLen Bwd Pkts": "Total Length of Bwd Packets",
    "Fwd Pkt Len Max": "Fwd Packet Length Max", "Fwd Pkt Len Min": "Fwd Packet Length Min",
    "Fwd Pkt Len Mean": "Fwd Packet Length Mean", "Fwd Pkt Len Std": "Fwd Packet Length Std",
    "Bwd Pkt Len Max": "Bwd Packet Length Max", "Bwd Pkt Len Min": "Bwd Packet Length Min",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean", "Bwd Pkt Len Std": "Bwd Packet Length Std",
    "Flow Byts/s": "Flow Bytes/s", "Flow Pkts/s": "Flow Packets/s",
    "Fwd IAT Tot": "Fwd IAT Total", "Bwd IAT Tot": "Bwd IAT Total",
    "Fwd Header Len": "Fwd Header Length", "Bwd Header Len": "Bwd Header Length",
    "Fwd Pkts/s": "Fwd Packets/s", "Bwd Pkts/s": "Bwd Packets/s",
    "Pkt Len Min": "Min Packet Length", "Pkt Len Max": "Max Packet Length", "Pkt Len Mean": "Packet Length Mean",
    "Pkt Len Std": "Packet Length Std", "Pkt Len Var": "Packet Length Variance",
    "FIN Flag Cnt": "FIN Flag Count", "SYN Flag Cnt": "SYN Flag Count", "RST Flag Cnt": "RST Flag Count",
    "PSH Flag Cnt": "PSH Flag Count", "ACK Flag Cnt": "ACK Flag Count", "URG Flag Cnt": "URG Flag Count",
    "ECE Flag Cnt": "ECE Flag Count", "Pkt Size Avg": "Average Packet Size",
    "Fwd Seg Size Avg": "Avg Fwd Segment Size", "Bwd Seg Size Avg": "Avg Bwd Segment Size",
    "Fwd Byts/b Avg": "Fwd Avg Bytes/Bulk", "Fwd Pkts/b Avg": "Fwd Avg Packets/Bulk",
    "Fwd Blk Rate Avg": "Fwd Avg Bulk Rate", "Bwd Byts/b Avg": "Bwd Avg Bytes/Bulk",
    "Bwd Pkts/b Avg": "Bwd Avg Packets/Bulk", "Bwd Blk Rate Avg": "Bwd Avg Bulk Rate",
    "Subflow Fwd Pkts": "Subflow Fwd Packets", "Subflow Fwd Byts": "Subflow Fwd Bytes",
    "Subflow Bwd Pkts": "Subflow Bwd Packets", "Subflow Bwd Byts": "Subflow Bwd Bytes",
    "Init Fwd Win Byts": "Init_Win_bytes_forward", "Init Bwd Win Byts": "Init_Win_bytes_backward",
    "Fwd Act Data Pkts": "act_data_pkt_fwd", "Fwd Seg Size Min": "min_seg_size_forward",
}


def load_insdn_raw():
    parts = []
    for f in INSDN_FILES:
        df = pd.read_csv(INSDN_DIR / f, low_memory=False)
        df["Source File"] = f            # служебна колона за проследимост (откъде е редът)
        parts.append(df)
    return pd.concat(parts, ignore_index=True)


def harmonize(df):
    """Преименуване към имената на CIC-IDS2017 и добавяне на производната колона Fwd Header Length.1."""
    df = df.rename(columns=lambda c: c.strip()).rename(columns=RENAME)
    df[LABEL_COL] = df[LABEL_COL].astype(str).str.strip()
    df["Fwd Header Length.1"] = df["Fwd Header Length"]
    return df


def binary_for(df, attack):
    """Подмножество: нормален трафик + потоците на съответната атака; y = 1 за атака."""
    lab = INSDN_LABEL[attack]
    sub = df[df[LABEL_COL].isin([INSDN_NORMAL, lab])]
    y = (sub[LABEL_COL] == lab).astype(int).to_numpy()
    return sub, y


def to_benign_label(df):
    """Етикетите на InSDN в нотацията на изследването (Normal -> BENIGN)."""
    df = df.copy()
    df[LABEL_COL] = df[LABEL_COL].replace({INSDN_NORMAL: BENIGN_LABEL})
    return df
