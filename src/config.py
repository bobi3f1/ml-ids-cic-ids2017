"""Обща конфигурация на експерименталното изследване (пътища, константи, атаки, алгоритми)."""
import os
from pathlib import Path
import sys

# joblib/loky не може да определи физическите ядра под Windows без wmic – задаваме логическите
os.environ.setdefault("LOKY_MAX_CPU_COUNT", str(os.cpu_count() or 1))

ROOT = Path(__file__).resolve().parents[1]

RAW_ZIP = ROOT / "data" / "raw" / "MachineLearningCSV.zip"
RAW_DIR = ROOT / "data" / "raw" / "MachineLearningCVE"
PROCESSED_DIR = ROOT / "data" / "processed"
MODELS_DIR = ROOT / "models"
RESULTS_DIR = ROOT / "results"
FIG_DIR = RESULTS_DIR / "figures"
TABLES_DIR = RESULTS_DIR / "tables"
PRED_DIR = RESULTS_DIR / "predictions"
LOGS_DIR = ROOT / "logs"
DOCS_DIR = ROOT / "docs"

# Източник на набора данни (официалният линк на UNB/CIC вече изисква регистрационна форма,
# затова е използвано огледало в Hugging Face, фиксирано към конкретен commit).
DATASET_NAME = "CIC-IDS2017 (MachineLearningCSV)"
DATASET_OFFICIAL_PAGE = "https://www.unb.ca/cic/datasets/ids-2017.html"
DATASET_MIRROR_URL = ("https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/"
                      "811c007f08d693a8a8b4226c197c138391806ce6/csvs/MachineLearningCSV.zip")
DATASET_SHA256 = "c3f26274b36c837ccf28ffd2dbf4582941c30b3ee70a635c6e5b2f87c4727928"

RANDOM_STATE = 42
TEST_SIZE = 0.30          # 70 % обучение (+ кръстосано валидиране), 30 % оперативен тест
CV_FOLDS = 5              # стратифицирано 5-кратно кръстосано валидиране
PCA_VARIANCE = 0.99       # PCA запазва 99 % от дисперсията

LABEL_COL = "Label"
BENIGN_LABEL = "BENIGN"

# positive – етикети, които образуват класа „атака“; exclude – етикети от същия файл, които не са обект на
# изследването и се отстраняват (редове, не колони); всички останали редове са BENIGN.
ATTACKS = {
    "DDoS": {
        "file": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
        "label": "DDoS",
        "positive": ["DDoS"],
        "exclude": [],
        "bg": "DDoS атака",
        "bg_def": "DDoS атаката",
        "bg_long": "Разпределена атака за отказ от услуга (DDoS, LOIC)",
    },
    "PortScan": {
        "file": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        "label": "PortScan",
        "positive": ["PortScan"],
        "exclude": [],
        "bg": "Сканиране на портове",
        "bg_def": "сканирането на портове",
        "bg_long": "Сканиране на портове (PortScan, Nmap)",
    },
    "DoS": {
        "file": "Wednesday-workingHours.pcap_ISCX.csv",
        "label": "DoS",
        "positive": ["DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest"],
        "exclude": ["Heartbleed"],
        "bg": "DoS атака",
        "bg_def": "DoS атаката",
        "bg_long": "Атака за отказ от услуга на приложно ниво (DoS: Hulk, GoldenEye, Slowloris, Slowhttptest)",
    },
    "BruteForce": {
        "file": "Tuesday-WorkingHours.pcap_ISCX.csv",
        "label": "Brute Force",
        "positive": ["FTP-Patator", "SSH-Patator"],
        "exclude": [],
        "bg": "Атака с груба сила",
        "bg_def": "атаката с груба сила",
        "bg_long": "Атака с груба сила срещу FTP и SSH (FTP-Patator, SSH-Patator)",
    },
}

ALGORITHMS = {
    "RF": {"name": "Random Forest", "bg": "Случайна гора (Random Forest)"},
    "KNN": {"name": "k-Nearest Neighbors", "bg": "k-най-близки съседи (k-NN)"},
    "MLP": {"name": "Multilayer Perceptron", "bg": "Многослоен перцептрон (MLP)"},
    "LR": {"name": "Logistic Regression", "bg": "Логистична регресия (LR)"},
}

# Разпределение на задачите в екипа: всеки член изследва 2 атаки с 2 алгоритъма (4 модела).
TEAM = [
    {"member": "Член 1", "attacks": ["DDoS", "PortScan"], "algorithms": ["RF", "KNN"]},
    {"member": "Член 2", "attacks": ["DoS", "BruteForce"], "algorithms": ["MLP", "LR"]},
]


def experiments():
    """Всички модели (атака, алгоритъм) – 2 члена × 2 атаки × 2 алгоритъма = 8 модела."""
    return [(a, g) for m in TEAM for a in m["attacks"] for g in m["algorithms"]]


def algorithms_for(attack):
    return next(m["algorithms"] for m in TEAM if attack in m["attacks"])


def member_of(attack):
    return next(m["member"] for m in TEAM if attack in m["attacks"])


def setup_console():
    """Позволява отпечатване на кирилица в конзолата на Windows."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except AttributeError:
            pass


def ensure_dirs():
    for d in (PROCESSED_DIR, MODELS_DIR, FIG_DIR, TABLES_DIR, PRED_DIR, LOGS_DIR, DOCS_DIR):
        d.mkdir(parents=True, exist_ok=True)
