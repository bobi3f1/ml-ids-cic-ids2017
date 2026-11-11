# Дневник на действията върху набора данни

Файлът се генерира автоматично от `src/action_log.py` при всяко изпълнение на конвейера.
Колони от набора данни **не се премахват** – логърът спира изпълнението, ако някоя стъпка намали броя им.

| № | Време | Скрипт | Набор | Действие | Редове преди → след | Колони преди → след | Описание |
|---|---|---|---|---|---|---|---|
| 1 | 2026-10-13T21:24:46 | step1_prepare_data | CIC-IDS2017 | Получаване на набора данни |  |  | Изтеглен MachineLearningCSV.zip (235 102 953 B), проверена SHA-256 сума, разархивирани 8 CSV файла. |
| 2 | 2026-10-13T21:24:49 | step1_prepare_data | DDoS | Зареждане и профилиране | 225 745 → 225 745 | 79 → 79 | Зареден файл Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv: 225 745 реда × 79 колони (78 характеристики + етикет). |
| 3 | 2026-10-13T21:24:49 | step1_prepare_data | DDoS | Анализ на излишни колони (без премахване) | 225 745 → 225 745 | 79 → 79 | 10 константни колони и 8 двойки идентични колони. Колоните се запазват – PCA им дава нулево/общо тегло. |
| 4 | 2026-10-13T21:24:49 | step1_prepare_data | DDoS | Нормализиране на имената на колоните | 225 745 → 225 745 | 79 → 79 | Премахнати водещи/крайни интервали в 65 имена на колони (преименуване, без премахване). |
| 5 | 2026-10-13T21:24:49 | step1_prepare_data | DDoS | Проверка на типовете данни | 225 745 → 225 745 | 79 → 79 | 78 числови характеристики (int64/float64) и 1 текстова колона 'Label'. |
| 6 | 2026-10-13T21:24:49 | step1_prepare_data | DDoS | Коригиране на NaN/Infinity | 225 745 → 225 745 | 79 → 79 | Стойностите NaN и Infinity във 'Flow Bytes/s' и 'Flow Packets/s' (при Flow Duration = 0) са преизчислени с продължителност 1 µs. Редове и колони не са премахвани. |
| 7 | 2026-10-13T21:24:50 | step1_prepare_data | DDoS | Премахване на дублирани редове | 225 745 → 223 112 | 79 → 79 | Премахнати 2 633 напълно идентични реда (запазено е първото срещане). |
| 8 | 2026-10-13T21:24:50 | step1_prepare_data | DDoS | Контролна проверка | 223 112 → 223 112 | 79 → 79 | Няма NaN/Infinity; няма еднакви вектори на характеристиките с противоречиви етикети. |
| 9 | 2026-10-13T21:24:54 | step1_prepare_data | DDoS | Запис на обработения набор | 223 112 → 223 112 | 79 → 79 | Записан data/processed/DDoS_clean.csv (223 112 реда × 79 колони). |
| 10 | 2026-10-13T21:25:10 | step1_prepare_data | PortScan | Зареждане и профилиране | 286 467 → 286 467 | 79 → 79 | Зареден файл Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv: 286 467 реда × 79 колони (78 характеристики + етикет). |
| 11 | 2026-10-13T21:25:10 | step1_prepare_data | PortScan | Анализ на излишни колони (без премахване) | 286 467 → 286 467 | 79 → 79 | 10 константни колони и 8 двойки идентични колони. Колоните се запазват – PCA им дава нулево/общо тегло. |
| 12 | 2026-10-13T21:25:10 | step1_prepare_data | PortScan | Нормализиране на имената на колоните | 286 467 → 286 467 | 79 → 79 | Премахнати водещи/крайни интервали в 65 имена на колони (преименуване, без премахване). |
| 13 | 2026-10-13T21:25:10 | step1_prepare_data | PortScan | Проверка на типовете данни | 286 467 → 286 467 | 79 → 79 | 78 числови характеристики (int64/float64) и 1 текстова колона 'Label'. |
| 14 | 2026-10-13T21:25:10 | step1_prepare_data | PortScan | Коригиране на NaN/Infinity | 286 467 → 286 467 | 79 → 79 | Стойностите NaN и Infinity във 'Flow Bytes/s' и 'Flow Packets/s' (при Flow Duration = 0) са преизчислени с продължителност 1 µs. Редове и колони не са премахвани. |
| 15 | 2026-10-13T21:25:11 | step1_prepare_data | PortScan | Премахване на дублирани редове | 286 467 → 214 114 | 79 → 79 | Премахнати 72 353 напълно идентични реда (запазено е първото срещане). |
| 16 | 2026-10-13T21:25:11 | step1_prepare_data | PortScan | Контролна проверка | 214 114 → 214 114 | 79 → 79 | Няма NaN/Infinity; няма еднакви вектори на характеристиките с противоречиви етикети. |
| 17 | 2026-10-13T21:25:14 | step1_prepare_data | PortScan | Запис на обработения набор | 214 114 → 214 114 | 79 → 79 | Записан data/processed/PortScan_clean.csv (214 114 реда × 79 колони). |
| 18 | 2026-10-13T21:25:36 | step1_prepare_data | DoS | Зареждане и профилиране | 692 703 → 692 703 | 79 → 79 | Зареден файл Wednesday-workingHours.pcap_ISCX.csv: 692 703 реда × 79 колони (78 характеристики + етикет). |
| 19 | 2026-10-13T21:25:36 | step1_prepare_data | DoS | Анализ на излишни колони (без премахване) | 692 703 → 692 703 | 79 → 79 | 10 константни колони и 6 двойки идентични колони. Колоните се запазват – PCA им дава нулево/общо тегло. |
| 20 | 2026-10-13T21:25:36 | step1_prepare_data | DoS | Нормализиране на имената на колоните | 692 703 → 692 703 | 79 → 79 | Премахнати водещи/крайни интервали в 65 имена на колони (преименуване, без премахване). |
| 21 | 2026-10-13T21:25:36 | step1_prepare_data | DoS | Проверка на типовете данни | 692 703 → 692 703 | 79 → 79 | 78 числови характеристики (int64/float64) и 1 текстова колона 'Label'. |
| 22 | 2026-10-13T21:25:36 | step1_prepare_data | DoS | Коригиране на NaN/Infinity | 692 703 → 692 703 | 79 → 79 | Стойностите NaN и Infinity във 'Flow Bytes/s' и 'Flow Packets/s' (при Flow Duration = 0) са преизчислени с продължителност 1 µs. Редове и колони не са премахвани. |
| 23 | 2026-10-13T21:25:36 | step1_prepare_data | DoS | Отстраняване на неизследвани атаки | 692 703 → 692 692 | 79 → 79 | Отстранени 11 реда с етикети Heartbleed – друг тип атака, която не е обект на този детектор. Колони не са премахвани. |
| 24 | 2026-10-13T21:25:39 | step1_prepare_data | DoS | Премахване на дублирани редове | 692 692 → 610 783 | 79 → 79 | Премахнати 81 909 напълно идентични реда (запазено е първото срещане). |
| 25 | 2026-10-13T21:25:39 | step1_prepare_data | DoS | Отстраняване на противоречиви записи | 610 783 → 610 687 | 79 → 79 | Отстранени 96 реда, чийто вектор на характеристиките се среща и като BENIGN, и като атака (неразрешима неяснота в етикетите). |
| 26 | 2026-10-13T21:25:40 | step1_prepare_data | DoS | Контролна проверка | 610 687 → 610 687 | 79 → 79 | Няма NaN/Infinity; няма еднакви вектори на характеристиките с противоречиви етикети. |
| 27 | 2026-10-13T21:25:50 | step1_prepare_data | DoS | Запис на обработения набор | 610 687 → 610 687 | 79 → 79 | Записан data/processed/DoS_clean.csv (610 687 реда × 79 колони). |
| 28 | 2026-10-13T21:26:08 | step1_prepare_data | BruteForce | Зареждане и профилиране | 445 909 → 445 909 | 79 → 79 | Зареден файл Tuesday-WorkingHours.pcap_ISCX.csv: 445 909 реда × 79 колони (78 характеристики + етикет). |
| 29 | 2026-10-13T21:26:08 | step1_prepare_data | BruteForce | Анализ на излишни колони (без премахване) | 445 909 → 445 909 | 79 → 79 | 10 константни колони и 6 двойки идентични колони. Колоните се запазват – PCA им дава нулево/общо тегло. |
| 30 | 2026-10-13T21:26:08 | step1_prepare_data | BruteForce | Нормализиране на имената на колоните | 445 909 → 445 909 | 79 → 79 | Премахнати водещи/крайни интервали в 65 имена на колони (преименуване, без премахване). |
| 31 | 2026-10-13T21:26:08 | step1_prepare_data | BruteForce | Проверка на типовете данни | 445 909 → 445 909 | 79 → 79 | 78 числови характеристики (int64/float64) и 1 текстова колона 'Label'. |
| 32 | 2026-10-13T21:26:08 | step1_prepare_data | BruteForce | Коригиране на NaN/Infinity | 445 909 → 445 909 | 79 → 79 | Стойностите NaN и Infinity във 'Flow Bytes/s' и 'Flow Packets/s' (при Flow Duration = 0) са преизчислени с продължителност 1 µs. Редове и колони не са премахвани. |
| 33 | 2026-10-13T21:26:10 | step1_prepare_data | BruteForce | Премахване на дублирани редове | 445 909 → 421 844 | 79 → 79 | Премахнати 24 065 напълно идентични реда (запазено е първото срещане). |
| 34 | 2026-10-13T21:26:11 | step1_prepare_data | BruteForce | Контролна проверка | 421 844 → 421 844 | 79 → 79 | Няма NaN/Infinity; няма еднакви вектори на характеристиките с противоречиви етикети. |
| 35 | 2026-10-13T21:26:17 | step1_prepare_data | BruteForce | Запис на обработения набор | 421 844 → 421 844 | 79 → 79 | Записан data/processed/BruteForce_clean.csv (421 844 реда × 79 колони). |
| 36 | 2026-10-13T21:59:51 | step2_dimensionality | DDoS | Разделяне на обучаващо/тестово множество | 223 112 → 223 112 | 79 → 79 | Стратифицирано разделяне 70/30 (random_state=42): 156 178 за обучение и валидиране, 66 934 за оперативен тест. |
| 37 | 2026-10-13T21:59:52 | step2_dimensionality | DDoS | Редукция на размерността (PCA) |  |  | Вектор на характеристиките 78 → 22 главни компоненти (99 % обяснена дисперсия, намаление 72 %). PCA е стъпка от конвейера, обучава се само върху обучаващите данни; колоните в набора остават непроменени (79). |
| 38 | 2026-10-13T21:59:54 | step2_dimensionality | PortScan | Разделяне на обучаващо/тестово множество | 214 114 → 214 114 | 79 → 79 | Стратифицирано разделяне 70/30 (random_state=42): 149 879 за обучение и валидиране, 64 235 за оперативен тест. |
| 39 | 2026-10-13T21:59:56 | step2_dimensionality | PortScan | Редукция на размерността (PCA) |  |  | Вектор на характеристиките 78 → 22 главни компоненти (99 % обяснена дисперсия, намаление 72 %). PCA е стъпка от конвейера, обучава се само върху обучаващите данни; колоните в набора остават непроменени (79). |
| 40 | 2026-10-13T22:00:02 | step2_dimensionality | DoS | Разделяне на обучаващо/тестово множество | 610 687 → 610 687 | 79 → 79 | Стратифицирано разделяне 70/30 (random_state=42): 427 480 за обучение и валидиране, 183 207 за оперативен тест. |
| 41 | 2026-10-13T22:00:06 | step2_dimensionality | DoS | Редукция на размерността (PCA) |  |  | Вектор на характеристиките 78 → 24 главни компоненти (99 % обяснена дисперсия, намаление 69 %). PCA е стъпка от конвейера, обучава се само върху обучаващите данни; колоните в набора остават непроменени (79). |
| 42 | 2026-10-13T22:00:10 | step2_dimensionality | BruteForce | Разделяне на обучаващо/тестово множество | 421 844 → 421 844 | 79 → 79 | Стратифицирано разделяне 70/30 (random_state=42): 295 290 за обучение и валидиране, 126 554 за оперативен тест. |
| 43 | 2026-10-13T22:00:13 | step2_dimensionality | BruteForce | Редукция на размерността (PCA) |  |  | Вектор на характеристиките 78 → 23 главни компоненти (99 % обяснена дисперсия, намаление 71 %). PCA е стъпка от конвейера, обучава се само върху обучаващите данни; колоните в набора остават непроменени (79). |
| 44 | 2026-10-13T22:25:37 | step5_external_test | InSDN | Получаване на външния набор данни |  |  | Изтеглен InSDN_DatasetCSV.zip (19 302 607 B) от University College Dublin, проверена SHA-256 сума, разархивирани 3 CSV файла. |
| 45 | 2026-10-13T22:25:40 | step5_external_test | InSDN | Зареждане | 343 889 → 343 889 | 84 → 85 | Заредени 343 889 потока × 84 колони (CICFlowMeter-V3), добавена служебна колона Source File (име на изходния файл). |
| 46 | 2026-10-13T22:25:40 | step5_external_test | InSDN | Съпоставяне на колоните с CIC-IDS2017 | 343 889 → 343 889 | 85 → 86 | 50 колони са преименувани към имената от CIC-IDS2017 (напр. Tot Fwd Pkts → Total Fwd Packets); добавена производна колона Fwd Header Length.1 = Fwd Header Length (в CIC-IDS2017 е точно копие). Колоните Flow ID, Src IP, Src Port, Dst IP, Protocol и Timestamp се запазват, но не се подават на моделите (не са използвани и при обучението). |
| 47 | 2026-10-13T22:25:40 | step5_external_test | InSDN | Проверка за NaN/Infinity | 343 889 → 343 889 | 86 → 86 | Няма невалидни стойности – корекция не е нужна. |
| 48 | 2026-10-13T22:25:41 | step5_external_test | InSDN | Премахване на дублирани записи | 343 889 → 218 637 | 86 → 86 | Премахнати 125 252 реда с идентичен вектор на 78-те характеристики и етикет (различават се само по IP адреси, портове на източника и време). |
| 49 | 2026-10-13T22:25:45 | step5_external_test | InSDN | Запис на обработения набор | 218 637 → 218 637 | 86 → 86 | Записан data/processed/InSDN_clean.csv (218 637 реда × 86 колони). |
| 50 | 2026-11-11T21:57:55 | step6_kdd99 | KDD99 | Получаване на набора данни | 494 021 → 494 021 | 42 → 42 | KDD Cup 99 (10 %): 494 021 записа × 42 колони (41 характеристики + етикет), изтеглен чрез scikit-learn (fetch_kddcup99) с проверка на SHA-256. |
| 51 | 2026-11-11T21:57:56 | step6_kdd99 | KDD99 | Премахване на дублирани записи | 494 021 → 145 586 | 42 → 42 | Премахнати 348 435 напълно идентични реда (70.5 %). |
| 52 | 2026-11-11T21:57:56 | step6_kdd99 | KDD99 | Кодиране на символните характеристики (в конвейера) | 145 586 → 145 586 | 42 → 42 | protocol_type, service и flag се кодират с one-hot вътре в конвейера (обучава се само върху обучаващите данни); колоните в набора остават непроменени. |
| 53 | 2026-11-11T21:58:42 | step6_kdd99 | KDD99 | Противоречиви записи (DoS) | 141 763 → 141 761 | 42 → 42 | От подмножеството normal + neptune, back, teardrop, pod, land са отстранени 2 реда с еднакъв вектор и двата етикета. |

## Подробности по стъпки

**1. [CIC-IDS2017] Получаване на набора данни**

```json
{
  "източник": "https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/811c007f08d693a8a8b4226c197c138391806ce6/csvs/MachineLearningCSV.zip",
  "sha256": "c3f26274b36c837ccf28ffd2dbf4582941c30b3ee70a635c6e5b2f87c4727928",
  "файлове": [
    [
      "MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv",
      225166395
    ],
    [
      "MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv",
      135078995
    ],
    [
      "MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
      52023263
    ],
    [
      "MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
      83102436
    ],
    [
      "MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv",
      176927918
    ],
    [
      "MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv",
      58316725
    ],
    [
      "MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
      76906168
    ],
    [
      "MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
      77123859
    ]
  ]
}
```

**2. [DDoS] Зареждане и профилиране**

```json
{
  "classes": {
    "DDoS": 128027,
    "BENIGN": 97718
  },
  "nan_cells": {
    "Flow Bytes/s": 4
  },
  "inf_cells": {
    "Flow Bytes/s": 30,
    "Flow Packets/s": 34
  },
  "duplicate_rows": 2633
}
```

**3. [DDoS] Анализ на излишни колони (без премахване)**

```json
{
  "константни": [
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "CWE Flag Count",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate"
  ],
  "идентични двойки": [
    [
      "Total Fwd Packets",
      "Subflow Fwd Packets"
    ],
    [
      "Total Backward Packets",
      "Subflow Bwd Packets"
    ],
    [
      "Total Length of Fwd Packets",
      "Subflow Fwd Bytes"
    ],
    [
      "Total Length of Bwd Packets",
      "Subflow Bwd Bytes"
    ],
    [
      "Fwd Packet Length Mean",
      "Avg Fwd Segment Size"
    ],
    [
      "Fwd PSH Flags",
      "SYN Flag Count"
    ],
    [
      "Fwd Header Length",
      "Fwd Header Length.1"
    ],
    [
      "RST Flag Count",
      "ECE Flag Count"
    ]
  ],
  "отрицателни стойности (минимум)": {
    "Flow Duration": -1.0,
    "Flow Bytes/s": -12000000.0,
    "Flow Packets/s": -2000000.0,
    "Flow IAT Mean": -1.0,
    "Flow IAT Max": -1.0,
    "Flow IAT Min": -12.0,
    "Fwd IAT Min": -12.0,
    "Init_Win_bytes_forward": -1.0,
    "Init_Win_bytes_backward": -1.0
  },
  "редове с отрицателна Flow Duration": 2
}
```

**4. [DDoS] Нормализиране на имената на колоните**

```json
{
  "преименувани": 65,
  "бележка": "Заглавието 'Fwd Header Length' се среща два пъти в оригиналния файл; pandas автоматично именува второто копие 'Fwd Header Length.1'. И двете колони са запазени."
}
```

**5. [DDoS] Проверка на типовете данни**

```json
{
  "int64": 54,
  "float64": 24
}
```

**6. [DDoS] Коригиране на NaN/Infinity**

```json
{
  "Flow Bytes/s": {
    "NaN": 4,
    "Infinity": 30,
    "по клас": {
      "BENIGN": 32,
      "DDoS": 2
    }
  },
  "Flow Packets/s": {
    "NaN": 0,
    "Infinity": 34,
    "по клас": {
      "BENIGN": 32,
      "DDoS": 2
    }
  }
}
```

**7. [DDoS] Премахване на дублирани редове**

```json
{
  "премахнати по клас": {
    "BENIGN": 2622,
    "DDoS": 11
  }
}
```

**8. [DDoS] Контролна проверка**

```json
{
  "NaN/Inf": 0,
  "противоречиви записи": 0,
  "класове": {
    "DDoS": 128016,
    "BENIGN": 95096
  }
}
```

**9. [DDoS] Запис на обработения набор**

```json
{
  "размер_MB": 78.0
}
```

**10. [PortScan] Зареждане и профилиране**

```json
{
  "classes": {
    "PortScan": 158930,
    "BENIGN": 127537
  },
  "nan_cells": {
    "Flow Bytes/s": 15
  },
  "inf_cells": {
    "Flow Bytes/s": 356,
    "Flow Packets/s": 371
  },
  "duplicate_rows": 72353
}
```

**11. [PortScan] Анализ на излишни колони (без премахване)**

```json
{
  "константни": [
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "CWE Flag Count",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate"
  ],
  "идентични двойки": [
    [
      "Total Fwd Packets",
      "Subflow Fwd Packets"
    ],
    [
      "Total Backward Packets",
      "Subflow Bwd Packets"
    ],
    [
      "Total Length of Fwd Packets",
      "Subflow Fwd Bytes"
    ],
    [
      "Total Length of Bwd Packets",
      "Subflow Bwd Bytes"
    ],
    [
      "Fwd Packet Length Mean",
      "Avg Fwd Segment Size"
    ],
    [
      "Fwd PSH Flags",
      "SYN Flag Count"
    ],
    [
      "Fwd Header Length",
      "Fwd Header Length.1"
    ],
    [
      "RST Flag Count",
      "ECE Flag Count"
    ]
  ],
  "отрицателни стойности (минимум)": {
    "Flow Duration": -13.0,
    "Flow Bytes/s": -193000000.0,
    "Flow Packets/s": -2000000.0,
    "Flow IAT Mean": -13.0,
    "Flow IAT Max": -13.0,
    "Flow IAT Min": -13.0,
    "Init_Win_bytes_forward": -1.0,
    "Init_Win_bytes_backward": -1.0
  },
  "редове с отрицателна Flow Duration": 36
}
```

**12. [PortScan] Нормализиране на имената на колоните**

```json
{
  "преименувани": 65,
  "бележка": "Заглавието 'Fwd Header Length' се среща два пъти в оригиналния файл; pandas автоматично именува второто копие 'Fwd Header Length.1'. И двете колони са запазени."
}
```

**13. [PortScan] Проверка на типовете данни**

```json
{
  "int64": 54,
  "float64": 24
}
```

**14. [PortScan] Коригиране на NaN/Infinity**

```json
{
  "Flow Bytes/s": {
    "NaN": 15,
    "Infinity": 356,
    "по клас": {
      "BENIGN": 245,
      "PortScan": 126
    }
  },
  "Flow Packets/s": {
    "NaN": 0,
    "Infinity": 371,
    "по клас": {
      "BENIGN": 245,
      "PortScan": 126
    }
  }
}
```

**15. [PortScan] Премахване на дублирани редове**

```json
{
  "премахнати по клас": {
    "PortScan": 68111,
    "BENIGN": 4242
  }
}
```

**16. [PortScan] Контролна проверка**

```json
{
  "NaN/Inf": 0,
  "противоречиви записи": 0,
  "класове": {
    "BENIGN": 123295,
    "PortScan": 90819
  }
}
```

**17. [PortScan] Запис на обработения набор**

```json
{
  "размер_MB": 63.5
}
```

**18. [DoS] Зареждане и профилиране**

```json
{
  "classes": {
    "BENIGN": 440031,
    "DoS Hulk": 231073,
    "DoS GoldenEye": 10293,
    "DoS slowloris": 5796,
    "DoS Slowhttptest": 5499,
    "Heartbleed": 11
  },
  "nan_cells": {
    "Flow Bytes/s": 1008
  },
  "inf_cells": {
    "Flow Bytes/s": 289,
    "Flow Packets/s": 1297
  },
  "duplicate_rows": 81909
}
```

**19. [DoS] Анализ на излишни колони (без премахване)**

```json
{
  "константни": [
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "CWE Flag Count",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate"
  ],
  "идентични двойки": [
    [
      "Total Fwd Packets",
      "Subflow Fwd Packets"
    ],
    [
      "Total Backward Packets",
      "Subflow Bwd Packets"
    ],
    [
      "Total Length of Fwd Packets",
      "Subflow Fwd Bytes"
    ],
    [
      "Fwd Packet Length Mean",
      "Avg Fwd Segment Size"
    ],
    [
      "Fwd PSH Flags",
      "SYN Flag Count"
    ],
    [
      "Fwd Header Length",
      "Fwd Header Length.1"
    ]
  ],
  "отрицателни стойности (минимум)": {
    "Flow Duration": -1.0,
    "Flow Bytes/s": -12000000.0,
    "Flow Packets/s": -2000000.0,
    "Flow IAT Mean": -1.0,
    "Flow IAT Max": -1.0,
    "Flow IAT Min": -14.0,
    "Fwd IAT Min": -8.0,
    "Fwd Header Length": -11.0,
    "Fwd Header Length.1": -11.0,
    "Init_Win_bytes_forward": -1.0,
    "Init_Win_bytes_backward": -1.0,
    "min_seg_size_forward": -1.0
  },
  "редове с отрицателна Flow Duration": 21
}
```

**20. [DoS] Нормализиране на имената на колоните**

```json
{
  "преименувани": 65,
  "бележка": "Заглавието 'Fwd Header Length' се среща два пъти в оригиналния файл; pandas автоматично именува второто копие 'Fwd Header Length.1'. И двете колони са запазени."
}
```

**21. [DoS] Проверка на типовете данни**

```json
{
  "int64": 54,
  "float64": 24
}
```

**22. [DoS] Коригиране на NaN/Infinity**

```json
{
  "Flow Bytes/s": {
    "NaN": 1008,
    "Infinity": 289,
    "по клас": {
      "DoS Hulk": 949,
      "BENIGN": 348
    }
  },
  "Flow Packets/s": {
    "NaN": 0,
    "Infinity": 1297,
    "по клас": {
      "DoS Hulk": 949,
      "BENIGN": 348
    }
  }
}
```

**23. [DoS] Отстраняване на неизследвани атаки**

```json
{
  "премахнати": {
    "Heartbleed": 11
  }
}
```

**24. [DoS] Премахване на дублирани редове**

```json
{
  "премахнати по клас": {
    "DoS Hulk": 58224,
    "BENIGN": 22996,
    "DoS slowloris": 411,
    "DoS Slowhttptest": 271,
    "DoS GoldenEye": 7
  }
}
```

**25. [DoS] Отстраняване на противоречиви записи**

```json
{
  "премахнати по етикет": {
    "BENIGN": 48,
    "DoS Hulk": 47,
    "DoS slowloris": 1
  }
}
```

**26. [DoS] Контролна проверка**

```json
{
  "NaN/Inf": 0,
  "противоречиви записи": 96,
  "класове": {
    "BENIGN": 416987,
    "DoS Hulk": 172802,
    "DoS GoldenEye": 10286,
    "DoS slowloris": 5384,
    "DoS Slowhttptest": 5228
  }
}
```

**27. [DoS] Запис на обработения набор**

```json
{
  "размер_MB": 213.6
}
```

**28. [BruteForce] Зареждане и профилиране**

```json
{
  "classes": {
    "BENIGN": 432074,
    "FTP-Patator": 7938,
    "SSH-Patator": 5897
  },
  "nan_cells": {
    "Flow Bytes/s": 201
  },
  "inf_cells": {
    "Flow Bytes/s": 63,
    "Flow Packets/s": 264
  },
  "duplicate_rows": 24065
}
```

**29. [BruteForce] Анализ на излишни колони (без премахване)**

```json
{
  "константни": [
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "CWE Flag Count",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate"
  ],
  "идентични двойки": [
    [
      "Total Fwd Packets",
      "Subflow Fwd Packets"
    ],
    [
      "Total Backward Packets",
      "Subflow Bwd Packets"
    ],
    [
      "Total Length of Fwd Packets",
      "Subflow Fwd Bytes"
    ],
    [
      "Fwd Packet Length Mean",
      "Avg Fwd Segment Size"
    ],
    [
      "Fwd PSH Flags",
      "SYN Flag Count"
    ],
    [
      "Fwd Header Length",
      "Fwd Header Length.1"
    ]
  ],
  "отрицателни стойности (минимум)": {
    "Flow Duration": -4.0,
    "Flow Packets/s": -2000000.0,
    "Flow IAT Mean": -4.0,
    "Flow IAT Max": -4.0,
    "Flow IAT Min": -13.0,
    "Fwd Header Length": -32212234632.0,
    "Bwd Header Length": -1073741320.0,
    "Fwd Header Length.1": -32212234632.0,
    "Init_Win_bytes_forward": -1.0,
    "Init_Win_bytes_backward": -1.0,
    "min_seg_size_forward": -536870661.0
  },
  "редове с отрицателна Flow Duration": 17
}
```

**30. [BruteForce] Нормализиране на имената на колоните**

```json
{
  "преименувани": 65,
  "бележка": "Заглавието 'Fwd Header Length' се среща два пъти в оригиналния файл; pandas автоматично именува второто копие 'Fwd Header Length.1'. И двете колони са запазени."
}
```

**31. [BruteForce] Проверка на типовете данни**

```json
{
  "int64": 54,
  "float64": 24
}
```

**32. [BruteForce] Коригиране на NaN/Infinity**

```json
{
  "Flow Bytes/s": {
    "NaN": 201,
    "Infinity": 63,
    "по клас": {
      "BENIGN": 261,
      "FTP-Patator": 3
    }
  },
  "Flow Packets/s": {
    "NaN": 0,
    "Infinity": 264,
    "по клас": {
      "BENIGN": 261,
      "FTP-Patator": 3
    }
  }
}
```

**33. [BruteForce] Премахване на дублирани редове**

```json
{
  "премахнати по клас": {
    "BENIGN": 19382,
    "SSH-Patator": 2678,
    "FTP-Patator": 2005
  }
}
```

**34. [BruteForce] Контролна проверка**

```json
{
  "NaN/Inf": 0,
  "противоречиви записи": 0,
  "класове": {
    "BENIGN": 412692,
    "FTP-Patator": 5933,
    "SSH-Patator": 3219
  }
}
```

**35. [BruteForce] Запис на обработения набор**

```json
{
  "размер_MB": 135.0
}
```

**36. [DDoS] Разделяне на обучаващо/тестово множество**

```json
{
  "обучение": {
    "общо": 156178,
    "атака": 89611
  },
  "тест": {
    "общо": 66934,
    "атака": 38405
  }
}
```

**37. [DDoS] Редукция на размерността (PCA)**

```json
{
  "трансформации": [
    "sign(x)·ln(1+|x|)",
    "StandardScaler",
    "PCA(n_components=0.99)"
  ],
  "компоненти за 90/95/99 %": [
    10,
    14,
    22
  ]
}
```

**38. [PortScan] Разделяне на обучаващо/тестово множество**

```json
{
  "обучение": {
    "общо": 149879,
    "атака": 63573
  },
  "тест": {
    "общо": 64235,
    "атака": 27246
  }
}
```

**39. [PortScan] Редукция на размерността (PCA)**

```json
{
  "трансформации": [
    "sign(x)·ln(1+|x|)",
    "StandardScaler",
    "PCA(n_components=0.99)"
  ],
  "компоненти за 90/95/99 %": [
    9,
    13,
    22
  ]
}
```

**40. [DoS] Разделяне на обучаващо/тестово множество**

```json
{
  "обучение": {
    "общо": 427480,
    "атака": 135590
  },
  "тест": {
    "общо": 183207,
    "атака": 58110
  }
}
```

**41. [DoS] Редукция на размерността (PCA)**

```json
{
  "трансформации": [
    "sign(x)·ln(1+|x|)",
    "StandardScaler",
    "PCA(n_components=0.99)"
  ],
  "компоненти за 90/95/99 %": [
    10,
    14,
    24
  ]
}
```

**42. [BruteForce] Разделяне на обучаващо/тестово множество**

```json
{
  "обучение": {
    "общо": 295290,
    "атака": 6406
  },
  "тест": {
    "общо": 126554,
    "атака": 2746
  }
}
```

**43. [BruteForce] Редукция на размерността (PCA)**

```json
{
  "трансформации": [
    "sign(x)·ln(1+|x|)",
    "StandardScaler",
    "PCA(n_components=0.99)"
  ],
  "компоненти за 90/95/99 %": [
    10,
    14,
    23
  ]
}
```

**44. [InSDN] Получаване на външния набор данни**

```json
{
  "източник": "https://aseados.ucd.ie/datasets/SDN/InSDN_DatasetCSV.zip",
  "sha256": "ee89ec66705c529fef26b27dd18c6aa56d469006f7ade9cd92fd4a503e320d7d",
  "файлове": [
    "Normal_data.csv",
    "OVS.csv",
    "metasploitable-2.csv"
  ]
}
```

**45. [InSDN] Зареждане**

```json
{
  "етикети": {
    "DDoS": 121942,
    "Probe": 98129,
    "Normal": 68424,
    "DoS": 53616,
    "BFA": 1405,
    "Web-Attack": 192,
    "BOTNET": 164,
    "U2R": 17
  }
}
```

**46. [InSDN] Съпоставяне на колоните с CIC-IDS2017**

```json
{
  "липсващи характеристики": []
}
```

**47. [InSDN] Проверка за NaN/Infinity**

```json
{
  "NaN": 0,
  "Inf": 0
}
```

**48. [InSDN] Премахване на дублирани записи**

```json
{
  "премахнати по етикет": {
    "DDoS": 120422,
    "DoS": 3176,
    "Normal": 1507,
    "Probe": 114,
    "BFA": 24,
    "Web-Attack": 9
  }
}
```

**50. [KDD99] Получаване на набора данни**

```json
{
  "източник": "http://kdd.ics.uci.edu/databases/kddcup99/kddcup99.html",
  "етикети": {
    "smurf": 280790,
    "neptune": 107201,
    "normal": 97278,
    "back": 2203,
    "satan": 1589,
    "ipsweep": 1247,
    "portsweep": 1040,
    "warezclient": 1020,
    "teardrop": 979,
    "pod": 264,
    "nmap": 231,
    "guess_passwd": 53,
    "buffer_overflow": 30,
    "land": 21,
    "warezmaster": 20,
    "imap": 12,
    "rootkit": 10,
    "loadmodule": 9,
    "ftp_write": 8,
    "multihop": 7,
    "phf": 4,
    "perl": 3,
    "spy": 2
  }
}
```

**51. [KDD99] Премахване на дублирани записи**

```json
{
  "премахнати по етикет": {
    "smurf": 280149,
    "neptune": 55381,
    "normal": 9446,
    "back": 1235,
    "satan": 683,
    "portsweep": 624,
    "ipsweep": 596,
    "warezclient": 127,
    "nmap": 73,
    "teardrop": 61,
    "pod": 58,
    "land": 2
  }
}
```

**52. [KDD99] Кодиране на символните характеристики (в конвейера)**

```json
{
  "брой стойности": {
    "protocol_type": 3,
    "service": 66,
    "flag": 11
  }
}
```
