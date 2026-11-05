"""Дневници на изследването.

* DataActionLog – всяко действие върху набора данни (брой редове/колони преди и след).
  Записва се в logs/data_actions_log.json и logs/data_actions_log.md.
* get_logger – текстов дневник на изпълнението (обучение, валидиране, времена) в logs/experiment_log.txt.
"""
import json
import logging
from datetime import datetime

from config import LOGS_DIR


def num(value):
    """Цяло число с интервал за хилядите (български формат): 225 745."""
    return f"{value:,}".replace(",", "\u00a0")


class DataActionLog:
    def __init__(self, source, name="data_actions_log", reset=False):
        """source – скриптът, който записва; при повторно изпълнение старите му записи се заменят."""
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        self.source = source
        self.json_path = LOGS_DIR / f"{name}.json"
        self.md_path = LOGS_DIR / f"{name}.md"
        self.entries = []
        if not reset and self.json_path.exists():
            old = json.loads(self.json_path.read_text(encoding="utf-8"))
            self.entries = [e for e in old if e.get("source") != source]
            for i, e in enumerate(self.entries, 1):
                e["step"] = i

    def record(self, dataset, action, description, rows_before=None, rows_after=None,
               cols_before=None, cols_after=None, details=None):
        if cols_before is not None and cols_after is not None and cols_after < cols_before:
            # Изискване на заданието: колони от набора данни не се премахват.
            raise RuntimeError(f"[{dataset}] '{action}' би премахнало колони ({cols_before} -> {cols_after})")
        entry = {
            "step": len(self.entries) + 1,
            "source": self.source,
            "time": datetime.now().isoformat(timespec="seconds"),
            "dataset": dataset,
            "action": action,
            "description": description,
            "rows_before": rows_before,
            "rows_after": rows_after,
            "cols_before": cols_before,
            "cols_after": cols_after,
            "details": details or {},
        }
        self.entries.append(entry)
        self.save()
        return entry

    def save(self):
        self.json_path.write_text(json.dumps(self.entries, ensure_ascii=False, indent=2, default=str),
                                  encoding="utf-8")
        lines = [
            "# Дневник на действията върху набора данни",
            "",
            "Файлът се генерира автоматично от `src/action_log.py` при всяко изпълнение на конвейера.",
            "Колони от набора данни **не се премахват** – логърът спира изпълнението, ако някоя стъпка намали броя им.",
            "",
            "| № | Време | Скрипт | Набор | Действие | Редове преди → след | Колони преди → след | Описание |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for e in self.entries:
            rows = "" if e["rows_before"] is None else f"{num(e['rows_before'])} → {num(e['rows_after'])}"
            cols = "" if e["cols_before"] is None else f"{e['cols_before']} → {e['cols_after']}"
            lines.append(f"| {e['step']} | {e['time']} | {e['source']} | {e['dataset']} | {e['action']} | {rows} | {cols} | "
                         f"{e['description']} |")
        lines += ["", "## Подробности по стъпки", ""]
        for e in self.entries:
            if e["details"]:
                lines.append(f"**{e['step']}. [{e['dataset']}] {e['action']}**")
                lines.append("")
                lines.append("```json")
                lines.append(json.dumps(e["details"], ensure_ascii=False, indent=2, default=str))
                lines.append("```")
                lines.append("")
        self.md_path.write_text("\n".join(lines), encoding="utf-8")


def get_logger(name="experiment"):
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s", "%Y-%m-%d %H:%M:%S")
        fh = logging.FileHandler(LOGS_DIR / "experiment_log.txt", encoding="utf-8")
        fh.setFormatter(fmt)
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        logger.addHandler(fh)
        logger.addHandler(sh)
    return logger
