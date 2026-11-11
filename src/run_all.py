"""Изпълнява целия експеримент последователно (фаза 1 и фаза 2)."""
import runpy
import time
from pathlib import Path

from config import setup_console

STEPS = ["step1_prepare_data.py", "step2_dimensionality.py", "step3_train_evaluate.py", "step4_figures.py",
         "overfitting_check.py", "step5_external_test.py", "step6_kdd99.py"]

if __name__ == "__main__":
    setup_console()
    here = Path(__file__).parent
    for step in STEPS:
        t = time.time()
        print(f"\n>>> {step}")
        runpy.run_path(str(here / step), run_name="__main__")
        print(f"<<< {step} ({time.time() - t:.0f} s)")
