"""Изтегляне и проверка на CIC-IDS2017 (235 MB, data/raw/) и на външния набор InSDN (19 MB, data/external/)."""
import hashlib
import urllib.request
import zipfile

from config import DATASET_MIRROR_URL, DATASET_SHA256, RAW_DIR, RAW_ZIP, setup_console


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    setup_console()
    RAW_ZIP.parent.mkdir(parents=True, exist_ok=True)
    if not RAW_ZIP.exists():
        print(f"Изтегляне от {DATASET_MIRROR_URL} ...")
        urllib.request.urlretrieve(DATASET_MIRROR_URL, RAW_ZIP)
    digest = sha256(RAW_ZIP)
    if digest != DATASET_SHA256:
        raise SystemExit(f"Грешна SHA-256 сума: {digest}")
    print("SHA-256 – OK")
    with zipfile.ZipFile(RAW_ZIP) as z:
        names = z.namelist()
        if any(not n.endswith((".csv", "/")) for n in names):
            raise SystemExit(f"Неочаквани файлове в архива: {names}")
        z.extractall(RAW_ZIP.parent)
    print(f"Разархивирани {len([n for n in names if n.endswith('.csv')])} CSV файла в {RAW_DIR}")
    download_insdn()


def download_insdn():
    """Външният набор InSDN (University College Dublin) за кръстосаната проверка."""
    from external_data import INSDN_DIR, INSDN_SHA256, INSDN_URL
    zip_path = INSDN_DIR.parent / "InSDN_DatasetCSV.zip"
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    if not zip_path.exists():
        print(f"Изтегляне от {INSDN_URL} ...")
        urllib.request.urlretrieve(INSDN_URL, zip_path)
    if sha256(zip_path) != INSDN_SHA256:
        raise SystemExit("Грешна SHA-256 сума на InSDN")
    with zipfile.ZipFile(zip_path) as z:
        if any(not n.endswith((".csv", "/")) for n in z.namelist()):
            raise SystemExit("Неочаквани файлове в архива на InSDN")
        z.extractall(zip_path.parent)
    print(f"InSDN – OK ({INSDN_DIR})")


if __name__ == "__main__":
    main()
