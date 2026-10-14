import io
import os
import re
import sys
import urllib.request
import zipfile
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
FEEDS_DIR = BASE_DIR / "signatures" / "feeds"
COMMUNITY_RULES_DIR = BASE_DIR / "signatures" / "rules" / "community"
KEY_FILE = BASE_DIR / "signatures" / ".abusech_key"

SHA256_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
MB_URL = "https://mb-api.abuse.ch/v2/files/exports/{key}/{name}"
RULES_ZIP = "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip"


def _download(url: str, timeout: int = 120) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "study-av-updater/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _get_key() -> str:
    key = os.environ.get("ABUSECH_AUTH_KEY", "").strip()
    if not key and KEY_FILE.exists():
        key = KEY_FILE.read_text(encoding="utf-8").strip()
    return key


def update_hashes(export_name: str = "recent.csv") -> None:
    key = _get_key()
    if not key:
        print("Нет Auth-Key: положите его в signatures/.abusech_key "
              "или задайте переменную ABUSECH_AUTH_KEY")
        return
    try:
        raw = _download(MB_URL.format(key=key, name=export_name))
    except Exception as e:  # ключ в сообщение не выводим
        print(f"Не удалось скачать список хэшей: {type(e).__name__}: {e}")
        return

    new = set()
    for line in raw.decode("utf-8", errors="ignore").splitlines():
        if line.startswith("#"):
            continue
        m = SHA256_RE.search(line)
        if m:
            new.add(m.group(0).lower())

    FEEDS_DIR.mkdir(parents=True, exist_ok=True)
    target = FEEDS_DIR / "malwarebazaar.txt"
    old = set()
    if target.exists():
        old = {l.strip() for l in target.read_text(encoding="utf-8").splitlines()
               if l.strip() and not l.startswith("#")}
    merged = old | new  # база накапливается между запусками
    target.write_text("# MalwareBazaar (abuse.ch)\n" + "\n".join(sorted(merged)) + "\n",
                      encoding="utf-8")
    print(f"Хэши: получено {len(new)}, новых {len(merged - old)}, всего {len(merged)}")


def update_rules() -> None:
    try:
        data = _download(RULES_ZIP)
    except Exception as e:
        print(f"Не удалось скачать правила: {type(e).__name__}: {e}")
        return

    COMMUNITY_RULES_DIR.mkdir(parents=True, exist_ok=True)
    for old in list(COMMUNITY_RULES_DIR.glob("*.yar")) + list(COMMUNITY_RULES_DIR.glob("*.yara")):
        old.unlink()

    count = 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for name in zf.namelist():
            if name.lower().endswith((".yar", ".yara")) and "/yara/" in name:
                # пишем под собственным именем, пути из архива не используем
                (COMMUNITY_RULES_DIR / Path(name).name).write_bytes(zf.read(name))
                count += 1
    print(f"Правила YARA: сохранено файлов {count} -> {COMMUNITY_RULES_DIR}")


if __name__ == "__main__":
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    if what in ("all", "hashes"):
        update_hashes(sys.argv[2] if len(sys.argv) > 2 else "recent.csv")
    if what in ("all", "rules"):
        update_rules()