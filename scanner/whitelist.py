import json
import os
import time
from datetime import datetime
from pathlib import Path

import trustseal
import userdata

BASE_DIR = Path(__file__).resolve().parent.parent  # корень проекта
WHITELIST_FILE = userdata.WHITELIST_FILE  # папка конфигурации пользователя


def trusted_hashes() -> set[str]:
    """SHA-256, которые проверки не считают угрозой: белый список пользователя и заранее
    известные безвредные программы релиза (exclusions, категория programs)."""
    from scanner import exclusions
    global _trusted
    now = time.monotonic()
    if _trusted is None or now - _trusted[0] > TRUSTED_SECONDS:
        # защита файлов спрашивает это на каждый файл: два файла JSON читались и
        # разбирались заново; изменение из программы сбрасывает запомненное сразу
        _trusted = (now, frozenset(load_whitelist()) | frozenset(
            exclusions.load().get("programs", {})))
    return set(_trusted[1])


TRUSTED_SECONDS = 2.0
_trusted: tuple[float, frozenset] | None = None
# интерфейс со службой (service/remote.py): белый список ведёт служба; в ней и без неё — None
_remote = None


def set_remote(backend) -> None:
    global _remote
    _remote = backend
    forget_trusted()


def forget_trusted() -> None:
    global _trusted
    _trusted = None


def load_whitelist() -> dict[str, dict]:
    """Возвращает {sha256: {"path": ..., "added_at": ...}}."""
    if _remote is not None:
        return _remote.load_whitelist()
    try:
        # trustseal: файл, изменённый не программой, не действует, пока пользователь не решит
        data = json.loads(trustseal.read(WHITELIST_FILE).decode("utf-8"))
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _save(data: dict) -> None:
    WHITELIST_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = WHITELIST_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, WHITELIST_FILE)  # запись через временный файл
    trustseal.saved(WHITELIST_FILE)
    forget_trusted()


def add_to_whitelist(sha256: str, path: str) -> bool:
    """Добавляет хэш. Возвращает False, если он уже был в списке."""
    if _remote is not None:
        forget_trusted()
        return _remote.add_to_whitelist(sha256, path)
    sha256 = sha256.strip().lower()
    data = load_whitelist()
    if sha256 in data:
        return False
    data[sha256] = {
        "path": path,
        "added_at": datetime.now().isoformat(timespec="seconds"),
    }
    _save(data)
    return True


def remove_from_whitelist(sha256: str) -> bool:
    """Убирает хэш. Возвращает False, если его там не было."""
    if _remote is not None:
        forget_trusted()
        return _remote.remove_from_whitelist(sha256)
    data = load_whitelist()
    if data.pop(sha256.strip().lower(), None) is None:
        return False
    _save(data)
    return True
