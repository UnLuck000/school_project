import json
import os
from datetime import datetime
from pathlib import Path

WHITELIST_FILE = Path("signatures/whitelist.json")


def load_whitelist() -> dict[str, dict]:
    """Возвращает {sha256: {"path": ..., "added_at": ...}}."""
    try:
        data = json.loads(WHITELIST_FILE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _save(data: dict) -> None:
    WHITELIST_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = WHITELIST_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, WHITELIST_FILE)  # запись через временный файл


def add_to_whitelist(sha256: str, path: str) -> bool:
    """Добавляет хэш. Возвращает False, если он уже был в списке."""
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
    data = load_whitelist()
    if data.pop(sha256.strip().lower(), None) is None:
        return False
    _save(data)
    return True