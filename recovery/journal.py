import json
import os
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Callable

BASE_DIR = Path(__file__).resolve().parent.parent
JOURNAL_DIR = BASE_DIR / "journal"
JOURNAL_FILE = JOURNAL_DIR / "actions.jsonl"
BACKUP_DIR = JOURNAL_DIR / "backup"

_lock = threading.Lock()
UNDO_HANDLERS: dict[str, Callable[[dict], str]] = {}


def undo_op(name: str):
    """Декоратор: регистрирует функцию отката для операции с таким именем."""
    def decorator(func):
        UNDO_HANDLERS[name] = func
        return func
    return decorator


def _read() -> list[dict]:
    if not JOURNAL_FILE.exists():
        return []
    records = []
    for line in JOURNAL_FILE.read_text(encoding="utf-8").splitlines():
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def _write(records: list[dict]) -> None:
    JOURNAL_DIR.mkdir(parents=True, exist_ok=True)
    tmp = JOURNAL_FILE.with_suffix(".jsonl.tmp")
    tmp.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records),
                   encoding="utf-8")
    os.replace(tmp, JOURNAL_FILE)  # запись через временный файл


def log_action(title: str, op: str, data: dict) -> str:
    """Записывает выполненное действие. op и data нужны для его отмены."""
    record = {"id": uuid.uuid4().hex, "time": datetime.now().isoformat(timespec="seconds"),
              "title": title, "op": op, "data": data, "undone": False, "undone_at": ""}
    with _lock:
        JOURNAL_DIR.mkdir(parents=True, exist_ok=True)
        with JOURNAL_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record["id"]


def read_all() -> list[dict]:
    with _lock:
        return _read()


def undo(record_id: str) -> str:
    """Отменяет действие. При неудаче бросает ValueError или OSError, запись остаётся."""
    with _lock:
        record = next((r for r in _read() if r["id"] == record_id), None)
    if record is None:
        raise ValueError("Запись журнала не найдена")
    if record["undone"]:
        raise ValueError("Это действие уже отменено")
    handler = UNDO_HANDLERS.get(record["op"])
    if handler is None:
        raise ValueError("Для этого действия откат не поддерживается")

    message = handler(record["data"])

    with _lock:
        records = _read()
        for r in records:
            if r["id"] == record_id:
                r["undone"] = True
                r["undone_at"] = datetime.now().isoformat(timespec="seconds")
        _write(records)
    return message