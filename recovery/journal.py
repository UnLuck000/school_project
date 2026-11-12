import json
import os
import threading
import uuid
from datetime import datetime
from pathlib import Path
from collections.abc import Callable

import userdata

BASE_DIR = Path(__file__).resolve().parent.parent
JOURNAL_DIR = userdata.JOURNAL_DIR  # папка конфигурации пользователя (userdata.py)
JOURNAL_FILE = JOURNAL_DIR / "actions.jsonl"
BACKUP_DIR = JOURNAL_DIR / "backup"

_lock = threading.Lock()
UNDO_HANDLERS: dict[str, Callable[[dict], str]] = {}
# op → проверка «действие ещё в силе» (False — его уже сняли без журнала: отменять нечего)
ACTIVE_CHECKS: dict[str, Callable[[dict], bool]] = {}


def undo_op(name: str):
    """Декоратор: регистрирует функцию отката для операции с таким именем."""
    def decorator(func):
        UNDO_HANDLERS[name] = func
        return func
    return decorator


def active_check(name: str):
    """Декоратор: проверка, что действие операции name ещё в силе (см. cleanup)."""
    def decorator(func):
        ACTIVE_CHECKS[name] = func
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
    try:
        from diag.log import get
        get("journal").info("Действие: %s (%s)", title, op)
    except Exception:  # noqa: S110 — дубль в app.log не обязателен
        pass
    with _lock:
        JOURNAL_DIR.mkdir(parents=True, exist_ok=True)
        with JOURNAL_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record["id"]


def log_notice(title: str, op: str, data: dict) -> str:
    """Запись-сообщение (сбой системной программы и т. п.): видна в журнале действий, но
    отменять в ней нечего. data["details"] — подробное описание (двойной щелчок)."""
    record = {"id": uuid.uuid4().hex, "time": datetime.now().isoformat(timespec="seconds"),
              "title": title, "op": op, "data": data, "undone": False, "undone_at": "",
              "notice": True}
    with _lock:
        JOURNAL_DIR.mkdir(parents=True, exist_ok=True)
        with JOURNAL_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record["id"]


def read_all() -> list[dict]:
    with _lock:
        return _read()


def forget(op: str, match: Callable[[dict], bool] | None = None) -> int:
    """Убрать неотменённые записи операции op (match(data) — какие именно): действие снято
    обычным путём (VPN отключился, блокировку сняли на странице «Сеть»), отменять нечего."""
    with _lock:
        records = _read()
        kept = [r for r in records if r["undone"] or r["op"] != op
                or (match is not None and not _safe(match, r["data"]))]
        if len(kept) != len(records):
            _write(kept)
        return len(records) - len(kept)


def _safe(func, data) -> bool:
    try:
        return bool(func(data))
    except Exception:
        return False


def _still_active(record: dict) -> bool:
    check = ACTIVE_CHECKS.get(record["op"])
    if check is None:
        return True
    try:
        return bool(check(record["data"]))
    except Exception:  # проверить не удалось — запись остаётся
        return True


def cleanup() -> int:
    """Убирает неотменённые записи, отмена которых ничего не сделает: действие уже снято
    другим путём (ACTIVE_CHECKS) или это повтор того же действия с теми же данными (остаётся
    последний). Возвращает, сколько записей убрано."""
    with _lock:
        records = _read()
    seen: set[str] = set()
    drop: set[str] = set()
    for r in reversed(records):  # с конца: остаётся последняя запись из повторов
        if r["undone"]:
            continue
        key = r["op"] + json.dumps(r["data"], sort_keys=True, ensure_ascii=False)
        if key in seen or not _still_active(r):
            drop.add(r["id"])
        seen.add(key)
    if not drop:
        return 0
    with _lock:
        records = [r for r in _read() if r["id"] not in drop]
        _write(records)
    try:
        from diag.log import get
        get("journal").info("Журнал: убрано записей, которые уже сняты или повторяются: %d",
                            len(drop))
    except Exception:  # noqa: S110 — дубль в app.log не обязателен
        pass
    return len(drop)


def undo(record_id: str) -> str:
    """Отменяет действие. При неудаче бросает ValueError или OSError, запись остаётся."""
    with _lock:
        record = next((r for r in _read() if r["id"] == record_id), None)
    if record is None:
        raise ValueError("Запись журнала не найдена")
    if record.get("notice"):
        raise ValueError("Это запись о сбое: отменять нечего")
    if record["undone"]:
        raise ValueError("Это действие уже отменено")
    handler = UNDO_HANDLERS.get(record["op"])
    if handler is None:
        raise ValueError("Для этого действия откат не поддерживается")

    from diag import features
    with features.track("journal.undo") as run:
        run.fact("op", record["op"])
        message = handler(record["data"])

    with _lock:
        records = _read()
        for r in records:
            if r["id"] == record_id:
                r["undone"] = True
                r["undone_at"] = datetime.now().isoformat(timespec="seconds")
        _write(records)
    return message
