"""Журнал действий: что программа изменила в системе и как это отменить.

Записи лежат в папке конфигурации пользователя (actions.jsonl) — писать туда может любая
программа этого пользователя. Отмена выполняется с правами администратора и делает то, что
написано в записи (значение реестра HKLM, файл hosts, служба...), поэтому каждая запись
подписана (mac: HMAC-SHA256 ключом trustseal.mac_key, его читают только администраторы).
При отмене: подпись верна — как раньше; подпись не сходится — запись подделана, отмена
запрещена; подписи нет (записи прежних версий или сделанные без прав администратора) —
UnsignedRecord: окно журнала показывает, что будет сделано, и спрашивает.
"""
import hashlib
import hmac
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


class UnsignedRecord(ValueError):
    """Запись без подписи: отменять — только после подтверждения пользователя."""


SIGNED_FIELDS = ("id", "time", "title", "op", "data")


def signature(record: dict) -> str:
    """Подпись записи; пустая — ключа нет (программа без прав администратора)."""
    import trustseal
    key = trustseal.mac_key()
    if not key:
        return ""
    body = json.dumps({k: record.get(k) for k in SIGNED_FIELDS}, sort_keys=True,
                      ensure_ascii=False)
    return hmac.new(key, body.encode("utf-8"), hashlib.sha256).hexdigest()


def check(record: dict) -> str:
    """ok — подпись верна; unsigned — подписи нет; forged — подпись не сходится (или не
    проверить: ключа нет, а запись подписана)."""
    mac = record.get("mac") or ""
    if not mac:
        return "unsigned"
    expected = signature(record)
    return "ok" if expected and hmac.compare_digest(mac, expected) else "forged"


def _signed(record: dict) -> dict:
    mac = signature(record)
    if mac:
        record["mac"] = mac
    return record


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


# окно со службой (service/remote.py): у службы свой журнал (её действия: брандмауэр, AMSI,
# журнал PowerShell, VPN с правами); в окне он виден вместе со своим, запись службы —
# с пометкой where="service", отмена — у службы (journal.undo, ослабляющая операция)
_remote = None


def set_remote(backend) -> None:
    global _remote
    _remote = backend


def _service_records() -> list[dict]:
    if _remote is None:
        return []
    return [dict(r, where="service") for r in _remote.journal_list()]


def log_action(title: str, op: str, data: dict) -> str:
    """Записывает выполненное действие. op и data нужны для его отмены."""
    record = _signed({"id": uuid.uuid4().hex,
                      "time": datetime.now().isoformat(timespec="seconds"),
                      "title": title, "op": op, "data": data, "undone": False, "undone_at": ""})
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
        local = _read()
    service = _service_records()
    if not service:
        return local
    return sorted(local + service, key=lambda r: r.get("time", ""))


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
    if _remote is not None:
        _remote.journal_cleanup()
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


def describe(record: dict) -> str:
    """Что сделает отмена: операция и её данные (для вопроса о записи без подписи)."""
    data = json.dumps(record.get("data"), ensure_ascii=False, indent=1)
    return f"{record.get('title', '')}\nОперация: {record.get('op')}\nДанные:\n{data[:1500]}"


def undo(record_id: str, unsigned_ok: bool = False) -> str:
    """Отменяет действие. При неудаче бросает ValueError или OSError, запись остаётся.
    Запись без подписи — UnsignedRecord, пока не передано unsigned_ok (пользователь видел,
    что будет сделано, и согласился)."""
    with _lock:
        record = next((r for r in _read() if r["id"] == record_id), None)
    if record is None and _remote is not None and \
            any(r["id"] == record_id for r in _service_records()):
        return _remote.journal_undo(record_id)
    if record is None:
        raise ValueError("Запись журнала не найдена")
    if record.get("notice"):
        raise ValueError("Это запись о сбое: отменять нечего")
    if record["undone"]:
        raise ValueError("Это действие уже отменено")
    handler = UNDO_HANDLERS.get(record["op"])
    if handler is None:
        raise ValueError("Для этого действия откат не поддерживается")
    state = check(record)
    if state == "forged":
        raise ValueError("Запись журнала изменена не программой (подпись не сходится) — "
                         "отменять её нельзя")
    if state == "unsigned" and not unsigned_ok:
        raise UnsignedRecord(describe(record))

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
