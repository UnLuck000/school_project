"""Журнал защиты: всё найденное (угрозы и подозрительное) с текущим состоянием.

Записи: journal/threats.json. Состояния: found — найдено, файл на месте (автокарантин
временно выключен: решение за пользователем), quarantined — в карантине, deleted — удалён,
restored — возвращён из карантина (и добавлен в белый список), dismissed — убран из списка.
Повторная находка того же файла с тем же вердиктом не создаёт новую запись: обновляется время
и счётчик. Файлы, помещённые в карантин в других местах (автозапуск, сканер папки), видны
здесь же — по метаданным карантина (merged).
"""
import json
import os
import threading
import uuid
from datetime import datetime
from pathlib import Path

from recovery.journal import JOURNAL_DIR

THREATS_FILE = JOURNAL_DIR / "threats.json"
LIMIT = 2000  # записей не больше: самые старые завершённые уходят первыми

FOUND, QUARANTINED, DELETED, RESTORED, DISMISSED = (
    "found", "quarantined", "deleted", "restored", "dismissed")
STATUS_TEXT = {FOUND: "Найдено", QUARANTINED: "В карантине", DELETED: "Удалено",
               RESTORED: "Восстановлено (белый список)", DISMISSED: "Убрано из списка"}
OPEN = (FOUND, QUARANTINED)  # требуют решения или ещё в карантине

_lock = threading.Lock()
# интерфейс со службой (service/remote.py): журнал защиты ведёт служба; в ней и без неё — None
_remote = None


def set_remote(backend) -> None:
    global _remote
    _remote = backend


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _read() -> list[dict]:
    try:
        data = json.loads(THREATS_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _write(records: list[dict]) -> None:
    if len(records) > LIMIT:
        done = [r for r in records if r["status"] not in OPEN]
        extra = set(id(r) for r in done[:len(records) - LIMIT])
        records = [r for r in records if id(r) not in extra]
    THREATS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = THREATS_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(records, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, THREATS_FILE)


def add(path: str, level: str, text: str, source: str = "", story: str = "",
        pid: int = 0) -> str:
    """Находка (level: threat | suspicious). Возвращает id записи. story — сводка по
    процессу на момент находки (processmanager.story): процесс к просмотру журнала
    обычно уже завершён."""
    if _remote is not None:
        return _remote.add(path, level, text, source, story, pid)
    key = os.path.normcase(path) if path else text
    with _lock:
        records = _read()
        for r in records:
            if r["status"] == FOUND and r.get("key") == key and r["text"] == text:
                r["time"], r["count"] = _now(), r.get("count", 1) + 1
                if story:
                    r["story"], r["pid"] = story, pid
                _write(records)
                return r["id"]
        record = {"id": uuid.uuid4().hex, "time": _now(), "first": _now(), "count": 1,
                  "key": key, "path": path, "level": level, "text": text,
                  "source": source, "status": FOUND, "qid": ""}
        if story:
            record["story"], record["pid"] = story, pid
        records.append(record)
        _write(records)
        return record["id"]


def set_status(record_id: str, status: str, qid: str = "") -> None:
    if _remote is not None:
        return _remote.set_status(record_id, status, qid)
    with _lock:
        records = _read()
        for r in records:
            if r["id"] == record_id:
                r["status"], r["changed"] = status, _now()
                if qid:
                    r["qid"] = qid
        _write(records)


def merged(include_done: bool = False) -> list[dict]:
    """Записи журнала и файлы карантина, которых в нём нет; состояние карантина — по его
    метаданным (файл могли восстановить или удалить из другого окна)."""
    if _remote is not None:
        return _remote.merged(include_done)
    from quarantine import STATUS_DELETED, STATUS_QUARANTINED, STATUS_RESTORED, list_quarantine
    q_status = {STATUS_QUARANTINED: QUARANTINED, STATUS_RESTORED: RESTORED,
                STATUS_DELETED: DELETED}
    metas = {m["id"]: m for m in list_quarantine(include_history=True)}
    with _lock:
        records = _read()
    linked = set()
    for r in records:
        meta = metas.get(r.get("qid") or "")
        if meta is not None:
            linked.add(meta["id"])
            r["status"] = q_status.get(meta["status"], r["status"])
    for meta in metas.values():
        if meta["id"] in linked:
            continue
        records.append({"id": "q:" + meta["id"], "time": meta["quarantined_at"].replace(" ", "T"),
                        "path": meta["original_path"], "level": "threat",
                        "text": meta.get("reason", ""), "source": "Карантин",
                        "status": q_status.get(meta["status"], QUARANTINED),
                        "qid": meta["id"], "count": 1, "sha256": meta.get("sha256", ""),
                        "signature": meta.get("signature", "")})
    if not include_done:
        records = [r for r in records if r["status"] in OPEN]
    return sorted(records, key=lambda r: r.get("time", ""), reverse=True)


def get(record_id: str) -> dict | None:
    if _remote is not None:
        return _remote.get(record_id)
    return next((r for r in merged(True) if r["id"] == record_id), None)


def mark_path(path: str, status: str, qid: str = "") -> None:
    """Файл из найденного обработан в другом месте (карантин с вкладки «Защита»)."""
    if _remote is not None:
        return _remote.mark_path(path, status, qid)
    key = os.path.normcase(path)
    with _lock:
        records = _read()
        for r in records:
            if r["status"] == FOUND and r.get("key") == key:
                r["status"], r["changed"] = status, _now()
                if qid:
                    r["qid"] = qid
        _write(records)


def dismiss(record_id: str) -> None:
    if _remote is not None:
        return _remote.dismiss(record_id)
    if record_id.startswith("q:"):
        return  # файл в карантине: решение — восстановить или удалить
    set_status(record_id, DISMISSED)


def open_count() -> int:
    return sum(1 for r in merged() if r["status"] == FOUND)


def exists(path: str) -> bool:
    return bool(path) and Path(path).exists()
