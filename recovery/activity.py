"""События работы программы: что делал пользователь и что нашла программа.

record() пишет событие в EVENTS_FILE (JSON Lines, хранится KEEP_DAYS дней) и дублирует его в
технический журнал logs/app.log. События читает окно «Ложные срабатывания»
(analyzer/fpwindow.py: файлы, на которые срабатывала защита за последние дни).

Отчёт о работе (периоды по 3 дня, папка outbox, отправка автору) убран 15.11.2026: отправки
так и не появилось, а для разработчика есть «Сведения для разработчика» (diag/bundle.py) с
полным журналом.
"""
import json
import threading
import time

import datadirs

ACTIVITY_DIR = datadirs.REPORTS / "activity"
EVENTS_FILE = ACTIVITY_DIR / "events.jsonl"
KEEP_DAYS = 90                                 # старые события удаляются
DAY = 86400

_lock = threading.Lock()


def record(kind: str, text: str, **details) -> None:
    """Добавляет событие. Ошибки записи не мешают работе программы."""
    item = {"time": time.time(), "kind": kind, "text": text}
    if details:
        item["details"] = details
    try:
        from diag.log import get
        get("activity").info("[%s] %s%s", kind, text,
                             f" {json.dumps(details, ensure_ascii=False, default=str)}"
                             if details else "")
    except Exception:  # noqa: S110 — дубль в app.log не обязателен
        pass
    try:
        with _lock:
            ACTIVITY_DIR.mkdir(parents=True, exist_ok=True)
            with EVENTS_FILE.open("a", encoding="utf-8") as f:
                f.write(json.dumps(item, ensure_ascii=False, default=str) + "\n")
    except OSError:
        pass


def read_events(since: float = 0.0, until: float | None = None) -> list[dict]:
    try:
        lines = EVENTS_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    events = []
    for line in lines:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("time", 0) >= since and (until is None or item["time"] < until):
            events.append(item)
    return events


def trim(now: float | None = None) -> None:
    """Удаляет события старше KEEP_DAYS дней."""
    border = (now or time.time()) - KEEP_DAYS * DAY
    with _lock:
        events = read_events(border)
        try:
            tmp = EVENTS_FILE.with_suffix(".tmp")
            tmp.write_text("".join(json.dumps(e, ensure_ascii=False, default=str) + "\n"
                                   for e in events), encoding="utf-8")
            tmp.replace(EVENTS_FILE)
        except OSError:
            pass
