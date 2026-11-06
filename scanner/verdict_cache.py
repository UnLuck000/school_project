"""Кэш вердиктов: повторная проверка неизменённого файла не читает его заново.

Запись привязана к пути, размеру и времени изменения файла, а также к «версии» проверки
(отпечатки баз хэшей и правил, ручные исключения, порог эвристики). Изменился файл или
обновились базы — файл проверяется заново. Хранится в cache/verdicts.sqlite.
Записи копятся в памяти и пишутся на диск пачками: SQLite медленно фиксирует по одной.
"""
import os
import sqlite3
import threading
import time
from pathlib import Path

CACHE_FILE = Path(__file__).resolve().parent.parent / "cache" / "verdicts.sqlite"
FLUSH_EVERY = 200      # записей
FLUSH_SECONDS = 3.0
KEEP_DAYS = 90         # старые записи удаляются при открытии

_lock = threading.RLock()
_conn: sqlite3.Connection | None = None
_conn_path: Path | None = None
_pending: dict[str, tuple] = {}
_last_flush = time.monotonic()
_hits = 0
_misses = 0


def _key(path) -> str:
    return os.path.normcase(os.path.abspath(str(path)))


def _db() -> sqlite3.Connection | None:
    global _conn, _conn_path
    if _conn is not None and _conn_path == CACHE_FILE:
        return _conn
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(CACHE_FILE), check_same_thread=False, timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("""CREATE TABLE IF NOT EXISTS verdicts (
            path TEXT PRIMARY KEY, size INTEGER, mtime INTEGER, version TEXT,
            sha256 TEXT, reason TEXT, checked REAL)""")
        conn.execute("DELETE FROM verdicts WHERE checked < ?", (time.time() - KEEP_DAYS * 86400,))
        conn.commit()
    except sqlite3.Error:
        return None  # кэш не обязателен: без него просто медленнее
    _conn, _conn_path = conn, CACHE_FILE
    return conn


def get(path, st: os.stat_result, version: str) -> tuple[str, str | None] | None:
    """(sha256, причина или None), если файл с тех пор не менялся и базы те же."""
    global _hits, _misses
    key = _key(path)
    with _lock:
        row = _pending.get(key)
        if row is None:
            conn = _db()
            if conn is None:
                return None
            try:
                found = conn.execute(
                    "SELECT size, mtime, version, sha256, reason FROM verdicts WHERE path = ?",
                    (key,)).fetchone()
            except sqlite3.Error:
                return None
            row = found and (found[0], found[1], found[2], found[3], found[4])
        if row and row[0] == st.st_size and row[1] == st.st_mtime_ns and row[2] == version:
            _hits += 1
            return row[3], row[4]
        _misses += 1
        return None


def put(path, st: os.stat_result, version: str, sha256: str, reason: str | None) -> None:
    with _lock:
        _pending[_key(path)] = (st.st_size, st.st_mtime_ns, version, sha256, reason)
        if len(_pending) >= FLUSH_EVERY or time.monotonic() - _last_flush > FLUSH_SECONDS:
            flush()


def flush() -> None:
    """Записывает накопленное на диск (в конце проверки папки и при выходе)."""
    global _last_flush
    with _lock:
        _last_flush = time.monotonic()
        if not _pending:
            return
        conn = _db()
        if conn is None:
            _pending.clear()
            return
        now = time.time()
        rows = [(k, *v, now) for k, v in _pending.items()]
        _pending.clear()
        try:
            conn.executemany("INSERT OR REPLACE INTO verdicts VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
            conn.commit()
        except sqlite3.Error:
            pass


def clear() -> None:
    with _lock:
        _pending.clear()
        conn = _db()
        if conn is not None:
            try:
                conn.execute("DELETE FROM verdicts")
                conn.commit()
            except sqlite3.Error:
                pass


def stats() -> tuple[int, int]:
    """(попаданий, промахов) за время работы программы."""
    return _hits, _misses


def forget(paths) -> None:
    """Убирает записи о файлах: следующая проверка прочитает их заново."""
    keys = [_key(p) for p in paths]
    with _lock:
        for key in keys:
            _pending.pop(key, None)
        conn = _db()
        if conn is None:
            return
        try:
            conn.executemany("DELETE FROM verdicts WHERE path = ?", [(k,) for k in keys])
            conn.commit()
        except sqlite3.Error:
            pass
