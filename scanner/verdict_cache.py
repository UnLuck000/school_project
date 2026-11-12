"""Кэш вердиктов: повторная проверка неизменённого файла не читает его заново.

Запись привязана к пути, размеру и времени изменения файла, а также к «версии» проверки
(отпечатки баз хэшей и правил, ручные исключения, порог эвристики). Изменился файл или
обновились базы — файл проверяется заново. Хранится в cache/verdicts.sqlite.

Защита от обхода:
  * у исполняемых файлов (EXECUTABLE_EXTS) запоминается ещё ChangeTime — время изменения
    записи NTFS. Обычную дату (mtime) программа может вернуть назад после заражения файла
    того же размера, ChangeTime обычными средствами не подделать;
  * строка подписана ключом, который читают только администраторы (trustseal.mac_key):
    дописать в базу «чистый» вердикт своему файлу, не зная ключа, нельзя.
Записи копятся в памяти и пишутся на диск пачками: SQLite медленно фиксирует по одной.
"""
import ctypes
import hashlib
import os
import sqlite3
import threading
import time
from ctypes import wintypes
from pathlib import Path

import trustseal
from scanner.media import EXECUTABLE_EXTS

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


def change_time(path) -> int:
    """ChangeTime файла (NTFS, единицы по 100 нс) или 0. Только для исполняемых файлов:
    лишнее открытие каждого файла замедлило бы проверку дисков."""
    if os.path.splitext(str(path))[1].lower() not in EXECUTABLE_EXTS:
        return 0
    try:
        k32 = ctypes.windll.kernel32
    except AttributeError:
        return 0
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    # FILE_READ_ATTRIBUTES, общий доступ на всё, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS
    handle = k32.CreateFileW(str(path), 0x80, 7, None, 3, 0x02000000, None)
    if handle in (None, wintypes.HANDLE(-1).value):
        return 0
    try:
        info = (ctypes.c_longlong * 5)()  # FILE_BASIC_INFO: 4 времени и атрибуты
        k32.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                     ctypes.c_void_p, wintypes.DWORD]
        if not k32.GetFileInformationByHandleEx(handle, 0, info, ctypes.sizeof(info)):
            return 0
        return int(info[3])
    finally:
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.CloseHandle(handle)


def _mac(key: str, size: int, mtime: int, ctime: int, version: str, sha256: str,
         reason: str | None) -> str:
    text = "\x1f".join((key, str(size), str(mtime), str(ctime), version, sha256 or "",
                        reason or ""))
    return hashlib.blake2b(text.encode("utf-8", "surrogatepass"), digest_size=12,
                           key=trustseal.mac_key()).hexdigest()


def _db() -> sqlite3.Connection | None:
    global _conn, _conn_path
    if _conn is not None and _conn_path == CACHE_FILE:
        return _conn
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(CACHE_FILE), check_same_thread=False, timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("DROP TABLE IF EXISTS verdicts")  # прежний вид: без ChangeTime и подписи
        conn.execute("""CREATE TABLE IF NOT EXISTS verdicts2 (
            path TEXT PRIMARY KEY, size INTEGER, mtime INTEGER, version TEXT,
            sha256 TEXT, reason TEXT, checked REAL, ctime INTEGER, mac TEXT)""")
        conn.execute("DELETE FROM verdicts2 WHERE checked < ?", (time.time() - KEEP_DAYS * 86400,))
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
                    "SELECT size, mtime, version, sha256, reason, ctime, mac FROM verdicts2 "
                    "WHERE path = ?", (key,)).fetchone()
            except (sqlite3.Error, OverflowError, ValueError):
                return None
            row = found and tuple(found)
        if row and row[0] == st.st_size and row[1] == st.st_mtime_ns and row[2] == version \
                and row[5] == change_time(path) \
                and row[6] == _mac(key, row[0], row[1], row[5], row[2], row[3], row[4]):
            _hits += 1
            return row[3], row[4]
        _misses += 1
        return None


INT64 = 2 ** 63


def put(path, st: os.stat_result, version: str, sha256: str, reason: str | None) -> None:
    # время изменения за пределами 64-битного числа SQLite (бывает у файлов с «битой» датой):
    # такой файл просто не кэшируется
    if not (-INT64 <= st.st_mtime_ns < INT64 and 0 <= st.st_size < INT64):
        return
    key = _key(path)
    ctime = change_time(path)
    mac = _mac(key, st.st_size, st.st_mtime_ns, ctime, version, sha256, reason)
    with _lock:
        _pending[key] = (st.st_size, st.st_mtime_ns, version, sha256, reason, ctime, mac)
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
        rows = [(k, *v[:5], now, v[5], v[6]) for k, v in _pending.items()]
        _pending.clear()
        try:
            conn.executemany("INSERT OR REPLACE INTO verdicts2 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                             rows)
            conn.commit()
        except (sqlite3.Error, OverflowError, ValueError):
            pass


def clear() -> None:
    with _lock:
        _pending.clear()
        conn = _db()
        if conn is not None:
            try:
                conn.execute("DELETE FROM verdicts2")
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
            conn.executemany("DELETE FROM verdicts2 WHERE path = ?", [(k,) for k in keys])
            conn.commit()
        except sqlite3.Error:
            pass
