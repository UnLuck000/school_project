"""Повторная проверка памяти: неизменившиеся системные процессы не сканируются заново.

Запоминается только чистый результат и только у системных процессов: файл в папке Windows
с действительной подписью и не подделка под системное имя. Обычные программы (браузеры,
мессенджеры, плееры) проверяются каждый раз: они часто обновляются, и в их процессы
внедряются вредоносы.

Запомненный результат действует, пока одновременно:
- это тот же процесс (PID и время запуска);
- его файл не изменён (размер и время изменения);
- набор исполняемой памяти тот же (fingerprint): внедрённый код, новая библиотека или
  регион с правами «запись + выполнение» меняют отпечаток;
- правила YARA те же;
- прошло не больше TTL секунд — изменение данных внутри уже существующих регионов
  отпечаток не замечает, поэтому через TTL проверка всё равно повторяется.
"""
import ctypes
import hashlib
import os
import threading
import time
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

TTL = 30 * 60
EXECUTE_MASK = 0x10 | 0x20 | 0x40 | 0x80  # PAGE_EXECUTE*


if TYPE_CHECKING:
    from processmanager.memscan import MemResult


@dataclass
class _Entry:
    exe_stamp: tuple
    fingerprint: str
    rules_key: str
    result: "MemResult"   # processmanager.memscan.MemResult
    checked_at: float     # time.time()


_lock = threading.Lock()
_entries: dict[tuple[int, float], _Entry] = {}
_system_exes: dict[tuple, bool] = {}


def exe_stamp(exe: str) -> tuple | None:
    try:
        st = os.stat(exe)
    except OSError:
        return None
    return exe.lower(), st.st_size, st.st_mtime_ns


def is_system(p) -> bool:
    """Системный процесс: файл в папке Windows, подпись действительна, не подделка."""
    windir = os.environ.get("SystemRoot", r"C:\Windows").lower().rstrip("\\") + "\\"
    if not p.exe or getattr(p, "masq", False) or not p.exe.lower().startswith(windir):
        return False
    stamp = exe_stamp(p.exe)
    if stamp is None:
        return False
    if stamp not in _system_exes:
        from pathlib import Path
        from scanner.signature import VALID, inspect_signature
        try:
            _system_exes[stamp] = inspect_signature(Path(p.exe)).status == VALID
        except OSError:
            _system_exes[stamp] = False
    return _system_exes[stamp]


def fingerprint(pid: int) -> str | None:
    """Отпечаток исполняемой памяти: (адрес, размер, права, тип) всех исполняемых регионов.
    None — нет доступа."""
    from processmanager import memdeep
    k32 = memdeep.kernel32
    handle = k32.OpenProcess(memdeep.PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        mbi = memdeep.MEMORY_BASIC_INFORMATION()
        address, limit = 0, 0x7FFFFFFFFFFF
        digest = hashlib.sha1(usedforsecurity=False)
        while address < limit:
            if not k32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi),
                                      ctypes.sizeof(mbi)):
                break
            base, size = mbi.BaseAddress or 0, mbi.RegionSize
            if mbi.State == memdeep.MEM_COMMIT and mbi.Protect & EXECUTE_MASK:
                digest.update(f"{base:x}:{size:x}:{mbi.Protect:x}:{mbi.Type:x};".encode())
            if size == 0:
                break
            address = base + size
        return digest.hexdigest()
    finally:
        k32.CloseHandle(handle)


def lookup(p, rules_key: str, now: float | None = None):
    """Запомненный чистый результат (MemResult с cached=True) или None — проверять заново.
    Второе значение — отпечаток для store() (None, если процесс не системный)."""
    if not is_system(p):
        return None, None
    fp = fingerprint(p.pid)
    if fp is None:
        return None, None
    now = time.time() if now is None else now
    with _lock:
        entry = _entries.get((p.pid, p.created))
    if (entry is not None and entry.rules_key == rules_key and entry.fingerprint == fp
            and entry.exe_stamp == exe_stamp(p.exe) and now - entry.checked_at < TTL):
        return replace(entry.result, cached=True, checked_at=entry.checked_at), fp
    return None, fp


def store(p, rules_key: str, fp: str | None, result) -> None:
    """Запоминает только чистый результат системного процесса (fp от lookup)."""
    if fp is None or result.status != "clean":
        with _lock:
            _entries.pop((p.pid, p.created), None)
        return
    with _lock:
        _entries[(p.pid, p.created)] = _Entry(exe_stamp(p.exe), fp, rules_key, result,
                                              time.time())


def forget(pid: int | None = None) -> None:
    """Забыть результаты процесса (или все: при обновлении правил)."""
    with _lock:
        if pid is None:
            _entries.clear()
        else:
            for key in [k for k in _entries if k[0] == pid]:
                del _entries[key]
