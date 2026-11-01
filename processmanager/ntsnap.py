"""Быстрый снимок процессов одним вызовом NtQuerySystemInformation.

psutil для каждого процесса заново перебирает весь список процессов системы (статус,
время ЦП для недоступных процессов), то есть работает за O(n²) и всё это время держит GIL:
на 300 процессах это ~2 секунды, в течение которых подвисает весь интерфейс. Здесь список
читается один раз (ctypes отпускает GIL на время вызова), а путь и пользователь процесса
запрашиваются только для новых процессов и кэшируются.
"""
import ctypes
import os
import struct
import sys
from dataclasses import dataclass

EPOCH_DIFF = 11644473600  # секунд между 1601-01-01 (FILETIME) и 1970-01-01
SystemProcessInformation = 5
SystemProcessIdInformation = 88
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# смещения в SYSTEM_PROCESS_INFORMATION и SYSTEM_THREAD_INFORMATION (x64)
PROC_STRUCT_SIZE = 0x100
THREAD_STRUCT_SIZE = 0x50
THREAD_STATE_WAITING, WAIT_REASON_SUSPENDED = 5, 5


@dataclass
class RawProc:
    pid: int
    ppid: int
    name: str
    threads: int
    created: float    # секунды Unix-времени
    cpu_time: float   # секунды (пользователь + ядро)
    rss: int          # рабочий набор, байт
    suspended: bool


if sys.platform == "win32" and struct.calcsize("P") == 8:
    from ctypes import wintypes

    _ntdll = ctypes.WinDLL("ntdll")
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _adv = ctypes.WinDLL("advapi32", use_last_error=True)
    _ntdll.NtQuerySystemInformation.argtypes = [
        wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG)]
    _ntdll.NtQuerySystemInformation.restype = ctypes.c_ulong
    _k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _k32.OpenProcess.restype = ctypes.c_void_p
    _k32.CloseHandle.argtypes = [ctypes.c_void_p]
    _k32.QueryFullProcessImageNameW.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    _k32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    _k32.QueryDosDeviceW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    _k32.QueryDosDeviceW.restype = wintypes.DWORD
    _adv.OpenProcessToken.argtypes = [ctypes.c_void_p, wintypes.DWORD,
                                      ctypes.POINTER(ctypes.c_void_p)]
    _adv.OpenProcessToken.restype = wintypes.BOOL
    _adv.GetTokenInformation.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                                         wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    _adv.GetTokenInformation.restype = wintypes.BOOL
    _adv.LookupAccountSidW.argtypes = [
        wintypes.LPCWSTR, ctypes.c_void_p, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
    _adv.LookupAccountSidW.restype = wintypes.BOOL
    _adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    _adv.ConvertSidToStringSidW.restype = wintypes.BOOL
    _k32.LocalFree.argtypes = [ctypes.c_void_p]

    class _UNICODE_STRING(ctypes.Structure):
        _fields_ = [("Length", wintypes.USHORT), ("MaximumLength", wintypes.USHORT),
                    ("Buffer", ctypes.c_void_p)]

    class _PROCESS_ID_INFO(ctypes.Structure):
        _fields_ = [("ProcessId", ctypes.c_void_p), ("ImageName", _UNICODE_STRING)]

    AVAILABLE = True
else:
    AVAILABLE = False

_buffer_size = 512 * 1024
_users_by_sid: dict[str, str] = {}
_devices: dict[str, str] | None = None


def list_processes() -> list[RawProc]:
    """Все процессы системы за один системный вызов."""
    global _buffer_size
    while True:
        buf = ctypes.create_string_buffer(_buffer_size)
        needed = wintypes.ULONG()
        status = _ntdll.NtQuerySystemInformation(
            SystemProcessInformation, buf, _buffer_size, ctypes.byref(needed))
        if status == STATUS_INFO_LENGTH_MISMATCH:
            _buffer_size = max(_buffer_size * 2, needed.value + 64 * 1024)
            continue
        if status != 0:
            raise OSError(f"NtQuerySystemInformation: 0x{status:08X}")
        break

    data = buf.raw
    base = ctypes.addressof(buf)
    result: list[RawProc] = []
    offset = 0
    while True:
        next_offset, threads = struct.unpack_from("<II", data, offset)
        create, user, kernel = struct.unpack_from("<qqq", data, offset + 32)
        name_len, = struct.unpack_from("<H", data, offset + 56)
        name_ptr, = struct.unpack_from("<Q", data, offset + 64)
        pid, ppid = struct.unpack_from("<QQ", data, offset + 80)
        working_set, = struct.unpack_from("<Q", data, offset + 144)
        if name_ptr and name_len:
            name = data[name_ptr - base:name_ptr - base + name_len].decode("utf-16-le", "replace")
        else:
            name = "System Idle Process" if pid == 0 else "?"

        suspended = threads > 0
        t = offset + PROC_STRUCT_SIZE
        for _ in range(threads):  # процесс приостановлен, если приостановлены все потоки
            state, reason = struct.unpack_from("<II", data, t + 68)
            if state != THREAD_STATE_WAITING or reason != WAIT_REASON_SUSPENDED:
                suspended = False
                break
            t += THREAD_STRUCT_SIZE

        result.append(RawProc(
            pid=pid, ppid=ppid, name=name, threads=threads,
            created=create / 1e7 - EPOCH_DIFF if create else 0.0,
            cpu_time=(user + kernel) / 1e7, rss=working_set,
            suspended=suspended and pid not in (0, 4)))
        if not next_offset:
            break
        offset += next_offset
    return result


def _device_map() -> dict[str, str]:
    """{'\\Device\\HarddiskVolume3': 'C:'} для перевода путей ядра в обычные."""
    global _devices
    if _devices is None:
        _devices = {}
        target = ctypes.create_unicode_buffer(1024)
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            if _k32.QueryDosDeviceW(f"{letter}:", target, 1024):
                _devices[target.value.lower()] = f"{letter}:"
    return _devices


def _exe_by_kernel(pid: int) -> str:
    """Путь файла без открытия процесса (работает и для защищённых процессов)."""
    size = 1024
    while size <= 65536:
        name_buf = ctypes.create_unicode_buffer(size // 2)
        info = _PROCESS_ID_INFO()
        info.ProcessId = pid
        info.ImageName.Length = 0
        info.ImageName.MaximumLength = size
        info.ImageName.Buffer = ctypes.cast(name_buf, ctypes.c_void_p)
        status = _ntdll.NtQuerySystemInformation(
            SystemProcessIdInformation, ctypes.byref(info), ctypes.sizeof(info), None)
        if status == STATUS_INFO_LENGTH_MISMATCH:
            size = info.ImageName.MaximumLength or size * 2
            continue
        if status != 0:
            return ""
        path = ctypes.wstring_at(info.ImageName.Buffer, info.ImageName.Length // 2)
        break
    else:
        return ""
    lower = path.lower()
    for device, letter in _device_map().items():
        if lower.startswith(device + "\\"):
            return letter + path[len(device):]
    return ""  # сетевой или нестандартный путь: оставляем пустым


def _token_user(handle) -> str:
    token = ctypes.c_void_p()
    if not _adv.OpenProcessToken(handle, 0x8, ctypes.byref(token)):  # TOKEN_QUERY
        return ""
    try:
        buf = ctypes.create_string_buffer(256)
        size = wintypes.DWORD()
        if not _adv.GetTokenInformation(token, 1, buf, 256, ctypes.byref(size)):  # TokenUser
            return ""
        sid = ctypes.c_void_p.from_buffer(buf).value
        text = wintypes.LPWSTR()
        key = ""
        if _adv.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            key = text.value
            _k32.LocalFree(text)
        if key in _users_by_sid:
            return _users_by_sid[key]
        name, domain = ctypes.create_unicode_buffer(256), ctypes.create_unicode_buffer(256)
        n_len, d_len, use = wintypes.DWORD(256), wintypes.DWORD(256), wintypes.DWORD()
        if not _adv.LookupAccountSidW(None, sid, name, ctypes.byref(n_len),
                                      domain, ctypes.byref(d_len), ctypes.byref(use)):
            return ""
        user = f"{domain.value}\\{name.value}" if domain.value else name.value
        if key:
            _users_by_sid[key] = user
        return user
    finally:
        _k32.CloseHandle(token)


def identity(pid: int) -> tuple[str, str]:
    """(путь к файлу, пользователь). Пустые строки, если сведения недоступны."""
    if pid in (0, 4):
        return "", ""
    exe = user = ""
    handle = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if handle:
        try:
            size = wintypes.DWORD(32768)
            buf = ctypes.create_unicode_buffer(size.value)
            if _k32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                exe = buf.value
            user = _token_user(handle)
        finally:
            _k32.CloseHandle(handle)
    if not exe:
        exe = _exe_by_kernel(pid)
    return os.path.normpath(exe) if exe else "", user
