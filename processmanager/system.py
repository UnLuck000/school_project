import ctypes
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import psutil

from scanner.hashing import sha256_of
from scanner.signature import describe, inspect_signature

PROTECTED = {"system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
             "services.exe", "lsass.exe", "memory compression", "system idle process"}


@dataclass
class ProcInfo:
    pid: int
    ppid: int
    name: str
    exe: str
    user: str
    rss: int
    cpu: float
    created: float
    sig: str = ""

    @property
    def key(self) -> str:
        return f"{self.pid}:{self.created:.3f}"  # PID сам по себе может повториться


def take_snapshot() -> list[ProcInfo]:
    ncpu = psutil.cpu_count() or 1
    result = []
    attrs = ["pid", "ppid", "name", "exe", "username", "memory_info",
             "cpu_percent", "create_time"]
    for p in psutil.process_iter(attrs):
        i = p.info
        mem = i.get("memory_info")
        result.append(ProcInfo(
            pid=i["pid"], ppid=i.get("ppid") or 0, name=i.get("name") or "?",
            exe=i.get("exe") or "", user=i.get("username") or "",
            rss=mem.rss if mem else 0, cpu=(i.get("cpu_percent") or 0.0) / ncpu,
            created=i.get("create_time") or 0.0))
    return result


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def relaunch_as_admin() -> bool:
    """Запускает программу заново с запросом UAC. True, если запрос принят."""
    params = " ".join(f'"{a}"' for a in sys.argv)
    try:
        return ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1) > 32
    except (AttributeError, OSError):
        return False


def enable_debug_privilege() -> bool:
    """Включает SeDebugPrivilege (нужно для чтения памяти чужих процессов)."""
    if sys.platform != "win32":
        return False
    try:
        from ctypes import wintypes

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wintypes.DWORD),
                        ("Privileges", LUID_AND_ATTRIBUTES * 1)]

        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        advapi32.OpenProcessToken.argtypes = [
            ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
        advapi32.OpenProcessToken.restype = wintypes.BOOL
        advapi32.LookupPrivilegeValueW.argtypes = [
            wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)]
        advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
        advapi32.AdjustTokenPrivileges.argtypes = [
            ctypes.c_void_p, wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES),
            wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p]
        advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL

        token = ctypes.c_void_p()
        # TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x20 | 0x8,
                                         ctypes.byref(token)):
            return False
        try:
            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            if not advapi32.LookupPrivilegeValueW(
                    None, "SeDebugPrivilege", ctypes.byref(tp.Privileges[0].Luid)):
                return False
            tp.Privileges[0].Attributes = 0x2  # SE_PRIVILEGE_ENABLED
            ctypes.set_last_error(0)
            if not advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None):
                return False
            return ctypes.get_last_error() == 0  # 1300: привилегия не назначена
        finally:
            kernel32.CloseHandle(token)
    except (OSError, ValueError, ctypes.ArgumentError):
        return False


def _get(pid: int, created: float) -> psutil.Process:
    p = psutil.Process(pid)
    if created and abs(p.create_time() - created) > 1:
        raise psutil.NoSuchProcess(pid)  # этот PID уже занят другой программой
    return p


def run_action(action: str, pid: int, created: float) -> str:
    """action: terminate | suspend | resume. Возвращает сообщение для пользователя."""
    try:
        p = _get(pid, created)
        name = p.name()
        if pid in (0, 4) or name.lower() in PROTECTED:
            return "Системный процесс: действие запрещено"
        if pid == os.getpid():
            return "Нельзя управлять процессом самой программы"
        if action == "terminate":
            p.terminate()
            p.wait(3)
            return f"Процесс {name} (PID {pid}) завершён"
        if action == "suspend":
            p.suspend()
            return f"Процесс {name} приостановлен"
        if action == "resume":
            p.resume()
            return f"Процесс {name} возобновлён"
        return "Неизвестное действие"
    except psutil.NoSuchProcess:
        return "Процесс уже завершён"
    except psutil.AccessDenied:
        return "Нет прав. Запустите программу от имени администратора"
    except psutil.TimeoutExpired:
        return "Процесс не завершился за 3 секунды"


def open_in_explorer(exe: str) -> None:
    subprocess.Popen(f'explorer /select,"{exe}"')


def process_details(pid: int, created: float) -> str:
    """Подробные сведения о процессе. Медленная функция: вызывать не из GUI-потока."""
    try:
        p = _get(pid, created)
    except psutil.Error:
        return "Процесс уже завершён."

    def safe(fn, default="недоступно"):
        try:
            value = fn()
        except (psutil.Error, OSError):
            return default
        return default if value in (None, "") else value

    exe = safe(p.exe, "")
    parent = safe(lambda: p.parent().name() if p.parent() else "", "")
    try:
        mem = p.memory_info()
    except (psutil.Error, OSError):
        mem = None
    started = datetime.fromtimestamp(created).strftime("%Y-%m-%d %H:%M:%S") if created else "?"
    lines = [
        f"Имя: {safe(p.name)}",
        f"PID: {pid}",
        f"Родитель: {safe(p.ppid)} {parent}",
        f"Путь: {exe or 'недоступно'}",
        f"Командная строка: {' '.join(safe(p.cmdline, [])) or 'недоступно'}",
        f"Пользователь: {safe(p.username)}",
        f"Запущен: {started}",
        f"Статус: {safe(p.status)}",
        f"Потоков: {safe(p.num_threads)}",
    ]
    if mem:
        lines.append(f"Память: рабочий набор {mem.rss / 1048576:.1f} МБ, "
                     f"виртуальная {mem.vms / 1048576:.1f} МБ")

    try:
        conns = p.net_connections(kind="inet")
    except (psutil.Error, OSError):
        conns = None
    lines.append("")
    if conns is None:
        lines.append("Сетевые соединения: недоступно")
    elif not conns:
        lines.append("Сетевые соединения: нет")
    else:
        lines.append(f"Сетевые соединения ({len(conns)}):")
        for c in conns[:30]:
            local = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
            remote = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
            lines.append(f"  {local} -> {remote}  {c.status}")

    if exe:
        lines += ["", "Файл:"]
        try:
            lines.append(f"  SHA-256: {sha256_of(Path(exe))}")
        except OSError:
            lines.append("  SHA-256: файл недоступен")
        try:
            lines.append(f"  Подпись: {describe(inspect_signature(Path(exe))) or 'не определена'}")
        except Exception:
            lines.append("  Подпись: не определена")
    return "\n".join(lines)