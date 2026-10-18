import ctypes
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import psutil

from scanner.hashing import sha256_of
from scanner.signature import describe, inspect_signature

SYSTEM_ROOT = Path(os.environ.get("SystemRoot", r"C:\Windows"))
ALLOWED_DIRS = {os.path.normcase(str(SYSTEM_ROOT / "System32")),
                os.path.normcase(str(SYSTEM_ROOT / "SysWOW64"))}
SYSTEM32 = os.path.normcase(str(SYSTEM_ROOT / "System32"))

# ключевые процессы Windows: их имя и путь проверяются вместе
CORE_NAMES = {"smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
              "services.exe", "lsass.exe", "lsm.exe"}
# за этими именами часто прячутся вредоносные программы
WATCHED_NAMES = CORE_NAMES | {"svchost.exe", "dllhost.exe", "conhost.exe", "taskhostw.exe"}
# системные процессы без файла на диске
NO_EXE_SYSTEM = {"system", "system idle process", "registry",
                 "memory compression", "secure system"}
SYSTEM_ACCOUNTS = ("NT AUTHORITY", "NT SERVICE", "WINDOW MANAGER", "FONT DRIVER HOST")


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
    status: str = ""
    sig: str = ""
    sig_status: str = ""
    packed: bool = False
    dotnet: bool = False
    service: bool = False
    elevated: bool | None = None
    wow64: bool = False
    critical: bool = False     # Windows пометила процесс критическим (его завершение = синий экран)
    core: bool = False         # System, Idle, их потомки, ключевые процессы из System32
    masq: bool = False         # имя системного процесса, но файл не из System32
    sys_account: bool = False
    own: bool = False

    @property
    def key(self) -> str:
        return f"{self.pid}:{self.created:.3f}"  # один PID может повторяться

    @property
    def protected(self) -> bool:
        return self.pid in (0, 4) or self.critical or self.core


try:
    OWN_USER = psutil.Process().username()
except (psutil.Error, OSError):
    OWN_USER = ""

# ---------- низкоуровневые сведения о процессе (Windows API) ----------
if sys.platform == "win32":
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _adv = ctypes.WinDLL("advapi32", use_last_error=True)
    _k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _k32.OpenProcess.restype = ctypes.c_void_p
    _k32.CloseHandle.argtypes = [ctypes.c_void_p]
    _k32.IsWow64Process.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL)]
    _k32.IsWow64Process.restype = wintypes.BOOL
    _k32.IsProcessCritical.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL)]
    _k32.IsProcessCritical.restype = wintypes.BOOL
    _adv.OpenProcessToken.argtypes = [ctypes.c_void_p, wintypes.DWORD,
                                      ctypes.POINTER(ctypes.c_void_p)]
    _adv.OpenProcessToken.restype = wintypes.BOOL
    _adv.GetTokenInformation.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                                         wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    _adv.GetTokenInformation.restype = wintypes.BOOL


def query_flags(pid: int) -> tuple[bool | None, bool, bool]:
    """(повышенные права, 32-разрядный, критический). Недоступный процесс: (None, False, False)."""
    if sys.platform != "win32" or pid in (0, 4):
        return None, False, False
    try:
        handle = _k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return None, False, False
        try:
            flag = wintypes.BOOL()
            wow64 = bool(_k32.IsWow64Process(handle, ctypes.byref(flag)) and flag.value)
            flag = wintypes.BOOL()
            critical = bool(_k32.IsProcessCritical(handle, ctypes.byref(flag)) and flag.value)
            elevated = None
            token = ctypes.c_void_p()
            if _adv.OpenProcessToken(handle, 0x8, ctypes.byref(token)):  # TOKEN_QUERY
                try:
                    value, size = wintypes.DWORD(), wintypes.DWORD()
                    # 20 = TokenElevation
                    if _adv.GetTokenInformation(token, 20, ctypes.byref(value),
                                                ctypes.sizeof(value), ctypes.byref(size)):
                        elevated = bool(value.value)
                finally:
                    _k32.CloseHandle(token)
            return elevated, wow64, critical
        finally:
            _k32.CloseHandle(handle)
    except (OSError, ValueError, ctypes.ArgumentError, AttributeError):
        return None, False, False


_flags_cache: dict[str, tuple] = {}
_svc_cache: tuple[float, set[int]] = (0.0, set())


def service_pids() -> set[int]:
    """PID процессов, в которых работают службы Windows (обновляется раз в 15 секунд)."""
    global _svc_cache
    now = time.monotonic()
    if now - _svc_cache[0] < 15:
        return _svc_cache[1]
    pids: set[int] = set()
    try:
        for service in psutil.win_service_iter():
            try:
                pid = service.pid()
            except psutil.Error:
                continue
            if pid:
                pids.add(pid)
    except (AttributeError, psutil.Error, OSError):
        pass
    _svc_cache = (now, pids)
    return pids


def mark_system(procs: list[ProcInfo]) -> None:
    """Определяет защищённые процессы и маскировку под системные."""
    by_pid = {p.pid: p for p in procs}
    for p in procs:
        name = p.name.lower()
        if p.pid in (0, 4) or (not p.exe and name in NO_EXE_SYSTEM):
            p.core = True
        elif p.exe and name in WATCHED_NAMES:
            folder = os.path.normcase(os.path.dirname(p.exe))
            if folder in ALLOWED_DIRS:
                if name in CORE_NAMES and folder == SYSTEM32:
                    p.core = True
            else:
                p.masq = True  # имя системного, путь чужой

    # потомки System (и Idle) по цепочке родителей; родитель должен быть старше потомка
    for p in procs:
        if p.core:
            continue
        node, hops = p, 0
        while hops < 50 and node.ppid in by_pid and node.ppid != node.pid:
            parent = by_pid[node.ppid]
            if parent.created > node.created:
                break  # PID родителя уже занят другой программой
            if parent.pid in (0, 4):
                p.core = True
                break
            node, hops = parent, hops + 1


def take_snapshot() -> list[ProcInfo]:
    ncpu = psutil.cpu_count() or 1
    services = service_pids()
    attrs = ["pid", "ppid", "name", "exe", "username", "memory_info",
             "cpu_percent", "create_time", "status"]
    procs: list[ProcInfo] = []
    for proc in psutil.process_iter(attrs):
        i = proc.info
        mem = i.get("memory_info")
        info = ProcInfo(
            pid=i["pid"], ppid=i.get("ppid") or 0, name=i.get("name") or "?",
            exe=i.get("exe") or "", user=i.get("username") or "",
            rss=mem.rss if mem else 0, cpu=(i.get("cpu_percent") or 0.0) / ncpu,
            created=i.get("create_time") or 0.0, status=i.get("status") or "")
        info.service = info.pid in services
        info.sys_account = info.user.upper().startswith(SYSTEM_ACCOUNTS)
        info.own = bool(OWN_USER) and info.user == OWN_USER
        flags = _flags_cache.get(info.key)
        if flags is None:
            flags = _flags_cache[info.key] = query_flags(info.pid)
        info.elevated, info.wow64, info.critical = flags
        procs.append(info)

    alive = {p.key for p in procs}
    for key in [k for k in _flags_cache if k not in alive]:
        del _flags_cache[key]
    mark_system(procs)
    return procs


# ---------- права администратора ----------
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def relaunch_as_admin() -> bool:
    """Запускает программу заново с запросом UAC. True, если запрос принят."""
    if getattr(sys, "frozen", False):  # собранный exe
        params = " ".join(f'"{a}"' for a in sys.argv[1:])
    else:
        args = [os.path.abspath(sys.argv[0])] + sys.argv[1:]
        params = " ".join(f'"{a}"' for a in args)
    try:
        # рабочая папка сохраняется: в проекте много относительных путей
        return ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, os.getcwd(), 1) > 32
    except (AttributeError, OSError):
        return False


def enable_debug_privilege() -> bool:
    """Включает SeDebugPrivilege (нужно для чтения памяти чужих процессов)."""
    if sys.platform != "win32":
        return False
    try:
        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wintypes.DWORD),
                        ("Privileges", LUID_AND_ATTRIBUTES * 1)]

        _k32.GetCurrentProcess.restype = ctypes.c_void_p
        _adv.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR,
                                               ctypes.POINTER(LUID)]
        _adv.LookupPrivilegeValueW.restype = wintypes.BOOL
        _adv.AdjustTokenPrivileges.argtypes = [
            ctypes.c_void_p, wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES),
            wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p]
        _adv.AdjustTokenPrivileges.restype = wintypes.BOOL

        token = ctypes.c_void_p()
        # TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
        if not _adv.OpenProcessToken(_k32.GetCurrentProcess(), 0x20 | 0x8, ctypes.byref(token)):
            return False
        try:
            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            if not _adv.LookupPrivilegeValueW(
                    None, "SeDebugPrivilege", ctypes.byref(tp.Privileges[0].Luid)):
                return False
            tp.Privileges[0].Attributes = 0x2  # SE_PRIVILEGE_ENABLED
            ctypes.set_last_error(0)
            if not _adv.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None):
                return False
            return ctypes.get_last_error() == 0  # 1300: привилегия не назначена
        finally:
            _k32.CloseHandle(token)
    except (OSError, ValueError, ctypes.ArgumentError, NameError, AttributeError):
        return False


# ---------- действия над процессом ----------
def _get(pid: int, created: float) -> psutil.Process:
    p = psutil.Process(pid)
    if created and abs(p.create_time() - created) > 1:
        raise psutil.NoSuchProcess(pid)  # этот PID уже занят другой программой
    return p


def run_action(action: str, info: ProcInfo) -> str:
    """action: terminate | suspend | resume. Возвращает сообщение для пользователя."""
    if info.protected or info.name.lower() in NO_EXE_SYSTEM:
        return "Системный процесс: действие запрещено"
    if info.pid == os.getpid():
        return "Нельзя управлять процессом самой программы"
    try:
        p = _get(info.pid, info.created)
        name = p.name()
        if action == "terminate":
            p.terminate()
            p.wait(3)
            return f"Процесс {name} (PID {info.pid}) завершён"
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
    mem = safe(p.memory_info, None)
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
        lines.append(f"Память: рабочий набор {int(mem.rss) / 1048576:.1f} МБ, "
                     f"виртуальная {int(mem.vms) / 1048576:.1f} МБ")

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