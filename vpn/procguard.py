"""Ядра VPN (xray.exe, sing-box.exe, openvpn.exe) не переживают программу.

• bind(proc) — процесс попадает в объект задания Windows (Job Object) с флагом
  KILL_ON_JOB_CLOSE. Описатель задания держит только наш процесс; когда он завершается —
  выход, падение или «Снять задачу» в диспетчере задач — Windows закрывает описатель и
  завершает все процессы задания. Иначе Xray и sing-box оставались бы работать сами по себе:
  туннель поднят, порты заняты, а управлять ими нечем.
• kill_orphans() — при запуске программы: ядра, оставшиеся от прошлого запуска (до этой защиты
  или если задание не удалось создать). Завершаются только процессы с конфигурацией из нашей
  папки cache/vpn в командной строке и с мёртвым родителем — чужие Xray (Happ, Throne и т. п.)
  не трогаются.
"""
import ctypes
import os
from ctypes import wintypes
from pathlib import Path

CORES = {"xray.exe", "sing-box.exe", "openvpn.exe"}
JobObjectExtendedLimitInformation = 9
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x0800


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD)]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t)]


_job = None  # описатель задания: не закрывается до конца процесса — в этом весь смысл


def _kernel32():
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateJobObjectW.restype = wintypes.HANDLE
    k.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    k.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                          wintypes.DWORD]
    k.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    return k


def job() -> int | None:
    global _job
    if _job is None and os.name == "nt":
        k = _kernel32()
        handle = k.CreateJobObjectW(None, None)
        if not handle:
            return None
        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
                                                 JOB_OBJECT_LIMIT_BREAKAWAY_OK)
        if not k.SetInformationJobObject(handle, JobObjectExtendedLimitInformation,
                                         ctypes.byref(info), ctypes.sizeof(info)):
            k.CloseHandle(handle)
            return None
        _job = handle
    return _job


def bind(proc, log=None) -> bool:
    """Привязать запущенный subprocess.Popen к заданию. False — не удалось (ядро тогда
    завершится при следующем запуске программы через kill_orphans)."""
    handle = job()
    if handle is None:
        if log:
            log("Не удалось создать объект задания: при аварийном закрытии программы ядро "
                "VPN останется работать до следующего запуска")
        return False
    if not _kernel32().AssignProcessToJobObject(handle, int(proc._handle)):
        if log:
            log(f"Ядро VPN не привязано к программе (ошибка {ctypes.get_last_error()})")
        return False
    return True


def _alive_before(ppid: int, created: float) -> bool:
    """Жив ли родитель — тот самый (создан раньше потомка; номер мог достаться другому)."""
    import psutil
    try:
        return psutil.Process(ppid).create_time() <= created + 1
    except (psutil.Error, OSError):
        return False


def kill_orphans(folder: Path | None = None) -> list[str]:
    """Завершить наши ядра VPN без живого родителя. Возвращает их описания."""
    import psutil
    from processmanager import ntsnap
    from vpn.backends import TUNNEL_DIR
    mark = os.path.normcase(str((folder or TUNNEL_DIR).resolve()))
    killed = []
    try:
        procs = ntsnap.list_processes()
    except OSError:
        return killed
    for p in procs:
        if p.name.lower() not in CORES or p.pid == os.getpid():
            continue
        try:
            proc = psutil.Process(p.pid)
            cmdline = os.path.normcase(" ".join(proc.cmdline()))
        except (psutil.Error, OSError):
            continue
        if mark not in cmdline or _alive_before(p.ppid, proc.create_time()):
            continue
        try:
            proc.kill()
            killed.append(f"{p.name} (PID {p.pid})")
        except (psutil.Error, OSError):
            pass
    return killed
