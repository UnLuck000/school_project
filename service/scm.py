"""Диспетчер служб Windows через ctypes: установка, удаление, запуск, остановка, состояние
и работа процесса как службы (StartServiceCtrlDispatcherW).

Служба — LocalSystem, SERVICE_WIN32_OWN_PROCESS, автозапуск, при сбое перезапуск через 5, 10
и 30 с. Права на саму службу — по умолчанию Windows: пользователи могут узнать состояние, но
не остановить её; управляют администраторы.
"""
import ctypes
import sys
import threading
from ctypes import wintypes

SERVICE_WIN32_OWN_PROCESS = 0x10
SERVICE_AUTO_START = 2
SERVICE_ERROR_NORMAL = 1
SERVICE_NO_CHANGE = 0xFFFFFFFF
SC_MANAGER_CONNECT = 0x0001
SC_MANAGER_CREATE_SERVICE = 0x0002
SERVICE_QUERY_STATUS = 0x0004
SERVICE_START = 0x0010
SERVICE_STOP = 0x0020
SERVICE_CHANGE_CONFIG = 0x0002
DELETE = 0x00010000
SERVICE_ALL_ACCESS = 0xF01FF
SERVICE_CONTROL_STOP = 1
SERVICE_CONTROL_INTERROGATE = 4
SERVICE_CONTROL_SHUTDOWN = 5
SERVICE_CONTROL_PRESHUTDOWN = 0xF
SERVICE_ACCEPT_STOP = 1
SERVICE_ACCEPT_SHUTDOWN = 4
SERVICE_ACCEPT_PRESHUTDOWN = 0x100
SERVICE_CONFIG_PRESHUTDOWN_INFO = 7
# выключение Windows: на SHUTDOWN службам дают ~5 с на всех, на PRESHUTDOWN — сколько попросят;
# отключение VPN (ядра, kill switch, DNS через PowerShell) на слабом ПК идёт десятки секунд
PRESHUTDOWN_TIMEOUT_MS = 60000
STOPPED, START_PENDING, STOP_PENDING, RUNNING = 1, 2, 3, 4
STATE_TEXT = {1: "остановлена", 2: "запускается", 3: "останавливается", 4: "работает",
              5: "продолжается", 6: "приостанавливается", 7: "приостановлена"}
ERROR_SERVICE_EXISTS = 1073
ERROR_SERVICE_DOES_NOT_EXIST = 1060
ERROR_SERVICE_NOT_ACTIVE = 1062
ERROR_FAILED_SERVICE_CONTROLLER_CONNECT = 1063
ERROR_CALL_NOT_IMPLEMENTED = 120
SERVICE_CONFIG_DESCRIPTION = 1
SERVICE_CONFIG_FAILURE_ACTIONS = 2
SERVICE_CONFIG_FAILURE_ACTIONS_FLAG = 4
SC_ACTION_RESTART = 1
RESTART_DELAYS = (5000, 10000, 30000)
CTRL_LOGOFF_EVENT = 5


class SERVICE_STATUS(ctypes.Structure):
    _fields_ = [("dwServiceType", wintypes.DWORD), ("dwCurrentState", wintypes.DWORD),
                ("dwControlsAccepted", wintypes.DWORD), ("dwWin32ExitCode", wintypes.DWORD),
                ("dwServiceSpecificExitCode", wintypes.DWORD), ("dwCheckPoint", wintypes.DWORD),
                ("dwWaitHint", wintypes.DWORD)]


class SERVICE_STATUS_PROCESS(ctypes.Structure):
    _fields_ = SERVICE_STATUS._fields_ + [("dwProcessId", wintypes.DWORD),
                                          ("dwServiceFlags", wintypes.DWORD)]


class SERVICE_DESCRIPTIONW(ctypes.Structure):
    _fields_ = [("lpDescription", wintypes.LPWSTR)]


class SC_ACTION(ctypes.Structure):
    _fields_ = [("Type", ctypes.c_int), ("Delay", wintypes.DWORD)]


class SERVICE_FAILURE_ACTIONSW(ctypes.Structure):
    _fields_ = [("dwResetPeriod", wintypes.DWORD), ("lpRebootMsg", wintypes.LPWSTR),
                ("lpCommand", wintypes.LPWSTR), ("cActions", wintypes.DWORD),
                ("lpsaActions", ctypes.POINTER(SC_ACTION))]


class SERVICE_FAILURE_ACTIONS_FLAG(ctypes.Structure):
    _fields_ = [("fFailureActionsOnNonCrashFailures", wintypes.BOOL)]


class SERVICE_PRESHUTDOWN_INFO(ctypes.Structure):
    _fields_ = [("dwPreshutdownTimeout", wintypes.DWORD)]


SERVICE_MAIN = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR))
HANDLER_EX = ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                ctypes.c_void_p, ctypes.c_void_p)
CTRL_HANDLER = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)


class SERVICE_TABLE_ENTRYW(ctypes.Structure):
    _fields_ = [("lpServiceName", wintypes.LPWSTR), ("lpServiceProc", SERVICE_MAIN)]


_api = None


def api():
    global _api
    if _api is not None:
        return _api
    a = ctypes.WinDLL("advapi32", use_last_error=True)
    H, D, S = wintypes.HANDLE, wintypes.DWORD, wintypes.LPCWSTR
    a.OpenSCManagerW.restype = H
    a.OpenSCManagerW.argtypes = [S, S, D]
    a.OpenServiceW.restype = H
    a.OpenServiceW.argtypes = [H, S, D]
    a.CreateServiceW.restype = H
    a.CreateServiceW.argtypes = [H, S, S, D, D, D, D, S, S, ctypes.c_void_p, S, S, S]
    a.ChangeServiceConfigW.argtypes = [H, D, D, D, S, S, ctypes.c_void_p, S, S, S, S]
    a.ChangeServiceConfig2W.argtypes = [H, D, ctypes.c_void_p]
    a.CloseServiceHandle.argtypes = [H]
    a.StartServiceW.argtypes = [H, D, ctypes.c_void_p]
    a.ControlService.argtypes = [H, D, ctypes.POINTER(SERVICE_STATUS)]
    a.DeleteService.argtypes = [H]
    a.QueryServiceStatusEx.argtypes = [H, ctypes.c_int, ctypes.c_void_p, D, ctypes.POINTER(D)]
    a.RegisterServiceCtrlHandlerExW.restype = H
    a.RegisterServiceCtrlHandlerExW.argtypes = [S, HANDLER_EX, ctypes.c_void_p]
    a.SetServiceStatus.argtypes = [H, ctypes.POINTER(SERVICE_STATUS)]
    a.StartServiceCtrlDispatcherW.argtypes = [ctypes.POINTER(SERVICE_TABLE_ENTRYW)]
    _api = a
    return a


def _err(text: str) -> OSError:
    code = ctypes.get_last_error()
    e = ctypes.WinError(code)
    return OSError(e.errno, f"{text}: {e.strerror}", None, code)


class _Handle:
    def __init__(self, h, what: str):
        if not h:
            raise _err(what)
        self.h = h

    def __enter__(self):
        return self.h

    def __exit__(self, *exc):
        api().CloseServiceHandle(self.h)


def _manager(access: int = SC_MANAGER_CONNECT) -> _Handle:
    return _Handle(api().OpenSCManagerW(None, None, access), "диспетчер служб")


def query(name: str) -> dict | None:
    """{"state", "pid", "exit_code"} или None — службы нет (или нет доступа)."""
    if sys.platform != "win32":
        return None
    a = api()
    try:
        with _manager() as scm:
            svc = a.OpenServiceW(scm, name, SERVICE_QUERY_STATUS)
            if not svc:
                return None
            try:
                st = SERVICE_STATUS_PROCESS()
                need = wintypes.DWORD()
                if not a.QueryServiceStatusEx(svc, 0, ctypes.byref(st), ctypes.sizeof(st),
                                              ctypes.byref(need)):
                    return None
                return {"state": st.dwCurrentState, "pid": st.dwProcessId,
                        "exit_code": st.dwWin32ExitCode}
            finally:
                a.CloseServiceHandle(svc)
    except OSError:
        return None


def command_line(exe: str | None = None) -> str:
    """Командная строка службы: StretchBIT.exe этой установки с ключом --service."""
    exe = exe or sys.executable
    return f'"{exe}" --service'


def install(name: str, display: str, description: str, binpath: str) -> str:
    """Создать или обновить службу (путь, автозапуск, описание, перезапуск при сбое).
    Возвращает «создана» или «обновлена». Нужны права администратора."""
    a = api()
    with _manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE) as scm:
        svc = a.CreateServiceW(scm, name, display, SERVICE_ALL_ACCESS,
                               SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
                               SERVICE_ERROR_NORMAL, binpath, None, None, None, None, None)
        what = "создана"
        if not svc:
            if ctypes.get_last_error() != ERROR_SERVICE_EXISTS:
                raise _err("создание службы")
            svc = a.OpenServiceW(scm, name, SERVICE_ALL_ACCESS)
            if not svc:
                raise _err("открытие службы")
            what = "обновлена"
            if not a.ChangeServiceConfigW(svc, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
                                          SERVICE_ERROR_NORMAL, binpath, None, None, None,
                                          None, None, display):
                a.CloseServiceHandle(svc)
                raise _err("изменение службы")
        try:
            desc = SERVICE_DESCRIPTIONW(description)
            a.ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, ctypes.byref(desc))
            actions = (SC_ACTION * len(RESTART_DELAYS))(
                *[SC_ACTION(SC_ACTION_RESTART, d) for d in RESTART_DELAYS])
            failure = SERVICE_FAILURE_ACTIONSW(86400, None, None, len(RESTART_DELAYS), actions)
            a.ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, ctypes.byref(failure))
            flag = SERVICE_FAILURE_ACTIONS_FLAG(True)  # и при выходе с ошибкой, а не только падении
            a.ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, ctypes.byref(flag))
            pre = SERVICE_PRESHUTDOWN_INFO(PRESHUTDOWN_TIMEOUT_MS)
            a.ChangeServiceConfig2W(svc, SERVICE_CONFIG_PRESHUTDOWN_INFO, ctypes.byref(pre))
        finally:
            a.CloseServiceHandle(svc)
    return what


SERVICE_DEMAND_START = 3


def set_start_type(name: str, start_type: int) -> bool:
    """Тип запуска службы (SERVICE_AUTO_START / SERVICE_DEMAND_START). False — службы нет."""
    a = api()
    with _manager() as scm:
        svc = a.OpenServiceW(scm, name, SERVICE_CHANGE_CONFIG)
        if not svc:
            if ctypes.get_last_error() == ERROR_SERVICE_DOES_NOT_EXIST:
                return False
            raise _err("служба")
        try:
            if not a.ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, start_type, SERVICE_NO_CHANGE,
                                          None, None, None, None, None, None, None):
                raise _err("изменение типа запуска службы")
        finally:
            a.CloseServiceHandle(svc)
    return True


def start(name: str) -> None:
    a = api()
    with _manager() as scm, _Handle(a.OpenServiceW(scm, name, SERVICE_START), "служба") as svc:
        if not a.StartServiceW(svc, 0, None) and ctypes.get_last_error() != 1056:  # уже работает
            raise _err("запуск службы")


def stop(name: str, wait: float = 30.0) -> bool:
    """Остановить и дождаться. False — службы нет или она и так остановлена."""
    import time
    a = api()
    with _manager() as scm:
        svc = a.OpenServiceW(scm, name, SERVICE_STOP | SERVICE_QUERY_STATUS)
        if not svc:
            if ctypes.get_last_error() == ERROR_SERVICE_DOES_NOT_EXIST:
                return False
            raise _err("служба")
        try:
            st = SERVICE_STATUS()
            if not a.ControlService(svc, SERVICE_CONTROL_STOP, ctypes.byref(st)):
                if ctypes.get_last_error() == ERROR_SERVICE_NOT_ACTIVE:
                    return False
                raise _err("остановка службы")
        finally:
            a.CloseServiceHandle(svc)
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        info = query(name)
        if not info or info["state"] == STOPPED:
            return True
        time.sleep(0.3)
    return True


def remove(name: str) -> bool:
    """Остановить и удалить. False — службы не было."""
    a = api()
    try:
        stop(name)
    except OSError:
        pass  # удалим и так: диспетчер уберёт службу, когда процесс завершится
    with _manager() as scm:
        svc = a.OpenServiceW(scm, name, DELETE)
        if not svc:
            if ctypes.get_last_error() == ERROR_SERVICE_DOES_NOT_EXIST:
                return False
            raise _err("служба")
        try:
            if not a.DeleteService(svc) and ctypes.get_last_error() != 1072:  # уже помечена
                raise _err("удаление службы")
        finally:
            a.CloseServiceHandle(svc)
    return True


# ---------- процесс как служба ----------
_keep: list = []   # ссылки на обратные вызовы: иначе сборщик мусора уберёт их из-под Windows


def _ignore_logoff() -> None:
    """Выход пользователя из системы присылает консольным процессам CTRL_LOGOFF_EVENT;
    обработчик по умолчанию завершил бы службу (python.exe при разработке)."""
    handler = CTRL_HANDLER(lambda kind: kind == CTRL_LOGOFF_EVENT)
    _keep.append(handler)
    ctypes.windll.kernel32.SetConsoleCtrlHandler(handler, True)


def run_as_service(name: str, start_core, stop_core, log) -> int:
    """Отдать основной поток диспетчеру служб. start_core() — запустить работу (быстро,
    тяжёлое — в своих потоках), stop_core() — остановить. 0 — служба отработала; 1 — процесс
    запущен не диспетчером служб."""
    a = api()
    stop_event = threading.Event()
    state = {"handle": None}
    status = SERVICE_STATUS(SERVICE_WIN32_OWN_PROCESS, START_PENDING, 0, 0, 0, 0, 30000)

    def report(current: int, accept: int = 0, wait_hint: int = 0, exit_code: int = 0):
        status.dwCurrentState = current
        status.dwControlsAccepted = accept
        status.dwWaitHint = wait_hint
        status.dwWin32ExitCode = exit_code
        status.dwCheckPoint = 0 if current in (RUNNING, STOPPED) else status.dwCheckPoint + 1
        if state["handle"]:
            a.SetServiceStatus(state["handle"], ctypes.byref(status))

    def handler(control, _event_type, _data, _ctx):
        if control in (SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN,
                       SERVICE_CONTROL_PRESHUTDOWN):
            report(STOP_PENDING, wait_hint=PRESHUTDOWN_TIMEOUT_MS)
            stop_event.set()
            return 0
        if control == SERVICE_CONTROL_INTERROGATE:
            return 0
        return ERROR_CALL_NOT_IMPLEMENTED

    def main(_argc, _argv):
        state["handle"] = a.RegisterServiceCtrlHandlerExW(name, handler_cb, None)
        if not state["handle"]:
            log.error("Служба: RegisterServiceCtrlHandlerExW: %s", ctypes.get_last_error())
            return
        report(START_PENDING, wait_hint=30000)
        try:
            start_core()
        except Exception:
            log.exception("Служба: не запустилась")
            report(STOPPED, exit_code=1064)  # ERROR_EXCEPTION_IN_SERVICE — перезапуск
            return
        # PRESHUTDOWN вместо SHUTDOWN: при выключении Windows служба получает время отключить
        # VPN. Раньше её завершали раньше, чем снимался kill switch, — блокировка брандмауэра
        # переживала перезагрузку, и до запуска службы интернета не было (14.11.2026)
        report(RUNNING, SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PRESHUTDOWN)
        log.info("Служба: работает")
        stop_event.wait()
        try:
            stop_core()
        except Exception:
            log.exception("Служба: ошибка при остановке")
        report(STOPPED)
        log.info("Служба: остановлена")

    handler_cb = HANDLER_EX(handler)
    main_cb = SERVICE_MAIN(main)
    _keep.extend([handler_cb, main_cb])
    _ignore_logoff()
    table = (SERVICE_TABLE_ENTRYW * 2)(SERVICE_TABLE_ENTRYW(name, main_cb),
                                       SERVICE_TABLE_ENTRYW(None, SERVICE_MAIN()))
    if not a.StartServiceCtrlDispatcherW(table):
        if ctypes.get_last_error() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT:
            return 1
        raise _err("StartServiceCtrlDispatcherW")
    return 0
