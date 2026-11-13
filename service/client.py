"""Клиент канала службы (интерфейс без прав администратора).

Канал открывается с SECURITY_IDENTIFICATION: сервер может узнать, кто подключился, но не
действовать от имени пользователя. До первого запроса сервер сверяется: его PID — PID
службы из диспетчера служб (собранная программа) или этот же интерпретатор (разработка,
python -m service --console). Иначе имя канала занял кто-то другой — ServiceUnavailable.
"""
import itertools
import os
import sys
import threading
import time

from service import protocol, winapi

CALL_TIMEOUT = 15.0       # запрос и ответ (проверка файла при карантине — дольше обычного)
CONNECT_TIMEOUT = 1.0


class ServiceError(OSError):
    """Служба ответила ошибкой, которая не мапится на стандартное исключение."""


class ServiceUnavailable(ServiceError):
    """Службы нет, канал занят чужим процессом или связь оборвалась."""


class Refused(PermissionError):
    """Служба отказала: операция ослабляет защиту, а она запрещена (lock_protection)."""


class NeedAdminRemote(PermissionError):
    """Нужны права администратора у клиента (config.set)."""


ERRORS = {"FileExistsError": FileExistsError, "FileNotFoundError": FileNotFoundError,
          "ValueError": ValueError, "PermissionError": PermissionError,
          "NeedAdmin": NeedAdminRemote, "Refused": Refused}


def service_server_check():
    """Сервер канала — запущенная служба (PID из диспетчера служб)."""
    from service import scm

    def check(pid: int) -> bool:
        info = scm.query(protocol.service_name())
        return bool(info) and info["pid"] == pid and info["state"] == scm.RUNNING
    return check


def dev_server_check():
    """Разработка: сервер — этот же интерпретатор (ядро в консоли или в этом процессе)."""
    me = os.path.normcase(os.path.abspath(sys.executable))

    def check(pid: int) -> bool:
        if pid == os.getpid():
            return True
        image = winapi.process_image(pid)
        return bool(image) and os.path.normcase(image) == me
    return check


class ServiceClient:
    """Одно подключение к каналу; запросы по очереди (lock). Обрыв — переподключение при
    следующем запросе."""

    def __init__(self, name: str | None = None, verify_server=None,
                 timeout: float = CALL_TIMEOUT):
        self.name = name or protocol.pipe_name()
        self.verify_server = verify_server or (
            dev_server_check() if protocol.dev_mode() else service_server_check())
        self.timeout = timeout
        self._h = None
        self._lock = threading.Lock()
        self._ids = itertools.count(1)

    def _open(self) -> None:
        k = winapi.k32()
        deadline = time.monotonic() + CONNECT_TIMEOUT
        while True:
            h = k.CreateFileW(self.name, winapi.CLIENT_ACCESS, 0, None, winapi.OPEN_EXISTING,
                              winapi.FILE_FLAG_OVERLAPPED | winapi.SECURITY_SQOS_PRESENT |
                              winapi.SECURITY_IDENTIFICATION, None)
            if h and h != winapi.INVALID_HANDLE:
                break
            err = winapi.last_error()
            if err != winapi.ERROR_PIPE_BUSY or time.monotonic() >= deadline:
                raise ServiceUnavailable(f"нет связи со службой ({err})")
            k.WaitNamedPipeW(self.name, 200)
        import ctypes
        from ctypes import wintypes
        mode = wintypes.DWORD(winapi.PIPE_READMODE_MESSAGE)
        k.SetNamedPipeHandleState(h, ctypes.byref(mode), None, None)
        pid = winapi.server_pid(h)
        if not pid or not self.verify_server(pid):
            winapi.close(h)
            raise ServiceUnavailable(f"канал {self.name} создан не службой (PID {pid})")
        self._h = h

    def close(self) -> None:
        with self._lock:
            winapi.close(self._h)
            self._h = None

    def call(self, op: str, timeout: float | None = None, **args):
        with self._lock:
            for attempt in (1, 2):
                if self._h is None:
                    self._open()
                rid = next(self._ids)
                data = protocol.request(rid, op, args)
                wait = timeout or self.timeout
                sent = winapi.write_message(self._h, data, wait)
                reply = winapi.read_message(self._h, protocol.MAX_REPLY, wait,
                                            first_timeout=wait) if sent else None
                if reply is not None:
                    break
                winapi.close(self._h)
                self._h = None
                # заново — только если запрос не ушёл (служба перезапущена, канал старый):
                # ушедший запрос мог выполниться (карантин), повтор сделал бы его дважды
                if sent or attempt == 2:
                    raise ServiceUnavailable(f"служба не ответила на {op}")
        msg = protocol.decode(reply)
        if msg.get("ok"):
            return msg.get("result")
        cls = ERRORS.get(msg.get("type"), ServiceError)
        raise cls(msg.get("error") or "ошибка службы")


class RemoteMonitor:
    """Защита файлов в службе — для окна вместо monitor.RealtimeMonitor (self.monitor):
    start/stop/reload_bases идут запросами. run — номер запуска защиты в службе: события
    прежних запусков окно не путает с текущим."""
    remote = True

    def __init__(self, client: ServiceClient, folders=None, run: int = 0):
        self.client = client
        self.folders = None if folders is None else [str(f) for f in folders]
        self.run = run

    def start(self) -> dict:
        args = {"on": True}
        if self.folders is not None:
            args["folders"] = self.folders
        status = self.client.call("protection.set", **args)
        self.run = status["run"]
        return status

    def stop(self) -> None:
        """Refused — выключение запрещено в настройках службы."""
        self.client.call("protection.set", on=False)

    def reload_bases(self) -> None:
        try:
            self.client.call("bases.reload")
        except ServiceError:
            from diag.log import swallowed
            swallowed("служба: перечитать базы")


class EventPump:
    """Поток длинного опроса событий: on_event(событие) для каждого нового и
    on_link(True/False) при появлении и потере связи. Своё подключение."""

    def __init__(self, client: ServiceClient, on_event, on_link=None, replay: int = 100):
        self.client = client
        self.on_event = on_event
        self.on_link = on_link or (lambda up: None)
        self.replay = replay
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.boot = ""
        self.seq = -1

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="svc-events", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self.client.close()

    def _run(self) -> None:
        up = None
        while not self._stop.is_set():
            try:
                since = self.seq if self.seq >= 0 else -self.replay
                got = self.client.call("events", timeout=8.0, since=since, wait=2.0,
                                       boot=self.boot)
            except ServiceError:
                if up is not False:
                    up = False
                    self.on_link(False)
                self._stop.wait(2.0)
                continue
            if up is not True:
                up = True
                self.on_link(True)
            replay = self.seq < 0  # первые события — прежние, для журнала на странице
            if got["boot"] != self.boot:  # служба перезапущена: номера заново
                self.boot = got["boot"]
            self.seq = got["seq"]
            for event in got["events"]:
                event["replay"] = replay
                try:
                    self.on_event(event)
                except Exception:  # noqa: BLE001 — ошибка обработчика не останавливает опрос
                    from diag.log import swallowed
                    swallowed("служба: обработчик события")


def connect(verify_server=None) -> ServiceClient | None:
    """Служба установлена, запущена и отвечает — клиент; иначе None (работа без службы)."""
    if not winapi.available():
        return None
    if not protocol.dev_mode():
        if not getattr(sys, "frozen", False):
            return None  # из исходников — только с ядром в консоли (STRETCHBIT_SERVICE_DEV=1)
        from service import scm
        info = scm.query(protocol.service_name())
        if not info or info["state"] != scm.RUNNING:
            return None
    client = ServiceClient(verify_server=verify_server)
    try:
        client.call("hello", timeout=3.0, protocol=protocol.PROTOCOL)
    except ServiceError as e:
        from diag.log import get
        get("service").warning("Служба защиты не ответила: %s", e)
        return None
    return client
