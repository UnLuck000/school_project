r"""Сервер канала службы с проверкой клиента.

Каждое подключение — свой поток: подключился → проверка образа процесса клиента (путь
StretchBIT.exe этой установки; чужие отключаются сразу, до чтения) → запросы один за другим
до разрыва. Учётная запись и права клиента узнаются из его маркера после первого запроса.
От одного процесса — не больше PER_CLIENT подключений, экземпляров канала — не больше
MAX_INSTANCES: молчащие подключения проверенного клиента держат только свои потоки.
"""
import os
import threading
from dataclasses import dataclass, field

from service import protocol, winapi

MAX_INSTANCES = 16
PER_CLIENT = 4
READ_TIMEOUT = 5.0      # сообщение целиком после начала
WRITE_TIMEOUT = 10.0
# SYSTEM и администраторы — всё; интерактивные пользователи (IU) — чтение и запись, но не
# FILE_CREATE_PIPE_INSTANCE (0x4) и не FILE_WRITE_EA: второй сервер с тем же именем
# программа пользователя создать не может
PIPE_SDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12018b;;;IU)"


def pipe_sddl(own_sid: str = "") -> str:
    """Сервер без прав администратора (тесты, ядро службы в консоли) создаёт экземпляры
    своего канала по праву своей учётной записи."""
    return PIPE_SDDL + (f"(A;;GA;;;{own_sid})" if own_sid else "")


@dataclass
class Client:
    pid: int
    image: str
    handle: int = 0
    sid: str = ""
    elevated: bool = False
    session: int = -1
    extra: dict = field(default_factory=dict)


class PipeServer:
    """handler(client, op, args) -> результат (JSON) или исключение.
    allowed(pid, image) -> bool — проверка клиента."""

    def __init__(self, name: str, handler, allowed, sddl: str | None = None):
        self.name = name
        self.handler = handler
        self.allowed = allowed
        self.sddl = sddl or PIPE_SDDL
        self.rejected = 0
        self.error = ""
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._clients: dict[int, int] = {}
        self._lock = threading.Lock()
        self._acceptor: threading.Thread | None = None

    # ---------- управление ----------
    def start(self) -> bool:
        if not winapi.available():
            self.error = "только Windows"
            return False
        self._stop.clear()
        self._sa, self._sd = winapi.security_attributes(self.sddl)
        first = self._create(first=True)
        if first is None:
            self.error = f"канал {self.name} уже создан другой программой"
            return False
        self._acceptor = threading.Thread(target=self._accept_loop, args=(first,),
                                          name="svc-accept", daemon=True)
        self._acceptor.start()
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._acceptor is not None:
            self._acceptor.join(timeout=3)
        for t in list(self._threads):
            t.join(timeout=3)
        self._threads = []
        if getattr(self, "_sd", None):
            winapi.k32().LocalFree(self._sd)
            self._sd = None

    @property
    def running(self) -> bool:
        return self._acceptor is not None and self._acceptor.is_alive()

    def _create(self, first: bool = False):
        mode = winapi.PIPE_ACCESS_DUPLEX | winapi.FILE_FLAG_OVERLAPPED | (
            winapi.FILE_FLAG_FIRST_PIPE_INSTANCE if first else 0)
        import ctypes
        h = winapi.k32().CreateNamedPipeW(
            self.name, mode,
            winapi.PIPE_TYPE_MESSAGE | winapi.PIPE_READMODE_MESSAGE |
            winapi.PIPE_REJECT_REMOTE_CLIENTS,
            MAX_INSTANCES, 64 * 1024, 64 * 1024, 0, ctypes.byref(self._sa))
        return None if not h or h == winapi.INVALID_HANDLE else h

    # ---------- приём подключений ----------
    def _connect(self, h) -> bool:
        import ctypes
        k = winapi.k32()
        ov = winapi.OVERLAPPED()
        ov.hEvent = k.CreateEventW(None, True, False, None)
        try:
            if k.ConnectNamedPipe(h, ctypes.byref(ov)):
                return True
            err = winapi.last_error()
            if err == winapi.ERROR_PIPE_CONNECTED:
                return True
            if err != winapi.ERROR_IO_PENDING:
                return False
            ok, _n, _err = winapi.wait_io(h, ov, None, self._stop)
            return ok
        finally:
            k.CloseHandle(ov.hEvent)

    def _accept_loop(self, handle) -> None:
        """Один поток ждёт подключения; подключённый экземпляр уходит своему потоку, а
        ожидание продолжается на новом экземпляре."""
        while not self._stop.is_set():
            h = handle or self._create()
            handle = None
            if h is None:  # экземпляры кончились: ждём, пока освободится
                self._stop.wait(0.2)
                continue
            if not self._connect(h) or self._stop.is_set():
                winapi.k32().DisconnectNamedPipe(h)
                winapi.close(h)
                continue
            client = self._check(h)
            if client is None:
                winapi.k32().DisconnectNamedPipe(h)
                winapi.close(h)
                continue
            t = threading.Thread(target=self._serve, args=(h, client), daemon=True,
                                 name=f"svc-client-{client.pid}")
            self._threads = [x for x in self._threads if x.is_alive()] + [t]
            t.start()

    def _check(self, h) -> Client | None:
        pid = winapi.client_pid(h)
        image = winapi.process_image(pid) if pid else ""
        try:
            allowed = bool(pid) and self.allowed(pid, image)
        except Exception:  # noqa: BLE001 — ошибка проверки = не пускать
            allowed = False
        if not allowed:
            self.rejected += 1
            from diag.log import get
            get("service").warning("Канал: отказано процессу %s (%s)", pid, image or "?")
            return None
        with self._lock:
            if self._clients.get(pid, 0) >= PER_CLIENT:
                self.rejected += 1
                return None
            self._clients[pid] = self._clients.get(pid, 0) + 1
        return Client(pid, image, h, session=winapi.session_of(pid))

    # ---------- обслуживание ----------
    def _serve(self, h, client: Client) -> None:
        try:
            while not self._stop.is_set():
                msg = winapi.read_message(h, protocol.MAX_REQUEST, READ_TIMEOUT, self._stop,
                                          first_timeout=None)
                if msg is None:
                    return
                if not client.sid:
                    client.sid, client.elevated = winapi.client_identity(h)
                reply = self._dispatch(client, msg)
                if not winapi.write_message(h, reply, WRITE_TIMEOUT):
                    return
        except Exception:  # noqa: BLE001 — одно подключение не должно остановить сервер
            from diag.log import swallowed
            swallowed("служба: подключение")
        finally:
            with self._lock:
                left = self._clients.get(client.pid, 0) - 1
                if left > 0:
                    self._clients[client.pid] = left
                else:
                    self._clients.pop(client.pid, None)
            winapi.k32().DisconnectNamedPipe(h)
            winapi.close(h)

    def _dispatch(self, client: Client, msg: bytes) -> bytes:
        try:
            req = protocol.decode(msg)
            rid, op, args = req.get("id"), req.get("op"), req.get("args") or {}
            if not isinstance(op, str) or not isinstance(args, dict):
                raise ValueError("неверный запрос")
        except (ValueError, AttributeError, UnicodeDecodeError):
            return protocol.fail(None, "неверный запрос", "ValueError")
        try:
            result = self.handler(client, op, args)
            data = protocol.ok(rid, result)
            if len(data) > protocol.MAX_REPLY:
                return protocol.fail(rid, "ответ слишком большой")
            return data
        except Exception as e:  # noqa: BLE001 — ошибку получает клиент
            kind = type(e).__name__
            if kind not in protocol.ERROR_TYPES:
                kind = "PermissionError" if isinstance(e, PermissionError) else "ServiceError"
            return protocol.fail(rid, str(e) or kind, kind)


def same_program(*images: str):
    """Проверка клиента: путь образа совпадает с одним из images (без учёта регистра)."""
    allowed = {os.path.normcase(os.path.abspath(i)) for i in images if i}

    def check(_pid: int, image: str) -> bool:
        return bool(image) and os.path.normcase(os.path.abspath(image)) in allowed
    return check
