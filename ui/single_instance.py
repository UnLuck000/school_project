import os
import sys
import time

from PySide6.QtCore import QObject, Signal
from PySide6.QtNetwork import QLocalServer, QLocalSocket


def server_process(socket: QLocalSocket) -> tuple[int, str]:
    """(PID, путь программы) сервера канала, к которому подключён socket (Windows)."""
    if sys.platform != "win32":
        return 0, ""
    import ctypes
    from ctypes import wintypes
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.GetNamedPipeServerProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
    k.OpenProcess.restype = wintypes.HANDLE
    k.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                             ctypes.POINTER(wintypes.DWORD)]
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    pid = wintypes.ULONG()
    if not k.GetNamedPipeServerProcessId(wintypes.HANDLE(int(socket.socketDescriptor())),
                                         ctypes.byref(pid)):
        return 0, ""
    proc = k.OpenProcess(0x1000, False, pid.value)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not proc:
        return pid.value, ""
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = wintypes.DWORD(len(buf))
        ok = k.QueryFullProcessImageNameW(proc, 0, buf, ctypes.byref(size))
        return pid.value, buf.value if ok else ""
    finally:
        k.CloseHandle(proc)


class SingleInstance(QObject):
    """Один экземпляр программы: второй запуск просит первый показать окно или открыть файл."""
    activated = Signal()
    file_received = Signal(str)

    def __init__(self, name: str):
        super().__init__()
        self.name = name
        self._server: QLocalServer | None = None
        # имя канала заняла чужая программа: (PID, путь). Раньше программа считала, что уже
        # запущена, и молча выходила — любой процесс без прав мог так не дать ей запуститься
        self.squatted: tuple[int, str] | None = None

    def already_running(self, notify: bool = True, wait: float = 0.0,
                        message: bytes = b"show") -> bool:
        """True, если другой экземпляр уже работает.
        wait: сколько секунд ждать, пока он завершится (нужно при перезапуске с повышением).
        message: b"show" или b"open\\n<путь к файлу>"."""
        deadline = time.monotonic() + wait
        while True:
            socket = QLocalSocket()
            socket.connectToServer(self.name)
            if not socket.waitForConnected(300):
                return False
            pid, exe = server_process(socket)
            if sys.platform == "win32" and os.path.normcase(exe) != \
                    os.path.normcase(os.path.abspath(sys.executable)):
                socket.abort()
                self.squatted = (pid, exe or "неизвестная программа")
                return False  # это не мы: запускаемся без защиты от второго экземпляра
            if time.monotonic() >= deadline:
                break
            socket.abort()
            time.sleep(0.15)
        if notify:
            socket.write(message)
            socket.flush()
            socket.waitForBytesWritten(500)
        socket.disconnectFromServer()
        return True

    def listen(self) -> bool:
        """Занимает имя. False, если его уже занял другой экземпляр."""
        QLocalServer.removeServer(self.name)  # остаток аварийно завершённого запуска
        server = QLocalServer(self)
        # доступ для обычных программ: иначе процесс без прав администратора
        # не сможет достучаться до экземпляра, запущенного с повышением
        server.setSocketOptions(QLocalServer.SocketOption.WorldAccessOption)
        if not server.listen(self.name):
            return False
        server.newConnection.connect(self._on_connection)
        self._server = server
        return True

    def release(self) -> None:
        """Освобождает имя сразу, не дожидаясь завершения процесса."""
        if self._server is not None:
            self._server.close()
            self._server = None

    def _on_connection(self):
        while self._server is not None and self._server.hasPendingConnections():
            conn = self._server.nextPendingConnection()
            conn.readyRead.connect(lambda c=conn: self._read(c))
            conn.disconnected.connect(conn.deleteLater)

    def _read(self, conn: QLocalSocket):
        data = bytes(conn.readAll())
        if data.startswith(b"open\n"):
            path = data[5:].decode("utf-8", "replace").strip()
            if path:
                self.file_received.emit(path)
        elif data.strip() == b"show":
            self.activated.emit()
