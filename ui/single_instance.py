import time

from PySide6.QtCore import QObject, Signal
from PySide6.QtNetwork import QLocalServer, QLocalSocket


class SingleInstance(QObject):
    """Один экземпляр программы: второй запуск просит первый показать окно или открыть файл."""
    activated = Signal()
    file_received = Signal(str)

    def __init__(self, name: str):
        super().__init__()
        self.name = name
        self._server: QLocalServer | None = None

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