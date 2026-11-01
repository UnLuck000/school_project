import hashlib
import secrets
import time
from pathlib import Path

from PySide6.QtCore import QEvent, QObject, Qt, QTimer, Signal

RESET_MS = 500  # набранные символы сбрасываются, если 0,5 секунды ничего не вводили
BLOCKING = (Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.AltModifier
            | Qt.KeyboardModifier.MetaModifier)
# папка исключена из Git: в чистой копии пароля нет и режим отладки открыт
PASSWORDS_FILE = Path(__file__).resolve().parent.parent / "debug_mode" / "passwords.txt"
MAX_LEN = 64
MIN_LEN = 6
HEADER = ("# Хэши допустимых комбинаций (не сами пароли).\n"
          "# Задаётся на вкладке «Отладка» или: python debug_mode/gate.py add\n")


class PasswordGate:
    """Проверка комбинации режима отладки. Хранятся только соль и SHA-256 комбинаций
    (формат совместим с debug_mode/gate.py)."""
    def __init__(self, path: Path = PASSWORDS_FILE):
        self.path = path
        self._salt, self._hashes = self._load()

    def _load(self) -> tuple[str, set[str]]:
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return "", set()
        salt, hashes = "", set()
        for line in (l.strip() for l in lines):
            if not line or line.startswith("#"):
                continue
            if line.startswith("salt:"):
                salt = line[5:]
            else:
                hashes.add(line.lower())
        return salt, hashes

    @staticmethod
    def _hash(salt: str, text: str) -> str:
        return hashlib.sha256((salt + text.lower()).encode("utf-8")).hexdigest()

    def has_password(self) -> bool:
        return bool(self._hashes)

    def check(self, typed: str) -> bool:
        """Заканчивается ли набранное на одну из комбинаций (без учёта регистра)."""
        if not self._hashes:
            return False
        tail = typed[-MAX_LEN:]
        return any(self._hash(self._salt, tail[i:]) in self._hashes for i in range(len(tail)))

    def set_password(self, password: str) -> None:
        """Заменяет все прежние комбинации одной новой."""
        if len(password) < MIN_LEN or len(password) > MAX_LEN:
            raise ValueError(f"Длина пароля: от {MIN_LEN} до {MAX_LEN} символов")
        salt = secrets.token_hex(8)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(HEADER + f"salt:{salt}\n{self._hash(salt, password)}\n", encoding="utf-8")
        tmp.replace(self.path)
        self._salt, self._hashes = self._load()

    def remove_password(self) -> None:
        self.path.unlink(missing_ok=True)
        self._salt, self._hashes = "", set()


def load_gate() -> PasswordGate:
    return PasswordGate()

class DebugKeyWatcher(QObject):
    """Следит за клавишами в окнах программы и сообщает, когда набрана комбинация."""
    triggered = Signal()

    def __init__(self, gate, parent=None):
        super().__init__(parent)
        self.gate = gate
        self.buffer = ""
        self._last_text = ""
        self._last_time = 0.0
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(RESET_MS)
        self._timer.timeout.connect(self.reset)

    def reset(self) -> None:
        self.buffer = ""

    def feed(self, text: str) -> bool:
        """Добавляет символы к набранному. True, если комбинация совпала."""
        if self.gate is None or not text:
            return False
        self.buffer = (self.buffer + text)[-64:]
        self._timer.start()  # отсчёт 1,5 секунды идёт от последнего символа
        if self.gate.check(self.buffer):
            self._timer.stop()
            self.reset()
            self.triggered.emit()
            return True
        return False

    def eventFilter(self, obj, event):
        if (event.type() == QEvent.Type.KeyPress and not event.isAutoRepeat()
                and not (event.modifiers() & BLOCKING)):
            text = event.text()
            if text and text.isprintable():
                now = time.monotonic()
                # одно нажатие приходит от нескольких виджетов подряд: повтор за 20 мс отбрасываем
                if not (text == self._last_text and now - self._last_time < 0.02):
                    self._last_text, self._last_time = text, now
                    self.feed(text)
        return False  # события не перехватываем: ввод работает как обычно