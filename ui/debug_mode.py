"""Пароль для дополнительных настроек и вкладки «Отладка».

Пароль вводится в окне по кнопке «Открыть дополнительные настройки и отладку» на странице
«Настройки» (клавиатура больше не отслеживается). Пароль по умолчанию (он же в релизной
версии) зашит хэшем и показывается подсказкой в окне ввода; его можно убрать, если задан
свой пароль, тогда подсказки нет. Свой пароль хранится только в PASSWORDS_FILE (папка
debug_mode исключена из Git и в релиз не попадает).
"""
import hashlib
import secrets
from pathlib import Path

from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QLabel, QLineEdit, QMessageBox, QVBoxLayout,
)

PASSWORDS_FILE = Path(__file__).resolve().parent.parent / "debug_mode" / "passwords.txt"
MAX_LEN = 64
DEFAULT_SALT = "myav-release"
DEFAULT_HASH = "6d1d08940134c90e4a2b00a618fadef0c0831e215501c32c545f9519195d4dd8"
DEFAULT_HINT = "1qaz2wsx3edc"  # подсказка в окне ввода, пока пароль по умолчанию не убран
DEFAULT_OFF = "default:off"     # строка в PASSWORDS_FILE: пароль по умолчанию убран
MIN_LEN = 6
HEADER = ("# Хэши допустимых паролей (не сами пароли).\n"
          "# Задаётся на вкладке «Отладка».\n")


class PasswordGate:
    """Проверка пароля. Хранятся только соль и SHA-256 паролей."""

    def __init__(self, path: Path = PASSWORDS_FILE, default: tuple[str, str] | None = None):
        self.path = path
        self._default = (DEFAULT_SALT, DEFAULT_HASH) if default is None else default
        self._salt, self._hashes, self._default_off = self._load()

    def _load(self) -> tuple[str, set[str], bool]:
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return "", set(), False
        salt, hashes, off = "", set(), False
        for line in (l.strip() for l in lines):
            if not line or line.startswith("#"):
                continue
            if line == DEFAULT_OFF:
                off = True
            elif line.startswith("salt:"):
                salt = line[5:]
            else:
                hashes.add(line.lower())
        return salt, hashes, off and bool(hashes)  # без своего пароля «убран» не действует

    def _save(self, salt: str, hashes: set[str], default_off: bool) -> None:
        if not hashes and not default_off:
            self.path.unlink(missing_ok=True)
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            body = HEADER + (DEFAULT_OFF + "\n" if default_off else "")
            body += f"salt:{salt}\n" + "".join(h + "\n" for h in sorted(hashes))
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(body, encoding="utf-8")
            tmp.replace(self.path)
        self._salt, self._hashes, self._default_off = self._load()

    @staticmethod
    def _hash(salt: str, text: str) -> str:
        return hashlib.sha256((salt + text.lower()).encode("utf-8")).hexdigest()

    def has_default(self) -> bool:
        """Действует ли пароль по умолчанию (и показывается ли подсказка)."""
        return bool(self._default[1]) and not self._default_off

    def has_own_password(self) -> bool:
        return bool(self._hashes)

    def has_password(self) -> bool:
        return self.has_own_password() or self.has_default()

    def check(self, typed: str) -> bool:
        """Верен ли пароль (без учёта регистра)."""
        text = typed.strip()[:MAX_LEN]
        if self._hashes and self._hash(self._salt, text) in self._hashes:
            return True
        return self.has_default() and self._hash(self._default[0], text) == self._default[1]

    def set_password(self, password: str) -> None:
        """Задаёт свой пароль (заменяет прежний свой)."""
        if len(password) < MIN_LEN or len(password) > MAX_LEN:
            raise ValueError(f"Длина пароля: от {MIN_LEN} до {MAX_LEN} символов")
        salt = secrets.token_hex(8)
        self._save(salt, {self._hash(salt, password)}, self._default_off)

    def remove_password(self) -> None:
        """Убирает свой пароль. Нельзя, если пароль по умолчанию тоже убран."""
        if self._default_off:
            raise ValueError("Сначала верните пароль по умолчанию: иначе не останется ни "
                             "одного пароля")
        self._save("", set(), False)

    def set_default_enabled(self, enabled: bool) -> None:
        """Убрать или вернуть пароль по умолчанию. Убрать можно только при своём пароле."""
        if not enabled and not self._hashes:
            raise ValueError("Сначала задайте свой пароль: иначе не останется ни одного")
        self._save(self._salt, self._hashes, not enabled)


def load_gate() -> PasswordGate:
    return PasswordGate()


def ask_password(parent, gate: PasswordGate) -> bool:
    """Окно ввода пароля. True — пароль верный."""
    dialog = QDialog(parent)
    dialog.setWindowTitle("Дополнительные настройки и отладка")
    box = QVBoxLayout(dialog)
    box.addWidget(QLabel("Введите пароль администратора программы:"))
    edit = QLineEdit()
    edit.setEchoMode(QLineEdit.EchoMode.Password)
    edit.setMinimumWidth(320)
    if gate.has_default():
        edit.setPlaceholderText(f"Подсказка: {DEFAULT_HINT}")
    box.addWidget(edit)
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                               | QDialogButtonBox.StandardButton.Cancel)
    buttons.accepted.connect(dialog.accept)
    buttons.rejected.connect(dialog.reject)
    box.addWidget(buttons)
    while dialog.exec() == QDialog.DialogCode.Accepted:
        if gate.check(edit.text()):
            return True
        from recovery import activity
        activity.record("access", "Неверный пароль дополнительных настроек")
        QMessageBox.warning(dialog, "Пароль", "Неверный пароль")
        edit.clear()
    return False
