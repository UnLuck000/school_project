from PySide6.QtCore import QEvent, QObject, Qt, QTimer, Signal
import time

RESET_MS = 500  # набранные символы сбрасываются, если 0,5 секунды ничего не вводили
BLOCKING = (Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.AltModifier
            | Qt.KeyboardModifier.MetaModifier)


def load_gate():
    """Модуль проверки из папки debug_mode/ или None, если её нет (чистая копия репозитория)."""
    try:
        from debug_mode import gate
        return gate
    except Exception as e:
        print(f"[debug_mode] проверка недоступна: {e}", file=sys.stderr)
        return None

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