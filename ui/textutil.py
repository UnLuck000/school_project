"""Длинные строки в диалогах: команда автозапуска может занимать тысячи символов, и окно
сообщения растягивается на весь экран так, что до кнопок не добраться."""
from PySide6.QtWidgets import QMessageBox

MAX_LINE = 300    # символов в одной строке сообщения
MAX_TEXT = 3000   # символов во всём сообщении


def elide(text: str, limit: int = MAX_LINE) -> str:
    """Обрезает строку до limit символов, добавляя многоточие."""
    text = str(text)
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


def elide_lines(text: str, line_limit: int = MAX_LINE, total: int = MAX_TEXT) -> str:
    """Обрезает каждую строку текста и весь текст целиком."""
    lines = [elide(line, line_limit) for line in str(text).split("\n")]
    return elide("\n".join(lines), total)


def install_message_box_limits() -> None:
    """Все QMessageBox.information/question/warning/critical обрезают длинный текст.
    Вызывается один раз при запуске программы."""
    for name in ("information", "question", "warning", "critical"):
        original = getattr(QMessageBox, name)
        if getattr(original, "_elided", False):
            continue

        def wrapper(parent, title, text, *args, _original=original, **kwargs):
            return _original(parent, elide(title, 120), elide_lines(text), *args, **kwargs)

        wrapper._elided = True
        setattr(QMessageBox, name, staticmethod(wrapper))
