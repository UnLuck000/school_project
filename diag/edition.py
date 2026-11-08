"""Версия сборки: test (тестовая) или release (релизная).

Тестовая: подробный журнал (DEBUG), кнопки «✓ Исправно» и «✎ Комментарий», страница
«Тестирование». Релизная: журнал INFO, кнопок нет, но отклонения функций от проверенной
версии всё равно пишутся в журнал как ошибки.

Собранная программа читает файл edition.txt рядом с модулями (его пишет build_release.py);
запуск из исходников (python gui.py) — всегда тестовая.
"""
import sys
from pathlib import Path

TEST, RELEASE = "test", "release"
FILE = "edition.txt"
_edition: str | None = None


def edition() -> str:
    global _edition
    if _edition is None:
        _edition = TEST
        if getattr(sys, "frozen", False):
            try:
                text = (Path(sys._MEIPASS) / FILE).read_text(encoding="utf-8").strip().lower()
                _edition = TEST if text == TEST else RELEASE
            except OSError:
                _edition = RELEASE  # нет файла — безопаснее релизная
    return _edition


def is_test() -> bool:
    return edition() == TEST


def title() -> str:
    return "тестовая" if is_test() else "релизная"
