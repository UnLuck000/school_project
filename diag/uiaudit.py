"""Действия пользователя в интерфейсе — в журнал без правки каждого обработчика.

Фильтр событий на всё приложение: нажатие кнопки (текст, имя объекта, окно), пункт меню,
переключение вкладки, флажки, выбор в списке, открытие и закрытие окон, переход по страницам.
Пароли и вводимый текст не пишутся (поля ввода не отслеживаются).
"""
from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtWidgets import (
    QAbstractButton, QApplication, QCheckBox, QComboBox, QMenu, QRadioButton, QTabBar, QWidget,
)

from diag import features
from diag.log import get

log = get("ui")


def _window_title(widget: QWidget) -> str:
    win = widget.window()
    return (win.windowTitle() or type(win).__name__) if win is not None else "?"


def _button_text(b: QAbstractButton) -> str:
    text = (b.text() or b.accessibleName() or b.toolTip() or "").replace("&", "").strip()
    return text.splitlines()[0][:80] if text else ""


class UiAudit(QObject):
    def eventFilter(self, obj, event):
        try:
            kind = event.type()
            if kind == QEvent.Type.MouseButtonRelease and event.button() == Qt.MouseButton.LeftButton:
                self._click(obj, event)
            elif kind == QEvent.Type.KeyPress and event.key() in (Qt.Key.Key_Return,
                                                                  Qt.Key.Key_Enter, Qt.Key.Key_Space):
                if isinstance(obj, QAbstractButton) and obj.hasFocus():
                    log.info("Клавиша на кнопке «%s» (%s) — окно «%s»", _button_text(obj),
                             obj.objectName() or type(obj).__name__, _window_title(obj))
            elif kind == QEvent.Type.Show and isinstance(obj, QWidget) and obj.isWindow() \
                    and not isinstance(obj, QMenu) and obj.windowTitle():
                log.info("Открыто окно «%s» (%s)", obj.windowTitle(), type(obj).__name__)
                features.window_shown(type(obj).__name__)
            elif kind == QEvent.Type.Close and isinstance(obj, QWidget) and obj.isWindow() \
                    and obj.windowTitle():
                log.info("Закрыто окно «%s»", obj.windowTitle())
                features.window_closed(type(obj).__name__)
        except Exception:
            pass
        return False

    def _click(self, obj, event):
        if isinstance(obj, QMenu):
            action = obj.actionAt(event.position().toPoint())
            if action is not None and action.isEnabled() and not action.menu():
                log.info("Меню: «%s» — окно «%s»", action.text().replace("&", ""),
                         _window_title(obj.parentWidget() or obj))
        elif isinstance(obj, QAbstractButton) and obj.isEnabled() and \
                obj.rect().contains(event.position().toPoint()):
            state = ""
            if isinstance(obj, (QCheckBox, QRadioButton)) or obj.isCheckable():
                state = " → " + ("выкл" if obj.isChecked() else "вкл")  # состояние до щелчка
            log.info("Кнопка «%s» (%s)%s — окно «%s»", _button_text(obj),
                     obj.objectName() or type(obj).__name__, state, _window_title(obj))
        elif isinstance(obj, QTabBar):
            index = obj.tabAt(event.position().toPoint())
            if index >= 0:
                log.info("Вкладка «%s» — окно «%s»", obj.tabText(index).replace("&", ""),
                         _window_title(obj))


_audit: UiAudit | None = None


def install(app: QApplication) -> None:
    global _audit
    _audit = UiAudit(app)
    app.installEventFilter(_audit)


def watch_combo(combo: QComboBox, name: str) -> None:
    """Выбор в выпадающем списке (по желанию модуля)."""
    combo.activated.connect(lambda i: log.info("%s: выбрано «%s»", name, combo.itemText(i)))
