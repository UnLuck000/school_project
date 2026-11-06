"""Уведомления Windows с кнопками (WinRT через пакет windows-toasts).

Значок в трее (QSystemTrayIcon.showMessage) показывает обычное уведомление без кнопок. Для
кнопок нужно настоящее уведомление WinRT от зарегистрированного приложения: AUMID
регистрируется один раз в HKCU\\Software\\Classes\\AppUserModelId\\<AUMID> (имя и значок,
которые Windows показывает в заголовке уведомления; только для текущего пользователя).

Notifier(parent).show(title, text, buttons, on_click): buttons — [(надпись, аргумент)],
on_click(аргумент) приходит в главный поток Qt ("" — щелчок по самому уведомлению,
None — уведомление закрыто или пропало). Без пакета или на старой Windows show() вернёт
False — тогда вызывающий показывает обычное уведомление через трей.
"""
from pathlib import Path

from PySide6.QtCore import QObject, Signal

import appinfo

AUMID = "StudyAV.myav"
ICON = Path(__file__).resolve().parent / "assets" / "icon.ico"
KEY = rf"Software\Classes\AppUserModelId\{AUMID}"


def register() -> None:
    """Имя и значок программы для уведомлений Windows (раз за запуск, без журнала:
    это регистрация самой программы, как пункт меню Проводника)."""
    import winreg
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, KEY) as key:
        winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, appinfo.SHORT_NAME)
        if ICON.exists():
            winreg.SetValueEx(key, "IconUri", 0, winreg.REG_SZ, str(ICON))


class Notifier(QObject):
    clicked = Signal(object, object)  # обработчик, аргумент — в главный поток

    def __init__(self, parent=None):
        super().__init__(parent)
        self.clicked.connect(lambda handler, arg: handler(arg))
        self._toaster = None
        self._toasts = []  # живые уведомления: иначе события не придут (сборщик мусора)

    def _get_toaster(self):
        if self._toaster is None:
            from windows_toasts import InteractableWindowsToaster
            register()
            self._toaster = InteractableWindowsToaster(appinfo.SHORT_NAME, AUMID)
        return self._toaster

    def show(self, title: str, text: str, buttons: list[tuple[str, str]], on_click,
             reminder: bool = True) -> bool:
        try:
            from windows_toasts import Toast, ToastButton, ToastScenario
            toaster = self._get_toaster()
            toast = Toast([title, text])
            if reminder:  # остаётся на экране, пока пользователь не выберет кнопку
                toast.scenario = ToastScenario.Reminder
            for label, argument in buttons:
                toast.AddAction(ToastButton(label, argument))
            toast.on_activated = lambda args: self.clicked.emit(on_click, args.arguments or "")
            toast.on_dismissed = lambda args: self.clicked.emit(on_click, None)
            self._toasts = (self._toasts + [toast])[-5:]
            toaster.show_toast(toast)
            return True
        except Exception:  # нет пакета, старая Windows, сбой WinRT — уведомление через трей
            return False
