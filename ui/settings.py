import sys
from pathlib import Path

from PySide6.QtCore import QSettings

import appinfo

try:
    import winreg
except ImportError:  # не Windows
    winreg = None

ORG, APP = "StudyAV", "myav"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_NAME = "StudyAV"
EXPLORER_KEY = r"Software\Classes\*\shell\StudyAV"
PROJECT_DIR = Path(__file__).resolve().parent.parent

DEFAULTS = {
    "startup/ask_admin": True,      # предлагать запуск от администратора
    "startup/auto_protect": False,  # включать защиту файлов при запуске
    "general/on_top": False,        # окна поверх остальных
    "general/theme": "system",      # system | light | dark
    "scan/threshold": 7,            # порог эвристики PE (баллы)
    "scan/workers": 4,              # потоков при сканировании памяти
    "process/interval": 2,          # обновление диспетчера процессов, сек
    "stats/last_scan": "",
    "general/close_to_tray": True,
}


def _store() -> QSettings:
    return QSettings(ORG, APP)  # новый объект на вызов: безопасно из разных потоков


def get(key: str):
    default = DEFAULTS[key]
    return _store().value(key, default, type=type(default))


def set_(key: str, value) -> None:
    _store().setValue(key, value)


def reset() -> None:
    store = _store()
    for key in DEFAULTS:
        if key != "stats/last_scan":
            store.remove(key)


# ---------- автозапуск вместе с Windows ----------
def _autostart_command() -> str:
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" --autostart'
    pythonw = Path(sys.executable).with_name("pythonw.exe")  # без окна консоли
    interpreter = pythonw if pythonw.exists() else Path(sys.executable)
    return f'"{interpreter}" "{PROJECT_DIR / "gui.py"}" --autostart'


def autostart_enabled() -> bool:
    if winreg is None:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            winreg.QueryValueEx(key, RUN_NAME)
            return True
    except OSError:
        return False


def set_autostart(enabled: bool) -> None:
    if winreg is None:
        raise OSError("Автозапуск поддерживается только в Windows")
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        if enabled:
            winreg.SetValueEx(key, RUN_NAME, 0, winreg.REG_SZ, _autostart_command())
        else:
            try:
                winreg.DeleteValue(key, RUN_NAME)
            except FileNotFoundError:
                pass


def _analyze_command() -> str:
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" --analyze "%1"'
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    interpreter = pythonw if pythonw.exists() else Path(sys.executable)
    return f'"{interpreter}" "{PROJECT_DIR / "gui.py"}" --analyze "%1"'


def explorer_menu_enabled() -> bool:
    if winreg is None:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, EXPLORER_KEY + r"\command"):
            return True
    except OSError:
        return False


def set_explorer_menu(enabled: bool) -> None:
    """Пункт контекстного меню файлов в Проводнике (только для текущего пользователя)."""
    if winreg is None:
        raise OSError("Пункт меню поддерживается только в Windows")
    if enabled:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, EXPLORER_KEY, 0,
                                winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, f"Проверить в {appinfo.SHORT_NAME}")
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, EXPLORER_KEY + r"\command", 0,
                                winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, _analyze_command())
    else:
        for path in (EXPLORER_KEY + r"\command", EXPLORER_KEY):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
            except FileNotFoundError:
                pass