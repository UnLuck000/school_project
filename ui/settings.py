import sys
from pathlib import Path

from PySide6.QtCore import QSettings

try:
    import winreg
except ImportError:  # не Windows
    winreg = None

ORG, APP = "StudyAV", "myav"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_NAME = "StudyAV"
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