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
    "general/block_exit": False,    # запрет выхода из программы (кроме диспетчера задач)
    "general/on_top": False,        # окна поверх остальных
    "lock/restore_point": True,     # запреты из дополнительных настроек (ui/access.py)
    "lock/sfc_dism": True,
    "lock/memory": True,
    "lock/usb": True,               # инструмент «USB-накопители» (защита флешек работает всегда)
    "lock/autoruns": False,         # остальные инструменты по умолчанию разрешены
    "lock/file_analyzer": False,
    "lock/process_manager": False,
    "lock/link_check": False,
    "lock/password_leak": False,
    "lock/system_checks": False,
    "lock/journal": False,
    "lock/drivers": False,
    "lock/extensions": False,
    "lock/vpn": False,
    "protect/launch": True,         # контроль запуска программ (scanner/launchguard.py)
    "protect/stealer": True,        # защита от стилеров (toolbox/stealerguard.py)
    "schedule/enabled": False,      # плановая проверка (scanner/schedule.py)
    "schedule/kind": "full",        # full | quick
    "schedule/period": "1w",        # 1w | 2w | 1m | 3m
    "schedule/time": "12:00",
    "schedule/last_run": 0.0,       # когда была последняя плановая проверка
    "schedule/postponed": 0.0,      # отложена до (секунды с 1970 года)
    "protect/decoys": True,         # ловушки для шифровальщиков вместе с защитой файлов
    "lock/protection": False,       # запрет выключать защиту файлов
    "lock/network": False,          # запрет выключать мониторинг сети
    "general/theme": "system",      # system | light | dark
    "scan/threshold": 7,            # порог эвристики PE (баллы)
    "scan/workers": 4,              # потоков при сканировании памяти
    "scan/mode": "balanced",        # режим проверки файлов: slow | balanced | fast
    "scan/ecores_only": False,      # проверка только на энергоэффективных ядрах
    "scan/revocation": True,        # проверять отзыв сертификатов подписи (нужен интернет)
    "net/windivert_dir": "",        # папка с WinDivert.dll (пусто — искать самостоятельно)
    "process/interval": 2,          # обновление диспетчера процессов, сек
    "stats/last_scan": "",
    "db/last_update": 0.0,          # время последнего обновления баз (секунды с 1970 года)
    "report/first_run": 0.0,        # первый запуск: от него считаются периоды отчёта
    "report/last_end": 0.0,         # конец последнего периода, отчёт за который готов
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
        if key not in ("stats/last_scan", "db/last_update", "report/first_run",
                       "report/last_end", "schedule/last_run"):
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