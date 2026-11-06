import os
import subprocess
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
    "startup/autostart": True,      # задание планировщика при входе в Windows (с правами)
    "vpn/autostart": False,         # подключать VPN вместе с программой (профиль автоподключения)
    "vpn/xray_path": "",            # xray.exe (пусто — искать самостоятельно, vpn/xray.py)
    "vpn/singbox_path": "",         # sing-box.exe (пусто — искать самостоятельно, vpn/singbox.py)
    "vpn/proxy_backup": "",         # прежний системный прокси, пока VPN его подменяет
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
    "lock/drivers": True,           # инструмент «Уязвимые драйверы» по умолчанию запрещён
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
TASK_NAME = "StudyAV"


def _autostart_parts() -> tuple[str, str]:
    """(программа, аргументы) для задания планировщика."""
    if getattr(sys, "frozen", False):
        return sys.executable, "--autostart"
    pythonw = Path(sys.executable).with_name("pythonw.exe")  # без окна консоли
    interpreter = pythonw if pythonw.exists() else Path(sys.executable)
    return str(interpreter), f'"{PROJECT_DIR / "gui.py"}" --autostart'


def _autostart_command() -> str:
    exe, args = _autostart_parts()
    return f'"{exe}" {args}'


def _xml_escape(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def task_xml(user: str) -> str:
    """Задание: при входе пользователя, с наивысшими правами (без окна UAC), без ограничения
    по времени и без остановки при работе от батареи (у задания по умолчанию — 3 дня и
    «только от сети»: антивирус на ноутбуке не запустился бы)."""
    exe, args = _autostart_parts()
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>{_xml_escape(appinfo.APP_NAME)}: защита при входе в Windows</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{_xml_escape(user)}</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>{_xml_escape(user)}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>5</Priority>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
  </Settings>
  <Actions Context="Author"><Exec><Command>{_xml_escape(exe)}</Command><Arguments>{_xml_escape(args)}</Arguments><WorkingDirectory>{_xml_escape(str(PROJECT_DIR))}</WorkingDirectory></Exec></Actions>
</Task>
"""


def _schtasks(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["schtasks", *args], capture_output=True, text=True,
                          encoding="oem", errors="replace",  # вывод консоли — в кодировке OEM
                          creationflags=0x08000000)  # CREATE_NO_WINDOW


def autostart_enabled() -> bool:
    if sys.platform != "win32":
        return False
    return _schtasks("/Query", "/TN", TASK_NAME).returncode == 0


def autostart_current() -> bool:
    """Задание есть и запускает именно эту копию программы (папку могли перенести)."""
    result = _schtasks("/Query", "/TN", TASK_NAME, "/XML")
    if result.returncode != 0:
        return False
    exe, _ = _autostart_parts()
    return exe.lower() in result.stdout.lower() and str(PROJECT_DIR).lower() in \
        result.stdout.lower()


def set_autostart(enabled: bool) -> None:
    r"""Задание планировщика (нужны права администратора: оно с наивысшими правами).
    Старый способ — значение в HKCU\...\Run — убирается."""
    if sys.platform != "win32":
        raise OSError("Автозапуск поддерживается только в Windows")
    _remove_run_value()
    if not enabled:
        if autostart_enabled():
            result = _schtasks("/Delete", "/TN", TASK_NAME, "/F")
            if result.returncode != 0:
                raise OSError((result.stderr or result.stdout).strip())
        return
    import getpass
    import tempfile
    user = f"{os.environ.get('USERDOMAIN', '')}\\{getpass.getuser()}".lstrip("\\")
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False,
                                     encoding="utf-16") as f:
        f.write(task_xml(user))
        xml_path = f.name
    try:
        result = _schtasks("/Create", "/TN", TASK_NAME, "/XML", xml_path, "/F")
    finally:
        os.unlink(xml_path)
    if result.returncode != 0:
        raise OSError((result.stderr or result.stdout).strip() or
                      "нужны права администратора")


def ensure_autostart() -> None:
    """При запуске с правами: задание есть (по умолчанию включено) и указывает сюда."""
    if not get("startup/autostart"):
        return
    try:
        if not autostart_current():
            set_autostart(True)
    except OSError:
        pass  # без прав администратора задание не создать: попробуем в следующий раз


def _remove_run_value() -> None:
    if winreg is None:
        return
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                            winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, RUN_NAME)
    except OSError:
        pass


def ensure_explorer_menu() -> None:
    """Пункт «Проверить в ...» в меню файлов включён всегда (настройки больше нет)."""
    try:
        if not explorer_menu_enabled() or not _explorer_current():
            set_explorer_menu(True)
    except OSError:
        pass


def _explorer_current() -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, EXPLORER_KEY + r"\command") as key:
            return winreg.QueryValueEx(key, "")[0] == _analyze_command()
    except OSError:
        return False


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