import json
import os
import subprocess
import sys
import threading
from pathlib import Path

from PySide6.QtCore import QSettings

import appinfo
import userdata

try:
    import winreg
except ImportError:  # не Windows
    winreg = None

ORG, APP = "StudyAV", "myav"  # прежнее место настроек в реестре (для переноса и уборки)
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_NAME = "StudyAV"
EXPLORER_KEY = r"Software\Classes\*\shell\StretchBIT"
LEGACY_EXPLORER_KEY = r"Software\Classes\*\shell\StudyAV"  # пункт меню прежних версий
PROJECT_DIR = Path(__file__).resolve().parent.parent

DEFAULTS = {
    "startup/autostart": False,     # задание планировщика при входе в Windows (с правами)
    "advanced/warned": False,       # предупреждение при первом открытии доп. настроек уже было
    "vpn/autostart": False,         # подключать VPN вместе с программой (профиль автоподключения)
    "vpn/xray_path": "",            # xray.exe (пусто — искать самостоятельно, vpn/xray.py)
    "vpn/singbox_path": "",         # sing-box.exe (пусто — искать самостоятельно, vpn/singbox.py)
    "vpn/proxy_backup": "",         # прежний системный прокси, пока VPN его подменяет
    "vpn/ip_mode": "ipv4",          # ipv4 | prefer_ipv6 | ipv6 (vpn/xray.IP_MODES)
    "vpn/block_quic": True,         # QUIC (UDP 443) блокируется — браузеры переходят на TCP
    "vpn/block_udp": False,         # весь UDP блокируется (DNS через сервер — по TCP)
    "vpn/dns_server": "1.1.1.1",    # DNS через сервер VPN (режим TUN)
    "vpn/rules_direct": "",         # свои правила: домены, IP/CIDR, geosite:, geoip: — по строке
    "vpn/rules_proxy": "",
    "vpn/rules_block": "",
    "vpn/cert_blocked": "",         # сайты с подменённым сертификатом (до разрешения)
    "vpn/cert_watch": True,         # проверять сертификаты сайтов во время подключения
    "vpn/last_profile": "",         # последний подключённый профиль (выбирается при открытии)
    # vpn/route_ru, block_ads, block_quic, block_udp, rules_* — прежние настройки маршрутизации:
    # с профилями (vpn/routing.py) только переносятся в Default при первом запуске
    "vpn/route_ru": True,           # российские сайты напрямую (vpn/xray.apply_options)
    "vpn/block_ads": False,         # реклама и трекеры блокируются
    "vpn/routing_profile": "default",  # выбранный профиль маршрутизации (vpn/routing.py)
    "vpn/strict_route": True,       # строгая маршрутизация sing-box (TUN): фильтры WFP
    "vpn/mux": False,               # Mux (не с flow=xtls-rprx-vision)
    "vpn/fragment": False,          # фрагментация ClientHello до сервера (обход DPI)
    "vpn/direct_apps": "",          # программы напрямую, мимо VPN (пути, по строке; TUN)
    "vpn/socks_enabled": True,      # локальный SOCKS5-прокси для программ (127.0.0.1)
    "vpn/socks_port": 2082,
    "vpn/http_enabled": False,      # локальный HTTP-прокси для программ (127.0.0.1)
    "vpn/http_port": 2081,
    "vpn/killswitch": True,         # интернет только через VPN (брандмауэр Windows / прокси)
    "vpn/killswitch_backup": "",    # прежние действия брандмауэра, пока блокировка включена
    "vpn/dns_backup": "",           # прежний DNS адаптеров, пока VPN его подменяет
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
    "protect/amsi": False,          # проверка скриптов через AMSI (scanner/amsi.py); нужна
                                    # регистрация провайдера с правами администратора
    "protect/pslog": True,          # журнал блоков скриптов PowerShell, событие 4104
                                    # (scanner/pslog.py): вторая линия после AMSI
    "protect/pslog_all": False,     # политика «записывать все блоки» (иначе — подозрительные)
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
    "protect/selfguard": True,      # сторож: перезапуск после нештатного завершения
    "process/interval": 2,          # обновление диспетчера процессов, сек
    "stats/last_scan": "",
    "db/last_update": 0.0,          # время последнего обновления баз (секунды с 1970 года)
    "update/last_check": 0.0,       # последняя проверка выпуска программы (updatecheck.py)
    "update/skipped": "",           # версия, которую пользователь решил пропустить
    "report/first_run": 0.0,        # первый запуск: от него считаются периоды отчёта
    "report/last_end": 0.0,         # конец последнего периода, отчёт за который готов
}


# Настройки, которыми вредонос без прав ослабил бы защиту или запустил свой код с правами
# администратора (путь к xray.exe, подключение VPN при запуске, выключенная защита, сняты
# запреты): settings.ini пишет любая программа пользователя. Они хранятся отдельно —
# secure_settings.json под trustseal (защищённая копия в %ProgramData%): файл, изменённый не
# программой, не действует, пока пользователь не решит при запуске (check_trust_files).
SECURE_PREFIXES = ("protect/", "lock/", "scan/")
SECURE_KEYS = {"startup/autostart", "vpn/autostart", "vpn/xray_path", "vpn/singbox_path",
               "vpn/killswitch", "vpn/direct_apps", "net/windivert_dir", "general/block_exit"}
_secure_lock = threading.RLock()
_secure_cache: tuple[bytes, dict] | None = None


def secure(key: str) -> bool:
    return key in SECURE_KEYS or key.startswith(SECURE_PREFIXES)


def _typed(value, default):
    if isinstance(default, bool):
        if isinstance(value, str):
            return value.strip().lower() in ("1", "true", "yes", "on")
        return bool(value)
    try:
        return type(default)(value)
    except (TypeError, ValueError):
        return default


def _secure_data() -> dict:
    """Защищённые настройки (то, чему можно доверять). Файла ещё нет — перенос значений из
    settings.ini (первый запуск этой версии)."""
    global _secure_cache
    import trustseal
    path = userdata.SECURE_SETTINGS_FILE
    with _secure_lock:
        if not path.exists():
            ini = store()
            data = {k: _typed(ini.value(k), DEFAULTS[k]) for k in DEFAULTS
                    if secure(k) and ini.contains(k)}
            _write_secure(data)
        raw = trustseal.read(path)
        if _secure_cache is not None and _secure_cache[0] == raw:
            return _secure_cache[1]
        try:
            data = json.loads(raw.decode("utf-8")) if raw else {}
        except ValueError:
            data = {}
        if not isinstance(data, dict):
            data = {}
        _secure_cache = (raw, data)
        return data


def _write_secure(data: dict) -> None:
    import trustseal
    path = userdata.SECURE_SETTINGS_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1, sort_keys=True),
                   encoding="utf-8")
    os.replace(tmp, path)
    trustseal.saved(path)


_stores = threading.local()


def store() -> QSettings:
    """settings.ini в папке конфигурации (userdata.py). ORG/APP — прежнее место в реестре:
    его переносит userdata.migrate и чистит удаление.
    Объект — один на поток и файл: создание QSettings на каждый cfg.get (таймеры раз в
    секунду) каждый раз сверяло файл с диском. Сам файл Qt делит между объектами процесса,
    так что запись из одного потока сразу видна остальным."""
    path = str(userdata.SETTINGS_FILE)
    cached = getattr(_stores, "item", None)
    if cached is None or cached[0] != path:
        cached = (path, QSettings(path, QSettings.Format.IniFormat))
        _stores.item = cached
    return cached[1]


def get(key: str):
    default = DEFAULTS[key]
    if secure(key):
        data = _secure_data()
        return _typed(data[key], default) if key in data else default
    return store().value(key, default, type=type(default))


def set_(key: str, value) -> None:
    if secure(key):
        with _secure_lock:
            data = dict(_secure_data())
            data[key] = value
            _write_secure(data)
        store().remove(key)  # прежнее место — чтобы не путало
        return
    store().setValue(key, value)


KEEP_ON_RESET = ("stats/last_scan", "db/last_update", "report/first_run", "report/last_end",
                 "schedule/last_run", "advanced/warned")


def reset() -> None:
    settings = store()
    for key in DEFAULTS:
        if key not in KEEP_ON_RESET:
            settings.remove(key)
    with _secure_lock:
        _write_secure({})


# ---------- автозапуск вместе с Windows ----------
TASK_NAME = "StretchBIT"
LEGACY_TASK = "StudyAV"  # задание прежних версий: заменяется новым


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
    if _schtasks("/Query", "/TN", LEGACY_TASK).returncode == 0:
        _schtasks("/Delete", "/TN", LEGACY_TASK, "/F")
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
    try:
        if _schtasks("/Query", "/TN", LEGACY_TASK).returncode == 0:
            # задание со старым названием: убрать, а при включённой настройке создать новое
            _schtasks("/Delete", "/TN", LEGACY_TASK, "/F")
    except OSError:
        pass
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
        for path in (LEGACY_EXPLORER_KEY + r"\command", LEGACY_EXPLORER_KEY):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
            except OSError:
                pass
        if not explorer_menu_enabled() or not explorer_current():
            set_explorer_menu(True)
    except OSError:
        pass


def explorer_current() -> bool:
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
