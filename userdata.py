r"""Конфигурация пользователя — отдельно от папки программы.

    %APPDATA%\StretchBitConfiguration        — релизная версия
    %APPDATA%\StretchBitConfiguration-test   — тестовая (и запуск из исходников)

Внутри:
    settings.ini        — все настройки (раньше реестр HKCU\Software\StudyAV\myav), в том
                          числе настройки VPN, диспетчера процессов, папки под наблюдением;
    journal\            — журнал действий с копиями для отмены, журнал защиты, снимки
                          файловых ассоциаций, копии расширений браузеров (ext_backup),
                          ловушки, разрешённые для паролей браузеров программы;
    whitelist.json      — белый список (возвращённое из карантина);
    exclusions.json     — исключения (автозапуск, проверка системы, сеть);
    overrides.json      — ложные срабатывания релизной версии (хэши, правила YARA, программы);
    vpn_profiles\       — профили VPN (под DPAPI);
    admin\              — пароль режима администратора;
    process_info.json   — запомненные подписи и сведения процессов (диспетчер процессов).

Переустановка или удаление папки программы их не трогает; удалить — флажком в
деинсталляторе Inno Setup («Удалить все настройки пользователя»).
В папке программы остаются базы, кэш, карантин, журналы работы (logs) и отчёты.

Путь можно подменить переменной окружения STRETCHBIT_CONFIG_DIR (тесты: tests/conftest.py).
"""
import os
import shutil
import sys
from pathlib import Path

NAME = "StretchBitConfiguration"
ENV = "STRETCHBIT_CONFIG_DIR"
# прежние места внутри папки программы (до 09.11.2026)
APP_DIR = Path(sys._MEIPASS) if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
OLD_REGISTRY = ("StudyAV", "myav")


def _config_dir() -> Path:
    if os.environ.get(ENV):
        return Path(os.environ[ENV])
    from diag import edition
    root = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    return root / (NAME + ("-test" if edition.is_test() else ""))


CONFIG_DIR = _config_dir()
SETTINGS_FILE = CONFIG_DIR / "settings.ini"
JOURNAL_DIR = CONFIG_DIR / "journal"
WHITELIST_FILE = CONFIG_DIR / "whitelist.json"
EXCLUSIONS_FILE = CONFIG_DIR / "exclusions.json"
OVERRIDES_FILE = CONFIG_DIR / "overrides.json"
VPN_PROFILES_DIR = CONFIG_DIR / "vpn_profiles"
ADMIN_DIR = CONFIG_DIR / "admin"
PROCESS_INFO_FILE = CONFIG_DIR / "process_info.json"

# что переносится из папки программы при первом запуске новой версии: старое -> новое
MOVES = (
    (APP_DIR / "journal", JOURNAL_DIR),
    (APP_DIR / "signatures" / "whitelist.json", WHITELIST_FILE),
    (APP_DIR / "signatures" / "exclusions.json", EXCLUSIONS_FILE),
    (APP_DIR / "signatures" / "overrides.json", OVERRIDES_FILE),
    (APP_DIR / "vpn_profiles", VPN_PROFILES_DIR),
    (APP_DIR / "debug_mode" / "passwords.txt", ADMIN_DIR / "passwords.txt"),
    (APP_DIR / "cache" / "process_info.json", PROCESS_INFO_FILE),
)


def _fix_journal_paths(old: Path, new: Path) -> None:
    """В записях журнала — полные пути к копиям (journal\\ext_backup\\...): после переноса
    папки отмена искала бы их на старом месте."""
    for name in ("actions.jsonl", "threats.json"):
        f = new / name
        if not f.is_file():
            continue
        text = f.read_text(encoding="utf-8")
        a, b = str(old), str(new)
        fixed = text.replace(a.replace("\\", "\\\\"), b.replace("\\", "\\\\"))  # в JSON
        fixed = fixed.replace(a, b)
        if fixed != text:
            f.write_text(fixed, encoding="utf-8")


def _migrate_registry() -> bool:
    """Настройки из реестра -> settings.ini (только если ini ещё нет)."""
    if SETTINGS_FILE.exists() or sys.platform != "win32":
        return False
    from PySide6.QtCore import QSettings
    old = QSettings(*OLD_REGISTRY)
    keys = old.allKeys()
    if not keys:
        return False
    new = QSettings(str(SETTINGS_FILE), QSettings.Format.IniFormat)
    for key in keys:
        new.setValue(key, old.value(key))
    new.sync()
    return True


def migrate(force: bool = False) -> list[str]:
    """Перенести прежние данные из папки программы и реестра. Что перенесено — список строк.
    Существующее в конфигурации не перезаписывается: прежний файл тогда остаётся на месте.

    С подменённой папкой (STRETCHBIT_CONFIG_DIR — тесты) ничего не переносится: тест,
    импортировавший gui.py, 09.11.2026 перенёс настоящие профили VPN, журнал и белый список
    проекта во временную папку. force — только для теста самого переноса (MOVES подменён)."""
    if os.environ.get(ENV) and not force:
        return []
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    done = []
    for old, new in MOVES:
        if not old.exists() or new.exists():
            continue
        try:
            new.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(old), str(new))
            if new == JOURNAL_DIR:
                _fix_journal_paths(old, new)
            done.append(f"{old} -> {new}")
        except OSError as e:
            done.append(f"{old}: не перенесено ({e})")
    try:
        if _migrate_registry():
            done.append(f"реестр HKCU\\Software\\{OLD_REGISTRY[0]}\\{OLD_REGISTRY[1]} -> "
                        f"{SETTINGS_FILE}")
    except Exception as e:  # noqa: BLE001 — без переноса программа всё равно запустится
        done.append(f"настройки из реестра не перенесены: {e}")
    return done
