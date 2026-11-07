"""Поиск программ для списка «напрямую, мимо VPN»: ярлыки «Пуска», запущенные процессы и
папки установки (Program Files, Program Files (x86), %LOCALAPPDATA%\\Programs, библиотеки
игр).

«Приложение» (is_app) — то, что пользователь запускает сам: на файл есть ярлык в «Пуске»,
или это запущенная программа с окном-описанием, или у файла в свойствах есть название
продукта и описание — и это не служебный файл (установщик, удаление, обновление, отчёт об
ошибках, помощник). Остальное (.dll, служебные .exe) показывается, только если выключить
фильтр «Только приложения».
"""
import ctypes
import os
import re
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path

MAX_DEPTH = 4
HELPER_RE = re.compile(
    r"(unins|uninst|setup|install|update|updater|upgrade|crash|report|helper|elevat|"
    r"redist|vc_?redist|dxsetup|dotnet|service|svc|agent|daemon|launcherpatcher|bootstrap|"
    r"notifier|broker|host|repair|diag|feedback|telemetry|sandbox|renderer|gpu|utility|"
    r"cef|webview|plugin|maintenance|register|regsvr|wow_helper|errorreport|crashpad)",
    re.IGNORECASE)
GAME_LIBRARIES = [r"%ProgramFiles(x86)%\Steam\steamapps\common", r"%ProgramFiles%\Epic Games",
                  r"C:\Program Files\Riot Games", r"C:\XboxGames"]


@dataclass
class App:
    path: str
    name: str = ""            # название продукта или имя файла
    description: str = ""     # описание файла
    company: str = ""
    sources: set[str] = field(default_factory=set)  # start | running | folder
    is_app: bool = False

    @property
    def kind(self) -> str:
        return os.path.splitext(self.path)[1].lower().lstrip(".")


# ---------- сведения о версии файла ----------
_version = ctypes.WinDLL("version") if os.name == "nt" else None


def version_info(path: str) -> dict[str, str]:
    """ProductName, FileDescription, CompanyName из ресурсов файла (пусто — нет сведений)."""
    if _version is None:
        return {}
    size = _version.GetFileVersionInfoSizeW(path, None)
    if not size:
        return {}
    data = ctypes.create_string_buffer(size)
    if not _version.GetFileVersionInfoW(path, 0, size, data):
        return {}
    ptr, length = ctypes.c_void_p(), wintypes.UINT()
    langs = []
    if _version.VerQueryValueW(data, "\\VarFileInfo\\Translation", ctypes.byref(ptr),
                               ctypes.byref(length)) and length.value >= 4:
        raw = ctypes.string_at(ptr, length.value)
        for i in range(0, len(raw) - 3, 4):
            lang = int.from_bytes(raw[i:i + 2], "little")
            cp = int.from_bytes(raw[i + 2:i + 4], "little")
            langs.append(f"{lang:04x}{cp:04x}")
    langs += ["040904b0", "040904e4", "041904b0"]
    result = {}
    for key in ("ProductName", "FileDescription", "CompanyName"):
        for lang in langs:
            if _version.VerQueryValueW(data, f"\\StringFileInfo\\{lang}\\{key}",
                                       ctypes.byref(ptr), ctypes.byref(length)) and length.value:
                value = ctypes.wstring_at(ptr, length.value).split("\0")[0].strip()
                if value:
                    result[key] = value
                    break
    return result


def long_path(path: str) -> str:
    """Полный путь без коротких имён 8.3 (C:\\PROGRA~2 → C:\\Program Files (x86))."""
    if os.name != "nt" or "~" not in path:
        return path
    buf = ctypes.create_unicode_buffer(32768)
    if ctypes.windll.kernel32.GetLongPathNameW(path, buf, 32768):
        return buf.value
    return path


def _key(path: str) -> str:
    return os.path.normcase(os.path.normpath(long_path(path)))


# ---------- источники ----------
def start_menu_targets() -> set[str]:
    """Программы, на которые есть ярлыки в «Пуске» (свой и общий)."""
    from usbguard.scan import parse_lnk
    roots = [Path(os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs")),
             Path(os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs"))]
    found = set()
    for root in roots:
        if not root.is_dir():
            continue
        for lnk in root.rglob("*.lnk"):
            try:
                target = parse_lnk(lnk.read_bytes()).target
            except (OSError, ValueError, IndexError):
                continue
            if target.lower().endswith(".exe") and os.path.isabs(target) and \
                    os.path.isfile(target):
                found.add(_key(target))
    return found


def app_paths() -> set[str]:
    """Главные программы из реестра App Paths (winword.exe, excel.exe, chrome.exe...): у
    ярлыков Office и других MSI-программ в «Пуске» нет пути к файлу."""
    import winreg
    found = set()
    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        try:
            root = winreg.OpenKey(hive, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths")
        except OSError:
            continue
        with root:
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(root, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(root, name) as key:
                        value = os.path.expandvars(str(winreg.QueryValueEx(key, "")[0])).strip('"')
                except OSError:
                    continue
                if value.lower().endswith(".exe") and os.path.isabs(value) and \
                        os.path.isfile(value):
                    found.add(_key(value))
    return found


def running_programs() -> set[str]:
    from processmanager import ntsnap
    found = set()
    windows = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows")) + os.sep
    try:
        procs = ntsnap.list_processes()
    except OSError:
        return found
    for p in procs:
        if p.pid in (0, 4):
            continue
        exe = ntsnap.identity(p.pid)[0]
        if exe and not os.path.normcase(exe).startswith(windows):
            found.add(os.path.normcase(os.path.normpath(exe)))
    return found


def install_folders() -> list[Path]:
    folders = [r"%ProgramFiles%", r"%ProgramFiles(x86)%", r"%LOCALAPPDATA%\Programs",
               *GAME_LIBRARIES]
    result, seen = [], set()
    for f in folders:
        path = Path(os.path.expandvars(f))
        key = os.path.normcase(str(path))
        if path.is_dir() and key not in seen:
            seen.add(key)
            result.append(path)
    return result


def folder_files(root: Path, depth: int = MAX_DEPTH, cancel=None) -> list[str]:
    """.exe и .dll в папке установки до depth уровней вложенности."""
    found = []
    stack = [(str(root), 0)]
    while stack:
        if cancel is not None and cancel.is_set():
            break
        folder, level = stack.pop()
        try:
            entries = list(os.scandir(folder))
        except OSError:
            continue
        for e in entries:
            try:
                if e.is_dir(follow_symlinks=False):
                    if level < depth:
                        stack.append((e.path, level + 1))
                elif e.name.lower().endswith((".exe", ".dll")):
                    found.append(os.path.normcase(os.path.normpath(e.path)))
            except OSError:
                continue
    return found


TOOL_DIRS = {"bin", "jre", "jdk", "tools", "tool", "utils", "utilities", "lib", "libs", "x86",
             "x64", "redist", "_update_staging", "updates", "update", "installer", "resources",
             "plugins", "extensions", "drivers", "support", "cdiresource"}


def _norm(text: str) -> str:
    return re.sub(r"[^0-9a-zа-я]", "", text.lower())


def _related(app: App, roots: list[str], games: list[str]) -> bool:
    r"""Файл — главный в своей папке установки: имя файла совпадает с именем папки программы
    (AIMP\AIMP.exe). В библиотеках игр — и по названию продукта (Rust\RustClient.exe)."""
    path = Path(app.path)
    if any(part.lower() in TOOL_DIRS for part in path.parent.parts[-2:]):
        return False
    low = app.path.lower()
    # самый длинный корень: steamapps\common внутри Program Files (x86) — своя папка игр
    matched = [r for r in roots if low.startswith(r + os.sep)]
    if not matched:
        return False
    root = max(matched, key=len)
    rest = Path(app.path[len(root) + 1:]).parts
    game = any(low.startswith(g + os.sep) for g in games)
    if len(rest) < 2 or len(rest) > (5 if game else 3):
        return False
    folder, stem = _norm(rest[0]), _norm(path.stem)
    if not folder or not stem:
        return False
    if stem in folder or folder in stem:
        return True
    product = _norm(app.name)
    return game and bool(product) and (product in folder or folder in product)


def classify(app: App, roots: list[str] | None = None, games: list[str] | None = None) -> bool:
    """Приложение ли это (то, что пользователь запускает сам), а не служебный файл."""
    if app.kind != "exe":
        return False
    if HELPER_RE.search(Path(app.path).stem):
        return False
    if "start" in app.sources:
        return True
    if HELPER_RE.search(app.description or ""):
        return False
    if "running" in app.sources and app.description:
        return True
    return _related(app, roots or [], games or [])


def discover(progress=None, cancel=None) -> list[App]:
    """Все найденные .exe и .dll с пометкой is_app. progress(text) — ход поиска."""
    say = progress or (lambda text: None)
    apps: dict[str, App] = {}

    def add(path: str, source: str) -> None:
        app = apps.setdefault(path, App(path))
        app.sources.add(source)

    say("Ярлыки «Пуска»...")
    for path in start_menu_targets():
        add(path, "start")
    for path in app_paths():
        add(path, "start")
    say("Запущенные программы...")
    for path in running_programs():
        add(path, "running")
    for folder in install_folders():
        if cancel is not None and cancel.is_set():
            break
        say(f"Папка {folder}...")
        for path in folder_files(folder, cancel=cancel):
            add(path, "folder")
    roots = [os.path.normcase(str(f)) for f in install_folders()]
    games = [os.path.normcase(os.path.expandvars(g)) for g in GAME_LIBRARIES]
    say("Сведения о файлах...")
    for app in apps.values():
        if cancel is not None and cancel.is_set():
            break
        if app.kind == "exe":
            info = version_info(app.path)
            app.name = info.get("ProductName", "")
            app.description = info.get("FileDescription", "")
            app.company = info.get("CompanyName", "")
        app.is_app = classify(app, roots, games)
        if not app.name:
            app.name = Path(app.path).stem
    return sorted(apps.values(), key=lambda a: (not a.is_app, a.name.lower()))
