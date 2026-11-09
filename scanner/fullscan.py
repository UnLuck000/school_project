"""Полная проверка диска: обход всех папок и проверка файлов в рабочих процессах (pool).

Чтобы не тратить часы на данные игр, обход пропускает то, в чём не бывает исполняемого
кода, но что весит больше всего:
• папки игр (Steam, Epic, Riot, движки Unity и Unreal, античиты) — в них проверяются только
  исполняемые файлы и скрипты (EXECUTABLE_EXTS), текстуры, звуки и архивы ресурсов — нет;
• архивы ресурсов игр по расширению (.vpk, .pak, .bundle, .assets, ...) в любой папке;
• крупные файлы данных (от 256 МБ) с неисполняемым расширением.
Вне папок игр пропущенный файл всё равно открывается на два байта: если в нём заголовок MZ
(программа под чужим расширением), он проверяется как обычно. В папке игры ресурс без
загрузчика не запустится, а загрузчики (exe, dll) проверяются всегда. Видео и аудио распознаёт pool (media.py).

Быстрая проверка (mode="quick", quick_plan) — только системный диск:
• файлы прямо в корне диска, в Windows, System32 и SysWOW64 (без вложенных папок) — до
  QUICK_SYSTEM_LIMIT (16 МБ);
• папка текущего пользователя (%USERPROFILE%) целиком — файлы до QUICK_USER_LIMIT (32 МБ),
  с теми же пропусками ресурсов игр, что и у полной.
Перед файлами (scanner/extras.py): быстрая проверяет весь автозапуск, полная — автозапуск,
проверку системы и память запущенных процессов.
"""
import ctypes
import os
import shutil
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from monitor import EXECUTABLE_EXTS

DATA_LIMIT = 256 * 1024 * 1024  # файл данных крупнее — пропускается (если в нём нет MZ)
QUICK_SYSTEM_LIMIT = 16 * 1024 * 1024  # быстрая: файлы корня диска и папок Windows меньше
QUICK_USER_LIMIT = 32 * 1024 * 1024    # быстрая: файлы папки пользователя меньше
BATCH = 256                     # файлов в одном обращении к pool: результаты идут потоком

# архивы ресурсов и данные игровых движков: в них нет исполняемого кода
ASSET_EXTS = {
    ".vpk", ".pak", ".utoc", ".ucas", ".uasset", ".uexp", ".ubulk", ".umap",   # Source, Unreal
    ".bundle", ".assets", ".ress", ".resource", ".unity3d",                    # Unity
    ".bank", ".bnk", ".wem", ".fsb", ".pck", ".xwb", ".xsb",                   # звук движков
    ".dds", ".ktx", ".ktx2", ".vtf", ".tga", ".texture", ".tex",                # текстуры
    ".bsa", ".ba2", ".esm", ".forge", ".big", ".rpf", ".wad", ".gcf", ".vpk_dir",
    ".arc", ".cpk", ".pac", ".dat_old", ".mdl", ".vvd", ".vtx", ".phy", ".nav", ".bsp",
    ".shadercache", ".ushaderbytecode", ".pso", ".fxc", ".cso",               # кэш шейдеров
}

# по этим файлам и папкам внутри папки видно, что это игра (имена в нижнем регистре)
GAME_MARKERS = {
    "steam_api.dll", "steam_api64.dll", "steam_appid.txt", "unityplayer.dll",
    "gameassembly.dll", "unitycrashhandler64.exe", "eossdk-win64-shipping.dll",
    "easyanticheat", "battleye", "easyanticheat_eos.sys", "globalgamemanagers",
    "game.dll", "engine.dll", "vstdlib.dll", "gameinfo.gi", "gameinfo.txt",
}
# папки библиотек лаунчеров: всё внутри — игры
GAME_LIBRARIES = {"steamapps", "epic games", "riot games", "xboxgames", "gog games",
                  "ubisoft game launcher", "ea games", "battle.net"}

# служебные места, где проверять нечего или нельзя
SKIP_DIRS = {"system volume information", "$winreagent", "$sysreset", "$windows.~bt",
             "$windows.~ws", "windows.old",
             # ловушки для шифровальщиков (toolbox.decoys.DECOY_NAME): свои файлы, а чтение
             # во время проверки поднимало тревогу «ловушки изменены, виновник не найден»
             "!myav — файлы-ловушки"}
SKIP_FILES = {"pagefile.sys", "hiberfil.sys", "swapfile.sys", "dumpstack.log.tmp"}


def _winsxs() -> str:
    """Хранилище компонентов Windows: те же файлы, что в System32 (жёсткие ссылки)."""
    return os.path.normcase(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "WinSxS"))


def own_dirs() -> set[str]:
    """Папка самой программы: в ней правила YARA и базы (совпадают сами с собой), карантин
    и кэш скомпилированных правил."""
    return {os.path.normcase(str(Path(__file__).resolve().parent.parent))}


# ---------- диски ----------
DRIVE_REMOVABLE, DRIVE_FIXED = 2, 3


@dataclass
class Drive:
    root: str            # «C:\»
    label: str
    removable: bool
    total: int
    free: int

    def title(self) -> str:
        from analyzer.fileops import human_size
        kind = "съёмный" if self.removable else "локальный"
        name = f"{self.root[:2]} {self.label}".strip() if self.label else self.root[:2]
        return (f"{name} ({kind}, занято {human_size(self.total - self.free)} "
                f"из {human_size(self.total)})")


def drives() -> list[Drive]:
    """Локальные и съёмные диски (сетевые и CD — нет)."""
    if sys.platform != "win32":
        return []
    kernel32 = ctypes.windll.kernel32
    mask = kernel32.GetLogicalDrives()
    found = []
    for i in range(26):
        if not mask & (1 << i):
            continue
        root = f"{chr(65 + i)}:\\"
        kind = kernel32.GetDriveTypeW(root)
        if kind not in (DRIVE_REMOVABLE, DRIVE_FIXED):
            continue
        label = ctypes.create_unicode_buffer(261)
        if not kernel32.GetVolumeInformationW(root, label, 261, None, None, None, None, 0):
            continue  # диска нет (пустой кардридер)
        try:
            usage = shutil.disk_usage(root)
        except OSError:
            continue
        found.append(Drive(root, label.value, kind == DRIVE_REMOVABLE, usage.total, usage.free))
    return found


# ---------- обход ----------
@dataclass
class Stats:
    files: int = 0           # найдено файлов
    queued: int = 0          # отдано на проверку
    checked: int = 0         # проверено
    skipped: int = 0         # пропущено файлов (ассеты, данные игр)
    skipped_bytes: int = 0
    game_dirs: list[str] = field(default_factory=list)  # найденные папки игр
    errors: int = 0          # не открылись
    threats: int = 0
    suspicious: int = 0
    autoruns: int = 0        # записей автозапуска проверено
    checks: int = 0          # проверок системы
    processes: int = 0       # процессов, чья память проверена
    current: str = ""        # папка (или этап), который сейчас идёт
    started: float = field(default_factory=time.time)


def is_game_dir(path: str, names: set[str]) -> bool:
    """Папка игры: в ней есть известные файлы движков, лаунчеров или античитов."""
    if names & GAME_MARKERS:
        return True
    # Unity: «<игра>_Data» рядом с «<игра>.exe»; Unreal: папки Engine и <игра>/Binaries
    if any(n.endswith("_data") and n[:-5] + ".exe" in names for n in names):
        return True
    return "engine" in names and any(n.endswith(".exe") for n in names) and \
        os.path.isdir(os.path.join(path, "Engine", "Binaries"))


def _has_mz(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"MZ"
    except OSError:
        return False


def skip_reason(name: str, size: int, in_game: bool) -> str | None:
    """Почему файл можно не проверять (None — проверять). Заголовок MZ проверяется отдельно."""
    ext = os.path.splitext(name)[1].lower()
    if ext in EXECUTABLE_EXTS:
        return None
    if in_game:
        return "данные игры"
    if ext in ASSET_EXTS:
        return "ресурсы игры"
    if size >= DATA_LIMIT:
        return "крупный файл данных"
    return None


def child_state(state: str, name: str) -> str:
    r"""Состояние вложенной папки: внутри игры — игра; Steam хранит игры в steamapps\common,
    остальные лаунчеры — прямо в своей папке («Epic Games\<игра>»)."""
    if state == "game":
        return "game"
    if name in GAME_LIBRARIES or state == "library" and name == "common":
        return "library"
    if state == "library":
        return "game"
    return ""


def system_drive() -> str:
    """Корень системного диска: «C:\»."""
    return os.environ.get("SystemDrive", "C:").rstrip("\\/") + os.sep


def is_system_drive(root: str) -> bool:
    return os.path.normcase(root.rstrip("\\/")) == \
        os.path.normcase(system_drive().rstrip("\\/"))


@dataclass
class QuickRoot:
    path: str
    recursive: bool    # False — только файлы прямо в папке
    limit: int | None  # файлы этого размера и крупнее пропускаются


def quick_plan() -> list[QuickRoot]:
    """Быстрая проверка: корень системного диска, Windows, System32, SysWOW64 — только их
    файлы (до 16 МБ); папка пользователя — целиком (до 32 МБ)."""
    windows = os.environ.get("SystemRoot", os.path.join(system_drive(), "Windows"))
    plan = [QuickRoot(p, False, QUICK_SYSTEM_LIMIT)
            for p in (system_drive(), windows, os.path.join(windows, "System32"),
                      os.path.join(windows, "SysWOW64"))]
    plan.append(QuickRoot(os.path.expanduser("~"), True, QUICK_USER_LIMIT))
    return [q for q in plan if os.path.isdir(q.path)]


def walk(root: str, stats: Stats, cancel: threading.Event, recursive: bool = True,
         limit: int | None = None):
    """Файлы для проверки (генератор). Ссылки на папки (junction, symlink) не раскрываются:
    иначе одни и те же папки обходятся по нескольку раз. recursive=False — только файлы
    самой папки; limit — файлы такого размера и крупнее пропускаются (быстрая проверка)."""
    skip = own_dirs() | {_winsxs()}
    # состояние папки: "" — обычная, "library" — библиотека лаунчера, "game" — папка игры
    stack = [(root, "")]
    while stack:
        if cancel.is_set():
            return
        folder, state = stack.pop()
        stats.current = folder
        try:
            entries = list(os.scandir(folder))
        except OSError:
            stats.errors += 1
            continue
        if state != "game" and is_game_dir(folder, {e.name.lower() for e in entries}):
            state = "game"
            stats.game_dirs.append(folder)
        in_game = state == "game"
        subdirs = []
        for entry in entries:
            try:
                if entry.is_symlink() or entry.is_junction():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if not recursive:
                        continue
                    low = entry.name.lower()
                    if low in SKIP_DIRS or os.path.normcase(entry.path) in skip:
                        continue
                    subdirs.append((entry.path, child_state(state, low)))
                    if (state == "library" and subdirs[-1][1] == "game"
                            and os.path.basename(folder).lower() != "steamapps"):
                        stats.game_dirs.append(entry.path)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                if entry.name.lower() in SKIP_FILES:
                    continue
                size = entry.stat(follow_symlinks=False).st_size
            except OSError:
                stats.errors += 1
                continue
            stats.files += 1
            if limit is not None and size >= limit:
                stats.skipped += 1
                stats.skipped_bytes += size
                continue
            reason = skip_reason(entry.name, size, in_game)
            # в папке игры ресурс без загрузчика не запустится, а загрузчики (exe, dll)
            # проверяются; вне игр файл открывается на два байта: не программа ли это
            if reason and (in_game or not _has_mz(entry.path)):
                stats.skipped += 1
                stats.skipped_bytes += size
                continue
            yield entry.path
        stack.extend(reversed(subdirs))  # обход по алфавиту


def run(roots: list[str], on_progress, on_found, cancel: threading.Event,
        mode: str = "full") -> Stats:
    """Полная (mode="full") проверка дисков roots или быстрая ("quick": quick_plan, roots не
    нужны). on_progress(stats) — пачками, on_found(path, level, text)."""
    from analyzer.folderview import classify, rules_and_bases
    from scanner import pool as scan_pool

    stats = Stats()
    signatures, rules, whitelist = rules_and_bases()
    last = 0.0

    def check(batch):
        nonlocal last
        for path, reason, error in scan_pool.check_files(batch, signatures, rules, whitelist,
                                                         cancel=cancel):
            stats.checked += 1
            if error is not None:
                stats.errors += 1
                continue
            level, text = classify(reason)
            if level in ("threat", "suspicious"):
                stats.threats += level == "threat"
                stats.suspicious += level == "suspicious"
                on_found(path, level, text)
            if time.monotonic() - last >= 0.5:
                last = time.monotonic()
                on_progress(stats)

    def found(path, level, text):
        stats.threats += level == "threat"
        stats.suspicious += level == "suspicious"
        on_found(path, level, text)

    def say(text):
        stats.current = text
        on_progress(stats)

    run_extras(mode, stats, signatures, rules, whitelist, found, cancel, say)
    plan = quick_plan() if mode == "quick" else [QuickRoot(r, True, None) for r in roots]
    for item in plan:
        batch = []
        for path in walk(item.path, stats, cancel, item.recursive, item.limit):
            batch.append(path)
            stats.queued += 1
            if len(batch) >= BATCH:
                check(batch)
                batch = []
        if batch and not cancel.is_set():
            check(batch)
        if cancel.is_set():
            break
    on_progress(stats)
    return stats


def run_extras(mode, stats, signatures, rules, whitelist, found, cancel, say) -> None:
    """Автозапуск (обе проверки), проверка системы и память (полная). Сбой этапа не
    останавливает проверку файлов: он попадает в находки как ошибка этапа."""
    from scanner import extras
    stages = [("автозапуск", lambda: setattr(stats, "autoruns", extras.scan_autoruns(
        signatures, rules, whitelist, found, cancel, say)))]
    if mode == "full":
        stages += [("проверка системы", lambda: setattr(stats, "checks", extras.scan_system(
                       found, cancel, say))),
                   ("память процессов", lambda: setattr(stats, "processes", extras.scan_memory(
                       found, cancel, say)))]
    for title, stage in stages:
        if cancel.is_set():
            return
        try:
            stage()
        except Exception as e:
            stats.errors += 1
            say(f"{title}: не выполнено ({e})")
