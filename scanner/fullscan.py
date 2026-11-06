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

Быстрая проверка (mode="quick", quick_plan): папки Windows и Users — целиком, как полная;
в остальных папках дисков — только файлы до QUICK_LIMIT (16 МБ): программы и библиотеки
(QUICK_EXTS: .exe, .dll, .sys, .pyd...) и файлы с заголовком MZ в начале. Ради MZ
открываются только файлы, под которые обычно прячут программы (QUICK_MZ_EXTS: без
расширения, .bin, .dat, .tmp, числовые): открытие файла стоит ~5 мс (его проверяет и
Защитник Windows), и проверка заголовков у всех 150 тыс. файлов вне Windows и Users заняла
14 минут; с этим правилом — около 35 тыс. открытий.
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
QUICK_LIMIT = 16 * 1024 * 1024  # быстрая проверка вне Windows и Users: файлы меньше
# быстрая проверка: программы и библиотеки — проверяются без открытия ради заголовка
QUICK_EXTS = {".exe", ".dll", ".sys", ".scr", ".com", ".pif", ".cpl", ".ocx", ".drv", ".efi",
              ".pyd", ".node", ".msi"}
# быстрая проверка: под эти расширения прячут программы — открываем и ищем MZ
QUICK_MZ_EXTS = {"", ".bin", ".dat", ".data", ".tmp", ".temp", ".bak", ".old", ".dll_",
                 ".exe_", ".dl_", ".ex_", ".jpg", ".png", ".txt", ".pdf", ".doc", ".docx"}
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
             "$windows.~ws", "windows.old"}
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
    current: str = ""        # папка, которую сейчас обходим
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


def quick_reason(name: str, size: int) -> str | None:
    """Быстрая проверка вне Windows и Users, файлы до 16 МБ: программы и библиотеки —
    проверять (None); подозрительные расширения — "mz" (открыть и посмотреть заголовок);
    остальное — причина пропуска."""
    if size >= QUICK_LIMIT:
        return "крупный файл (быстрая проверка)"
    ext = os.path.splitext(name)[1].lower()
    if ext in QUICK_EXTS:
        return None
    if ext in QUICK_MZ_EXTS or ext[1:].isdigit():
        return "mz"
    return "не программа (быстрая проверка)"


def full_roots() -> list[str]:
    """Папки, которые быстрая проверка проходит целиком: Windows и Users."""
    windows = os.environ.get("SystemRoot", r"C:\Windows")
    users = os.path.join(os.environ.get("SystemDrive", "C:") + os.sep, "Users")
    return [p for p in (windows, users) if os.path.isdir(p)]


def quick_plan(roots: list[str]) -> list[tuple[str, bool]]:
    """(папка, быстрый фильтр): Windows и Users целиком, остальные диски — с фильтром."""
    plan = [(p, False) for p in full_roots()]
    plan += [(root, True) for root in roots]
    return plan


def walk(root: str, stats: Stats, cancel: threading.Event, quick: bool = False,
         skip_dirs: set[str] | None = None):
    """Файлы для проверки (генератор). Ссылки на папки (junction, symlink) не раскрываются:
    иначе одни и те же папки обходятся по нескольку раз. quick — фильтр быстрой проверки
    (quick_reason), skip_dirs — папки, уже проверенные целиком."""
    skip = own_dirs() | {_winsxs()} | {os.path.normcase(d) for d in skip_dirs or ()}
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
            if quick:
                reason = quick_reason(entry.name, size)
                if reason == "mz" and not in_game and _has_mz(entry.path):
                    reason = None
                if reason:
                    stats.skipped += 1
                    stats.skipped_bytes += size
                    continue
                yield entry.path
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
    """Полная (mode="full") или быстрая ("quick") проверка дисков.
    on_progress(stats) — пачками, on_found(path, level, text)."""
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

    plan = quick_plan(roots) if mode == "quick" else [(root, False) for root in roots]
    whole = [root for root, quick in plan if not quick] if mode == "quick" else []
    for root, quick in plan:
        batch = []
        for path in walk(root, stats, cancel, quick, set(whole) if quick else None):
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
