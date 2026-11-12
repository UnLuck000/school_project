"""Проверка съёмного диска.

Как действует «вирус-ярлык»: переносит все файлы флешки в скрытую системную папку (часто
с пустым именем из неразрывного пробела или похожих символов), кладёт рядом свой скрипт
или программу, а в корне создаёт ярлык с именем и значком флешки или папки. Ярлык
запускает cmd/wscript со скриптом вируса и тут же открывает спрятанную папку — пользователь
видит свои файлы и ничего не замечает. Старый вариант — autorun.inf с командой open=.

Здесь только чтение: находки и что с ними сделать (fix). Исправления — usbguard/repair.py.
"""
import ctypes
import os
import re
import stat
import struct
from dataclasses import dataclass, field
from pathlib import Path

DRIVE_REMOVABLE = 2
HIDDEN, SYSTEM = stat.FILE_ATTRIBUTE_HIDDEN, stat.FILE_ATTRIBUTE_SYSTEM
SERVICE_DIRS = {"system volume information", "$recycle.bin", "recycler", "recycled"}
SCRIPT_EXTS = {".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".bat", ".cmd", ".ps1", ".hta"}
PROGRAM_EXTS = {".exe", ".scr", ".pif", ".com", ".dll", ".cpl"}
INTERPRETERS = ("cmd.exe", "cmd ", "/c ", "wscript", "cscript", "powershell", "mshta",
                "rundll32", "regsvr32", "conhost", "explorer.exe ")
MAX_DEPTH = 2  # насколько глубоко смотреть в скрытые папки

# уровни: threat — точно вредоносное, suspicious — проверить, info — просто исправить
# fix: quarantine | unhide | restore_folder | "" (только показать)


@dataclass
class Finding:
    path: str
    kind: str          # autorun | shortcut | script | program | hidden_folder | hidden_file
    level: str
    title: str
    detail: str = ""
    fix: str = ""


@dataclass
class DriveReport:
    root: str
    label: str = ""
    findings: list[Finding] = field(default_factory=list)
    programs: list[str] = field(default_factory=list)  # для проверки сканером
    error: str = ""

    @property
    def infected(self) -> bool:
        return any(f.level == "threat" for f in self.findings)

    @property
    def problems(self) -> list[Finding]:
        return [f for f in self.findings if f.level in ("threat", "suspicious")]


def removable_drives() -> list[tuple[str, str]]:
    """[(корень «E:\\», метка)] съёмных дисков."""
    if os.name != "nt":
        return []
    k32 = ctypes.windll.kernel32
    mask = k32.GetLogicalDrives()
    drives = []
    for i in range(26):
        if not mask & (1 << i):
            continue
        root = f"{chr(65 + i)}:\\"
        if k32.GetDriveTypeW(root) != DRIVE_REMOVABLE:
            continue
        label = ctypes.create_unicode_buffer(261)
        ok = k32.GetVolumeInformationW(root, label, 261, None, None, None, None, 0)
        if ok:  # без носителя (пустой картридер) GetVolumeInformation не проходит
            drives.append((root, label.value))
    return drives


def attributes(path: str) -> int:
    try:
        return os.stat(path, follow_symlinks=False).st_file_attributes
    except (OSError, AttributeError):
        return 0


def odd_name(name: str) -> bool:
    """Имя без видимых букв: пробелы, неразрывный пробел, служебные символы Юникода."""
    visible = re.sub(r"[\s\u00a0\u2000-\u200f\u2028-\u202f\u205f\u3000\ufeff_.]", "", name)
    return not visible


# ---------- ярлыки (.lnk, формат MS-SHLLINK) ----------
@dataclass
class Shortcut:
    target: str = ""
    arguments: str = ""
    working_dir: str = ""
    icon: str = ""
    raw_text: str = ""  # все строки файла: запасной вариант, если разбор не удался


def parse_lnk(data: bytes) -> Shortcut:
    link = Shortcut()
    # строки из «сырых» байт: и ANSI, и UTF-16 — так видно цель даже в списке ID
    ascii_parts = re.findall(rb"[\x20-\x7e]{4,}", data)
    wide_parts = re.findall(rb"(?:[\x20-\x7e]\x00){4,}", data)
    link.raw_text = " ".join([p.decode("ascii") for p in ascii_parts]
                             + [p.decode("utf-16-le") for p in wide_parts])
    if len(data) < 0x4C or struct.unpack_from("<I", data, 0)[0] != 0x4C:
        return link
    flags = struct.unpack_from("<I", data, 0x14)[0]
    pos = 0x4C
    try:
        if flags & 0x01:  # HasLinkTargetIDList
            pos += 2 + struct.unpack_from("<H", data, pos)[0]
        if flags & 0x02:  # HasLinkInfo
            size, header, info_flags, _vol, base_off = struct.unpack_from("<5I", data, pos)
            if info_flags & 1:
                if header >= 0x24:
                    off = struct.unpack_from("<I", data, pos + 0x1C)[0]
                    end = data.find(b"\x00\x00", pos + off)
                    while end != -1 and (end - pos - off) % 2:
                        end = data.find(b"\x00\x00", end + 1)
                    link.target = data[pos + off:end].decode("utf-16-le", "replace")
                else:
                    end = data.find(b"\x00", pos + base_off)
                    link.target = data[pos + base_off:end].decode("mbcs", "replace")
            pos += size
        unicode = bool(flags & 0x80)
        names = [(0x04, None), (0x08, "relative"), (0x10, "working_dir"),
                 (0x20, "arguments"), (0x40, "icon")]
        for bit, attr in names:
            if not flags & bit:
                continue
            count = struct.unpack_from("<H", data, pos)[0]
            pos += 2
            width = 2 if unicode else 1
            raw = data[pos:pos + count * width]
            pos += count * width
            text = raw.decode("utf-16-le" if unicode else "mbcs", "replace")
            if attr == "relative" and not link.target:
                link.target = text
            elif attr in ("working_dir", "arguments", "icon"):
                setattr(link, attr, text)
    except (struct.error, IndexError):
        pass
    return link


def judge_shortcut(path: str, root: str) -> Finding:
    try:
        link = parse_lnk(Path(path).read_bytes())
    except OSError as e:
        return Finding(path, "shortcut", "suspicious", "Ярлык не прочитан", str(e), "")
    command = f"{link.target} {link.arguments}".strip()
    text = f"{command} {link.raw_text}".lower()
    shown = command or link.raw_text[:200]
    script = any(ext in text for ext in SCRIPT_EXTS)
    interpreter = any(word in text for word in INTERPRETERS)
    on_drive = link.target.lower().startswith(root[:2].lower())
    if interpreter or script:
        return Finding(path, "shortcut", "threat",
                       "Ярлык запускает команду или скрипт — признак вируса-ярлыка",
                       f"Команда: {shown}", "quarantine")
    if on_drive and Path(link.target).suffix.lower() in PROGRAM_EXTS:
        return Finding(path, "shortcut", "suspicious", "Ярлык запускает программу с флешки",
                       f"Команда: {shown}", "quarantine")
    return Finding(path, "shortcut", "info", "Ярлык в корне флешки",
                   f"Цель: {shown or 'неизвестна'}", "")


def judge_autorun(path: str) -> Finding:
    if os.path.isdir(path):  # «прививка»: папка autorun.inf мешает вирусу создать файл
        return Finding(path, "autorun", "info", "Защитная папка autorun.inf", "", "")
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        text = str(e)
    commands = [s.strip() for s in text.splitlines()
                if re.match(r"\s*(open|shellexecute|shell\\.*\\command)\s*=", s, re.I)]
    level = "threat" if commands else "suspicious"
    return Finding(path, "autorun", level,
                   "autorun.inf с командой запуска" if commands else "Файл autorun.inf",
                   "; ".join(commands)[:300], "quarantine")


def _walk_hidden(folder: str, depth: int, report: DriveReport) -> None:
    """Скрипты и программы внутри скрытых папок: там их и держит вирус-ярлык."""
    try:
        entries = list(os.scandir(folder))
    except OSError:
        return
    for entry in entries:
        ext = os.path.splitext(entry.name)[1].lower()
        if entry.is_dir(follow_symlinks=False):
            if depth < MAX_DEPTH:
                _walk_hidden(entry.path, depth + 1, report)
        elif ext in SCRIPT_EXTS:
            report.findings.append(Finding(entry.path, "script", "threat",
                                           "Скрипт в скрытой папке", "", "quarantine"))
        elif ext in PROGRAM_EXTS:
            report.programs.append(entry.path)


def scan_drive(root: str, label: str = "") -> DriveReport:
    report = DriveReport(root, label)
    try:
        entries = list(os.scandir(root))
    except OSError as e:
        report.error = str(e)
        return report
    for entry in entries:
        name, path = entry.name, entry.path
        low = name.lower()
        ext = os.path.splitext(low)[1]
        attrs = attributes(path)
        hidden = bool(attrs & (HIDDEN | SYSTEM))
        if low == "autorun.inf":
            report.findings.append(judge_autorun(path))
        elif entry.is_dir(follow_symlinks=False):
            if low in SERVICE_DIRS:
                continue
            if odd_name(name):
                report.findings.append(Finding(
                    path, "hidden_folder", "suspicious" if hidden else "info",
                    "Папка без имени" + (", скрытая" if hidden else "")
                    + " — сюда вирус-ярлык переносит файлы флешки",
                    "Файлы будут перенесены обратно в корень флешки", "restore_folder"))
            elif hidden:
                report.findings.append(Finding(path, "hidden_folder", "info",
                                               "Скрытая папка", "Атрибуты будут сняты",
                                               "unhide"))
            if hidden or odd_name(name):
                _walk_hidden(path, 1, report)
        elif ext == ".lnk":
            report.findings.append(judge_shortcut(path, root))
        elif ext in SCRIPT_EXTS:
            report.findings.append(Finding(
                path, "script", "threat" if hidden else "suspicious",
                "Скрытый скрипт в корне флешки" if hidden else "Скрипт в корне флешки",
                "", "quarantine"))
        elif ext in PROGRAM_EXTS:
            report.programs.append(path)
            if hidden:
                report.findings.append(Finding(path, "program", "suspicious",
                                               "Скрытая программа в корне флешки", "",
                                               "quarantine"))
        elif hidden:
            report.findings.append(Finding(path, "hidden_file", "info", "Скрытый файл",
                                           "Атрибуты будут сняты", "unhide"))
    return report


def add_program_verdicts(report: DriveReport, results) -> None:
    """results: [(путь, причина или None, ошибка)] от scanner.pool.check_files."""
    known = {f.path: f for f in report.findings}
    for path, reason, error in results:
        if error is not None or not reason:
            continue
        old = known.get(path)
        finding = Finding(path, "program", "threat", "Сканер: " + reason, "", "quarantine")
        if old is not None:
            report.findings[report.findings.index(old)] = finding
        else:
            report.findings.append(finding)


ORDER = {"threat": 0, "suspicious": 1, "info": 2}


def sort_findings(report: DriveReport) -> None:
    report.findings.sort(key=lambda f: (ORDER.get(f.level, 3), f.path.lower()))
