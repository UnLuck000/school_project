import hashlib
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import pefile

from scanner.features import entropy
from scanner.heuristics import API_GROUPS, PEReport, analyze_pe, get_threshold
from scanner.signature import SignatureInfo, inspect_signature
from scanner.yara_engine import MAX_FILE_SIZE, match_file

HEAD_LIMIT = 16 * 1024 * 1024  # сколько начала файла держим в памяти (энтропия, строки)
STRINGS_LIMIT = 8 * 1024 * 1024  # в какой части файла ищем строки
MAX_STRINGS = 30000
MAX_STRING_LEN = 400
SECTION_ENTROPY_LIMIT = 4 * 1024 * 1024
SYSTEM_ROOT = os.environ.get("SystemRoot", r"C:\Windows")

# сигнатура начала файла, идентификатор типа, название
MAGIC = [
    (b"MZ", "pe", "Исполняемый файл Windows (PE)"),
    (b"%PDF", "pdf", "PDF-документ"),
    (b"PK\x03\x04", "zip", "ZIP-контейнер (также docx, xlsx, jar, apk)"),
    (b"7z\xbc\xaf\x27\x1c", "7z", "Архив 7-Zip"),
    (b"Rar!\x1a\x07", "rar", "Архив RAR"),
    (b"\x7fELF", "elf", "Исполняемый файл Linux (ELF)"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole", "Документ Office старого формата (OLE)"),
    (b"\x89PNG\r\n\x1a\n", "png", "Изображение PNG"),
    (b"\xff\xd8\xff", "jpeg", "Изображение JPEG"),
    (b"GIF8", "gif", "Изображение GIF"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "lnk", "Ярлык Windows (LNK)"),
    (b"\x1f\x8b", "gzip", "Архив GZIP"),
]
EXTENSIONS = {
    "pe": {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".drv", ".efi"},
    "pdf": {".pdf"},
    "zip": {".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".odt", ".ods", ".xpi",
            ".nupkg", ".whl"},
    "7z": {".7z"}, "rar": {".rar"}, "gzip": {".gz", ".tgz"},
    "elf": {"", ".so", ".bin", ".elf"},
    "ole": {".doc", ".xls", ".ppt", ".msi", ".msg"},
    "png": {".png"}, "jpeg": {".jpg", ".jpeg"}, "gif": {".gif"}, "lnk": {".lnk"},
}
SCRIPT_EXTS = {".ps1", ".vbs", ".vbe", ".js", ".jse", ".bat", ".cmd", ".hta", ".wsf", ".py", ".sh"}
EXEC_EXTS = {".exe", ".scr", ".com", ".bat", ".cmd", ".js", ".vbs", ".lnk", ".hta", ".ps1", ".msi"}
DOC_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".jpeg", ".png",
            ".mp3", ".mp4", ".zip", ".rar"}

MACHINES = {0x14C: "x86 (32 бита)", 0x8664: "x64 (64 бита)", 0x1C0: "ARM", 0xAA64: "ARM64"}
SUBSYSTEMS = {1: "Native (драйвер)", 2: "Windows GUI", 3: "Windows, консоль",
              9: "Windows CE", 10: "EFI"}

# функции, которые используют правила эвристики
SUSPICIOUS_APIS = {name for _, needs, _ in API_GROUPS for group in needs for name in group}

ASCII_RE = re.compile(rb"[\x20-\x7e]{5,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")
INTERESTING = re.compile(
    r"https?://|ftp://|\b\d{1,3}(?:\.\d{1,3}){3}\b|HKEY_|\\CurrentVersion\\Run|powershell|"
    r"cmd\.exe|\.onion|CreateRemoteThread|VirtualAlloc|WriteProcessMemory|password|passwd|"
    r"token|wallet|bitcoin|\.ps1|-enc\b", re.IGNORECASE)


def human_size(n: int) -> str:
    size = float(n)
    for unit in ("байт", "КБ", "МБ", "ГБ"):
        if size < 1024 or unit == "ГБ":
            return f"{size:.0f} {unit}" if unit == "байт" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} байт"


def is_windows_path(path: Path) -> bool:
    return os.path.normcase(str(path)).startswith(os.path.normcase(SYSTEM_ROOT))


def is_suspicious_api(name: str) -> bool:
    n = name.lower()
    return n in SUSPICIOUS_APIS or (n[-1:] in ("a", "w") and n[:-1] in SUSPICIOUS_APIS)


def _fmt_time(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, OverflowError, ValueError):
        return "?"


# ---------- данные о PE ----------
@dataclass
class PEDetails:
    header: list[tuple[str, str]] = field(default_factory=list)
    sections: list[dict] = field(default_factory=list)
    imports: dict[str, list[str]] = field(default_factory=dict)
    exports: list[str] = field(default_factory=list)


def _section_flags(characteristics: int) -> str:
    parts = []
    if characteristics & 0x40000000:
        parts.append("R")
    if characteristics & 0x80000000:
        parts.append("W")
    if characteristics & 0x20000000:
        parts.append("X")
    return "/".join(parts)


def read_pe(path: Path, file_size: int) -> PEDetails | None:
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except Exception:
        return None
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        header, optional = pe.FILE_HEADER, pe.OPTIONAL_HEADER
        details = PEDetails()

        kind = "DLL" if pe.is_dll() else ("драйвер (SYS)" if pe.is_driver() else "программа (EXE)")
        details.header = [
            ("Тип", kind),
            ("Архитектура", MACHINES.get(header.Machine, hex(header.Machine))),
            ("Подсистема", SUBSYSTEMS.get(optional.Subsystem, str(optional.Subsystem))),
            ("Время компиляции (из заголовка)", _fmt_time(header.TimeDateStamp)),
            ("Точка входа (RVA)", hex(optional.AddressOfEntryPoint)),
            ("Базовый адрес", hex(optional.ImageBase)),
            ("Размер образа", f"{optional.SizeOfImage:,} байт".replace(",", " ")),
            ("Секций", str(header.NumberOfSections)),
        ]
        if header.TimeDateStamp == 0 or header.TimeDateStamp > time.time() + 86400:
            details.header.append(
                ("Замечание", "Время компиляции нулевое или в будущем: "
                              "заголовок мог быть подделан или сборка воспроизводимая"))
        overlay = pe.get_overlay_data_start_offset()
        if overlay and file_size > overlay:
            details.header.append(("Данные после конца PE (overlay)",
                                   f"{file_size - overlay:,} байт".replace(",", " ")))
        imphash = pe.get_imphash()
        if imphash:
            details.header.append(("Imphash", imphash))

        with path.open("rb") as f:
            for s in pe.sections:
                raw = s.SizeOfRawData
                value = 0.0
                if raw >= 1024:
                    f.seek(s.PointerToRawData)
                    value = entropy(f.read(min(raw, SECTION_ENTROPY_LIMIT)))
                details.sections.append({
                    "name": s.Name.rstrip(b"\x00").decode("latin-1"),
                    "virtual": s.Misc_VirtualSize, "raw": raw,
                    "entropy": value, "flags": _section_flags(s.Characteristics)})

        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            functions = []
            for imp in entry.imports[:500]:
                functions.append(imp.name.decode("ascii", "ignore") if imp.name
                                 else f"#{imp.ordinal}")
            details.imports[entry.dll.decode("ascii", "ignore")] = functions

        exports = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if exports is not None:
            for sym in exports.symbols[:2000]:
                details.exports.append(sym.name.decode("ascii", "ignore") if sym.name
                                       else f"#{sym.ordinal}")

        if any(dll.lower() == "mscoree.dll" for dll in details.imports):
            details.header.insert(1, (".NET", "Да (управляемый код)"))
        return details
    except Exception:
        return None
    finally:
        pe.close()


# ---------- тип файла, имя, строки ----------
def detect_type(head: bytes, ext: str) -> tuple[str, str]:
    for magic, key, title in MAGIC:
        if head.startswith(magic):
            return key, title
    sample = head[:4096]
    if not sample:
        return "empty", "Пустой файл"
    if b"\x00" not in sample:
        printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b <= 126 or b >= 128)
        if printable / len(sample) > 0.95:
            return ("script", "Скрипт") if ext in SCRIPT_EXTS else ("text", "Текстовый файл")
    return "unknown", "Неизвестный формат (двоичные данные)"


def _name_notes(name: str, ext: str, key: str, title: str) -> tuple[list[str], bool]:
    """Предупреждения об имени и расширении. Второе значение: признак маскировки."""
    notes: list[str] = []
    masquerade = False
    if "\u202e" in name:
        notes.append("В имени есть символ U+202E (разворот текста): им скрывают настоящее расширение")
        masquerade = True
    parts = name.lower().split(".")
    if len(parts) >= 3 and f".{parts[-1]}" in EXEC_EXTS and f".{parts[-2]}" in DOC_EXTS:
        notes.append(f"Двойное расширение «.{parts[-2]}.{parts[-1]}»: "
                     "исполняемый файл выдаёт себя за документ")
        masquerade = True
    expected = EXTENSIONS.get(key)
    if expected is not None and ext not in expected:
        shown = ext or "нет"
        if key == "pe":
            notes.append(f"Файл является исполняемым (PE), но расширение «{shown}»: "
                         "так маскируют программы под документы и картинки")
            masquerade = True
        else:
            notes.append(f"Расширение «{shown}» не соответствует содержимому ({title})")
    return notes, masquerade


def extract_strings(data: bytes) -> list[tuple[int, str, str]]:
    """[(смещение, вид, строка)] — ASCII и UTF-16 длиной от 5 символов."""
    found: list[tuple[int, str, str]] = []
    for m in ASCII_RE.finditer(data):
        found.append((m.start(), "ASCII", m.group().decode("ascii")[:MAX_STRING_LEN]))
        if len(found) >= MAX_STRINGS:
            break
    if len(found) < MAX_STRINGS:
        for m in UTF16_RE.finditer(data):
            found.append((m.start(), "UTF-16", m.group().decode("utf-16le")[:MAX_STRING_LEN]))
            if len(found) >= MAX_STRINGS:
                break
    found.sort(key=lambda s: s[0])
    return found


def _hash_and_head(path: Path) -> tuple[str, str, str, bytes]:
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    head = bytearray()
    with path.open("rb") as f:
        while block := f.read(1 << 20):
            md5.update(block)
            sha1.update(block)
            sha256.update(block)
            if len(head) < HEAD_LIMIT:
                head += block[:HEAD_LIMIT - len(head)]
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest(), bytes(head)


# ---------- итоговый отчёт ----------
@dataclass
class FileReport:
    path: str
    name: str
    ext: str
    size: int
    created: str
    modified: str
    accessed: str
    type_key: str
    file_type: str
    notes: list[str]
    md5: str
    sha1: str
    sha256: str
    entropy: float
    signature: SignatureInfo
    whitelisted: bool
    hash_match: bool
    hash_db_size: int
    rules_ok: bool
    yara_skipped: bool
    yara: list[str]
    heuristics: PEReport
    threshold: int
    pe: PEDetails | None
    strings: list[tuple[int, str, str]]
    verdict: str
    level: str  # threat | suspicious | clean | info


def build_report(path: Path, signatures: set[str], rules, whitelist: set[str]) -> FileReport:
    """Собирает все сведения о файле. Медленная функция: вызывать не из GUI-потока.
    Все слои проверки считаются независимо, чтобы было видно результат каждого."""
    stat = path.stat()
    md5, sha1, sha256, head = _hash_and_head(path)
    ext = path.suffix.lower()
    key, title = detect_type(head, ext)
    notes, masquerade = _name_notes(path.name, ext, key, title)

    signature = inspect_signature(path)
    whitelisted = sha256 in whitelist
    hash_match = sha256 in signatures
    yara_skipped = stat.st_size > MAX_FILE_SIZE
    yara_names = [] if (rules is None or yara_skipped) else match_file(rules, path)
    heuristics = analyze_pe(path)
    threshold = get_threshold()
    pe = read_pe(path, stat.st_size) if key == "pe" else None

    if whitelisted:
        verdict, level = "В белом списке: файл восстановлен пользователем, проверки пропускаются", "info"
    elif hash_match:
        verdict, level = "Угроза: хэш файла найден в базе сигнатур", "threat"
    elif yara_names:
        verdict, level = "Угроза: сработали правила YARA: " + ", ".join(yara_names), "threat"
    elif heuristics.score >= threshold:
        if signature.status == "valid":
            verdict = (f"Эвристика сработала ({heuristics.score} баллов), но подпись действительна: "
                       "файл пропускается")
            level = "info"
        else:
            verdict = (f"Подозрительно: эвристика PE, {heuristics.score} баллов "
                       f"при пороге {threshold}")
            level = "suspicious"
    else:
        verdict, level = "Угроз не найдено", "clean"
    if level == "clean" and masquerade:
        verdict, level = "Подозрительно: " + notes[0], "suspicious"

    return FileReport(
        path=str(path), name=path.name, ext=ext, size=stat.st_size,
        created=_fmt_time(stat.st_ctime), modified=_fmt_time(stat.st_mtime),
        accessed=_fmt_time(stat.st_atime), type_key=key, file_type=title, notes=notes,
        md5=md5, sha1=sha1, sha256=sha256, entropy=entropy(head),
        signature=signature, whitelisted=whitelisted, hash_match=hash_match,
        hash_db_size=len(signatures), rules_ok=rules is not None, yara_skipped=yara_skipped,
        yara=yara_names, heuristics=heuristics, threshold=threshold, pe=pe,
        strings=extract_strings(head[:STRINGS_LIMIT]), verdict=verdict, level=level)
