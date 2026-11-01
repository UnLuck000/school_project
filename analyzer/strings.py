"""Извлечение строк из всего файла (до 256 МБ через mmap), категории и экспорт."""
import csv
import mmap
import re
from dataclasses import dataclass
from pathlib import Path

MAX_FILE = 256 * 1024 * 1024
MAX_STRINGS = 500_000
MAX_LEN = 2000

# (идентификатор, название, шаблон). Строка получает первую подходящую категорию.
CATEGORIES = [(cid, title, re.compile(p, re.IGNORECASE)) for cid, title, p in [
    ("url", "Адреса (URL)", r"(?:https?|ftp|wss?)://|\.onion\b"),
    ("ip", "IP-адреса", r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"),
    ("email", "Почта", r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b"),
    ("registry", "Реестр", r"HKEY_|HKLM\\|HKCU\\|\\CurrentVersion\\|SOFTWARE\\|SYSTEM\\CurrentControlSet"),
    ("command", "Команды и скрипты",
     r"powershell|cmd(?:\.exe)?\s*/c|\b(?:-enc|iex|invoke-expression|downloadstring)\b|"
     r"schtasks|vssadmin|bcdedit|wmic|certutil|bitsadmin|rundll32|regsvr32|mshta"),
    ("crypto", "Криптовалюта и пароли",
     r"wallet|bitcoin|monero|\bbtc\b|password|passwd|\btoken\b|\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b"),
    ("api", "Функции WinAPI",
     r"^(?:Nt|Zw|Rtl|Virtual|Create|Open|Write|Read|Reg|Internet|Http|Win[A-Z]|Load|Get|Set|"
     r"Crypt|Shell|Find|Process32|Module32|Adjust|Lookup|Is[A-Z]|Url)\w{2,}(?:A|W|Ex|ExA|ExW)?$"),
    ("dll", "Библиотеки", r"^[\w.-]+\.(?:dll|sys|drv|ocx)$"),
    ("path", "Пути и файлы", r"[A-Za-z]:\\|\\\\|%\w+%|\.(?:exe|bat|cmd|ps1|vbs|js|scr|lnk|tmp)\b"),
    ("guid", "GUID", r"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?"),
]]
CATEGORY_TITLES = {cid: title for cid, title, _ in CATEGORIES} | {"other": "Прочее"}
INTERESTING_IDS = {"url", "ip", "email", "registry", "command", "crypto"}


@dataclass(slots=True)
class FoundString:
    offset: int
    kind: str      # ASCII | UTF-16
    text: str
    category: str


def classify(text: str) -> str:
    for cid, _, pattern in CATEGORIES:
        if pattern.search(text):
            return cid
    return "other"


def extract(path: Path, min_len: int = 5, cancel=None, progress=None) -> tuple[list[FoundString], str]:
    """(строки, пояснение). Медленная функция: вызывать не из GUI-потока."""
    size = path.stat().st_size
    if size == 0:
        return [], "Файл пустой."
    ascii_re = re.compile(rb"[\x20-\x7e\t]{%d,}" % min_len)
    utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00|[\x10-\x4f]\x04){%d,}" % min_len)  # с кириллицей
    found: list[FoundString] = []
    note = ""
    limit = min(size, MAX_FILE)
    with path.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
        for kind, regex, encoding in (("ASCII", ascii_re, "ascii"),
                                      ("UTF-16", utf16_re, "utf-16-le")):
            if progress:
                progress(f"Ищу строки {kind}...")
            for i, match in enumerate(regex.finditer(m, 0, limit)):
                if len(found) >= MAX_STRINGS:
                    note = f"Найдено больше {MAX_STRINGS:,} строк: показаны первые. "
                    break
                if i % 20000 == 0 and cancel is not None and cancel.is_set():
                    return found, "Остановлено."
                text = match.group().decode(encoding, "replace")[:MAX_LEN]
                found.append(FoundString(match.start(), kind, text, classify(text)))
    found.sort(key=lambda s: s.offset)
    if size > MAX_FILE:
        note += f"Просмотрены первые 256 МБ из {size / 1048576:.0f} МБ. "
    return found, (note + f"Строк: {len(found):,}, минимальная длина {min_len}.").replace(",", " ")


def export(strings: list[FoundString], target: Path) -> None:
    """CSV (по расширению .csv) или простой текст: одна строка на строчку."""
    if target.suffix.lower() == ".csv":
        with target.open("w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f, delimiter=";")
            writer.writerow(["Смещение", "Вид", "Категория", "Строка"])
            for s in strings:
                writer.writerow([f"0x{s.offset:08X}", s.kind, CATEGORY_TITLES[s.category], s.text])
    else:
        with target.open("w", encoding="utf-8") as f:
            for s in strings:
                f.write(s.text.replace("\r", " ").replace("\n", " ") + "\n")
