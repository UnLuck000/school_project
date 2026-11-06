"""Связь неподписанной библиотеки с подписанной программой из той же папки.

Многие программы подписывают только главный файл (или драйвер), а их библиотеки идут без
подписи. Пример: WinDivert.dll без подписи, а драйвер WinDivert64.sys подписан, и библиотека
ссылается на него по имени (строка UTF-16 внутри DLL). Связь ищется так:
  - подписанный файл из той же папки импортирует эту библиотеку (таблица импорта PE,
    в том числе отложенный импорт) или упоминает её имя (LoadLibrary по строке);
  - сама библиотека импортирует подписанный файл или упоминает его имя (драйвер,
    который она устанавливает).

Связь снимает только слабые срабатывания (эвристика, правила класса PUA, HackTool,
Suspicious, правила с низкой оценкой). Совпадение по хэшу и правила, описывающие
конкретное вредоносное ПО, остаются угрозой: подмена библиотеки рядом с подписанной
программой (DLL sideloading) — известный приём вредоносов.
"""
import os
import re
import threading
from pathlib import Path

import pefile

from scanner.signature import VALID, inspect_signature

PE_EXTS = (".exe", ".dll", ".sys", ".ocx", ".cpl", ".drv", ".scr", ".efi")
MAX_SIBLINGS = 300            # в папках вроде System32 строки не ищем: слишком много файлов
MAX_READ = 32 * 1024 * 1024   # сколько байт файла просматривается в поиске имён
WEAK_SCORE = 70               # оценка правила (meta score) ниже этой — слабое срабатывание
WEAK_RE = re.compile(r"pua|hktl|hacktool|susp|riskware|generic|grayware|potentially",
                     re.IGNORECASE)

_lock = threading.Lock()
_signed: dict[tuple[str, int, int], bool] = {}  # (путь, размер, mtime) -> подпись действительна


def weak_match(match) -> bool:
    """Слабое ли срабатывание правила YARA: класс «потенциально нежелательное» или
    низкая оценка в метаданных. Такое снимается связью с подписанной программой."""
    meta = getattr(match, "meta", None) or {}
    score = meta.get("score")
    if isinstance(score, int) and score < WEAK_SCORE:
        return True
    text = " ".join(str(x) for x in (match.rule, match.namespace,
                                     meta.get("category", ""), meta.get("threat_name", "")))
    return bool(WEAK_RE.search(text))


def _is_signed(path: Path) -> bool:
    try:
        st = path.stat()
    except OSError:
        return False
    key = (os.path.normcase(str(path)), st.st_size, st.st_mtime_ns)
    with _lock:
        if key in _signed:
            return _signed[key]
    valid = inspect_signature(path).status == VALID
    with _lock:
        _signed[key] = valid
    return valid


def imports(path: Path) -> set[str]:
    """Имена библиотек из таблицы импорта (обычной и отложенной), в нижнем регистре."""
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except (pefile.PEFormatError, OSError):
        return set()
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"]])
        names = set()
        for attr in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
            for entry in getattr(pe, attr, []):
                if entry.dll:
                    names.add(entry.dll.decode("ascii", "replace").lower())
        return names
    except Exception:  # pefile на битых файлах бросает что угодно
        return set()
    finally:
        pe.close()


def _read(path: Path) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(MAX_READ).lower()
    except OSError:
        return b""


def mentions(data: bytes, name: str) -> bool:
    """Есть ли имя файла в данных (ASCII или UTF-16LE, без учёта регистра).
    data уже в нижнем регистре."""
    low = name.lower()
    return low.encode("ascii", "ignore") in data or low.encode("utf-16-le") in data


def _siblings(path: Path) -> list[Path]:
    try:
        entries = list(os.scandir(path.parent))
    except OSError:
        return []
    own = path.name.lower()
    return [Path(e.path) for e in entries
            if e.name.lower() != own and e.name.lower().endswith(PE_EXTS) and e.is_file()]


def signed_partner(path: Path) -> tuple[str, str] | None:
    """Подписанный файл из той же папки, с которым связан path.
    Возвращает (имя файла, как связаны) или None."""
    siblings = _siblings(path)
    if not siblings:
        return None
    by_name = {p.name.lower(): p for p in siblings}
    own_imports = imports(path)
    for name in sorted(own_imports & by_name.keys()):  # сама импортирует подписанный файл
        if _is_signed(by_name[name]):
            return by_name[name].name, f"импортирует {by_name[name].name}"
    if len(siblings) > MAX_SIBLINGS:
        return None
    data = _read(path)
    for p in siblings:  # сама ссылается на подписанный файл (например, на свой драйвер)
        if mentions(data, p.name) and _is_signed(p):
            return p.name, f"ссылается на {p.name}"
    own = path.name
    for p in siblings:  # подписанный файл загружает эту библиотеку
        if not _is_signed(p):
            continue
        if own.lower() in imports(p):
            return p.name, f"{p.name} импортирует этот файл"
        if mentions(_read(p), own):
            return p.name, f"{p.name} ссылается на этот файл"
    return None
