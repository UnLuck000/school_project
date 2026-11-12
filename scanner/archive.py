"""Содержимое архивов при обычной проверке.

Раньше архив проверялся как один файл: хэш самого архива и правила по сжатым данным.
Известный вредонос внутри .zip находила только распаковка в анализаторе (analyzer/unpack).
Теперь при любой проверке (защита файлов, папки, диски) для ZIP-архивов и всего, что
устроено как ZIP (.jar, .docx/.xlsm, .apk...), смотрятся вложенные файлы:
  * хэши вложенных программ и скриптов сверяются с базами (в главном процессе — базы там);
  * по ним же идут правила YARA; считаются только правила вредоносов: «слабые» (PUA,
    HackTool, низкая оценка) без проверки подписи дали бы ложные срабатывания, а подпись у
    файла в архиве не проверить.

Смотрятся не все вложенные файлы, а те, что могут выполниться: программы (по началу «MZ»),
скрипты и ярлыки (по расширению), макросы Office (vbaProject.bin). Картинки, XML и классы
Java не трогаем — иначе каждый .jar проверялся бы по секунде.

Ограничения (и защита от «zip-бомб»): архив до 64 МБ, до 400 записей в оглавлении, вложенный
файл до 16 МБ, всего до 96 МБ распакованного, сжатие не сильнее 200 раз; зашифрованные
записи и архивы в архивах не раскрываются.
"""
import hashlib
import io
import os
import zipfile
from pathlib import Path

from scanner.media import EXECUTABLE_EXTS
from scanner.relations import weak_match
from scanner.yara_engine import match_details

ARCHIVE_LIMIT = 64 * 1024 * 1024
MEMBER_LIMIT = 16 * 1024 * 1024
TOTAL_LIMIT = 96 * 1024 * 1024
MAX_ENTRIES = 400
MAX_RATIO = 200
ZIP_MAGIC = (b"PK\x03\x04",)
MACRO_NAMES = ("vbaproject.bin",)
MEMBERS = "members"  # метка ответа рабочего процесса: ("members", причина, [хэши])


def is_archive(data: bytes | None, path: Path | None = None) -> bool:
    if data is not None:
        return data.startswith(ZIP_MAGIC) and len(data) <= ARCHIVE_LIMIT
    try:
        if path is None or path.stat().st_size > ARCHIVE_LIMIT:
            return False
        with open(path, "rb") as f:
            return f.read(4).startswith(ZIP_MAGIC)
    except OSError:
        return False


def _interesting(name: str) -> bool:
    low = name.lower()
    return os.path.splitext(low)[1] in EXECUTABLE_EXTS or os.path.basename(low) in MACRO_NAMES


def members(path: Path, data: bytes | None = None):
    """(имя, содержимое) вложенных файлов, которые стоит проверять."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data) if data is not None else path)
    except (zipfile.BadZipFile, OSError, ValueError):
        return
    total = 0
    with zf:
        for info in zf.infolist()[:MAX_ENTRIES]:
            if info.is_dir() or info.flag_bits & 0x1:      # папка или запись под паролем
                continue
            if not 0 < info.file_size <= MEMBER_LIMIT:
                continue
            if info.compress_size and info.file_size / info.compress_size > MAX_RATIO:
                continue                                    # похоже на «zip-бомбу»
            named = _interesting(info.filename)
            if not named and info.file_size < 64:
                continue
            try:
                with zf.open(info) as f:
                    head = f.read(2)
                    if not named and head != b"MZ":
                        continue                            # не программа и не скрипт
                    if total + info.file_size > TOTAL_LIMIT:
                        return
                    body = head + f.read(MEMBER_LIMIT)
            except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError, ValueError,
                    EOFError):
                continue
            total += len(body)
            yield info.filename, body


def inspect(path: Path, data: bytes | None, rules) -> tuple[str | None, list[tuple]]:
    """(причина по правилам YARA или None, [(имя, sha256, md5, размер)] вложенных файлов)."""
    if not is_archive(data, path):
        return None, []
    hashes = []
    for name, body in members(path, data):
        hashes.append((name, hashlib.sha256(body).hexdigest(),
                       hashlib.md5(body, usedforsecurity=False).hexdigest(), len(body)))
        if rules is not None:
            strong = [m for m in match_details(rules, Path(name), data=body) if not weak_match(m)]
            if strong:
                return ("YARA: " + ", ".join(m.rule for m in strong) +
                        f" (в архиве: {name})"), hashes
    return None, hashes


def pack(reason: str | None, path: Path, data: bytes | None, rules):
    """Ответ рабочего процесса: причина как есть, либо ("members", причина, хэши), если у
    чистого на вид архива есть вложенные файлы для сверки с базами хэшей."""
    if reason is not None:
        return reason
    found, hashes = inspect(path, data, rules)
    if found or not hashes:
        return found
    return MEMBERS, None, hashes


def resolve(analyzed, signatures, hash_verdict):
    """Ответ рабочего процесса → причина. Хэши вложенных файлов сверяются здесь: базы хэшей
    есть только в главном процессе."""
    if not (isinstance(analyzed, tuple) and analyzed and analyzed[0] == MEMBERS):
        return analyzed
    _, reason, hashes = analyzed
    if reason:
        return reason
    for name, sha256, md5, size in hashes:
        verdict = hash_verdict(size, sha256, md5, signatures)
        if verdict:
            return f"{verdict} (в архиве: {name})"
    return None
