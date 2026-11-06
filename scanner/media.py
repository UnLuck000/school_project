"""Распознавание видео и аудио по содержимому — до хэшей и YARA.

Замер на видео 1,6 ГБ: хэши читают весь файл (около 4 с, на HDD — десятки секунд),
на файле 90 МБ YARA добавляет ещё 0,7 с. Ни то, ни другое для настоящего видео не нужно:
в базах вредоносов нет роликов, правила YARA ищут код. Поэтому файл, который оказался
обычным медиафайлом, проверяется по-другому (engine.check_file, pool.check_files):
до MEDIA_HASH_LIMIT — только хэши, крупнее — ничего не читается целиком.

«Обычный медиафайл» — это не расширение (вирус легко назвать video.mp4), а содержимое:
1. сигнатура формата в начале файла (MP4/MOV, MKV/WebM, AVI, WAV, MP3, FLAC, OGG, WMV,
   MPEG-TS/PS);
2. для MP4/MOV и AVI/WAV — структура: блоки контейнера идут подряд и заканчиваются
   ровно в конце файла, то есть в конец ничего не дописано;
3. в первых и последних PE_WINDOW байтах нет исполняемого файла (MZ ... PE\\0\\0);
4. расширение не исполняемое (у .exe с заголовком MP4 — полная проверка).
Не прошёл хоть одно условие — обычная полная проверка.
"""
import struct
from pathlib import Path

MEDIA_HASH_LIMIT = 64 * 1024 * 1024  # крупнее — без хэшей и YARA
PE_WINDOW = 4 * 1024 * 1024          # сколько байт с начала и с конца искать вложенный PE
MAX_BOXES = 100_000

EXECUTABLE_EXTS = {".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".sys", ".msi", ".bat",
                   ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".lnk",
                   ".jar"}
ASF_GUID = bytes.fromhex("3026B2758E66CF11A6D900AA0062CE6C")


def sniff(head: bytes) -> str:
    """Формат по первым байтам: iso, riff, mkv, mp3, flac, ogg, asf, mpeg или ""."""
    if len(head) >= 12 and head[4:8] == b"ftyp":
        return "iso"            # MP4, MOV, M4A, 3GP
    if head[:4] == b"RIFF" and head[8:12] in (b"AVI ", b"WAVE"):
        return "riff"
    if head[:4] == b"\x1a\x45\xdf\xa3":
        return "mkv"            # Matroska, WebM
    if head[:3] == b"ID3" or (len(head) > 1 and head[0] == 0xFF and head[1] & 0xE0 == 0xE0):
        return "mp3"
    if head[:4] == b"fLaC":
        return "flac"
    if head[:4] == b"OggS":
        return "ogg"
    if head[:16] == ASF_GUID:
        return "asf"            # WMV, WMA
    if head[:4] == b"\x00\x00\x01\xba" or (len(head) > 376 and head[0] == head[188] ==
                                           head[376] == 0x47):
        return "mpeg"
    return ""


def has_pe(data: bytes) -> bool:
    """Есть ли внутри исполняемый файл Windows: «MZ» и по смещению e_lfanew — «PE\\0\\0»."""
    pos = data.find(b"MZ")
    while pos != -1:
        if pos + 0x40 <= len(data):
            lfanew = struct.unpack_from("<I", data, pos + 0x3C)[0]
            if 0x40 <= lfanew <= 4096 and data[pos + lfanew:pos + lfanew + 4] == b"PE\0\0":
                return True
        pos = data.find(b"MZ", pos + 1)
    return False


def _iso_ok(f, size: int) -> bool:
    """Блоки MP4/MOV (размер + тип) идут подряд до самого конца файла."""
    pos = boxes = 0
    while pos < size:
        f.seek(pos)
        head = f.read(16)
        if len(head) < 8:
            return False
        length, kind = struct.unpack_from(">I4s", head)
        if not all(32 <= c < 127 for c in kind):
            return False
        if length == 1 and len(head) == 16:
            length = struct.unpack_from(">Q", head, 8)[0]
        elif length == 0:
            length = size - pos  # последний блок «до конца файла»
        if length < 8:
            return False
        pos += length
        boxes += 1
        if boxes > MAX_BOXES:
            return False
    return pos == size


def _riff_ok(f, size: int) -> bool:
    """AVI/WAV: один или несколько блоков RIFF (AVI больше 1 ГБ — RIFF AVIX) до конца файла."""
    pos = 0
    while pos < size:
        f.seek(pos)
        head = f.read(12)
        if len(head) < 12 or head[:4] != b"RIFF":
            return False
        length = struct.unpack_from("<I", head, 4)[0]
        pos += 8 + length + (length & 1)
    return pos == size


def plain_media(path: Path, size: int | None = None) -> str:
    """Формат, если файл — обычный медиафайл без вложенного кода, иначе ""."""
    path = Path(path)
    if path.suffix.lower() in EXECUTABLE_EXTS:
        return ""
    try:
        size = path.stat().st_size if size is None else size
        with path.open("rb") as f:
            kind = sniff(f.read(512))  # для не-медиафайлов читается только это
            if not kind:
                return ""
            f.seek(0)
            if has_pe(f.read(min(size, PE_WINDOW))):
                return ""
            if size > PE_WINDOW:
                f.seek(max(PE_WINDOW, size - PE_WINDOW))
                if has_pe(f.read()):
                    return ""
            if kind == "iso" and not _iso_ok(f, size):
                return ""
            if kind == "riff" and not _riff_ok(f, size):
                return ""
    except OSError:
        return ""
    return kind
