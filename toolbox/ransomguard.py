"""Шифровальщик по поведению: много документов за минуту превратились в «шум».

Ловушки (toolbox/decoys.py) срабатывают, только если шифровальщик дошёл до их папки. Здесь —
второй признак, по самим файлам пользователя. Защита файлов и так видит каждый изменённый
файл; для документов, фото и архивов проверяется:
  * начало файла больше не соответствует расширению (у .docx нет «PK», у .jpg — FF D8,
    у .pdf — «%PDF»...), либо к документу дописано новое расширение (отчёт.docx.locked);
  * содержимое выглядит случайным: энтропия первых 64 КБ выше 7,5 бита на байт.
Один такой файл ничего не значит (битая загрузка, свой зашифрованный архив). Тревога — когда
за WINDOW_SEC секунд их набралось THRESHOLD в разных файлах: так ведёт себя только программа,
которая переписывает документы подряд.

Виновника ищет тот же механизм, что у ловушек (DecoyWatcher.find_culprit: неподписанный
процесс с наибольшим объёмом записи), окно — toolbox.windows.decoy_alarm.
"""
import os
import time
from collections import OrderedDict

from scanner.features import entropy

SAMPLE = 64 * 1024
ENTROPY_LIMIT = 7.5
THRESHOLD = 10          # столько «зашифрованных» файлов...
WINDOW_SEC = 60.0       # ...за столько секунд
QUIET_SEC = 300.0       # после тревоги — пауза: одно окно, а не десять

ZIP, OLE = (b"PK\x03\x04", b"PK\x05\x06"), (b"\xd0\xcf\x11\xe0",)
# расширение -> с чего должен начинаться файл (пусто — текст: проверяется только энтропия)
MAGIC = {
    ".docx": ZIP, ".xlsx": ZIP, ".pptx": ZIP, ".odt": ZIP, ".ods": ZIP, ".odp": ZIP,
    ".zip": ZIP, ".doc": OLE, ".xls": OLE, ".ppt": OLE, ".pdf": (b"%PDF",),
    ".jpg": (b"\xff\xd8\xff",), ".jpeg": (b"\xff\xd8\xff",), ".png": (b"\x89PNG",),
    ".gif": (b"GIF8",), ".bmp": (b"BM",), ".rtf": (b"{\\rtf",),
    ".7z": (b"7z\xbc\xaf",), ".rar": (b"Rar!",), ".psd": (b"8BPS",),
    ".txt": (), ".csv": (), ".md": (), ".json": (), ".xml": (), ".html": (), ".sql": (),
    ".py": (), ".cs": (), ".cpp": (), ".java": (), ".js": (), ".ini": (),
}


def document_ext(name: str) -> tuple[str, bool]:
    """(расширение документа, дописано ли к нему ещё одно). ("", False) — не документ."""
    low = name.lower()
    stem, ext = os.path.splitext(low)
    if ext in MAGIC:
        return ext, False
    inner = os.path.splitext(stem)[1]
    if inner in MAGIC and ext and len(ext) <= 12:
        return inner, True  # отчёт.docx.locked
    return "", False


def looks_encrypted(path, head: bytes | None = None) -> bool:
    """Документ, содержимое которого похоже на зашифрованное."""
    ext, renamed = document_ext(os.path.basename(str(path)))
    if not ext:
        return False
    if head is None:
        try:
            with open(path, "rb") as f:
                head = f.read(SAMPLE)
        except OSError:
            return False
    if len(head) < 2048:
        return False  # на коротком отрезке энтропия ничего не говорит
    magic = MAGIC[ext]
    if magic and head.startswith(magic) and not renamed:
        return False  # формат цел
    if magic and head.startswith(magic) and renamed:
        return False  # файл просто переименовали — содержимое прежнее
    return entropy(head) > ENTROPY_LIMIT


class BurstDetector:
    """Счётчик «зашифрованных» файлов в скользящем окне."""

    def __init__(self, threshold: int = THRESHOLD, window: float = WINDOW_SEC):
        self.threshold, self.window = threshold, window
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._quiet_until = 0.0

    def feed(self, path, now: float | None = None, head: bytes | None = None) -> list[str]:
        """Файл изменился. Возвращает список файлов, если набралась тревога, иначе []."""
        now = time.monotonic() if now is None else now
        if not looks_encrypted(path, head):
            return []
        key = os.path.normcase(str(path))
        self._seen.pop(key, None)
        self._seen[key] = now
        while self._seen and now - next(iter(self._seen.values())) > self.window:
            self._seen.popitem(last=False)
        if len(self._seen) < self.threshold or now < self._quiet_until:
            return []
        self._quiet_until = now + QUIET_SEC
        found = list(self._seen)
        self._seen.clear()
        return found
