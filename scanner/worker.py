"""Рабочий процесс проверки файлов (запускает scanner.pool).

Отдельный процесс нужен из-за GIL: разбор PE (pefile) и обвязка вокруг YARA — это
Python-код, и в потоках главного процесса он отнимал время у интерфейса. Здесь
интерфейса нет, а Windows раскладывает процессы по ядрам независимо.

Обмен через stdin/stdout: кадр = длина (4 байта) + pickle.
Запрос: (номер, вид, путь, параметры). Вид: "hash" — хэши, "analyze" — YARA, эвристика,
подпись и связи, "full" — всё вместе. Ответ: (номер, True, результат) или
(номер, False, (errno, текст)).
"""
import os
import io
import pickle
import struct
import sys
from pathlib import Path

HEADER = struct.Struct("<I")


MAX_FRAME = 64 * 1024 * 1024  # кадр — путь, настройки или вердикт с хэшами: десятки КБ


class _PlainUnpickler(pickle.Unpickler):
    """Кадры несут только простые значения (кортежи, строки, числа, словари). Рабочий
    процесс разбирает чужие файлы (YARA, разбор PE на C++): если ошибка в них отдаст
    процесс вредоносному файлу, обычный pickle позволил бы ему выполнить код в главном
    процессе — в службе с правами системы. Любой объект класса — отказ."""

    def find_class(self, module, name):
        raise pickle.UnpicklingError(f"в кадре объект {module}.{name}")


def read_frame(stream):
    """Кадр или None: канал закрыт, кадр оборван, слишком велик или не из простых значений
    (для главного процесса всё это — «рабочий процесс завершился»)."""
    head = stream.read(HEADER.size)
    if len(head) < HEADER.size:
        return None
    (size,) = HEADER.unpack(head)
    if size > MAX_FRAME:
        return None
    body = stream.read(size)
    if len(body) < size:
        return None
    try:
        return _PlainUnpickler(io.BytesIO(body)).load()
    except Exception:  # noqa: BLE001 — испорченный кадр: любая ошибка разбора
        return None


def write_frame(stream, obj) -> None:
    body = pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL)
    stream.write(HEADER.pack(len(body)) + body)
    stream.flush()


def _handle(kind: str, path: Path, options: dict, rules):
    from scanner.engine import analyze, read_small
    from scanner.hashing import data_hashes, file_hashes
    if kind == "hash":
        return file_hashes(path)
    data = read_small(path, path.stat().st_size)  # до 32 МБ: одно чтение на все слои
    reason = analyze(path, rules, options.get("heuristics", True), options.get("threshold"),
                     options.get("revocation"), data=data)
    from scanner import archive
    reason = archive.pack(reason, path, data, rules)  # вложенные файлы ZIP (scanner/archive.py)
    if kind == "analyze":
        return reason
    return (data_hashes(data) if data is not None else file_hashes(path)), reason


def main() -> None:
    inp, out = sys.stdin.buffer, sys.stdout.buffer
    sys.stdout = sys.stderr  # случайный print не должен портить канал
    if "--background" in sys.argv and sys.platform == "win32":
        import ctypes
        PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000
        kernel32 = ctypes.WinDLL("kernel32")
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        kernel32.SetPriorityClass.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        kernel32.SetPriorityClass(kernel32.GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN)
    from processmanager.memscan import get_rules
    rules = get_rules("all")
    write_frame(out, ("ready", os.getpid()))
    while True:
        request = read_frame(inp)
        if request is None:
            return  # главный процесс закрыл канал
        number, kind, path, options = request
        try:
            write_frame(out, (number, True, _handle(kind, Path(path), options, rules)))
        except OSError as e:
            write_frame(out, (number, False, (e.errno, e.strerror or str(e))))
        except Exception as e:  # битый файл не должен ронять процесс
            write_frame(out, (number, False, (None, f"{type(e).__name__}: {e}")))


if __name__ == "__main__":
    main()
