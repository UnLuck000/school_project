"""Проверка памяти процессов правилами YARA.

Быстрый режим (по умолчанию) проверяет только приватную память процесса (кучи, стеки,
внедрённый и распакованный код) и модули с правами RWX. Отображённые файлы и обычные
модули (DLL) занимают бо́льшую часть памяти, но лежат на диске и проверяются сканером
файлов: их чтение и было главной причиной долгой проверки. Память читает модуль на C++
(scanner/_native, отпускает GIL), без него работает запасной вариант на ctypes.
Полный режим (вся память, как rules.match(pid=...)) включается флажком в диспетчере.
"""
import importlib
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import yara

from scanner import overrides
from scanner.yara_engine import load_rules

def _load_native_reader() -> Callable[..., list] | None:
    """read_regions из нативного модуля scanner/_native (C++) или None, если он не собран."""
    try:
        native = importlib.import_module("scanner._native")
    except ImportError:
        return None
    reader = getattr(native, "read_regions", None)
    return reader if callable(reader) else None


_read_native: Callable[..., list] | None = _load_native_reader()

RULES_ROOT = Path(__file__).resolve().parent.parent / "signatures" / "rules"
MEMORY_RULES_DIR = RULES_ROOT / "memory"
SCAN_TIMEOUT = 30  # секунд на один процесс
MAX_REGION = 16 * 1024 * 1024    # регионы больше (огромные кучи браузеров) пропускаются
MAX_TOTAL = 128 * 1024 * 1024    # не больше стольких байт с одного процесса
PORTION = 16 * 1024 * 1024       # читается и проверяется порциями: меньше пик памяти
BATCH = 4 * 1024 * 1024          # мелкие регионы склеиваются в блоки: меньше вызовов YARA
GAP = b"\0" * 256                # разделитель склеенных регионов

_cache: dict[str, object] = {}
_lock = threading.Lock()


ELASTIC_DIR = RULES_ROOT / "community" / "elastic"  # сигнатуры Elastic написаны для памяти
# правила, которые для памяти не нужны и при этом медленнее всех: уязвимые драйверы ищутся
# среди файлов .sys, веб-шеллы — среди страниц PHP/ASP/JSP на диске
NOT_FOR_MEMORY = r"vuln_?driver|webshell"


def get_rules(kind: str):
    """kind: 'all' — все правила проекта (для файлов);
    'memory' — правила для памяти (свои и Elastic), быстро;
    'memory_all' — все правила, кроме бесполезных для памяти (NOT_FOR_MEMORY).
    Компилируются один раз за запуск программы (и кэшируются на диске). Может вернуть None."""
    with _lock:
        if kind not in _cache:
            if kind == "memory":
                rules, _ = load_rules([MEMORY_RULES_DIR, ELASTIC_DIR], skip=NOT_FOR_MEMORY,
                                      purpose="memory")
            elif kind == "memory_all":
                rules, _ = load_rules(RULES_ROOT, skip=NOT_FOR_MEMORY, purpose="memory")
            else:
                rules, _ = load_rules(RULES_ROOT)
            _cache[kind] = rules
        return _cache[kind]


def shared_rules(rules_dir: Path):
    """Правила для проверки файлов. Для папки signatures/rules — общая копия на всю
    программу (каждая копия 10 тыс. правил занимает около 40 МБ памяти)."""
    if Path(rules_dir).resolve() == RULES_ROOT.resolve():
        return get_rules("all")
    rules, _ = load_rules(Path(rules_dir))
    return rules


def reset_cache() -> None:
    """Вызывать после обновления правил, чтобы они перекомпилировались."""
    with _lock:
        _cache.clear()


def backend() -> str:
    return "native (C++)" if _read_native is not None else "python (ctypes)"


@dataclass
class MemResult:
    status: str  # clean | match | signed | denied | timeout | error
    # signed: совпадение в процессе с действительной подписью — скорее ложное
    matches: list[str] = field(default_factory=list)
    message: str = ""
    scanned: int = 0  # байт проверено

    def text(self) -> str:
        if self.status == "clean":
            return "Чисто"
        if self.status == "match":
            return "Найдено: " + ", ".join(self.matches)
        if self.status == "signed":
            return "Проверить (программа подписана): " + ", ".join(self.matches)
        if self.status == "timeout":
            return "Таймаут" + (": " + ", ".join(self.matches) if self.matches else "")
        if self.status == "denied":
            return "Нет доступа"
        return "Ошибка"


def _read_python(pid: int, max_region: int, max_total: int,
                 start: int = 0) -> tuple[list[tuple[int, bytes]], int]:
    """Запасной вариант без C++: то же самое через ctypes."""
    from processmanager import memdeep
    k32 = memdeep.kernel32
    handle = k32.OpenProcess(memdeep.PROCESS_QUERY_INFORMATION | memdeep.PROCESS_VM_READ,
                             False, pid)
    if not handle:
        raise PermissionError(f"OpenProcess: {memdeep.ctypes.GetLastError()}")
    try:
        result, total = [], 0
        for r in memdeep.list_regions(handle):
            if r.base < start:
                continue
            readable = (r.state == memdeep.MEM_COMMIT and r.protect
                        and not r.protect & (memdeep.PAGE_GUARD | memdeep.PAGE_NOACCESS))
            wanted = r.type == memdeep.MEM_PRIVATE or (
                r.type == memdeep.MEM_IMAGE
                and r.protect & 0xFF == memdeep.PAGE_EXECUTE_READWRITE)
            if not (readable and wanted and r.size <= max_region):
                continue
            if total and total + r.size > max_total:
                return result, r.base
            data = memdeep.read_memory(handle, r.base, min(r.size, max_total))
            if data:
                result.append((r.base, data))
                total += len(data)
        return result, 0
    finally:
        k32.CloseHandle(handle)


def read_portion(pid: int, start: int = 0, portion: int | None = None,
                 max_region: int | None = None) -> tuple[list[tuple[int, bytes]], int]:
    """Порция приватной памяти: ([(адрес, данные)], адрес продолжения или 0).
    OSError, если нет доступа."""
    portion = PORTION if portion is None else portion
    max_region = MAX_REGION if max_region is None else max_region
    if _read_native is not None:
        return _read_native(pid, max_region, portion, True, start)
    return _read_python(pid, max_region, portion, start)


def read_regions(pid: int, max_region: int | None = None,
                 max_total: int | None = None) -> list[tuple[int, bytes]]:
    """Вся проверяемая память процесса сразу (до max_total байт)."""
    max_total = MAX_TOTAL if max_total is None else max_total
    result, total, start = [], 0, 0
    while True:
        chunk, start = read_portion(pid, start, max_region=max_region)
        result += chunk
        total += sum(len(d) for _, d in chunk)
        if not start or total >= max_total:
            return result


def _batches(regions: list[tuple[int, bytes]]):
    """Склеивает мелкие регионы в блоки до BATCH байт, крупные отдаёт как есть."""
    parts, size = [], 0
    for _, data in regions:
        if len(data) >= BATCH:
            yield data
            continue
        if size + len(data) > BATCH and parts:
            yield GAP.join(parts)
            parts, size = [], 0
        parts.append(data)
        size += len(data) + len(GAP)
    if parts:
        yield GAP.join(parts)


def scan_process(rules, pid: int, timeout: int = SCAN_TIMEOUT, full: bool = False) -> MemResult:
    """Сканирует память процесса правилами YARA (full=True: всю память, медленно)."""
    if rules is None:
        return MemResult("error", message="Нет скомпилированных правил")
    if pid == os.getpid():
        return MemResult("error", message="Собственный процесс не сканируется")
    if full:
        return _scan_full(rules, pid, timeout)
    deadline = time.monotonic() + timeout
    found: list[str] = []
    scanned, start, first = 0, 0, True
    while True:  # порциями: в памяти одновременно не больше PORTION байт чужого процесса
        try:
            regions, start = read_portion(pid, start)
        except OSError as e:
            if first:
                return MemResult("denied", message=str(e))  # нет прав, защищённый или завершён
            break  # процесс завершился посреди проверки: что успели, то проверили
        except Exception as e:
            return MemResult("error", message=str(e))
        first = False
        for block in _batches(regions):
            left = deadline - time.monotonic()
            if left <= 0:
                return MemResult("timeout", found, scanned=scanned)
            try:
                # fast: каждая строка ищется до первого совпадения, этого достаточно
                matches = rules.match(data=block, timeout=max(1, int(left)), fast=True)
            except yara.TimeoutError:
                return MemResult("timeout", found, scanned=scanned)
            except yara.Error as e:
                return MemResult("error", found, message=str(e), scanned=scanned)
            scanned += len(block)
            for m in matches:
                if m.rule not in found and not overrides.rule_disabled(m.rule):
                    found.append(m.rule)
        del regions
        if not start or scanned >= MAX_TOTAL:
            break
    return MemResult("match" if found else "clean", found, scanned=scanned)


def _scan_full(rules, pid: int, timeout: int) -> MemResult:
    try:
        matches = rules.match(pid=pid, timeout=timeout, fast=True)
    except yara.Error as e:
        name_and_text = (type(e).__name__ + str(e)).lower()
        if "timeout" in name_and_text:
            return MemResult("timeout")
        return MemResult("denied", message=str(e))  # нет прав, защищённый или завершённый процесс
    except Exception as e:
        return MemResult("error", message=str(e))
    names = overrides.active_rules([m.rule for m in matches])
    if names:
        return MemResult("match", names)
    return MemResult("clean")
