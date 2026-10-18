import os
import threading
from dataclasses import dataclass, field
from pathlib import Path

import yara

from scanner.yara_engine import load_rules

RULES_ROOT = Path(__file__).resolve().parent.parent / "signatures" / "rules"
MEMORY_RULES_DIR = RULES_ROOT / "memory"
SCAN_TIMEOUT = 30  # секунд на один процесс

_cache: dict[str, object] = {}
_lock = threading.Lock()


def get_rules(kind: str):
    """kind: 'memory' (только правила для памяти) или 'all' (все правила проекта).
    Компилируются один раз за запуск программы. Может вернуть None."""
    with _lock:
        if kind not in _cache:
            rules, _ = load_rules(MEMORY_RULES_DIR if kind == "memory" else RULES_ROOT)
            _cache[kind] = rules
        return _cache[kind]


def reset_cache() -> None:
    """Вызывать после обновления правил, чтобы они перекомпилировались."""
    with _lock:
        _cache.clear()


@dataclass
class MemResult:
    status: str  # clean | match | denied | timeout | error
    matches: list[str] = field(default_factory=list)
    message: str = ""

    def text(self) -> str:
        if self.status == "clean":
            return "Чисто"
        if self.status == "match":
            return "Найдено: " + ", ".join(self.matches)
        if self.status == "timeout":
            return "Таймаут"
        if self.status == "denied":
            return "Нет доступа"
        return "Ошибка"


def scan_process(rules, pid: int, timeout: int = SCAN_TIMEOUT) -> MemResult:
    """Сканирует память процесса правилами YARA."""
    if rules is None:
        return MemResult("error", message="Нет скомпилированных правил")
    if pid == os.getpid():
        return MemResult("error", message="Собственный процесс не сканируется")
    try:
        matches = rules.match(pid=pid, timeout=timeout)
    except yara.Error as e:
        name_and_text = (type(e).__name__ + str(e)).lower()
        if "timeout" in name_and_text:
            return MemResult("timeout")
        return MemResult("denied", message=str(e))  # нет прав, защищённый или завершённый процесс
    except Exception as e:
        return MemResult("error", message=str(e))
    if matches:
        return MemResult("match", [m.rule for m in matches])
    return MemResult("clean")