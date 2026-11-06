"""Поиск «маячков» (beaconing): программа связывается с одним и тем же адресом через
почти равные промежутки времени. Так бот спрашивает у управляющего сервера команды
(Cobalt Strike, Sliver и т. п. по умолчанию — раз в 60 секунд с небольшим разбросом).

Источники событий: новые TCP-соединения (снимки мониторинга сети), DNS-запросы (ETW) и
начала TLS-соединений (WinDivert). Ключ — (программа, адрес или домен).

Признак маячка: не меньше MIN_EVENTS событий, средний промежуток от MIN_PERIOD до
MAX_PERIOD секунд, и промежутки почти равные: коэффициент вариации (стандартное отклонение,
делённое на среднее) меньше MAX_CV. Обновления и телеметрия обычных программ тоже бывают
периодическими, поэтому подписанные программы показываются только в списке, а
оповещение получает только неподписанная программа.
"""
import statistics
import threading
from collections import deque
from dataclasses import dataclass

MIN_EVENTS = 6
MIN_PERIOD = 5.0
MAX_PERIOD = 2 * 3600.0
MAX_CV = 0.15
MERGE_SECONDS = 1.0   # события ближе этого считаются одним (DNS + TCP + TLS одного обращения)
HISTORY = 30


@dataclass
class Beacon:
    program: str        # имя процесса
    exe: str
    target: str         # адрес или домен
    period: float       # средний промежуток, с
    cv: float           # разброс промежутков
    count: int          # сколько событий
    last: float         # время последнего события
    source: str         # tcp | dns | tls


class BeaconDetector:
    def __init__(self):
        self._events: dict[tuple[str, str], deque] = {}
        self._info: dict[tuple[str, str], tuple[str, str]] = {}
        self._reported: dict[tuple[str, str], float] = {}  # ключ -> период при оповещении
        self._lock = threading.Lock()

    def feed(self, program: str, exe: str, target: str, when: float,
             source: str) -> Beacon | None:
        """Добавляет событие. Возвращает Beacon, если маячок найден впервые (или его
        период заметно изменился)."""
        if not target or not program:
            return None
        key = (exe.lower() or program.lower(), target.lower())
        with self._lock:
            times = self._events.setdefault(key, deque(maxlen=HISTORY))
            if times and when - times[-1] < MERGE_SECONDS:
                return None
            times.append(when)
            self._info[key] = (program, exe, source)
            beacon = self._check(key, target)
            if beacon is None:
                return None
            old = self._reported.get(key)
            if old is not None and abs(old - beacon.period) < old * 0.2:
                return None
            self._reported[key] = beacon.period
            return beacon

    def _check(self, key, target: str) -> Beacon | None:
        times = self._events[key]
        if len(times) < MIN_EVENTS:
            return None
        gaps = [b - a for a, b in zip(times, list(times)[1:])]
        mean = statistics.fmean(gaps)
        if not MIN_PERIOD <= mean <= MAX_PERIOD:
            return None
        cv = statistics.pstdev(gaps) / mean
        if cv > MAX_CV:
            return None
        program, exe, source = self._info[key]
        return Beacon(program, exe, target, mean, cv, len(times), times[-1], source)

    def current(self) -> list[Beacon]:
        """Все пары, которые сейчас выглядят как маячки."""
        with self._lock:
            result = []
            for key in list(self._events):
                beacon = self._check(key, key[1])
                if beacon is not None:
                    result.append(beacon)
            return sorted(result, key=lambda b: b.cv)

    def forget_older(self, border: float) -> None:
        """Выбрасывает пары без событий после border (чтобы память не росла)."""
        with self._lock:
            for key in [k for k, v in self._events.items() if v and v[-1] < border]:
                self._events.pop(key, None)
                self._info.pop(key, None)
                self._reported.pop(key, None)
