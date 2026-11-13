"""Сколько ресурсов потребляет программа: замер собственного процесса во время работы
функций, которые нагружают систему (загрузка баз, проверка файлов, памяти процессов,
подписей, снимки процессов и соединений).

Сборщик раз в SAMPLE_MS опрашивает свой процесс и его дочерние процессы (рабочие процессы
проверки файлов, scanner.pool) через psutil: загрузку процессора (в процентах от всех
ядер, как в диспетчере задач), память (рабочий набор), потоки и чтение с диска. Каждая
точка помечена сценарием, который в этот момент выполнялся.
"""
import csv
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

import psutil
import datadirs

SAMPLE_MS = 250
REPORTS_DIR = datadirs.REPORTS
SIG_DIR = Path(__file__).resolve().parent.parent / "signatures"
RULES_DIR = SIG_DIR / "rules"
WINDOWS = Path(os.environ.get("SystemRoot", r"C:\Windows"))


@dataclass
class Sample:
    t: float          # секунды от начала замера
    scenario: str
    cpu: float        # % от всех ядер
    rss: int          # байт
    threads: int
    read: int         # байт прочитано с начала замера
    write: int


@dataclass
class Summary:
    scenario: str
    seconds: float
    cpu_avg: float
    cpu_peak: float
    rss_peak: int
    rss_delta: int    # прирост памяти за сценарий
    read_mb: float
    threads_peak: int
    note: str = ""


@dataclass
class Report:
    samples: list[Sample] = field(default_factory=list)
    summaries: list[Summary] = field(default_factory=list)
    started: float = 0.0
    cpu_count: int = 1
    total_ram: int = 0


class Sampler:
    """Фоновый опрос своего процесса и дочерних (рабочих процессов проверки)."""

    def __init__(self, report: Report):
        self.report = report
        self.scenario = "—"
        self._proc = psutil.Process(os.getpid())
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._procs: dict[int, psutil.Process] = {}
        self._io_last: dict[int, tuple[int, int]] = {}  # pid -> последние счётчики
        self._read = self._write = 0  # сумма приростов: дочерние процессы приходят и уходят

    def _family(self) -> list[psutil.Process]:
        try:
            current = [self._proc] + self._proc.children(recursive=True)
        except psutil.Error:
            current = [self._proc]
        alive = {}
        for proc in current:
            known = self._procs.get(proc.pid)
            if known is None:
                known = proc
                try:
                    known.cpu_percent(None)  # первый вызов всегда 0: задаёт точку отсчёта
                except psutil.Error:
                    continue
            alive[proc.pid] = known
        self._procs = alive
        return list(alive.values())

    def _add_io(self, proc: psutil.Process) -> None:
        try:
            io = proc.io_counters()
        except (psutil.Error, AttributeError):
            return
        last = self._io_last.get(proc.pid)
        self._io_last[proc.pid] = io.read_bytes, io.write_bytes
        if last is not None:
            self._read += max(0, io.read_bytes - last[0])
            self._write += max(0, io.write_bytes - last[1])

    def start(self):
        self.report.started = time.monotonic()
        self.report.cpu_count = psutil.cpu_count() or 1
        self.report.total_ram = psutil.virtual_memory().total
        for proc in self._family():
            self._add_io(proc)
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=2)

    def _run(self):
        cores = self.report.cpu_count
        while not self._stop.wait(SAMPLE_MS / 1000):
            cpu = 0.0
            mem = threads = 0
            for proc in self._family():
                try:
                    cpu += proc.cpu_percent(None) / cores
                    mem += proc.memory_info().rss
                    threads += proc.num_threads()
                except psutil.Error:
                    continue
                self._add_io(proc)
            self.report.samples.append(Sample(
                time.monotonic() - self.report.started, self.scenario, cpu, mem, threads,
                self._read, self._write))


# ---------- сценарии нагрузки ----------
def _system_files(limit: int) -> list[Path]:
    files = []
    for entry in os.scandir(WINDOWS / "System32"):
        if entry.is_file() and entry.name.lower().endswith((".exe", ".dll")):
            files.append(Path(entry.path))
            if len(files) >= limit:
                break
    return files


def scenario_idle(ctx: dict) -> str:
    ctx["cancel"].wait(ctx.get("idle_seconds", 8))
    return ("фон: защита файлов и мониторинг сети работают; сразу после включения мониторинг "
            "сети проверяет файлы программ с соединениями (отсюда чтение с диска)")


def scenario_load_bases(ctx: dict) -> str:
    from scanner.hashing import load_all_signatures
    from scanner.yara_engine import load_rules
    db = load_all_signatures(SIG_DIR)
    rules, _ = load_rules(RULES_DIR, use_cache=False)  # полная компиляция, как после обновления
    ctx["signatures"], ctx["rules"] = db, rules
    count = f"{len(db):,}".replace(",", " ")
    return f"хэшей {count}, правила скомпилированы заново"


def _scan(ctx: dict, use_cache: bool) -> str:
    from scanner import pool as scan_pool, verdict_cache
    files = ctx["files"]
    if not use_cache:
        verdict_cache.forget(files)  # первая проверка: файлы читаются целиком
    pool = scan_pool.get_pool()
    for _ in scan_pool.check_files(files, ctx["signatures"], ctx["rules"], cancel=ctx["cancel"]):
        pass
    workers_mb = sum(_rss(pid) for pid in pool.pids()) / 1048576
    pool.shutdown()  # иначе простаивающие процессы попали бы в замер следующих сценариев
    size = sum(p.stat().st_size for p in files if p.exists()) / 1048576
    return (f"{len(files)} файлов System32 ({size:.0f} МБ), рабочих процессов {pool.size} "
            f"(вместе {workers_mb:.0f} МБ); {pool.cores_text()}")


def _rss(pid: int) -> int:
    try:
        return psutil.Process(pid).memory_info().rss
    except psutil.Error:
        return 0


def scenario_scan_first(ctx: dict) -> str:
    return _scan(ctx, use_cache=False)


def scenario_scan_cached(ctx: dict) -> str:
    return "те же файлы, ответ из кэша вердиктов: " + _scan(ctx, use_cache=True)


def scenario_memory(ctx: dict) -> str:
    from processmanager.memscan import get_rules, scan_process
    from processmanager.ntsnap import list_processes
    rules = get_rules("memory")
    pids = [p.pid for p in list_processes() if p.pid not in (0, 4, os.getpid())]
    with ThreadPoolExecutor(ctx.get("workers", 4)) as pool:
        results = list(pool.map(
            lambda pid: None if ctx["cancel"].is_set() else scan_process(rules, pid), pids))
    checked = sum(1 for r in results if r is not None and r.status not in ("denied", "error"))
    return f"процессов {len(pids)}, доступно для проверки {checked}"


def scenario_signatures(ctx: dict) -> str:
    from scanner.signature import inspect_signature
    files = ctx["files"][:150]
    for path in files:
        if ctx["cancel"].is_set():
            break
        inspect_signature(path)
    return f"{len(files)} файлов (WinVerifyTrust, каталоги Windows)"


def scenario_processes(ctx: dict) -> str:
    from processmanager.ntsnap import list_processes
    for _ in range(30):
        if ctx["cancel"].is_set():
            break
        list_processes()
        time.sleep(0.1)
    return "30 снимков процессов (как диспетчер при обновлении)"


def scenario_network(ctx: dict) -> str:
    from networkmonitor.connections import snapshot
    for _ in range(20):
        if ctx["cancel"].is_set():
            break
        snapshot()
        time.sleep(0.1)
    return "20 снимков соединений (как мониторинг сети)"


SCENARIOS = [
    ("Фон (покой)", scenario_idle),
    ("Загрузка баз и компиляция YARA", scenario_load_bases),
    ("Проверка файлов (первая)", scenario_scan_first),
    ("Проверка файлов (повторная)", scenario_scan_cached),
    ("Проверка памяти процессов", scenario_memory),
    ("Проверка цифровых подписей", scenario_signatures),
    ("Снимки процессов", scenario_processes),
    ("Снимки сетевых соединений", scenario_network),
]


def summarize(report: Report, scenario: str, t0: float, t1: float, note: str) -> Summary:
    points = [s for s in report.samples if t0 <= s.t <= t1 and s.scenario == scenario]
    if not points:
        return Summary(scenario, t1 - t0, 0, 0, 0, 0, 0, 0, note)
    before = [s for s in report.samples if s.t < t0]
    base_rss = before[-1].rss if before else points[0].rss
    base_read = before[-1].read if before else points[0].read
    return Summary(
        scenario, t1 - t0,
        sum(s.cpu for s in points) / len(points), max(s.cpu for s in points),
        max(s.rss for s in points), points[-1].rss - base_rss,
        (points[-1].read - base_read) / 1048576, max(s.threads for s in points), note)


def run_all(report: Report, sampler: Sampler, cancel: threading.Event, progress=None,
            files: int = 400, workers: int = 4) -> None:
    """Выполняет сценарии по очереди. progress(текст) вызывается из этого потока."""
    from scanner import pool as scan_pool
    scan_pool.shutdown()  # фон меряется без процессов, оставшихся от прошлой проверки
    ctx = {"cancel": cancel, "files": _system_files(files), "workers": workers}
    for title, func in SCENARIOS:
        if cancel.is_set():
            break
        if progress:
            progress(f"Сценарий: {title}...")
        if "signatures" not in ctx and func not in (scenario_idle, scenario_load_bases):
            scenario_load_bases(ctx)  # базы нужны проверке файлов
        sampler.scenario = title
        t0 = time.monotonic() - report.started
        try:
            note = func(ctx)
        except Exception as e:  # один сценарий не должен ронять замер
            note = f"ошибка: {type(e).__name__}: {e}"
        time.sleep(SAMPLE_MS / 1000 * 1.5)  # последняя точка сценария
        t1 = time.monotonic() - report.started
        sampler.scenario = "—"
        report.summaries.append(summarize(report, title, t0, t1, note))


def save_csv(report: Report) -> tuple[Path, Path]:
    """Сохраняет итоги и все точки в reports/. (файл итогов, файл точек)."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    summary_path = REPORTS_DIR / f"resources_{stamp}_summary.csv"
    samples_path = REPORTS_DIR / f"resources_{stamp}_samples.csv"
    with summary_path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["Сценарий", "Время, с", "ЦП среднее, %", "ЦП пик, %", "Память пик, МБ",
                    "Прирост памяти, МБ", "Прочитано, МБ", "Потоков (пик)", "Примечание"])
        for s in report.summaries:
            w.writerow([s.scenario, f"{s.seconds:.2f}", f"{s.cpu_avg:.1f}", f"{s.cpu_peak:.1f}",
                        f"{s.rss_peak / 1048576:.1f}", f"{s.rss_delta / 1048576:.1f}",
                        f"{s.read_mb:.1f}", s.threads_peak, s.note])
    with samples_path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["Время, с", "Сценарий", "ЦП, %", "Память, МБ", "Потоков", "Прочитано, МБ"])
        for s in report.samples:
            w.writerow([f"{s.t:.2f}", s.scenario, f"{s.cpu:.1f}", f"{s.rss / 1048576:.1f}",
                        s.threads, f"{s.read / 1048576:.1f}"])
    return summary_path, samples_path
