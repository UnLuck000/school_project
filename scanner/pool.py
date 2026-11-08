"""Проверка многих файлов в отдельных рабочих процессах (scanner.worker).

Зачем процессы, а не потоки: разбор PE и обвязка YARA — Python-код под GIL. В потоках
главного процесса он отнимал время у интерфейса, и программа «замирала» на время
проверки. Рабочие процессы не делят GIL с интерфейсом, работают с пониженным
приоритетом и привязываются к ядрам по нагрузке (scanner.cpucores): если производительные
ядра заняты (например, игрой), проверка уходит на энергоэффективные.

Крупный файл (от SPLIT_SIZE) делится на две задачи для двух процессов: хэши и остальные
слои (YARA, эвристика, подпись) считаются одновременно, а остальные процессы тем
временем проверяют мелкие файлы. Крупные файлы ставятся в очередь первыми.

Процессы запускаются при первой проверке и закрываются после IDLE_SECONDS простоя.
Ответы, как и в check_file, кэшируются (scanner.verdict_cache).
"""
import os
import queue
import subprocess
import sys
import threading
import time
from concurrent.futures import Future
from dataclasses import dataclass, field
from pathlib import Path

from scanner import cpucores, overrides, verdict_cache
from scanner import media
from scanner.engine import cache_version, hash_verdict, revocation_enabled
from scanner.heuristics import get_threshold
from scanner.worker import read_frame, write_frame

ROOT = Path(__file__).resolve().parent.parent
SPLIT_SIZE = 8 * 1024 * 1024   # с какого размера файл проверяют два процесса сразу
IDLE_SECONDS = 15              # простой, после которого процесс закрывается (память!)
TASK_TIMEOUT = 180             # зависший на одном файле процесс перезапускается
CONTROL_SECONDS = 2.0          # как часто пересматривается выбор ядер

BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
CREATE_NO_WINDOW = 0x08000000


# режимы проверки (настройка scan/mode): сколько рабочих процессов; каждый держит свою
# копию правил YARA (около 70 МБ) и занимает одно ядро
MODES = {
    "slow": (2, "Медленный", "Для слабых ПК. Включите, если испытываете проблемы с "
                             "производительностью"),
    "balanced": (4, "Сбалансированный", "По умолчанию"),
    "fast": (6, "Быстрый", "Для мощных ПК"),
}
DEFAULT_MODE = "balanced"


def default_size() -> int:
    return MODES[DEFAULT_MODE][0]


def mode_size(mode: str) -> int:
    return MODES.get(mode, MODES[DEFAULT_MODE])[0]


def _command() -> list[str]:
    if getattr(sys, "frozen", False):  # собранная программа: gui.py понимает этот ключ
        return [sys.executable, "--scan-worker"]
    return [sys.executable, "-m", "scanner.worker"]


class _Worker:
    """Один рабочий процесс."""

    def __init__(self, generation: int, background: bool = False):
        self.generation = generation
        self.busy_since = 0.0
        flags = (BELOW_NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW) if sys.platform == "win32" else 0
        self.proc = subprocess.Popen(
            _command() + (["--background"] if background else []), cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, creationflags=flags)
        ready = read_frame(self.proc.stdout)
        if not ready or ready[0] != "ready":
            self.close()
            raise OSError("рабочий процесс проверки не запустился")
        self.pid = self.proc.pid

    def call(self, request):
        self.busy_since = time.monotonic()
        try:
            write_frame(self.proc.stdin, request)
            reply = read_frame(self.proc.stdout)
        finally:
            self.busy_since = 0.0
        if reply is None:
            raise EOFError("рабочий процесс завершился")
        return reply

    def alive(self) -> bool:
        return self.proc.poll() is None

    def close(self) -> None:
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.proc.kill()


@dataclass
class _Task:
    number: int
    kind: str
    path: str
    options: dict
    future: Future = field(default_factory=Future)


class ScanPool:
    def __init__(self, size: int | None = None):
        self.size = size or default_size()
        # фоновый режим Windows (только «Медленный»): ниже приоритет не только процессора,
        # но и диска и памяти; проверка при этом в 2-3 раза медленнее даже на свободном ПК
        self.background = False
        self.chooser = cpucores.CoreChooser()
        self._tasks: queue.Queue = queue.Queue()
        self._lock = threading.Lock()
        self._threads = 0
        self._idle = 0                            # потоков, ждущих задачу
        self._slots = 0                           # номера слотов не повторяются
        self._workers: dict[int, _Worker] = {}   # слот -> процесс
        self._applied: dict[int, object] = {}    # pid -> ядра, к которым привязан
        self._generation = 0
        self._number = 0
        self._controller: threading.Thread | None = None

    # ---------- задачи ----------
    def submit(self, kind: str, path: str, options: dict) -> Future:
        with self._lock:
            self._number += 1
            task = _Task(self._number, kind, path, options)
        self._tasks.put(task)
        with self._lock:
            # новый процесс — только если задач больше, чем свободных процессов: защита,
            # проверяющая по одному файлу, держит один процесс (правила YARA в каждом
            # процессе — десятки мегабайт), а проверка папки разворачивает все
            if self._threads < self.size and self._tasks.qsize() > self._idle:
                self._threads += 1
                self._slots += 1
                threading.Thread(target=self._serve, args=(self._slots,), daemon=True,
                                 name="scan-pool").start()
            if self._controller is None or not self._controller.is_alive():
                self._controller = threading.Thread(target=self._control, daemon=True,
                                                    name="scan-pool-control")
                self._controller.start()
        return task.future

    def _serve(self, slot: int) -> None:
        worker: _Worker | None = None
        retired = False
        try:
            while True:
                with self._lock:
                    if self._threads > self.size:  # режим сменился на более лёгкий
                        self._threads -= 1
                        retired = True
                        return
                with self._lock:
                    self._idle += 1
                try:
                    task = self._tasks.get(timeout=IDLE_SECONDS)
                except queue.Empty:
                    with self._lock:
                        self._idle -= 1
                        if self._tasks.empty():
                            # простой: процесс больше не нужен; счётчик уменьшается под той
                            # же блокировкой, иначе новая задача решит, что поток ещё есть
                            self._threads -= 1
                            retired = True
                            return
                    continue
                with self._lock:
                    self._idle -= 1
                if not task.future.set_running_or_notify_cancel():
                    continue  # проверку отменили, пока задача ждала
                if worker is not None and (worker.generation != self._generation
                                           or not worker.alive()):
                    self._drop(slot, worker)
                    worker = None
                if worker is None:
                    try:
                        worker = _Worker(self._generation, self.background)
                    except OSError as e:
                        task.future.set_exception(e)
                        continue
                    with self._lock:
                        self._workers[slot] = worker
                    self._apply(worker)
                try:
                    _, ok, payload = worker.call((task.number, task.kind, task.path, task.options))
                except (OSError, EOFError, ValueError):
                    self._drop(slot, worker)
                    worker = None
                    task.future.set_exception(OSError(
                        None, "проверка прервана: файл обрабатывался слишком долго"))
                    continue
                if ok:
                    task.future.set_result(payload)
                else:
                    errno, text = payload
                    task.future.set_exception(OSError(errno, text))
        finally:
            if worker is not None:
                self._drop(slot, worker)
            if not retired:
                with self._lock:
                    self._threads -= 1

    def _drop(self, slot: int, worker: _Worker) -> None:
        worker.close()
        with self._lock:
            if self._workers.get(slot) is worker:
                del self._workers[slot]
            self._applied.pop(worker.pid, None)

    # ---------- ядра и сторож ----------
    def _apply(self, worker: _Worker) -> None:
        cpus = self.chooser.cpus()
        cpucores.apply(worker.pid, cpus)
        with self._lock:
            self._applied[worker.pid] = cpus

    def _control(self) -> None:
        while True:
            time.sleep(CONTROL_SECONDS)
            with self._lock:
                workers = list(self._workers.values())
                if not workers and self._threads == 0:
                    self._controller = None
                    return
            now = time.monotonic()
            for w in workers:
                if w.busy_since and now - w.busy_since > TASK_TIMEOUT:
                    w.proc.kill()  # call() получит конец канала и перезапустит процесс
            try:
                # своя нагрузка: рабочие процессы и сама программа (она разбирает ответы)
                self.chooser.update([os.getpid()] + [w.pid for w in workers])
            except Exception:  # замер нагрузки не должен останавливать проверку
                continue
            cpus = self.chooser.cpus()
            for w in workers:
                if self._applied.get(w.pid, "-") != cpus:
                    cpucores.apply(w.pid, cpus)
                    with self._lock:
                        self._applied[w.pid] = cpus

    # ---------- управление ----------
    def pids(self) -> list[int]:
        with self._lock:
            return [w.pid for w in self._workers.values()]

    def resize(self, size: int) -> None:
        """Новый режим: лишние процессы закроются после текущих файлов, недостающие
        запустятся со следующими задачами."""
        with self._lock:
            self.size = max(1, size)
            self.background = size <= MODES["slow"][0]
            self._generation += 1  # процессы перезапустятся с новым приоритетом

    def cores_text(self) -> str:
        return self.chooser.text()

    def reset(self) -> None:
        """Базы обновились: процессы перезапустятся с новыми правилами перед следующей задачей."""
        with self._lock:
            self._generation += 1

    def shutdown(self) -> None:
        while True:
            try:
                task = self._tasks.get_nowait()
            except queue.Empty:
                break
            task.future.cancel()
        with self._lock:
            workers = list(self._workers.values())
        for w in workers:
            w.proc.kill()


_pool: ScanPool | None = None
_pool_lock = threading.Lock()


def get_pool() -> ScanPool:
    global _pool
    with _pool_lock:
        if _pool is None:
            _pool = ScanPool(_configured_size())
            _pool.background = _pool.size <= MODES["slow"][0]
        return _pool


def _configured_size() -> int:
    from ui import settings as cfg
    try:
        return mode_size(str(cfg.get("scan/mode")))
    except (KeyError, TypeError, ValueError):
        return default_size()


def apply_settings() -> None:
    """Перечитать режим проверки и «Только E-ядра» (после изменения настроек)."""
    from scanner import engine
    from ui import settings as cfg
    cpucores.set_efficient_only(bool(cfg.get("scan/ecores_only")))
    engine.set_revocation(bool(cfg.get("scan/revocation")))
    if _pool is not None:
        _pool.resize(_configured_size())


def reset() -> None:
    if _pool is not None:
        _pool.reset()


def shutdown() -> None:
    if _pool is not None:
        _pool.shutdown()


@dataclass
class _Job:
    path: str
    p: Path
    st: os.stat_result
    parts: dict = field(default_factory=dict)
    error: OSError | None = None
    waiting: int = 0
    media: str = ""  # формат обычного медиафайла (scanner/media.py): без YARA и эвристики


def check_files(paths, signatures, rules, whitelist: set[str] | None = None,
                heuristics: bool = True, cancel: threading.Event | None = None,
                pool: ScanPool | None = None):
    """Проверяет файлы в рабочих процессах. Генератор: (путь, причина или None, ошибка
    OSError или None) в порядке готовности. Ответ по неизменённым файлам берётся из кэша сразу.

    rules — правила главного процесса: по ним определяется версия для кэша, сами
    рабочие процессы загружают тот же набор «all» из cache/."""
    pool = pool or get_pool()
    version = cache_version(signatures, rules, heuristics)
    options = {"heuristics": heuristics, "threshold": get_threshold(),
               "revocation": revocation_enabled()}
    results: queue.Queue = queue.Queue()
    jobs: list[_Job] = []
    for path in paths:
        if cancel is not None and cancel.is_set():
            return
        p = Path(path)
        try:
            st = p.stat()
        except OSError as e:
            yield str(path), None, e
            continue
        if version:
            cached = verdict_cache.get(p, st, version)
            if cached is not None:
                digest, reason = cached
                yield str(path), None if whitelist and digest in whitelist else reason, None
                continue
        job = _Job(str(path), p, st)
        job.media = media.plain_media(p, st.st_size)  # видео и аудио: без YARA (media.py)
        if job.media and st.st_size > media.MEDIA_HASH_LIMIT:
            if version:
                verdict_cache.put(p, st, version, "", None)
            yield str(path), None, None  # крупный медиафайл целиком не читается
            continue
        jobs.append(job)
    # крупные файлы первыми: пока два процесса заняты ими, остальные берут мелкие
    jobs.sort(key=lambda j: j.st.st_size < SPLIT_SIZE)
    futures: list[Future] = []
    for job in jobs:
        if job.media:
            kinds = ("hash",)
        else:
            kinds = ("hash", "analyze") if job.st.st_size >= SPLIT_SIZE else ("full",)
        job.waiting = len(kinds)
        for kind in kinds:
            future = pool.submit(kind, job.path, options)
            future.add_done_callback(lambda f, job=job, kind=kind: results.put((job, kind, f)))
            futures.append(future)
    left = len(jobs)
    try:
        while left:
            if cancel is not None and cancel.is_set():
                return
            try:
                job, kind, future = results.get(timeout=0.2)
            except queue.Empty:
                continue
            job.waiting -= 1
            if future.cancelled():
                job.error = job.error or OSError(None, "проверка отменена")
            elif future.exception() is not None:
                job.error = job.error or future.exception()
            else:
                job.parts[kind] = future.result()
            if job.waiting:
                continue
            left -= 1
            if job.error is not None:
                yield job.path, None, job.error
                continue
            if "full" in job.parts:
                (digest, md5), analyzed = job.parts["full"]
            elif job.media:
                (digest, md5), analyzed = job.parts["hash"], None
            else:
                (digest, md5), analyzed = job.parts["hash"], job.parts["analyze"]
            reason = overrides.filter_reason(
                digest, hash_verdict(job.st.st_size, digest, md5, signatures) or analyzed)
            if version:
                verdict_cache.put(job.p, job.st, version, digest, reason)
            yield job.path, None if whitelist and digest in whitelist else reason, None
    finally:
        for future in futures:
            future.cancel()  # отмена или выход из генератора: ждущие задачи не нужны
        verdict_cache.flush()
