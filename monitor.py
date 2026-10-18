import os
import threading
import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from quarantine import quarantine_file
from scanner.engine import check_file
from scanner.hashing import load_all_signatures
from scanner.whitelist import load_whitelist
from scanner.yara_engine import load_rules

# временные файлы браузеров и загрузчиков: проверяем уже после переименования
TEMP_SUFFIXES = {".crdownload", ".part", ".partial", ".tmp", ".download", ".opdownload"}
MAX_TRIES = 6  # сколько раз повторять, если файл занят другой программой


class _Handler(FileSystemEventHandler):
    def __init__(self, enqueue):
        self._enqueue = enqueue

    def on_created(self, event):
        if not event.is_directory:
            self._enqueue(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._enqueue(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._enqueue(event.dest_path)  # файл получил итоговое имя


class RealtimeMonitor:
    """Следит за папками и проверяет новые и изменённые файлы.

    on_event(kind, text): kind = status | scanned | threat | error | stopped.
    Вызывается из потока монитора, поэтому GUI должен передавать его в главный
    поток через сигнал Qt.
    """

    def __init__(self, folders, sig_dir: Path, rules_dir: Path,
                 exclude: list[Path], on_event, settle: float = 1.5):
        self.folders = [Path(f) for f in folders]
        self.sig_dir = sig_dir
        self.rules_dir = rules_dir
        self.exclude = [e.resolve() for e in exclude]
        self.on_event = on_event
        self.settle = settle

        self._pending: dict[Path, tuple[float, int]] = {}  # путь -> (время события, попытки)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._signatures: set[str] = set()
        self._rules = None

    # ---------- управление ----------
    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=15)

    def _emit(self, kind: str, text: str = ""):
        try:
            self.on_event(kind, text)
        except Exception:
            pass  # ошибка в обработчике интерфейса не должна ронять монитор

    # ---------- очередь ----------
    def _enqueue(self, raw_path, tries: int = 0):
        path = Path(os.fsdecode(raw_path))
        if path.suffix.lower() in TEMP_SUFFIXES:
            return
        with self._lock:
            # каждое новое событие по файлу сдвигает время проверки вперёд
            self._pending[path] = (time.monotonic(), tries)

    def _take_ready(self) -> list[tuple[Path, int]]:
        now = time.monotonic()
        with self._lock:
            ready = [(p, tries) for p, (ts, tries) in self._pending.items()
                     if now - ts >= self.settle]
            for p, _ in ready:
                del self._pending[p]
        return ready

    # ---------- основной цикл ----------
    def _run(self):
        self._emit("status", "Загружаю базы сигнатур и правила...")
        try:
            self._signatures = load_all_signatures(self.sig_dir)
            self._rules, _ = load_rules(self.rules_dir)
        except Exception as e:
            self._emit("error", f"Не удалось загрузить базы: {e}")
            self._emit("stopped")
            return

        observer = Observer()
        handler = _Handler(self._enqueue)
        watching = 0
        for folder in self.folders:
            if folder.is_dir():
                observer.schedule(handler, str(folder), recursive=True)
                watching += 1
            else:
                self._emit("error", f"Папка не найдена: {folder}")
        if watching == 0:
            self._emit("error", "Нет доступных папок для наблюдения")
            self._emit("stopped")
            return

        observer.start()
        self._emit("status", f"Защита включена. Папок под наблюдением: {watching}, "
                             f"хэшей: {len(self._signatures)}")
        try:
            while not self._stop.wait(0.5):
                for path, tries in self._take_ready():
                    if self._stop.is_set():
                        break
                    self._handle(path, tries)
        finally:
            observer.stop()
            observer.join(timeout=5)
            self._emit("stopped", "Защита выключена")

    def _handle(self, path: Path, tries: int):
        try:
            if not path.is_file():
                return  # файл успели удалить или переименовать
            if any(e in path.resolve().parents for e in self.exclude):
                return
            # белый список читаем при каждой проверке: восстановление файла
            # пользователем должно учитываться сразу
            reason = check_file(path, self._signatures, self._rules, set(load_whitelist()))
        except OSError:
            if tries + 1 < MAX_TRIES:
                self._enqueue(path, tries + 1)  # файл занят, попробуем позже
            else:
                self._emit("error", f"Не удалось прочитать файл: {path}")
            return

        if reason is None:
            self._emit("scanned", f"OK: {path}")
            return
        try:
            quarantine_file(path, reason=reason)
            self._emit("threat", f"[!] {path} ({reason}) -> в карантине")
        except OSError as e:
            self._emit("threat", f"[!] {path} ({reason}) -> не удалось изолировать: {e}")