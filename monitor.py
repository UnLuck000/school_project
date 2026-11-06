import os
import threading
import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver

from quarantine import quarantine_file  # noqa: F401  (нужен, когда автокарантин включён, см. _handle)
from scanner.engine import check_file
from scanner.hashing import load_all_signatures
from scanner.whitelist import load_whitelist, trusted_hashes
from processmanager.memscan import shared_rules

# временные файлы браузеров и загрузчиков: проверяем уже после переименования
TEMP_SUFFIXES = {".crdownload", ".part", ".partial", ".tmp", ".download", ".opdownload"}
MAX_TRIES = 6  # сколько раз повторять, если файл занят другой программой
SCAN_EXISTING = True  # при включении проверить файлы, которые уже лежат в папках пользователя

# в системных папках файлы меняются постоянно (журналы, кэши, базы): там проверяем только
# то, что может запуститься, — программы, библиотеки, драйверы, скрипты и ярлыки
EXECUTABLE_EXTS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".pif", ".cpl", ".ocx", ".drv", ".efi", ".msi",
    ".msp", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".hta", ".lnk", ".url", ".jar", ".reg", ".inf", ".application", ".appx", ".msix",
}


def system_folders() -> list[tuple[Path, bool, bool]]:
    """Системные папки, за которыми защита следит всегда: (папка, с подпапками, все файлы).

    «Все файлы» — для папок автозапуска и заданий планировщика: там любой файл может
    оказаться способом закрепиться в системе. В остальных проверяются только
    исполняемые файлы и скрипты (EXECUTABLE_EXTS)."""
    env = os.environ.get
    windows = Path(env("SystemRoot", r"C:\Windows"))
    program_data = Path(env("ProgramData", r"C:\ProgramData"))
    appdata = Path(env("APPDATA", str(Path.home() / "AppData" / "Roaming")))
    local = Path(env("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
    startup = r"Microsoft\Windows\Start Menu\Programs\Startup"
    folders = [
        (appdata / startup, True, True),                       # автозагрузка пользователя
        (program_data / startup.replace("Startup", "StartUp"), True, True),  # для всех
        (windows / "System32" / "Tasks", True, True),          # задания планировщика
        (windows, False, False),
        (windows / "System32", False, False),
        (windows / "System32" / "drivers", False, False),
        (windows / "SysWOW64", False, False),
        (windows / "Temp", True, False),
        (Path(env("TEMP", str(local / "Temp"))), True, False),
        (appdata, True, False),
        (local, True, False),
        (program_data, True, False),
        (Path(env("PUBLIC", r"C:\Users\Public")), True, False),
        (Path(env("ProgramFiles", r"C:\Program Files")), True, False),
        (Path(env("ProgramFiles(x86)", r"C:\Program Files (x86)")), True, False),
    ]
    seen, result = set(), []
    for folder, recursive, all_files in folders:
        key = str(folder).lower()
        if key not in seen:
            seen.add(key)
            result.append((folder, recursive, all_files))
    return result


def _inside(path: Path, folder: Path) -> bool:
    try:
        return path == folder or path.is_relative_to(folder)
    except ValueError:
        return False


def _readable(folder: Path) -> bool:
    """Папку можно читать: без доступа watchdog падает целиком при запуске."""
    try:
        with os.scandir(folder):
            return True
    except OSError:
        return False


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

    folders — папки пользователя (все файлы, с подпапками); кроме них всегда
    наблюдаются системные папки (system_folders), если не передано system=[].
    on_event(kind, text): kind = status | scanned | threat | error | stopped.
    У события threat текст имеет вид «путь\\tпричина\\tчто сделано».
    Вызывается из потока монитора, поэтому GUI должен передавать его в главный
    поток через сигнал Qt.
    """

    def __init__(self, folders, sig_dir: Path, rules_dir: Path,
                 exclude: list[Path], on_event, settle: float = 1.5,
                 system: list[tuple[Path, bool, bool]] | None = None):
        self.folders = [Path(f) for f in folders]
        self.system = system_folders() if system is None else system
        self.sig_dir = sig_dir
        self.rules_dir = rules_dir
        self.exclude = [e.resolve() for e in exclude]
        self.on_event = on_event
        self.settle = settle

        self._pending: dict[Path, tuple[float, int]] = {}  # путь -> (время события, попытки)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._reload = threading.Event()
        self._thread: threading.Thread | None = None
        self._signatures = None
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

    def reload_bases(self):
        """Базы обновились: перечитать их в потоке монитора."""
        self._reload.set()

    def _emit(self, kind: str, text: str = ""):
        try:
            self.on_event(kind, text)
        except Exception:
            pass  # ошибка в обработчике интерфейса не должна ронять монитор

    # ---------- очередь ----------
    def _wanted(self, path: Path) -> bool:
        if path.suffix.lower() in TEMP_SUFFIXES:
            return False
        if any(_inside(path, f) for f in self.folders):
            return True  # папка пользователя: все файлы
        for folder, recursive, all_files in self.system:
            if (_inside(path, folder) if recursive else path.parent == folder):
                if all_files or path.suffix.lower() in EXECUTABLE_EXTS:
                    return True
        return False

    def _enqueue(self, raw_path, tries: int = 0):
        path = Path(os.fsdecode(raw_path))
        if not self._wanted(path):
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
    def _load_bases(self):
        self._signatures = load_all_signatures(self.sig_dir)
        self._rules = shared_rules(self.rules_dir)

    def _schedule(self, observer: BaseObserver, handler) -> tuple[int, int]:
        """Ставит папки на наблюдение. (папок пользователя, системных)."""
        user = system = 0
        recursive_roots: list[Path] = []
        for folder in self.folders:
            if folder.is_dir() and _readable(folder):
                observer.schedule(handler, str(folder), recursive=True)
                recursive_roots.append(folder)
                user += 1
            else:
                self._emit("error", f"Папка не найдена или нет доступа: {folder}")
        for folder, recursive, _ in self.system:
            if not folder.is_dir() or not _readable(folder):
                continue  # например, C:\Windows\Temp без прав администратора
            if any(_inside(folder, root) for root in recursive_roots):
                system += 1  # события и так приходят от папки выше
                continue
            observer.schedule(handler, str(folder), recursive=recursive)
            if recursive:
                recursive_roots.append(folder)
            system += 1
        return user, system

    def _run(self):
        self._emit("status", "Загружаю базы сигнатур и правила...")
        try:
            self._load_bases()
        except Exception as e:
            self._emit("error", f"Не удалось загрузить базы: {e}")
            self._emit("stopped")
            return

        observer = Observer()
        handler = _Handler(self._enqueue)
        user, system = self._schedule(observer, handler)
        if user + system == 0:
            self._emit("error", "Нет доступных папок для наблюдения")
            self._emit("stopped")
            return
        try:
            observer.start()
        except OSError as e:
            self._emit("error", f"Не удалось начать наблюдение: {e}")
            self._emit("stopped")
            return

        if SCAN_EXISTING:  # только папки пользователя: системные слишком большие
            for folder in self.folders:
                if folder.is_dir():
                    for existing in folder.rglob("*"):
                        if existing.is_file():
                            self._enqueue(existing)
        self._emit("status", f"Защита включена. Папок пользователя: {user}, системных: "
                             f"{system}")
        try:
            while not self._stop.wait(0.5):
                if self._reload.is_set():
                    self._reload.clear()
                    try:
                        self._load_bases()
                    except Exception as e:
                        self._emit("error", f"Не удалось перечитать базы: {e}")
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
            reason = check_file(path, self._signatures, self._rules, trusted_hashes())
        except OSError:
            if tries + 1 < MAX_TRIES:
                self._enqueue(path, tries + 1)  # файл занят, попробуем позже
            else:
                self._emit("error", f"Не удалось прочитать файл: {path}")
            return

        if reason is None:
            self._emit("scanned", f"OK: {path}")
            return

        # ================================================================================
        # АВТОМАТИЧЕСКИЙ КАРАНТИН ВРЕМЕННО ОТКЛЮЧЁН: под наблюдением теперь и системные
        # папки, и ложное срабатывание на системный файл не должно его убрать.
        # Чтобы вернуть автокарантин: раскомментировать блок «try ... except» ниже
        # и удалить две строки после него (action = ... и self._emit(...)).
        # ================================================================================
        # try:
        #     quarantine_file(path, reason=reason)
        #     self._emit("threat", f"{path}\t{reason}\tперемещён в карантин")
        # except OSError as e:
        #     self._emit("threat", f"{path}\t{reason}\tне удалось изолировать: {e}")
        # return
        action = "обнаружен, автокарантин отключён (правый клик: «В карантин»)"
        self._emit("threat", f"{path}\t{reason}\t{action}")
