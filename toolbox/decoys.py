"""Ловушки для шифровальщиков.

В «Документах» и «Изображениях» создаётся папка DECOY_NAME с обычными на вид файлами
(docx, xlsx, pdf, jpg, txt). Папка — «защищённая системная» (атрибуты скрытый +
системный): Проводник её не показывает, пока не снят флажок «Скрывать защищённые
системные файлы», а шифровальщик перебирает папки через API и видит её; имя с «!» в
начале ставит её первой в списке. Файлы внутри — обычные. Ловушки создаются сами вместе
с защитой файлов (ensure), настройка protect/decoys.
Изменение, удаление или переименование такого файла — сигнал: DecoyWatcher находит
процесс, который больше всех писал на диск в последние секунды (неподписанный, не сама
программа и не Проводник), и приостанавливает его. Решение — за пользователем.

Создание и удаление ловушек пишется в журнал с откатом; хэши файлов — в MANIFEST.
"""
import hashlib
import json
import os
import secrets
import shutil
import threading
import time
from collections import deque
from pathlib import Path

from recovery import journal
from recovery.journal import active_check, undo_op

DECOY_NAME = "!myav — файлы-ловушки"
MANIFEST = journal.JOURNAL_DIR / "decoys.json"
README = "ПРОЧТИТЕ.txt"
SAMPLE_SECONDS = 1.0
HISTORY = 8           # сколько секунд истории записи хранить
IGNORE_NAMES = {"explorer.exe", "searchindexer.exe", "searchprotocolhost.exe",
                "onedrive.exe", "system", "registry", "memcompression"}

# имя файла → начало содержимого (настоящие заголовки форматов, дальше случайные байты)
FILES = {
    "Договор аренды 2025.docx": b"PK\x03\x04\x14\x00\x06\x00",
    "Бюджет семьи.xlsx": b"PK\x03\x04\x14\x00\x06\x00",
    "Паспорт скан.pdf": b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n",
    "Фото 2024-07-12.jpg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00",
    "Пароли.txt": "Не храните пароли в текстовых файлах.\r\n".encode("utf-8"),
}


KNOWN_FOLDERS = {  # FOLDERID_Documents, FOLDERID_Pictures
    "Documents": "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}",
    "Pictures": "{33E28130-4E1E-4676-835A-98395C3BC3BB}",
}


def _known_folder(guid: str) -> Path | None:
    """Настоящий путь папки: «Документы» могут быть перенесены, например в OneDrive."""
    import ctypes
    import uuid
    if os.name != "nt":
        return None
    raw = (ctypes.c_byte * 16).from_buffer_copy(uuid.UUID(guid).bytes_le)
    out = ctypes.c_wchar_p()
    if ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(raw), 0, None,
                                                  ctypes.byref(out)) != 0:
        return None
    path = out.value
    ctypes.windll.ole32.CoTaskMemFree(out)
    return Path(path) if path else None


def default_folders() -> list[Path]:
    home = Path.home()
    return [_known_folder(guid) or home / name for name, guid in KNOWN_FOLDERS.items()]


def _content(head: bytes) -> bytes:
    return head + secrets.token_bytes(48 * 1024)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_manifest() -> dict[str, str]:
    """{путь к файлу-ловушке: sha256}."""
    try:
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_manifest(data: dict) -> None:
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    if data:
        MANIFEST.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    else:
        MANIFEST.unlink(missing_ok=True)


def installed() -> bool:
    return bool(load_manifest())


def decoy_dirs(manifest: dict | None = None) -> list[Path]:
    return sorted({Path(p).parent for p in (manifest or load_manifest())})


def _create(folders: list[Path]) -> dict[str, str]:
    manifest = {}
    for base in folders:
        if not base.is_dir():
            continue
        folder = base / DECOY_NAME
        folder.mkdir(exist_ok=True)
        set_attributes(folder, 0)  # в папку с «только чтение» нельзя писать
        (folder / README).write_text(
            "Это файлы-ловушки антивируса. Не открывайте и не изменяйте их: если какая-то "
            "программа начнёт их менять, антивирус остановит её как шифровальщик.\r\n"
            "Убрать ловушки: Инструменты → «Ловушки для шифровальщиков».\r\n",
            encoding="utf-8-sig")
        for name, head in FILES.items():
            path = folder / name
            path.write_bytes(_content(head))
            manifest[str(path)] = _sha(path)
        protect_folder(folder)
    return manifest


HIDDEN, SYSTEM = 0x2, 0x4


def set_attributes(path: Path, attrs: int) -> None:
    if os.name == "nt":
        import ctypes
        ctypes.windll.kernel32.SetFileAttributesW(str(path), attrs or 0x80)


def protect_folder(folder: Path) -> None:
    """Защищённая системная папка: скрыта в Проводнике, файлы внутри обычные."""
    set_attributes(folder, HIDDEN | SYSTEM)


def is_protected(folder: Path) -> bool:
    try:
        attrs = os.stat(folder).st_file_attributes
    except (OSError, AttributeError):
        return False
    return attrs & (HIDDEN | SYSTEM) == HIDDEN | SYSTEM


def ensure() -> int:
    """Защита включена: ловушки на месте и папки защищены. Создаёт их, если их нет."""
    manifest = load_manifest()
    if not manifest:
        manifest = _create(default_folders())
        _save_manifest(manifest)
        return len(manifest)
    for folder in decoy_dirs(manifest):
        if folder.is_dir() and not is_protected(folder):
            protect_folder(folder)  # папки, созданные прежней версией, были видимыми
    return len(manifest)


def remove_all() -> None:
    """Настройка «Ловушки» выключена: папки удаляются без записи в журнал."""
    _remove_dirs(decoy_dirs())
    _save_manifest({})


def install(folders: list[Path] | None = None) -> int:
    manifest = load_manifest()
    manifest.update(_create(folders or default_folders()))
    _save_manifest(manifest)
    journal.log_action(f"Созданы файлы-ловушки для шифровальщиков ({len(manifest)})",
                       "decoys_remove", {"folders": [str(f) for f in decoy_dirs(manifest)]})
    return len(manifest)


def _remove_dirs(dirs: list[Path]) -> None:
    for folder in dirs:
        if folder.name == DECOY_NAME:  # удаляем только свои папки
            set_attributes(folder, 0)
            shutil.rmtree(folder, ignore_errors=True)


def uninstall() -> None:
    dirs = decoy_dirs()
    _remove_dirs(dirs)
    _save_manifest({})
    journal.log_action("Файлы-ловушки для шифровальщиков убраны", "decoys_create",
                       {"folders": [str(d.parent) for d in dirs]})


@active_check("decoys_remove")
def _decoys_active(d: dict) -> bool:
    return bool(load_manifest())


@active_check("decoys_create")
def _no_decoys_active(d: dict) -> bool:
    return not load_manifest()


@undo_op("decoys_remove")
def _undo_install(d: dict) -> str:
    _remove_dirs([Path(f) for f in d["folders"]])
    _save_manifest({})
    return "Файлы-ловушки убраны"


@undo_op("decoys_create")
def _undo_uninstall(d: dict) -> str:
    manifest = _create([Path(f) for f in d["folders"]])
    _save_manifest(manifest)
    return f"Файлы-ловушки созданы снова ({len(manifest)})"


def repair() -> int:
    """Пересоздаёт изменённые и удалённые ловушки (после срабатывания)."""
    manifest = load_manifest()
    parents = {Path(p).parent.parent for p in manifest}
    fresh = _create(sorted(parents))
    _save_manifest(fresh)
    return len(fresh)


def is_decoy(path) -> bool:
    """Файл внутри папки ловушек: проверка дисков и защита файлов их не читают."""
    return any(part.lower() == DECOY_NAME.lower() for part in Path(path).parts)


LOCK_RETRIES = 6      # занятый файл (антивирус, индексатор) — ждём до ~3 с, это не изменение
LOCK_WAIT = 0.5


def _file_changed(path: Path, sha: str) -> bool:
    for attempt in range(LOCK_RETRIES):
        try:
            return _sha(path) != sha
        except (FileNotFoundError, NotADirectoryError):
            return True                     # удалён или переименован
        except OSError:                     # занят другим процессом на чтение
            if attempt + 1 < LOCK_RETRIES:
                time.sleep(LOCK_WAIT)
    return True  # всё время заблокирован: так делает и шифровальщик


def changed_files(manifest: dict | None = None) -> list[str]:
    return [path for path, sha in (manifest or load_manifest()).items()
            if _file_changed(Path(path), sha)]


class DecoyWatcher:
    """Следит за ловушками; при изменении находит и приостанавливает виновника.

    on_alarm(changed: list[str], culprit: dict | None) вызывается из рабочего потока.
    """

    def __init__(self, on_alarm):
        self.on_alarm = on_alarm
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._history: deque = deque(maxlen=HISTORY)
        self._paused_until = 0.0
        self._muted_until = 0.0

    def mute(self, seconds: float) -> None:
        """Не поднимать тревогу: программа сама пересоздаёт приманки."""
        self._muted_until = time.monotonic() + seconds

    def start(self) -> None:
        if self._thread is None and installed():
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, daemon=True, name="decoys")
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread = None

    @property
    def running(self) -> bool:
        return self._thread is not None

    def _snapshot(self) -> dict[int, tuple[int, str]]:
        from processmanager import ntsnap
        try:
            return {p.pid: (p.written, p.name) for p in ntsnap.list_processes()}
        except OSError:
            return {}

    def _run(self) -> None:
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer
        from scanner.watchflags import use_content_flags
        use_content_flags()  # чтение ловушки (индексатор, проверка) — не повод проверять хэши

        manifest = load_manifest()
        files = {os.path.normcase(p) for p in manifest}
        touched = threading.Event()

        class Handler(FileSystemEventHandler):
            def on_any_event(self, event):
                paths = [event.src_path, getattr(event, "dest_path", "")]
                if any(os.path.normcase(p) in files for p in paths if p):
                    touched.set()

        observer = Observer()
        for folder in decoy_dirs(manifest):
            if folder.is_dir():
                observer.schedule(Handler(), str(folder), recursive=False)
        observer.start()
        try:
            while not self._stop.is_set():
                self._history.append((time.monotonic(), self._snapshot()))
                if touched.wait(SAMPLE_SECONDS):
                    touched.clear()
                    if time.monotonic() < self._muted_until:
                        continue
                    time.sleep(0.3)  # дать процессу дописать: виновник станет заметнее
                    self._history.append((time.monotonic(), self._snapshot()))
                    changed = changed_files()  # манифест свежий: его меняет repair()
                    if changed and time.monotonic() >= self._paused_until:
                        self._paused_until = time.monotonic() + 30  # одно окно, не десять
                        culprit = self.find_culprit()
                        if culprit:
                            culprit["suspended"] = suspend(culprit["pid"])
                        self.on_alarm(changed, culprit)
        finally:
            observer.stop()

    def find_culprit(self) -> dict | None:
        if len(self._history) < 2:
            return None
        (_, first), (_, last) = self._history[0], self._history[-1]
        own = {os.getpid(), os.getppid(), 0, 4}
        ranked = sorted(((written - first.get(pid, (written, ""))[0], pid, name)
                         for pid, (written, name) in last.items()), reverse=True)
        for delta, pid, name in ranked[:15]:
            if delta <= 0:
                break
            if pid in own or name.lower() in IGNORE_NAMES:
                continue
            exe = _exe(pid)
            if exe and _signed(exe):
                continue
            return {"pid": pid, "name": name, "exe": exe, "written": delta}
        return None


def _exe(pid: int) -> str:
    try:
        import psutil
        return psutil.Process(pid).exe()
    except Exception:
        return ""


def _signed(exe: str) -> bool:
    try:
        from scanner.signature import VALID, inspect_signature
        return inspect_signature(Path(exe)).status == VALID
    except Exception:
        return False


def suspend(pid: int) -> bool:
    try:
        import psutil
        psutil.Process(pid).suspend()
        return True
    except Exception:
        return False


def resume(pid: int) -> bool:
    try:
        import psutil
        psutil.Process(pid).resume()
        return True
    except Exception:
        return False
