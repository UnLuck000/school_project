r"""Защита списков доверия от подмены.

Белый список, исключения и переопределения баз лежат в папке конфигурации пользователя
(%APPDATA%): туда может писать любая программа этого пользователя. Вредоносу достаточно было
дописать свой хэш в whitelist.json — и проверки переставали его замечать.

Здесь у каждого такого файла есть защищённая копия в %ProgramData%\StretchBIT\trusted: писать
туда могут только администраторы (программа обычно работает с правами администратора), читать —
все. Правило чтения:
  файл совпадает с копией            → берём его;
  файл записала сама программа       → берём его (и обновляем копию, если есть права);
  файл изменён кем-то ещё            → берём защищённую копию, изменение ждёт решения
                                       пользователя (pending / accept / reject).
Первое включение: копий ещё нет — текущие файлы принимаются как есть («доверие при первом
использовании»), дальше — только через программу.

Там же ключ для кэша вердиктов (mac_key): файл ключа читают только администраторы, поэтому
запись в cache/verdicts.sqlite нельзя подделать, не зная его. Без прав ключ пустой: записи,
сделанные без прав и с правами, друг другу не доверяют (файл просто проверяется заново).

Папку можно подменить переменной STRETCHBIT_SEAL_DIR (тесты); STRETCHBIT_SEAL=off выключает.
"""
import ctypes
import hashlib
import os
import secrets
import subprocess
import threading
from pathlib import Path

ENV_DIR = "STRETCHBIT_SEAL_DIR"
ENV_OFF = "STRETCHBIT_SEAL"
CREATE_NO_WINDOW = 0x08000000

_lock = threading.RLock()
_self_saved: dict[str, str] = {}      # путь -> sha256 содержимого, записанного этой программой
_pending: dict[str, str] = {}         # путь -> что случилось (для окна при запуске)
_cache: dict[str, tuple] = {}         # путь -> (отметка файла, отметка копии, bytes)
_key: bytes | None = None
_admin: bool | None = None


def enabled() -> bool:
    return os.environ.get(ENV_OFF, "").lower() != "off"


def protected_dir() -> Path:
    if os.environ.get(ENV_DIR):
        return Path(os.environ[ENV_DIR])
    from diag import edition
    root = Path(os.environ.get("ProgramData") or r"C:\ProgramData")
    return root / ("StretchBIT-test" if edition.is_test() else "StretchBIT")


def is_admin() -> bool:
    global _admin
    if _admin is None:
        try:
            _admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            _admin = False
    return _admin


def can_write() -> bool:
    """Можно ли менять защищённые копии: права администратора (или папка тестов)."""
    return bool(os.environ.get(ENV_DIR)) or is_admin()


def _icacls(*args: str) -> None:
    import syscmd
    try:
        subprocess.run([syscmd.system_exe("icacls.exe"), *args], capture_output=True,
                       timeout=30, creationflags=CREATE_NO_WINDOW)
    except (OSError, subprocess.SubprocessError):
        pass


def _trusted_dir(create: bool = False) -> Path:
    folder = protected_dir() / "trusted"
    if create and not folder.is_dir():
        folder.mkdir(parents=True, exist_ok=True)
        if not os.environ.get(ENV_DIR):
            # администраторы и система — полный доступ, пользователи — только чтение;
            # наследование от ProgramData (там пользователям можно создавать файлы) убираем
            _icacls(str(protected_dir()), "/inheritance:r", "/grant:r",
                    "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX")
    return folder


def _mirror(path: Path) -> Path:
    tag = hashlib.sha256(os.path.normcase(str(path)).encode("utf-8")).hexdigest()[:10]
    return _trusted_dir() / f"{path.name}.{tag}"


def _stamp(path: Path) -> tuple:
    try:
        st = path.stat()
        return st.st_mtime_ns, st.st_size
    except OSError:
        return 0, -1


def _read(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError:
        return b""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _store(path: Path, data: bytes) -> bool:
    if not can_write():
        return False
    try:
        mirror = _trusted_dir(create=True) / _mirror(path).name
        tmp = mirror.with_name(mirror.name + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, mirror)
        return True
    except OSError:
        return False


def saved(path) -> None:
    """Программа только что записала файл: это её изменение, не чужое."""
    if not enabled():
        return
    path = Path(path)
    data = _read(path)
    with _lock:
        _self_saved[str(path)] = _sha(data)
        _pending.pop(str(path), None)
        _cache.pop(str(path), None)
        _store(path, data)


def read(path) -> bytes:
    """Содержимое, которому можно доверять: сам файл или его защищённая копия."""
    path = Path(path)
    if not enabled():
        return _read(path)
    key = str(path)
    with _lock:
        mirror = _mirror(path)
        stamps = (_stamp(path), _stamp(mirror))
        hit = _cache.get(key)
        if hit and hit[0] == stamps:
            return hit[1]
        data = _read(path)
        result = data
        if not _trusted_dir().is_dir():
            # первое включение: копий нет ни у одного файла — принимаем как есть
            if data:
                _store(path, data)
        elif mirror.is_file():
            trusted = _read(mirror)
            if data != trusted:
                if _self_saved.get(key) == _sha(data):
                    _store(path, data)  # записано без прав, теперь права есть
                else:
                    _pending[key] = "изменён не программой"
                    result = trusted
        elif data and _self_saved.get(key) != _sha(data):
            if _pending_first(path):
                _store(path, data)
            else:
                _pending[key] = "появился не из программы"
                result = b""
        elif data:
            _store(path, data)
        _cache[key] = ((_stamp(path), _stamp(mirror)), result)
        return result


def _pending_first(path: Path) -> bool:
    """Папка копий уже есть, а у этого файла копии нет: так бывает сразу после обновления
    со старой версии, когда первым прочитали другой файл. Пока в папке нет отметки «все
    файлы приняты», такой файл тоже принимается как есть."""
    return not (_trusted_dir() / ".initialized").exists()


def finish_first_run(paths) -> None:
    """После запуска: все файлы прочитаны хотя бы раз — дальше новые файлы без копии
    считаются чужими. Вызывается из gui.py."""
    if not enabled() or not can_write():
        return
    for path in paths:
        read(path)
    try:
        (_trusted_dir(create=True) / ".initialized").write_text("1", encoding="ascii")
    except OSError:
        pass


def pending() -> dict[str, str]:
    with _lock:
        return dict(_pending)


def accept(path) -> None:
    """Пользователь подтвердил изменение файла."""
    path = Path(path)
    data = _read(path)
    with _lock:
        _self_saved[str(path)] = _sha(data)
        _pending.pop(str(path), None)
        _cache.pop(str(path), None)
        _store(path, data)


def reject(path) -> None:
    """Вернуть файл к защищённой копии (нет копии — файл очищается)."""
    path = Path(path)
    with _lock:
        mirror = _mirror(path)
        data = _read(mirror) if mirror.is_file() else b""
        try:
            if data:
                path.write_bytes(data)
            else:
                path.unlink(missing_ok=True)
        except OSError:
            pass
        _self_saved[str(path)] = _sha(data)
        _pending.pop(str(path), None)
        _cache.pop(str(path), None)


def mac_key() -> bytes:
    """Ключ для кэша вердиктов. Без прав администратора — пустой."""
    global _key
    if _key is not None:
        return _key
    with _lock:
        if _key is not None:
            return _key
        key = b""
        if enabled():
            path = protected_dir() / "cache.key"
            try:
                key = path.read_bytes()
            except OSError:
                if can_write():
                    try:
                        _trusted_dir(create=True)
                        key = secrets.token_bytes(32)
                        path.write_bytes(key)
                        if not os.environ.get(ENV_DIR):
                            _icacls(str(path), "/inheritance:r", "/grant:r",
                                    "*S-1-5-32-544:F", "*S-1-5-18:F")
                    except OSError:
                        key = b""
        _key = key
        return key


def reset_state() -> None:
    """Для тестов: забыть всё, что помнит процесс."""
    global _key, _admin
    with _lock:
        _self_saved.clear()
        _pending.clear()
        _cache.clear()
        _key = None
        _admin = None
