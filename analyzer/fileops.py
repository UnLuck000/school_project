"""Действия с файлами и папками для страницы «Сканирование папки/файла»: свойства, размер
на диске, владелец, открытие, удаление в Корзину, переименование и белый список с откатом."""
import ctypes
import functools
import hashlib
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from recovery import journal
from recovery.journal import undo_op
from scanner.whitelist import add_to_whitelist, remove_from_whitelist

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def human_size(n: int) -> str:
    for unit in ("байт", "КБ", "МБ", "ГБ"):
        if n < 1024 or unit == "ГБ":
            return f"{n:.0f} {unit}" if unit == "байт" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def _num(n: int) -> str:
    return f"{n:,}".replace(",", " ")


def exact_size(n: int) -> str:
    return f"{human_size(n)} ({_num(n)} байт)"


def fmt_time(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts).strftime("%d.%m.%Y %H:%M:%S")
    except (OSError, ValueError, OverflowError):
        return "—"


# ---------- размер на диске и владелец ----------
_cluster_cache: dict[str, int] = {}


def _cluster_size(path: str) -> int:
    drive = os.path.splitdrive(os.path.abspath(path))[0] + "\\"
    if drive not in _cluster_cache:
        sectors, bytes_per = ctypes.c_ulong(), ctypes.c_ulong()
        free, total = ctypes.c_ulong(), ctypes.c_ulong()
        ok = sys.platform == "win32" and ctypes.windll.kernel32.GetDiskFreeSpaceW(
            drive, ctypes.byref(sectors), ctypes.byref(bytes_per), ctypes.byref(free),
            ctypes.byref(total))
        _cluster_cache[drive] = sectors.value * bytes_per.value if ok else 4096
    return _cluster_cache[drive] or 4096


def size_on_disk(path: str) -> int:
    """Сколько места файл занимает на диске (с учётом сжатия NTFS и размера кластера)."""
    try:
        if sys.platform == "win32":
            high = ctypes.c_ulong()
            kernel = ctypes.windll.kernel32
            kernel.GetCompressedFileSizeW.restype = ctypes.c_ulong
            low = kernel.GetCompressedFileSizeW(str(path), ctypes.byref(high))
            if low == 0xFFFFFFFF and ctypes.GetLastError():
                raise OSError
            size = (high.value << 32) + low
        else:
            size = os.stat(path).st_size
    except OSError:
        size = os.stat(path).st_size
    cluster = _cluster_size(str(path))
    return (size + cluster - 1) // cluster * cluster


def owner(path: str) -> str:
    """Владелец файла (ДОМЕН\\пользователь) или «—»."""
    if sys.platform != "win32":
        return "—"
    from ctypes import wintypes
    adv = ctypes.windll.advapi32
    sid = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    # 1 = SE_FILE_OBJECT, 1 = OWNER_SECURITY_INFORMATION
    adv.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    if adv.GetNamedSecurityInfoW(str(path), 1, 1, ctypes.byref(sid), None, None, None,
                                 ctypes.byref(descriptor)) != 0:
        return "—"
    try:
        name, domain = ctypes.create_unicode_buffer(256), ctypes.create_unicode_buffer(256)
        n_len, d_len, use = wintypes.DWORD(256), wintypes.DWORD(256), wintypes.DWORD()
        adv.LookupAccountSidW.argtypes = [
            wintypes.LPCWSTR, ctypes.c_void_p, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
            wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
        if not adv.LookupAccountSidW(None, sid, name, ctypes.byref(n_len), domain,
                                     ctypes.byref(d_len), ctypes.byref(use)):
            return "—"
        return f"{domain.value}\\{name.value}" if domain.value else name.value
    finally:
        ctypes.windll.kernel32.LocalFree(descriptor)


def file_type(path: str) -> str:
    """Тип файла, как его показывает Проводник («Приложение», «Текстовый документ»...)."""
    return _type_by_ext(os.path.splitext(path)[1].lower())


@functools.lru_cache(maxsize=2048)
def _type_by_ext(ext: str) -> str:
    if not ext:
        return "Файл"
    try:
        from recovery.assoc import ASSOCSTR_FRIENDLYDOCNAME, query_assoc
        return query_assoc(ext, ASSOCSTR_FRIENDLYDOCNAME) or f"Файл «{ext[1:].upper()}»"
    except Exception:
        return f"Файл «{ext[1:].upper()}»"


# ---------- свойства ----------
def file_properties(path: str) -> list[tuple[str, str]]:
    """Медленно (хэши): вызывать не из GUI-потока."""
    st = os.stat(path)
    md5, sha256 = hashlib.md5(usedforsecurity=False), hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(1 << 20):
            md5.update(block)
            sha256.update(block)
    return [
        ("Название", os.path.basename(path)),
        ("Тип файла", file_type(path)),
        ("Полный путь", os.path.abspath(path)),
        ("Размер", exact_size(st.st_size)),
        ("Размер на диске", exact_size(size_on_disk(path))),
        ("SHA-256", sha256.hexdigest()),
        ("MD5", md5.hexdigest()),
        ("Создан", fmt_time(st.st_ctime)),
        ("Изменён", fmt_time(st.st_mtime)),
        ("Владелец", owner(path)),
    ]


def folder_stats(path: str, cancel=None) -> tuple[int, int, int, int]:
    """(файлов, папок, размер, размер на диске) с учётом вложенных папок."""
    files = folders = size = on_disk = 0
    stack = [path]
    while stack:
        if cancel is not None and cancel.is_set():
            break
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    folders += 1
                    stack.append(entry.path)
                elif entry.is_file(follow_symlinks=False):
                    files += 1
                    n = entry.stat(follow_symlinks=False).st_size
                    size += n
                    cluster = _cluster_size(entry.path)
                    on_disk += (n + cluster - 1) // cluster * cluster
            except OSError:
                continue
    return files, folders, size, on_disk


def folder_properties(path: str, cancel=None) -> list[tuple[str, str]]:
    st = os.stat(path)
    files, folders, size, on_disk = folder_stats(path, cancel)
    return [
        ("Название", os.path.basename(os.path.normpath(path)) or path),
        ("Полный путь", os.path.abspath(path)),
        ("Содержит", f"файлов: {_num(files)}, папок: {_num(folders)}"),
        ("Размер", exact_size(size)),
        ("Размер на диске", exact_size(on_disk)),
        ("Создана", fmt_time(st.st_ctime)),
    ]


# ---------- открыть ----------
def open_file(path: str) -> None:
    os.startfile(path)  # программа по ассоциации, как двойной щелчок в Проводнике


def open_as_admin(path: str) -> bool:
    """Запуск с запросом UAC. False, если запрос отклонён."""
    return ctypes.windll.shell32.ShellExecuteW(
        None, "runas", str(path), None, str(Path(path).parent), 1) > 32


def show_in_explorer(path: str) -> None:
    subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])


def open_folder(path: str) -> None:
    subprocess.Popen(["explorer", os.path.normpath(path)])


# ---------- удалить в Корзину ----------
def to_recycle_bin(paths: list[str]) -> None:
    """Перемещает файлы и папки в Корзину (их можно вернуть оттуда)."""
    if sys.platform != "win32":
        raise OSError("Доступно только в Windows")
    from ctypes import wintypes

    class SHFILEOPSTRUCTW(ctypes.Structure):
        _fields_ = [("hwnd", wintypes.HWND), ("wFunc", wintypes.UINT),
                    ("pFrom", wintypes.LPCWSTR), ("pTo", wintypes.LPCWSTR),
                    ("fFlags", ctypes.c_ushort), ("fAnyOperationsAborted", wintypes.BOOL),
                    ("hNameMappings", ctypes.c_void_p), ("lpszProgressTitle", wintypes.LPCWSTR)]

    op = SHFILEOPSTRUCTW()
    op.wFunc = 3  # FO_DELETE
    op.pFrom = "\0".join(os.path.abspath(p) for p in paths) + "\0\0"
    # FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI
    op.fFlags = 0x40 | 0x10 | 0x4 | 0x400
    result = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
    if result != 0 or op.fAnyOperationsAborted:
        raise OSError(f"Не удалось удалить (код {result}): файл занят или нет прав")


# ---------- переименовать (с откатом) ----------
def rename(path: str, new_name: str) -> str:
    if not new_name or any(c in new_name for c in '\\/:*?"<>|'):
        raise ValueError('Имя не может быть пустым и содержать символы \\ / : * ? " < > |')
    target = os.path.join(os.path.dirname(path), new_name)
    if os.path.exists(target):
        raise ValueError(f"«{new_name}» уже существует")
    os.rename(path, target)
    journal.log_action(f"Переименовано: «{os.path.basename(path)}» → «{new_name}»",
                       "file_rename", {"from": path, "to": target})
    return target


@undo_op("file_rename")
def _undo_rename(d: dict) -> str:
    if os.path.exists(d["from"]):
        raise ValueError(f"Имя «{os.path.basename(d['from'])}» уже занято")
    os.rename(d["to"], d["from"])
    return f"Возвращено имя «{os.path.basename(d['from'])}»"


# ---------- карантин (откат регистрирует autoruns.actions) ----------
def quarantine(path: str, reason: str) -> str:
    """Перемещает файл в карантин и пишет действие в журнал. PermissionError: файл занят."""
    import autoruns.actions  # noqa: F401  (регистрирует откат «quarantine_restore»)
    from quarantine import quarantine_file
    item_id = quarantine_file(Path(path), reason=reason)
    journal.log_action(f"Файл «{os.path.basename(path)}» перемещён в карантин",
                       "quarantine_restore", {"id": item_id})
    return item_id


# ---------- белый список (с откатом) ----------
def whitelist_file(path: str) -> bool:
    """Добавляет хэш файла в белый список. False, если он уже был там."""
    sha256 = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    if not add_to_whitelist(sha256, path):
        return False
    journal.log_action(f"Файл «{os.path.basename(path)}» добавлен в белый список",
                       "whitelist_remove", {"sha256": sha256, "path": path})
    return True


@undo_op("whitelist_remove")
def _undo_whitelist(d: dict) -> str:
    remove_from_whitelist(d["sha256"])
    return f"Файл «{os.path.basename(d['path'])}» убран из белого списка"
