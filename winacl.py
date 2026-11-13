r"""Кто может менять файл: только администраторы и система — или кто-то ещё.

Программа работает с правами администратора и загружает чужие библиотеки (WinDivert.dll из
папки zapret) и запускает чужие программы (xray.exe по пути из настроек). Если в файл или в
его папку может писать обычный пользователь, любая программа без прав подменит его — и её код
выполнится с правами администратора. admin_only() проверяет список доступа (DACL) файла,
папки и папок выше:
  * сам файл — запись, удаление, смена прав или владельца;
  * его папка — добавление файлов, удаление вложенного, смена прав или владельца;
  * папки выше — удаление вложенного, смена прав или владельца (переименовать папку и
    положить на её место свою); создавать в них новые папки можно (C:\ это разрешает всем);
  * владелец везде — администраторы, система или TrustedInstaller (владелец может вернуть
    себе любые права).
Права, наследуемые только вложенными объектами (INHERIT_ONLY), к самому объекту не относятся.
"""
import ctypes
import os
import sys
from ctypes import wintypes
from pathlib import Path

TRUSTED = {"S-1-5-18",                 # система
           "S-1-5-32-544",             # администраторы
           "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"}  # TrustedInstaller
FILE_WRITE_DATA, FILE_APPEND_DATA, FILE_WRITE_EA = 0x2, 0x4, 0x10
FILE_DELETE_CHILD, DELETE, WRITE_DAC, WRITE_OWNER = 0x40, 0x10000, 0x40000, 0x80000
GENERIC_ALL, GENERIC_WRITE = 0x10000000, 0x40000000
TAKE_OVER = WRITE_DAC | WRITE_OWNER | GENERIC_ALL
FILE_MASK = FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | TAKE_OVER | GENERIC_WRITE
FOLDER_MASK = FILE_WRITE_DATA | FILE_DELETE_CHILD | TAKE_OVER | GENERIC_WRITE  # 0x2 — новый файл
ANCESTOR_MASK = FILE_DELETE_CHILD | TAKE_OVER
INHERIT_ONLY = 0x08


class _AclSize(ctypes.Structure):
    _fields_ = [("AceCount", wintypes.DWORD), ("AclBytesInUse", wintypes.DWORD),
                ("AclBytesFree", wintypes.DWORD)]


def _api():
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p)]
    advapi.GetAclInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD,
                                         ctypes.c_int]
    advapi.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    return advapi


def _sid(advapi, psid) -> str:
    text = wintypes.LPWSTR()
    if not advapi.ConvertSidToStringSidW(psid, ctypes.byref(text)):
        return "?"
    try:
        return text.value
    finally:
        ctypes.windll.kernel32.LocalFree(text)


def access(path) -> tuple[str, list[tuple[str, int]]] | None:
    """(владелец, [(SID, права) разрешающих записей, действующих на сам объект]); None — не
    удалось прочитать (нет файла или доступа). Пустой список DACL (NULL) — всем всё."""
    advapi = _api()
    owner, dacl, sd = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    err = advapi.GetNamedSecurityInfoW(str(path), 1, 0x1 | 0x4, ctypes.byref(owner), None,
                                       ctypes.byref(dacl), None, ctypes.byref(sd))
    if err:
        return None
    try:
        owner_sid = _sid(advapi, owner)
        if not dacl.value:
            return owner_sid, [("S-1-1-0", GENERIC_ALL)]
        info = _AclSize()
        advapi.GetAclInformation(dacl, ctypes.byref(info), ctypes.sizeof(info), 2)
        allowed = []
        for i in range(info.AceCount):
            ace = ctypes.c_void_p()
            if not advapi.GetAce(dacl, i, ctypes.byref(ace)):
                continue
            kind, flags = ctypes.c_ubyte.from_address(ace.value).value, \
                ctypes.c_ubyte.from_address(ace.value + 1).value
            if kind != 0 or flags & INHERIT_ONLY:  # ACCESS_ALLOWED_ACE, действует на объект
                continue
            mask = wintypes.DWORD.from_address(ace.value + 4).value
            allowed.append((_sid(advapi, ctypes.c_void_p(ace.value + 8)), mask))
        return owner_sid, allowed
    finally:
        ctypes.windll.kernel32.LocalFree(sd)


def _problem(path: Path, mask: int, what: str) -> str:
    got = access(path)
    if got is None:
        return f"не удалось прочитать права {what} {path}"
    owner, allowed = got
    if owner not in TRUSTED:
        return f"владелец {what} {path} — не администраторы ({owner})"
    for sid, rights in allowed:
        if sid not in TRUSTED and rights & mask:
            return f"менять {what} {path} может не только администратор ({sid})"
    return ""


def admin_only(path) -> tuple[bool, str]:
    """(True, "") — файл и путь до него меняют только администраторы и система; иначе
    (False, причина)."""
    if sys.platform != "win32":
        return True, ""
    path = Path(os.path.abspath(path))
    reason = _problem(path, FILE_MASK, "файла") or _problem(path.parent, FOLDER_MASK, "папки")
    if reason:
        return False, reason
    for folder in list(path.parent.parents):
        reason = _problem(folder, ANCESTOR_MASK, "папки")
        if reason:
            return False, reason
    return True, ""
