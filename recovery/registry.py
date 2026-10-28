import re
import subprocess

try:
    import winreg
except ImportError:  # не Windows
    winreg = None

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
HKU_PREFIX = "HKU\\"
REG_DWORD = 4


def resolve(hive: str, path: str):
    """(куст, путь) -> (корневой раздел реестра, полный путь).
    Куст: HKCU, HKLM или HKU\\<SID> (раздел другого пользователя)."""
    if hive == "HKCU":
        return winreg.HKEY_CURRENT_USER, path
    if hive == "HKLM":
        return winreg.HKEY_LOCAL_MACHINE, path
    if hive.startswith(HKU_PREFIX):
        return winreg.HKEY_USERS, hive[len(HKU_PREFIX):] + "\\" + path
    raise ValueError(f"Неизвестный куст: {hive}")


def read_value(hive: str, path: str, name: str):
    """(существует, значение, тип)."""
    if winreg is None:
        return False, None, None
    try:
        root, full = resolve(hive, path)
        with winreg.OpenKey(root, full) as key:
            value, reg_type = winreg.QueryValueEx(key, name)
            return True, value, reg_type
    except OSError:
        return False, None, None


def list_values(hive: str, path: str) -> dict:
    """{имя: (значение, тип)} для всех значений раздела."""
    result: dict = {}
    if winreg is None:
        return result
    try:
        root, full = resolve(hive, path)
        key = winreg.OpenKey(root, full)
    except OSError:
        return result
    with key:
        i = 0
        while True:
            try:
                name, value, reg_type = winreg.EnumValue(key, i)
            except OSError:
                break
            result[name] = (value, reg_type)
            i += 1
    return result


def list_subkeys(hive: str, path: str) -> list:
    names: list = []
    if winreg is None:
        return names
    try:
        root, full = resolve(hive, path)
        key = winreg.OpenKey(root, full)
    except OSError:
        return names
    with key:
        i = 0
        while True:
            try:
                names.append(winreg.EnumKey(key, i))
            except OSError:
                break
            i += 1
    return names


def current_sid():
    """SID текущего пользователя или None."""
    try:
        result = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"],
                                capture_output=True, timeout=10, creationflags=NO_WINDOW)
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"S-1-5-21(?:-\d+)+", result.stdout.decode("latin-1", "replace"))
    return match.group(0) if match else None


def hives_to_scan() -> list:
    """HKLM, HKCU и загруженные разделы других пользователей (нужны права администратора)."""
    hives = ["HKLM", "HKCU"]
    sid = current_sid()
    if sid is None or winreg is None:
        return hives
    for name in _users_keys():
        if name.startswith("S-1-5-21") and not name.endswith("_Classes") and name != sid:
            hives.append(HKU_PREFIX + name)
    return hives


def _users_keys() -> list:
    names: list = []
    try:
        with winreg.OpenKey(winreg.HKEY_USERS, "") as key:
            i = 0
            while True:
                try:
                    names.append(winreg.EnumKey(key, i))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return names