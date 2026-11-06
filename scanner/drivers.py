"""Уязвимые и вредоносные драйверы (BYOVD — «принеси свой уязвимый драйвер»).

Вредонос с правами администратора ставит старый подписанный драйвер с известной уязвимостью
(чтение и запись памяти ядра) и через него выключает антивирусы и защиту Windows. Подпись
у такого драйвера настоящая, поэтому проверка подписи его не ловит: нужен список известных
уязвимых драйверов — база LOLDrivers (loldrivers.io), её скачивает updater.py drivers в
signatures/feeds/loldrivers.tsv.

Какие драйверы смотрим:
• службы-драйверы из реестра (HKLM\\SYSTEM\\CurrentControlSet\\Services, Type 1 и 2) и их
  состояние (EnumServicesStatusExW: запущен ли);
• все .sys в System32\\drivers (драйвер может лежать без службы);
• с правами администратора — загруженные в ядро модули (EnumDeviceDrivers).
Сравнение: SHA-256 файла и Authenticode-хэш (Authentihash: хэш PE без поля контрольной
суммы, записи каталога сертификатов и самих сертификатов — совпадает и у переподписанного
драйвера). Совпадение только по имени файла — слабый признак, и только вне папки Windows.
"""
import ctypes
import hashlib
import os
import struct
import sys
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path

from recovery import journal

DB_FILE = Path("signatures/feeds/loldrivers.tsv")
SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"
START_TEXT = {0: "при загрузке", 1: "системный", 2: "автоматически", 3: "вручную",
              4: "отключён"}
MATCH_HASH, MATCH_AUTH, MATCH_NAME = "hash", "authentihash", "name"


@dataclass
class DbEntry:
    category: str     # vulnerable driver | malicious
    name: str
    description: str


@dataclass
class Driver:
    path: str
    service: str = ""        # имя службы
    display: str = ""
    start: int | None = None
    running: bool = False
    loaded: bool = False     # виден в EnumDeviceDrivers (только с правами администратора)
    sha256: str = ""
    match: str = ""          # hash | authentihash | name | ""
    entry: DbEntry | None = None
    error: str = ""
    excluded: bool = False   # пользователь доверяет (исключения, категория drivers)

    @property
    def name(self) -> str:
        return os.path.basename(self.path)

    @property
    def level(self) -> str:
        """danger (уязвимый или вредоносный по хэшу), warning (только имя), clean."""
        if self.entry is None or self.excluded:
            return "clean"
        return "warning" if self.match == MATCH_NAME else "danger"

    def verdict(self) -> str:
        if self.excluded and self.entry is not None:
            return f"В исключениях (в базе: {self.entry.category}, {self.entry.name})"
        if self.entry is None:
            return "Нет в базе уязвимых драйверов"
        kind = "Вредоносный драйвер" if self.entry.category == "malicious" else \
            "Уязвимый драйвер"
        if self.match == MATCH_NAME:
            return f"Имя совпадает с уязвимым драйвером {self.entry.name} (хэш другой)"
        how = "хэш файла" if self.match == MATCH_HASH else "Authenticode-хэш"
        return f"{kind} ({how} в базе LOLDrivers)"


@dataclass
class Database:
    by_hash: dict[str, DbEntry] = field(default_factory=dict)
    by_auth: dict[str, DbEntry] = field(default_factory=dict)
    by_name: dict[str, DbEntry] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.by_hash)


def load_db(path: Path = DB_FILE) -> Database:
    """Строки «sha256 \\t authentihash \\t категория \\t имя \\t описание»."""
    db = Database()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return db
    for line in lines:
        if not line or line.startswith("#"):
            continue
        parts = (line.split("\t") + [""] * 5)[:5]
        sha, auth, category, name, desc = parts
        entry = DbEntry(category, name, desc)
        if sha:
            db.by_hash[sha.lower()] = entry
        if auth:
            db.by_auth[auth.lower()] = entry
        if name:
            db.by_name.setdefault(name.lower(), entry)
    return db


def convert_loldrivers(items: list[dict]) -> str:
    """drivers.json с loldrivers.io → компактная таблица для load_db."""
    rows = ["# LOLDrivers: sha256\tauthentihash\tcategory\tname\tdescription"]
    for item in items:
        category = (item.get("Category") or "").lower()
        tags = item.get("Tags") or []
        commands = item.get("Commands") or {}
        desc = commands.get("Description", "") if isinstance(commands, dict) else ""
        desc = " ".join(str(desc).split())[:300]
        for sample in item.get("KnownVulnerableSamples") or []:
            sha = str(sample.get("SHA256") or "").lower()
            auth = sample.get("Authentihash") or {}
            auth = str(auth.get("SHA256") or "").lower() if isinstance(auth, dict) else ""
            evidence = sample.get("ResearchEvidence") or {}
            name = (evidence.get("Filename") if isinstance(evidence, dict) else "") or \
                (tags[0] if tags else "")
            if sha or auth:
                rows.append("\t".join((sha, auth, category, str(name).lower(), desc)))
    return "\n".join(rows) + "\n"


# ---------- Authentihash ----------
def authentihash(data: bytes) -> str:
    """SHA-256 Authenticode: PE без CheckSum, без записи IMAGE_DIRECTORY_ENTRY_SECURITY и
    без самих сертификатов. Пустая строка, если это не PE."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return ""
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        return ""
    opt = pe + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    dirs = opt + (96 if magic == 0x10B else 112)  # PE32 / PE32+
    checksum = opt + 64
    security = dirs + 4 * 8
    if security + 8 > len(data):
        return ""
    cert_off, cert_size = struct.unpack_from("<II", data, security)
    h = hashlib.sha256()
    h.update(data[:checksum])
    h.update(data[checksum + 4:security])
    if cert_off and cert_size and cert_off <= len(data):
        h.update(data[security + 8:cert_off])
        h.update(data[cert_off + cert_size:])
    else:
        h.update(data[security + 8:])
    return h.hexdigest()


# ---------- список драйверов ----------
def _system_root() -> str:
    return os.environ.get("SystemRoot", r"C:\Windows")


def resolve_path(image: str) -> str:
    r"""ImagePath службы → обычный путь: \SystemRoot\..., system32\..., \??\C:\..."""
    path = os.path.expandvars(image.strip().strip('"'))
    low = path.lower()
    root = _system_root()
    if low.startswith("\\systemroot\\"):
        path = root + path[len("\\systemroot"):]
    elif low.startswith("\\??\\"):
        path = path[4:]
    elif low.startswith("system32\\") or low.startswith("syswow64\\"):
        path = os.path.join(root, path)
    elif not os.path.isabs(path):
        path = os.path.join(root, "System32", "drivers", path)
    return os.path.normpath(path)


def _services() -> list[Driver]:
    try:
        import winreg
    except ImportError:
        return []
    found = []
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SERVICES_KEY)
    except OSError:
        return []
    with root:
        i = 0
        while True:
            try:
                name = winreg.EnumKey(root, i)
            except OSError:
                break
            i += 1
            try:
                with winreg.OpenKey(root, name) as key:
                    kind = winreg.QueryValueEx(key, "Type")[0]
                    if kind not in (1, 2):  # SERVICE_KERNEL_DRIVER, SERVICE_FILE_SYSTEM_DRIVER
                        continue
                    try:
                        image = winreg.QueryValueEx(key, "ImagePath")[0]
                    except OSError:
                        image = f"System32\\drivers\\{name}.sys"
                    try:
                        start = winreg.QueryValueEx(key, "Start")[0]
                    except OSError:
                        start = None
                    try:
                        display = winreg.QueryValueEx(key, "DisplayName")[0]
                    except OSError:
                        display = ""
            except OSError:
                continue
            if display.startswith("@"):
                display = ""  # ссылка на ресурс: «@%SystemRoot%\...dll,-100»
            found.append(Driver(resolve_path(image), name, display, start))
    return found


class ENUM_SERVICE_STATUS_PROCESSW(ctypes.Structure):
    _fields_ = [("lpServiceName", wintypes.LPWSTR), ("lpDisplayName", wintypes.LPWSTR),
                ("dwServiceType", wintypes.DWORD), ("dwCurrentState", wintypes.DWORD),
                ("dwControlsAccepted", wintypes.DWORD), ("dwWin32ExitCode", wintypes.DWORD),
                ("dwServiceSpecificExitCode", wintypes.DWORD), ("dwCheckPoint", wintypes.DWORD),
                ("dwWaitHint", wintypes.DWORD), ("dwProcessId", wintypes.DWORD),
                ("dwServiceFlags", wintypes.DWORD)]


def running_driver_services() -> set[str]:
    """Имена запущенных служб-драйверов (нижний регистр). Права администратора не нужны."""
    if sys.platform != "win32":
        return set()
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.OpenSCManagerW.restype = ctypes.c_void_p
    advapi.EnumServicesStatusExW.argtypes = [
        ctypes.c_void_p, ctypes.c_int, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD), wintypes.LPCWSTR]
    advapi.CloseServiceHandle.argtypes = [ctypes.c_void_p]
    scm = advapi.OpenSCManagerW(None, None, 0x0004)  # SC_MANAGER_ENUMERATE_SERVICE
    if not scm:
        return set()
    try:
        needed, count, resume = wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD(0)
        # SC_ENUM_PROCESS_INFO, SERVICE_DRIVER (0xB), SERVICE_ACTIVE (1)
        advapi.EnumServicesStatusExW(scm, 0, 0xB, 1, None, 0, ctypes.byref(needed),
                                     ctypes.byref(count), ctypes.byref(resume), None)
        buf = ctypes.create_string_buffer(needed.value + 4096)
        resume = wintypes.DWORD(0)
        if not advapi.EnumServicesStatusExW(scm, 0, 0xB, 1, buf, len(buf), ctypes.byref(needed),
                                            ctypes.byref(count), ctypes.byref(resume), None):
            return set()
        items = ctypes.cast(buf, ctypes.POINTER(ENUM_SERVICE_STATUS_PROCESSW))
        return {items[i].lpServiceName.lower() for i in range(count.value)}
    finally:
        advapi.CloseServiceHandle(scm)


def loaded_modules() -> set[str]:
    """Пути модулей ядра (EnumDeviceDrivers). Без прав администратора адреса скрыты — пусто."""
    if sys.platform != "win32":
        return set()
    psapi = ctypes.WinDLL("psapi")
    psapi.GetDeviceDriverFileNameW.argtypes = [ctypes.c_void_p, wintypes.LPWSTR,
                                               wintypes.DWORD]
    arr = (ctypes.c_void_p * 4096)()
    needed = wintypes.DWORD()
    if not psapi.EnumDeviceDrivers(arr, ctypes.sizeof(arr), ctypes.byref(needed)):
        return set()
    bases = [arr[i] for i in range(min(4096, needed.value // ctypes.sizeof(ctypes.c_void_p)))]
    if not any(bases):
        return set()
    buf = ctypes.create_unicode_buffer(1024)
    result = set()
    for base in bases:
        if base and psapi.GetDeviceDriverFileNameW(base, buf, 1024):
            result.add(os.path.normcase(resolve_path(buf.value)))
    return result


def list_drivers() -> list[Driver]:
    by_path: dict[str, Driver] = {}
    running = running_driver_services()
    for d in _services():
        d.running = d.service.lower() in running
        by_path.setdefault(os.path.normcase(d.path), d)
    folder = Path(_system_root()) / "System32" / "drivers"
    try:
        for p in folder.glob("*.sys"):
            by_path.setdefault(os.path.normcase(str(p)), Driver(str(p)))
    except OSError:
        pass
    loaded = loaded_modules()
    for path in loaded:
        if path.endswith(".sys"):
            by_path.setdefault(path, Driver(path))
    for key, d in by_path.items():
        d.loaded = key in loaded
    return sorted(by_path.values(), key=lambda d: d.name.lower())


def _name_match(driver: Driver, db: Database) -> DbEntry | None:
    """Совпадение только по имени — для файлов вне папки Windows: системные драйверы
    (afd.sys, csc.sys) делят имена с уязвимыми сборками сторонних программ."""
    windows = os.path.normcase(_system_root()) + os.sep
    if os.path.normcase(driver.path).startswith(windows):
        return None
    return db.by_name.get(driver.name.lower())


def excluded_hashes() -> set[str]:
    """SHA-256 драйверов, которым пользователь доверяет (попадают в релиз)."""
    from scanner import exclusions
    return set(exclusions.load().get("drivers", {}))


def exclude(driver: Driver) -> None:
    from scanner import exclusions
    exclusions.add("drivers", driver.sha256, driver.name,
                   f"{driver.path} — {driver.verdict()}")
    driver.excluded = True


def include(driver: Driver) -> None:
    from scanner import exclusions
    exclusions.remove("drivers", driver.sha256)
    driver.excluded = False


def check(driver: Driver, db: Database, excluded: set[str] | None = None) -> Driver:
    driver = _check(driver, db)
    driver.excluded = bool(excluded and driver.sha256 in excluded)
    return driver


def _check(driver: Driver, db: Database) -> Driver:
    try:
        data = Path(driver.path).read_bytes()
    except OSError as e:
        driver.error = e.strerror or str(e)
        entry = _name_match(driver, db)
        if entry:
            driver.entry, driver.match = entry, MATCH_NAME
        return driver
    driver.sha256 = hashlib.sha256(data).hexdigest()
    entry = db.by_hash.get(driver.sha256)
    if entry:
        driver.entry, driver.match = entry, MATCH_HASH
        return driver
    auth = authentihash(data)
    if auth and auth in db.by_auth:
        driver.entry, driver.match = db.by_auth[auth], MATCH_AUTH
        return driver
    entry = _name_match(driver, db)
    if entry:
        driver.entry, driver.match = entry, MATCH_NAME
    return driver


def blocklist_status() -> dict[str, bool | None]:
    """Встроенная защита Windows: список блокировки уязвимых драйверов Microsoft и HVCI
    (целостность памяти). None — не удалось прочитать."""
    result: dict[str, bool | None] = {"blocklist": None, "hvci": None}
    try:
        import winreg
    except ImportError:
        return result
    for key, path, value, default in (
            ("blocklist", r"SYSTEM\CurrentControlSet\Control\CI\Config",
             "VulnerableDriverBlocklistEnable", True),  # в Windows 11 включён по умолчанию
            ("hvci", r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios"
                     r"\HypervisorEnforcedCodeIntegrity", "Enabled", False)):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as k:
                result[key] = bool(winreg.QueryValueEx(k, value)[0])
        except FileNotFoundError:
            result[key] = default
        except OSError:
            pass
    return result


# ---------- действия ----------
def disable_service(service: str) -> str:
    """Start = 4 (отключён): драйвер не загрузится при следующем запуске Windows.
    Нужны права администратора. Пишется в журнал с откатом."""
    import winreg
    path = SERVICES_KEY + "\\" + service
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                        winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
        old = winreg.QueryValueEx(key, "Start")[0]
        if old == 4:
            return f"Служба {service} уже отключена"
        winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 4)
    journal.log_action(f"Отключена служба драйвера {service} (запуск был: "
                       f"{START_TEXT.get(old, old)})", "driver_enable",
                       {"service": service, "start": old})
    return (f"Служба драйвера {service} отключена. Если драйвер уже загружен, он выгрузится "
            "после перезагрузки компьютера.")


@journal.undo_op("driver_enable")
def _undo_disable(d: dict) -> str:
    import winreg
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SERVICES_KEY + "\\" + d["service"], 0,
                        winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, int(d["start"]))
    return f"Служба драйвера {d['service']} снова включена ({START_TEXT.get(d['start'])})"
