"""Память процесса глубже: регионы памяти (VirtualQueryEx) и загруженные модули.

Признаки внедрения кода (инъекции):
- приватная память (MEM_PRIVATE) с правом выполнения: код, которого нет ни в одном файле;
- регионы с правами чтение + запись + выполнение (RWX): так часто выглядит распакованный
  или внедрённый код (но так же работают JIT-компиляторы браузеров, .NET и Java);
- заголовок PE («MZ») в приватной памяти: программа загружена вручную, в обход загрузчика;
- образ (MEM_IMAGE), которого нет в списке модулей: модуль скрыт или отображён вручную.
"""
import ctypes
import os
import sys
from dataclasses import dataclass, field

PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY = 0x01, 0x02, 0x04, 0x08
PAGE_EXECUTE, PAGE_EXECUTE_READ = 0x10, 0x20
PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY = 0x40, 0x80
PAGE_GUARD = 0x100
EXEC_MASK = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
WRITE_EXEC = PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
MEM_COMMIT, MEM_FREE, MEM_RESERVE = 0x1000, 0x10000, 0x2000
MEM_PRIVATE, MEM_MAPPED, MEM_IMAGE = 0x20000, 0x40000, 0x1000000
PROCESS_QUERY_INFORMATION, PROCESS_VM_READ = 0x0400, 0x0010
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

TYPE_TEXT = {MEM_PRIVATE: "Приватная", MEM_MAPPED: "Отображённый файл", MEM_IMAGE: "Образ (модуль)"}
STATE_TEXT = {MEM_COMMIT: "Выделена", MEM_RESERVE: "Зарезервирована", MEM_FREE: "Свободна"}
# процессы, которым JIT-компиляция законно нужна: RWX у них не повод для тревоги
JIT_HINTS = ("chrome.exe", "msedge.exe", "firefox.exe", "browser.exe", "opera.exe", "brave.exe",
             "java.exe", "javaw.exe", "node.exe", "electron", "code.exe", "teams", "slack",
             "discord", "spotify", "steamwebhelper", "pwsh.exe", "powershell.exe",
             "dotnet.exe", "msedgewebview2.exe", "claude.exe", "telegram")
JIT_MODULES = {"clr.dll", "coreclr.dll", "clrjit.dll", "mscorwks.dll", "jvm.dll", "libcef.dll",
               "node.dll", "chrome.dll", "msedge.dll", "xul.dll", "v8.dll", "mono-2.0-bdwgc.dll",
               "gameassembly.dll", "jscript9.dll", "chakra.dll", "luajit.dll", "electron.exe"}
SMALL_RWX = 64 * 1024  # байт
USER_DIRS = ("\\appdata\\local\\temp\\", "\\downloads\\", "\\users\\public\\", "\\appdata\\roaming\\")


def protect_text(protect: int) -> str:
    base = protect & 0xFF
    text = {PAGE_NOACCESS: "---", PAGE_READONLY: "R--", PAGE_READWRITE: "RW-",
            PAGE_WRITECOPY: "RC-", PAGE_EXECUTE: "--X", PAGE_EXECUTE_READ: "R-X",
            PAGE_EXECUTE_READWRITE: "RWX", PAGE_EXECUTE_WRITECOPY: "RCX"}.get(base, f"0x{protect:X}")
    if protect & PAGE_GUARD:
        text += " guard"
    return text


@dataclass
class Region:
    base: int
    allocation_base: int
    size: int
    state: int
    protect: int
    allocation_protect: int
    type: int
    mapped_file: str = ""
    has_pe_header: bool = False
    level: str = "normal"            # normal | check | suspicious
    reasons: list[str] = field(default_factory=list)

    @property
    def executable(self) -> bool:
        return self.state == MEM_COMMIT and bool(self.protect & EXEC_MASK) \
            and not self.protect & PAGE_GUARD


@dataclass
class Module:
    path: str
    base: int
    size: int
    sig: str = ""
    sig_status: str = ""
    level: str = "normal"
    reasons: list[str] = field(default_factory=list)


@dataclass
class MemoryReport:
    pid: int
    name: str
    regions: list[Region] = field(default_factory=list)
    modules: list[Module] = field(default_factory=list)
    error: str = ""
    wow64: bool = False

    @property
    def suspicious(self) -> list[Region]:
        return [r for r in self.regions if r.level == "suspicious"]

    def summary(self) -> str:
        if self.error:
            return self.error
        exec_regions = [r for r in self.regions if r.executable]
        private_exec = [r for r in exec_regions if r.type == MEM_PRIVATE]
        rwx = [r for r in exec_regions if r.protect & WRITE_EXEC]
        return (f"Регионов: {len(self.regions)}, исполняемых: {len(exec_regions)}, "
                f"приватных исполняемых: {len(private_exec)}, RWX: {len(rwx)}, "
                f"подозрительных: {len(self.suspicious)}, модулей: {len(self.modules)}")


if sys.platform == "win32":
    from ctypes import wintypes

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wintypes.DWORD), ("PartitionId", wintypes.WORD),
                    ("RegionSize", ctypes.c_size_t), ("State", wintypes.DWORD),
                    ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD)]

    class MODULEINFO(ctypes.Structure):
        _fields_ = [("lpBaseOfDll", ctypes.c_void_p), ("SizeOfImage", wintypes.DWORD),
                    ("EntryPoint", ctypes.c_void_p)]

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _psapi = ctypes.WinDLL("psapi", use_last_error=True)
    _k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _k32.OpenProcess.restype = ctypes.c_void_p
    _k32.CloseHandle.argtypes = [ctypes.c_void_p]
    _k32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                    ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
    _k32.VirtualQueryEx.restype = ctypes.c_size_t
    _k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                       ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    _k32.ReadProcessMemory.restype = wintypes.BOOL
    _k32.IsWow64Process.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL)]
    _k32.IsWow64Process.restype = wintypes.BOOL
    _psapi.GetMappedFileNameW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.LPWSTR,
                                          wintypes.DWORD]
    _psapi.GetMappedFileNameW.restype = wintypes.DWORD
    _psapi.EnumProcessModulesEx.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
                                            wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                            wintypes.DWORD]
    _psapi.EnumProcessModulesEx.restype = wintypes.BOOL
    _psapi.GetModuleFileNameExW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.LPWSTR,
                                            wintypes.DWORD]
    _psapi.GetModuleFileNameExW.restype = wintypes.DWORD
    _psapi.GetModuleInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                            ctypes.POINTER(MODULEINFO), wintypes.DWORD]
    _psapi.GetModuleInformation.restype = wintypes.BOOL


def _device_to_dos(path: str) -> str:
    from processmanager.ntsnap import _device_map
    lower = path.lower()
    for device, letter in _device_map().items():
        if lower.startswith(device + "\\"):
            return letter + path[len(device):]
    return path


def _read(handle, address: int, size: int) -> bytes:
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t()
    if _k32.ReadProcessMemory(handle, ctypes.c_void_p(address), buf, size, ctypes.byref(read)):
        return buf.raw[:read.value]
    return b""


def _regions(handle) -> list[Region]:
    result: list[Region] = []
    mbi = MEMORY_BASIC_INFORMATION()
    address = 0
    limit = 0x7FFFFFFFFFFF if struct_size_is_64() else 0x7FFFFFFF
    name = ctypes.create_unicode_buffer(1024)
    mapped_cache: dict[int, str] = {}
    while address < limit:
        if not _k32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi),
                                   ctypes.sizeof(mbi)):
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize
        if mbi.State != MEM_FREE:
            region = Region(base, mbi.AllocationBase or 0, size, mbi.State, mbi.Protect,
                            mbi.AllocationProtect, mbi.Type)
            if mbi.Type in (MEM_IMAGE, MEM_MAPPED):
                alloc = region.allocation_base
                if alloc not in mapped_cache:
                    n = _psapi.GetMappedFileNameW(handle, ctypes.c_void_p(base), name, 1024)
                    mapped_cache[alloc] = _device_to_dos(name.value[:n]) if n else ""
                region.mapped_file = mapped_cache[alloc]
            if region.executable and mbi.Type == MEM_PRIVATE and base == region.allocation_base:
                region.has_pe_header = _read(handle, base, 2) == b"MZ"
            result.append(region)
        if size == 0:
            break
        address = base + size
    return result


def struct_size_is_64() -> bool:
    return ctypes.sizeof(ctypes.c_void_p) == 8


def _modules(handle) -> list[Module]:
    count = 1024
    while True:
        arr = (ctypes.c_void_p * count)()
        needed = wintypes.DWORD()
        if not _psapi.EnumProcessModulesEx(handle, arr, ctypes.sizeof(arr),
                                           ctypes.byref(needed), 0x03):  # LIST_MODULES_ALL
            return []
        n = needed.value // ctypes.sizeof(ctypes.c_void_p)
        if n <= count:
            break
        count = n + 64
    modules = []
    name = ctypes.create_unicode_buffer(1024)
    info = MODULEINFO()
    for i in range(n):
        h = arr[i]
        length = _psapi.GetModuleFileNameExW(handle, ctypes.c_void_p(h), name, 1024)
        size = 0
        if _psapi.GetModuleInformation(handle, ctypes.c_void_p(h), ctypes.byref(info),
                                       ctypes.sizeof(info)):
            size = info.SizeOfImage
        modules.append(Module(name.value[:length] if length else "?", h or 0, size))
    return modules


def uses_jit(report: MemoryReport) -> bool:
    """Есть ли в процессе среда с JIT-компиляцией: по имени программы или по модулям."""
    if any(hint in report.name.lower() for hint in JIT_HINTS):
        return True
    names = {os.path.basename(m.path).lower() for m in report.modules}
    return bool(names & JIT_MODULES)


def _raise(region: Region, level: str) -> None:
    order = {"normal": 0, "check": 1, "suspicious": 2}
    if order[level] > order[region.level]:
        region.level = level


def _assess(report: MemoryReport) -> None:
    jit = uses_jit(report)
    module_bases = {m.base for m in report.modules}
    for r in report.regions:
        if not r.executable:
            continue
        if r.has_pe_header:
            _raise(r, "suspicious")
            r.reasons.append("заголовок PE в приватной памяти: программа загружена вручную")
        if r.type == MEM_PRIVATE:
            if r.protect & WRITE_EXEC:
                r.reasons.append("приватная память RWX")
                # мелкие RWX-участки создают переходники (ctypes, libffi, перехватчики окон)
                _raise(r, "suspicious" if not jit and r.size > SMALL_RWX else "check")
            else:
                r.reasons.append("приватная исполняемая память")
                _raise(r, "check")
        elif r.type == MEM_MAPPED and not r.mapped_file:
            r.reasons.append("исполняемое отображение без файла")
            _raise(r, "check")
        elif r.type == MEM_IMAGE:
            if r.protect & PAGE_EXECUTE_READWRITE:
                r.reasons.append("секция модуля стала RWX (возможна правка кода в памяти)")
                _raise(r, "check" if jit else "suspicious")
            if report.modules and r.allocation_base not in module_bases:
                r.reasons.append("образ не числится в списке модулей (скрыт или загружен вручную)")
                _raise(r, "check")
    if jit:
        for r in report.regions:
            if r.reasons and r.level == "check":
                r.reasons.append("у программ с JIT (браузеры, .NET, Java) это обычно норма")


def assess_modules(modules: list[Module]) -> None:
    """Подписи модулей. Медленно: вызывать из фонового потока."""
    from pathlib import Path
    from scanner.signature import describe, inspect_signature
    cache: dict[str, tuple] = {}
    for m in modules:
        key = os.path.normcase(m.path)
        if key not in cache:
            try:
                info = inspect_signature(Path(m.path))
                cache[key] = (describe(info) or "—", info.status)
            except Exception:
                cache[key] = ("—", "")
        m.sig, m.sig_status = cache[key]
        low = key.lower()
        if m.sig_status == "invalid":
            m.level = "suspicious"
            m.reasons.append("подпись недействительна")
        elif m.sig_status == "unsigned":
            m.level = "check"
            m.reasons.append("нет подписи")
        if any(d in low for d in USER_DIRS):
            m.reasons.append("загружен из пользовательской или временной папки")
            m.level = "suspicious" if m.sig_status != "valid" else "check"
        if not os.path.exists(m.path):
            m.reasons.append("файл модуля не найден на диске")
            m.level = "suspicious"


def read_region(pid: int, address: int, size: int) -> tuple[bytes, str]:
    """(байты, ошибка): начало региона памяти процесса для просмотра."""
    if sys.platform != "win32":
        return b"", "Доступно только в Windows"
    handle = _k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        return b"", "Нет доступа к памяти процесса (нужны права администратора)"
    try:
        data = _read(handle, address, size)
    finally:
        _k32.CloseHandle(handle)
    return data, "" if data else "Память не читается (страница защищена или освобождена)"


def inspect_process(pid: int, name: str = "", with_modules: bool = True) -> MemoryReport:
    """Регионы и модули процесса. Вызывать не из GUI-потока."""
    report = MemoryReport(pid, name)
    if sys.platform != "win32":
        report.error = "Доступно только в Windows"
        return report
    if pid in (0, 4):
        report.error = "У системных процессов System и Idle нет пользовательской памяти"
        return report
    handle = _k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        handle = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            report.error = ("Нет доступа к процессу (нужны права администратора, "
                            "или это защищённый процесс)")
            return report
    try:
        flag = wintypes.BOOL()
        report.wow64 = bool(_k32.IsWow64Process(handle, ctypes.byref(flag)) and flag.value)
        report.regions = _regions(handle)
        if with_modules:
            report.modules = _modules(handle)
        if not report.regions:
            report.error = "Не удалось прочитать карту памяти (процесс защищён или завершился)"
    finally:
        _k32.CloseHandle(handle)
    _assess(report)
    return report
