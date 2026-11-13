"""WinAPI через ctypes для канала службы: каналы с ожиданием по времени, процессы, маркеры,
дескрипторы файлов. Общее у сервера (служба) и клиента (интерфейс)."""
import ctypes
import os
import sys
import time
from ctypes import wintypes

INVALID_HANDLE = ctypes.c_void_p(-1).value
PIPE_ACCESS_DUPLEX = 3
FILE_FLAG_OVERLAPPED = 0x40000000
FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
PIPE_TYPE_MESSAGE = 4
PIPE_READMODE_MESSAGE = 2
PIPE_REJECT_REMOTE_CLIENTS = 8
PIPE_UNLIMITED_INSTANCES = 255
ERROR_ACCESS_DENIED = 5
ERROR_SHARING_VIOLATION = 32
ERROR_FILE_EXISTS = 80
ERROR_ALREADY_EXISTS = 183
ERROR_BROKEN_PIPE = 109
ERROR_MORE_DATA = 234
ERROR_PIPE_BUSY = 231
ERROR_PIPE_CONNECTED = 535
ERROR_IO_PENDING = 997
WAIT_TIMEOUT = 258
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
DELETE = 0x00010000
FILE_WRITE_DATA = 0x2
FILE_WRITE_ATTRIBUTES = 0x100
FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE = 1, 2, 4
CREATE_NEW, CREATE_ALWAYS, OPEN_EXISTING = 1, 2, 3
SECURITY_SQOS_PRESENT = 0x00100000
SECURITY_IDENTIFICATION = 0x00010000
# права клиента канала: без GENERIC_WRITE — в нём FILE_CREATE_PIPE_INSTANCE, которого у
# пользователей нет (см. scanner/amsi.py: так обычный PowerShell получал «отказано»)
CLIENT_ACCESS = GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES
PROCESS_DUP_HANDLE = 0x0040
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
DUPLICATE_SAME_ACCESS = 2
FILE_TYPE_DISK = 1
FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_DISPOSITION_INFO = 4
TOKEN_QUERY = 0x0008


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", wintypes.BOOL)]


class OVERLAPPED(ctypes.Structure):
    _fields_ = [("Internal", ctypes.c_void_p), ("InternalHigh", ctypes.c_void_p),
                ("Offset", wintypes.DWORD), ("OffsetHigh", wintypes.DWORD),
                ("hEvent", wintypes.HANDLE)]


class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [("dwFileAttributes", wintypes.DWORD), ("ftCreationTime", wintypes.FILETIME),
                ("ftLastAccessTime", wintypes.FILETIME), ("ftLastWriteTime", wintypes.FILETIME),
                ("dwVolumeSerialNumber", wintypes.DWORD), ("nFileSizeHigh", wintypes.DWORD),
                ("nFileSizeLow", wintypes.DWORD), ("nNumberOfLinks", wintypes.DWORD),
                ("nFileIndexHigh", wintypes.DWORD), ("nFileIndexLow", wintypes.DWORD)]


_k = None
_a = None


def k32():
    global _k
    if _k is not None:
        return _k
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    H, D, B = wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL
    k.CreateNamedPipeW.restype = H
    k.CreateNamedPipeW.argtypes = [wintypes.LPCWSTR, D, D, D, D, D, D,
                                   ctypes.POINTER(SECURITY_ATTRIBUTES)]
    k.CreateFileW.restype = H
    k.CreateFileW.argtypes = [wintypes.LPCWSTR, D, D, ctypes.c_void_p, D, D, H]
    k.ConnectNamedPipe.argtypes = [H, ctypes.c_void_p]
    k.ReadFile.argtypes = [H, ctypes.c_void_p, D, ctypes.POINTER(D), ctypes.c_void_p]
    k.WriteFile.argtypes = [H, ctypes.c_void_p, D, ctypes.POINTER(D), ctypes.c_void_p]
    k.GetNamedPipeClientProcessId.argtypes = [H, ctypes.POINTER(wintypes.ULONG)]
    k.GetNamedPipeServerProcessId.argtypes = [H, ctypes.POINTER(wintypes.ULONG)]
    k.SetNamedPipeHandleState.argtypes = [H, ctypes.POINTER(D), ctypes.c_void_p, ctypes.c_void_p]
    k.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, D]
    k.DisconnectNamedPipe.argtypes = [H]
    k.CloseHandle.argtypes = [H]
    k.CreateEventW.restype = H
    k.CreateEventW.argtypes = [ctypes.c_void_p, B, B, wintypes.LPCWSTR]
    k.WaitForSingleObject.argtypes = [H, D]
    k.WaitForSingleObject.restype = D
    k.GetOverlappedResult.argtypes = [H, ctypes.c_void_p, ctypes.POINTER(D), B]
    k.CancelIoEx.argtypes = [H, ctypes.c_void_p]
    k.OpenProcess.restype = H
    k.OpenProcess.argtypes = [D, B, D]
    k.QueryFullProcessImageNameW.argtypes = [H, D, wintypes.LPWSTR, ctypes.POINTER(D)]
    k.GetCurrentProcess.restype = H
    k.GetCurrentThread.restype = H
    k.DuplicateHandle.argtypes = [H, H, H, ctypes.POINTER(H), D, B, D]
    k.GetFileType.argtypes = [H]
    k.GetFileType.restype = D
    k.GetFileInformationByHandle.argtypes = [H, ctypes.POINTER(BY_HANDLE_FILE_INFORMATION)]
    k.GetFinalPathNameByHandleW.argtypes = [H, wintypes.LPWSTR, D, D]
    k.GetFinalPathNameByHandleW.restype = D
    k.SetFileInformationByHandle.argtypes = [H, ctypes.c_int, ctypes.c_void_p, D]
    k.LocalFree.argtypes = [ctypes.c_void_p]
    k.ProcessIdToSessionId.argtypes = [D, ctypes.POINTER(D)]
    _k = k
    return k


def advapi():
    global _a
    if _a is not None:
        return _a
    a = ctypes.WinDLL("advapi32", use_last_error=True)
    H, D = wintypes.HANDLE, wintypes.DWORD
    a.ImpersonateNamedPipeClient.argtypes = [H]
    a.OpenThreadToken.argtypes = [H, D, wintypes.BOOL, ctypes.POINTER(H)]
    a.GetTokenInformation.argtypes = [H, ctypes.c_int, ctypes.c_void_p, D, ctypes.POINTER(D)]
    a.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, D, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    _a = a
    return a


def last_error() -> int:
    return ctypes.get_last_error()


def os_error(code: int | None = None, text: str = "") -> OSError:
    code = last_error() if code is None else code
    err = ctypes.WinError(code)
    if text:
        err = OSError(err.errno, f"{text}: {err.strerror}", None, code)
    return err


# ---------- ввод-вывод с ограничением по времени ----------
def wait_io(h, ov: OVERLAPPED, timeout: float | None, stop=None) -> tuple[bool, int, int]:
    """Дождаться операции: (успех, байт, код). Не дождались или stop — отменить.
    timeout None — без ограничения (проверка stop раз в 0,5 с)."""
    k = k32()
    done = wintypes.DWORD()
    deadline = None if timeout is None else time.monotonic() + timeout
    while True:
        left = 0.5 if deadline is None else max(0.0, min(0.5, deadline - time.monotonic()))
        if k.WaitForSingleObject(ov.hEvent, int(left * 1000)) == 0:
            ok = k.GetOverlappedResult(h, ctypes.byref(ov), ctypes.byref(done), False)
            return bool(ok), done.value, 0 if ok else last_error()
        if (stop is not None and stop.is_set()) or \
                (deadline is not None and time.monotonic() >= deadline):
            k.CancelIoEx(h, ctypes.byref(ov))
            k.GetOverlappedResult(h, ctypes.byref(ov), ctypes.byref(done), True)
            return False, 0, WAIT_TIMEOUT


def io(h, write: bool, buf, size: int, timeout: float | None, stop=None):
    k = k32()
    ov = OVERLAPPED()
    ov.hEvent = k.CreateEventW(None, True, False, None)
    if not ov.hEvent:
        return False, 0, last_error()
    try:
        fn = k.WriteFile if write else k.ReadFile
        if not fn(h, buf, size, None, ctypes.byref(ov)):
            err = last_error()
            if err not in (ERROR_IO_PENDING, ERROR_MORE_DATA):
                return False, 0, err
        return wait_io(h, ov, timeout, stop)
    finally:
        k.CloseHandle(ov.hEvent)


def read_message(h, limit: int, timeout: float | None, stop=None,
                 first_timeout: float | None = None) -> bytes | None:
    """Сообщение канала целиком. None — тайм-аут, разрыв или больше limit.
    first_timeout — сколько ждать начала сообщения (простой подключения), timeout — всё
    сообщение после начала."""
    buf = ctypes.create_string_buffer(64 * 1024)
    parts, total = [], 0
    wait = first_timeout
    while True:
        ok, got, err = io(h, False, buf, len(buf), wait, stop)
        if not ok and err != ERROR_MORE_DATA:
            return None
        parts.append(buf.raw[:got])
        total += got
        if total > limit:
            return None
        if ok:
            return b"".join(parts)
        wait = timeout


def write_message(h, data: bytes, timeout: float) -> bool:
    ok, got, _err = io(h, True, data, len(data), timeout)
    return ok and got == len(data)


# ---------- процессы и маркеры ----------
def process_image(pid: int) -> str:
    k = k32()
    proc = k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not proc:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = wintypes.DWORD(len(buf))
        return buf.value if k.QueryFullProcessImageNameW(proc, 0, buf, ctypes.byref(size)) else ""
    finally:
        k.CloseHandle(proc)


def session_of(pid: int) -> int:
    sid = wintypes.DWORD()
    return sid.value if k32().ProcessIdToSessionId(pid, ctypes.byref(sid)) else -1


def client_pid(h) -> int:
    pid = wintypes.ULONG()
    return pid.value if k32().GetNamedPipeClientProcessId(h, ctypes.byref(pid)) else 0


def server_pid(h) -> int:
    pid = wintypes.ULONG()
    return pid.value if k32().GetNamedPipeServerProcessId(h, ctypes.byref(pid)) else 0


def _token_info(token, kind: int) -> ctypes.Array | None:
    a = advapi()
    size = wintypes.DWORD()
    a.GetTokenInformation(token, kind, None, 0, ctypes.byref(size))
    if not size.value:
        return None
    buf = ctypes.create_string_buffer(size.value)
    if not a.GetTokenInformation(token, kind, buf, size, ctypes.byref(size)):
        return None
    return buf


def sid_string(psid) -> str:
    text = wintypes.LPWSTR()
    if not advapi().ConvertSidToStringSidW(ctypes.c_void_p(psid), ctypes.byref(text)):
        return ""
    try:
        return text.value
    finally:
        k32().LocalFree(text)


def client_identity(h) -> tuple[str, bool]:
    """(SID учётной записи, с правами ли администратора) клиента канала. Нужен хотя бы один
    прочитанный запрос: до этого Windows не даёт войти в маркер клиента. Клиент подключается
    с SECURITY_IDENTIFICATION — служба может только узнать, кто это, но не действовать от его
    имени."""
    a, k = advapi(), k32()
    if not a.ImpersonateNamedPipeClient(h):
        return "", False
    token = wintypes.HANDLE()
    try:
        if not a.OpenThreadToken(k.GetCurrentThread(), TOKEN_QUERY, True, ctypes.byref(token)):
            return "", False
    finally:
        a.RevertToSelf()
    try:
        user = _token_info(token, 1)       # TokenUser
        elev = _token_info(token, 20)      # TokenElevation
        sid = sid_string(ctypes.c_void_p.from_buffer(user).value) if user else ""
        elevated = bool(int.from_bytes(elev.raw[:4], "little")) if elev else False
        return sid, elevated
    finally:
        k.CloseHandle(token)


def current_sid() -> str:
    a, k = advapi(), k32()
    a.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                   ctypes.POINTER(wintypes.HANDLE)]
    token = wintypes.HANDLE()
    if not a.OpenProcessToken(k.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
        return ""
    try:
        user = _token_info(token, 1)
        return sid_string(ctypes.c_void_p.from_buffer(user).value) if user else ""
    finally:
        k.CloseHandle(token)


def security_attributes(sddl: str) -> tuple[SECURITY_ATTRIBUTES, ctypes.c_void_p]:
    sd = ctypes.c_void_p()
    if not advapi().ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(sd), None):
        raise os_error(text="SDDL канала")
    return SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), sd, False), sd


# ---------- дескрипторы файлов клиента ----------
def open_file(path: str, access: int, share: int, disposition: int) -> int:
    """CreateFileW со своими правами (интерфейс). OSError с понятным текстом."""
    h = k32().CreateFileW(str(path), access, share, None, disposition, 0x80, None)
    if not h or h == INVALID_HANDLE:
        code = last_error()
        if code == ERROR_SHARING_VIOLATION:
            raise PermissionError(13, "файл занят другой программой", str(path))
        if code == ERROR_ACCESS_DENIED:
            raise PermissionError(13, "нет прав на файл у этой учётной записи", str(path))
        if code in (ERROR_FILE_EXISTS, ERROR_ALREADY_EXISTS):
            raise FileExistsError(17, "файл уже есть", str(path))
        raise os_error(code, str(path))
    return h


def close(h) -> None:
    if h:
        k32().CloseHandle(h)


def take_handle(pid: int, value: int) -> int:
    """Копия дескриптора value процесса pid в этом процессе (с теми же правами, что у
    клиента: служба получает ровно то, что пользователь открыл сам)."""
    k = k32()
    proc = k.OpenProcess(PROCESS_DUP_HANDLE, False, pid)
    if not proc:
        raise os_error(text="процесс клиента")
    try:
        out = wintypes.HANDLE()
        if not k.DuplicateHandle(proc, wintypes.HANDLE(value), k.GetCurrentProcess(),
                                 ctypes.byref(out), 0, False, DUPLICATE_SAME_ACCESS):
            raise os_error(text="дескриптор клиента")
        return out.value
    finally:
        k.CloseHandle(proc)


def check_disk_file(h) -> None:
    """Дескриптор — обычный файл на диске (не канал, не устройство, не папка)."""
    k = k32()
    if k.GetFileType(h) != FILE_TYPE_DISK:
        raise ValueError("передан не файл на диске")
    info = BY_HANDLE_FILE_INFORMATION()
    if not k.GetFileInformationByHandle(h, ctypes.byref(info)):
        raise os_error(text="сведения о файле")
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY:
        raise ValueError("передана папка, а не файл")


def final_path(h) -> str:
    buf = ctypes.create_unicode_buffer(32768)
    n = k32().GetFinalPathNameByHandleW(h, buf, len(buf), 0)
    if not n or n >= len(buf):
        return ""
    path = buf.value
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[8:]
    return path[4:] if path.startswith("\\\\?\\") else path


def delete_by_handle(h) -> None:
    """Пометить файл на удаление через дескриптор (нужно право DELETE у дескриптора).
    Файл исчезнет, когда закроются все дескрипторы."""
    flag = ctypes.c_ubyte(1)
    if not k32().SetFileInformationByHandle(h, FILE_DISPOSITION_INFO, ctypes.byref(flag), 1):
        raise os_error(text="удаление файла")


def fd_from_handle(h, write: bool) -> int:
    """Номер файла CRT для open(): закрытие файла закроет и дескриптор."""
    import msvcrt
    return msvcrt.open_osfhandle(h, (os.O_WRONLY if write else os.O_RDONLY) | os.O_BINARY)


# ---------- запуск окна в сеансе пользователя ----------
NO_SESSION = 0xFFFFFFFF
CREATE_UNICODE_ENVIRONMENT = 0x00000400


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
                ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
                ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE),
                ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]


def active_session() -> int:
    """Сеанс, который сейчас на экране компьютера, или -1."""
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.WTSGetActiveConsoleSessionId.restype = wintypes.DWORD
    session = k.WTSGetActiveConsoleSessionId()
    return -1 if session == NO_SESSION else session


def launch_in_session(session: int, exe: str, args: str = "") -> int:
    """Запустить программу от имени пользователя, вошедшего в сеанс (без прав
    администратора: маркер сеанса у администратора с UAC — ограниченный). Только для службы
    (LocalSystem): WTSQueryUserToken требует привилегии SeTcbPrivilege. Возвращает PID."""
    H, D = wintypes.HANDLE, wintypes.DWORD
    wts = ctypes.WinDLL("wtsapi32", use_last_error=True)
    userenv = ctypes.WinDLL("userenv", use_last_error=True)
    a = ctypes.WinDLL("advapi32", use_last_error=True)
    wts.WTSQueryUserToken.argtypes = [wintypes.ULONG, ctypes.POINTER(H)]
    userenv.CreateEnvironmentBlock.argtypes = [ctypes.POINTER(ctypes.c_void_p), H, wintypes.BOOL]
    userenv.DestroyEnvironmentBlock.argtypes = [ctypes.c_void_p]
    a.CreateProcessAsUserW.argtypes = [
        H, wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wintypes.BOOL,
        D, ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(STARTUPINFOW),
        ctypes.POINTER(PROCESS_INFORMATION)]
    token = H()
    if not wts.WTSQueryUserToken(session, ctypes.byref(token)):
        raise os_error(text=f"маркер пользователя сеанса {session} не получен")
    env = ctypes.c_void_p()
    try:
        if not userenv.CreateEnvironmentBlock(ctypes.byref(env), token, False):
            env = ctypes.c_void_p()  # без окружения пользователя окно не найдёт %APPDATA%
            raise os_error(text="окружение пользователя не получено")
        startup = STARTUPINFOW()
        startup.cb = ctypes.sizeof(startup)
        startup.lpDesktop = "winsta0\\default"   # рабочий стол пользователя, не службы
        info = PROCESS_INFORMATION()
        command = ctypes.create_unicode_buffer(f'"{exe}" {args}'.strip())
        if not a.CreateProcessAsUserW(token, exe, command, None, None, False,
                                      CREATE_UNICODE_ENVIRONMENT, env, os.path.dirname(exe),
                                      ctypes.byref(startup), ctypes.byref(info)):
            raise os_error(text="окно в сеансе пользователя не запущено")
        k32().CloseHandle(info.hThread)
        k32().CloseHandle(info.hProcess)
        return info.dwProcessId
    finally:
        if env:
            userenv.DestroyEnvironmentBlock(env)
        k32().CloseHandle(token)


def available() -> bool:
    return sys.platform == "win32"
