r"""AMSI: проверка скриптов перед выполнением (PowerShell, VBScript/JScript, макросы Office).

Бесфайловые атаки не оставляют на диске ничего для проверки файлов: PowerShell получает
команду через -enc, скачивает скрипт в память (IEX (New-Object Net.WebClient)...), макрос
документа собирает команду из кусков. Windows перед выполнением такого содержимого — уже
расшифрованного — вызывает все зарегистрированные провайдеры AMSI (Antimalware Scan
Interface). Наш провайдер — native/amsi/sbit_amsi.cpp (64- и 32-битная библиотека) — передаёт
содержимое сюда по каналу \\.\pipe\sbit-amsi, а AmsiServer отвечает «угроза» или «чисто».

Что считается угрозой (ответ DETECTED — PowerShell не выполнит скрипт):
  * SHA-256 содержимого в базах;
  * попытка отключить сам AMSI (флаг «инициализация не удалась», класс-помощник AMSI в
    PowerShell, правка функции проверки буфера в памяти) — BYPASS_PARTS;
  * правило YARA вредоноса (не «слабое»: PUA, HackTool и низкая оценка — только сообщение).
Подозрительное (слабые правила) — сообщение в журнале защиты, выполнение не мешаем.
Свои запуски PowerShell (родитель — эта программа) не проверяются.

Регистрация (install, нужны права администратора): библиотеки копируются в
%ProgramData%\StretchBIT[-test]\amsi (запись — только администраторам: библиотека грузится и в
процессы с правами администратора) под именем с хэшем — новая версия не мешает старой, ещё
загруженной в запущенный PowerShell; в HKLM пишутся CLSID (64- и 32-битное представление
реестра), ключ AMSI\Providers и список программ-серверов (HKLM\SOFTWARE\StretchBIT\AMSI
Servers): провайдер отдаёт содержимое только им. Отмена — через журнал действий (amsi_unregister)
и при удалении программы (uninstall.py).
"""
import ctypes
import hashlib
import os
import re
import shutil
import sys
import threading
import time
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

from recovery import journal

CLSID = "{946D2B07-6D1A-49DF-AE1B-C626C27B2DF1}"  # то же в native/amsi/sbit_amsi.cpp
PIPE_NAME = r"\\.\pipe\sbit-amsi"
SERVERS_KEY = r"SOFTWARE\StretchBIT\AMSI"
PROVIDERS_KEY = r"SOFTWARE\Microsoft\AMSI\Providers"
CLASSES_KEY = r"SOFTWARE\Classes\CLSID"
BIN_DIR = Path(__file__).resolve().parent.parent / "native" / "amsi" / "bin"
DLLS = {64: "sbit_amsi64.dll", 32: "sbit_amsi32.dll"}
MAGIC_REQUEST = 0x31414253
MAGIC_REPLY = 0x52414253
HEADER = 32           # struct Request в sbit_amsi.cpp
MAX_MESSAGE = 8 * 1024 * 1024 + 256 * 1024   # MAX_CONTENT провайдера + имена
WORKERS = 8           # экземпляров канала: одновременно обслуживаемых запросов
YARA_TIMEOUT = 3      # с: провайдер ждёт ответа 6 с, дольше — скрипт прошёл бы без проверки
EXCERPT = 4000        # сколько символов скрипта показать в журнале защиты
CACHE_SIZE = 4096
# все права, кроме создания своих экземпляров канала (FILE_CREATE_PIPE_INSTANCE): иначе
# любая программа пользователя могла бы встать «вторым сервером» и отвечать «чисто»
PIPE_SDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12018b;;;AU)"

# отключение AMSI из скрипта: так начинаются почти все вредоносные загрузчики PowerShell.
# Строки собираются из частей при запуске: целиком они есть только в памяти. Иначе сам файл
# программы похож на скрипт обхода AMSI, и антивирусы (Defender: BypassAMSI) убирают его.
_AMSI = "am" + "si"
_PATCH = r"(Virtual" + r"Protect|WriteProcess" + r"Memory|Marshal\]?::Copy)"
BYPASS_PARTS = (_AMSI + "Init" + "Failed", _AMSI + "Ut" + "ils", _AMSI + "Con" + "text",
                _AMSI + "Ses" + "sion")
BYPASS_RE = re.compile(
    "|".join(BYPASS_PARTS)
    + "|" + _AMSI + "Scan" + "Buffer" + r"[\s\S]{0,400}" + _PATCH
    + "|" + _PATCH + r"[\s\S]{0,400}" + _AMSI + "Scan" + "Buffer", re.I)
# склейка и экранирование: 'am'+'si…', "a`msi…", "am" + "si…" — без кавычек, плюсов,
# обратных кавычек PowerShell, ^ cmd и пробелов строка снова целая
_SQUASH = re.compile(r"[\s'\"+`^]+")


def squash(text: str) -> str:
    return _SQUASH.sub("", text)


@dataclass
class Verdict:
    level: str      # threat | suspicious | clean
    reason: str = ""


def _decode(data: bytes) -> str:
    """Текст скрипта: PowerShell отдаёт UTF-16LE, WSH и Office — по-разному."""
    sample = data[:4096]
    if len(sample) >= 4 and sample[1::2].count(0) > len(sample) // 4:
        return data.decode("utf-16-le", "replace")
    return data.decode("utf-8", "replace")


def scan_content(data: bytes, name: str = "", signatures=None, rules=None) -> Verdict:
    """Проверка содержимого скрипта (без канала — её же вызывают тесты)."""
    if not data:
        return Verdict("clean")
    from scanner import overrides
    sha = hashlib.sha256(data).hexdigest()
    if signatures and sha in signatures and not overrides.hash_ignored(sha):
        return Verdict("threat", "хэш содержимого в базе сигнатур")
    text = _decode(data)
    bypass = BYPASS_RE.search(text) or BYPASS_RE.search(squash(text))
    if bypass:
        return Verdict("threat", f"попытка отключить AMSI («{bypass.group(0)[:60]}»)")
    if rules is None:
        return Verdict("clean")
    from scanner.relations import weak_match
    from scanner.yara_engine import match_details
    path = Path(name or "script.ps1")
    matches = match_details(rules, path, timeout=YARA_TIMEOUT, data=data)
    utf8 = text.encode("utf-8", "replace")
    if utf8 != data:  # правила пишут строки в ASCII — проверяем и текст
        names = {m.rule for m in matches}
        matches += [m for m in match_details(rules, path, timeout=YARA_TIMEOUT, data=utf8)
                    if m.rule not in names]
    strong = [m.rule for m in matches if not weak_match(m)]
    if strong:
        return Verdict("threat", "правила YARA: " + ", ".join(strong[:5]))
    if matches:
        return Verdict("suspicious", "правила YARA (слабые): " + ", ".join(m.rule for m in matches[:5]))
    return Verdict("clean")


# ---------- канал ----------
PIPE_ACCESS_DUPLEX = 3
FILE_FLAG_OVERLAPPED = 0x40000000
FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
PIPE_TYPE_MESSAGE = 4
PIPE_READMODE_MESSAGE = 2
PIPE_REJECT_REMOTE_CLIENTS = 8
PIPE_UNLIMITED_INSTANCES = 255
ERROR_PIPE_CONNECTED = 535
ERROR_MORE_DATA = 234
ERROR_IO_PENDING = 997
WAIT_TIMEOUT = 258
INVALID_HANDLE = ctypes.c_void_p(-1).value
# Запрос целиком (от подключения до последнего байта) и ответ — не дольше: иначе любая
# программа, подключившись и замолчав, держала бы поток сервера, а провайдер, не дождавшись
# свободного экземпляра, отвечал бы «чисто» (так сервер «усыплялся» четырьмя подключениями).
READ_TIMEOUT = 2.0
WRITE_TIMEOUT = 2.0
PER_CLIENT = 2        # одновременных подключений одного процесса: остальные сразу закрываются


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", wintypes.BOOL)]


class OVERLAPPED(ctypes.Structure):
    _fields_ = [("Internal", ctypes.c_void_p), ("InternalHigh", ctypes.c_void_p),
                ("Offset", wintypes.DWORD), ("OffsetHigh", wintypes.DWORD),
                ("hEvent", wintypes.HANDLE)]


def _kernel32():
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateNamedPipeW.restype = wintypes.HANDLE
    k.CreateNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                   wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                   wintypes.DWORD, ctypes.POINTER(SECURITY_ATTRIBUTES)]
    k.ConnectNamedPipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    k.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                           ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    k.WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                            ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    k.GetNamedPipeClientProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
    k.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    k.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    k.CreateEventW.restype = wintypes.HANDLE
    k.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
    k.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k.WaitForSingleObject.restype = wintypes.DWORD
    k.GetOverlappedResult.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                      ctypes.POINTER(wintypes.DWORD), wintypes.BOOL]
    k.CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    return k


def _user_sid() -> str:
    """SID учётной записи процесса строкой (S-1-5-21-...)."""
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                        ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                           wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        size = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))  # TokenUser
        buf = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 1, buf, size, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid = ctypes.c_void_p.from_buffer(buf).value  # TOKEN_USER.User.Sid
        text = wintypes.LPWSTR()
        if not advapi.ConvertSidToStringSidW(ctypes.c_void_p(sid), ctypes.byref(text)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return text.value
        finally:
            kernel.LocalFree(text)
    finally:
        kernel.CloseHandle(token)


def pipe_sddl(admin: bool) -> str:
    """Права канала. С правами администратора — только PIPE_SDDL. Без них процесс не может
    создавать экземпляры своего же канала (право есть только у администраторов), и сервер
    держал бы один экземпляр; тогда право получает своя учётная запись — у программ этого
    пользователя и так есть власть над процессом без прав (завершить, приостановить)."""
    if admin:
        return PIPE_SDDL
    return PIPE_SDDL + f"(A;;GA;;;{_user_sid()})"


def _security(admin: bool | None = None) -> tuple[SECURITY_ATTRIBUTES, ctypes.c_void_p]:
    if admin is None:
        import trustseal
        admin = trustseal.is_admin()
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    sd = ctypes.c_void_p()
    if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            pipe_sddl(admin), 1, ctypes.byref(sd), None):
        raise ctypes.WinError(ctypes.get_last_error())
    return SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), sd, False), sd


def parse_request(msg: bytes) -> tuple[int, int, str, str, bytes, int] | None:
    """(pid, флаги, приложение, имя содержимого, содержимое, полный размер)."""
    if len(msg) < HEADER:
        return None
    magic, pid, flags, app_len, name_len, content_len = (
        int.from_bytes(msg[i:i + 4], "little") for i in range(0, 24, 4))
    full = int.from_bytes(msg[24:32], "little")
    if magic != MAGIC_REQUEST or HEADER + app_len + name_len + content_len != len(msg):
        return None
    app = msg[HEADER:HEADER + app_len].decode("utf-16-le", "replace")
    name = msg[HEADER + app_len:HEADER + app_len + name_len].decode("utf-16-le", "replace")
    return pid, flags, app, name, msg[HEADER + app_len + name_len:], full


def reply(detected: bool) -> bytes:
    return MAGIC_REPLY.to_bytes(4, "little") + (1 if detected else 0).to_bytes(4, "little")


class AmsiServer:
    """Сервер канала: WORKERS потоков, у каждого свой экземпляр канала. Подключение →
    запрос не дольше READ_TIMEOUT → проверка → ответ не дольше WRITE_TIMEOUT; от одного
    процесса — не больше PER_CLIENT подключений сразу. on_event(сведения) — о каждой угрозе
    и подозрительном."""

    def __init__(self, on_event=None, pipe_name: str = PIPE_NAME, block: bool = True,
                 skip_own: bool = True, admin: bool | None = None):
        self.on_event = on_event or (lambda info: None)
        self.pipe_name = pipe_name
        self.block = block
        self.skip_own = skip_own
        self.admin = admin
        self.scanned = 0
        self.blocked = 0
        self.dropped = 0          # подключений закрыто: молчали или лишние от одного процесса
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._cache: dict[str, Verdict] = {}
        self._bases = None
        self._clients: dict[int, int] = {}
        self._clients_lock = threading.Lock()
        self.error = ""

    def start(self) -> bool:
        if sys.platform != "win32":
            self.error = "только Windows"
            return False
        self._stop.clear()
        self._k = _kernel32()
        self._sa, self._sd = _security(self.admin)
        handle = self._create(first=True)  # первый экземпляр: имя никто не занял до нас
        if handle is None:
            self.error = ("канал sbit-amsi уже создан другой программой (или вторым "
                          "экземпляром StretchBIT)")
            return False
        for i in range(WORKERS):
            t = threading.Thread(target=self._serve, args=(handle if i == 0 else None,),
                                 daemon=True, name=f"amsi-{i}")
            t.start()
            self._threads.append(t)
        return True

    def stop(self) -> None:
        self._stop.set()  # ожидание подключения проверяет флаг раз в 0,5 с
        for t in self._threads:
            t.join(timeout=3)
        self._threads = []
        if getattr(self, "_sd", None):
            ctypes.windll.kernel32.LocalFree(self._sd)
            self._sd = None

    @property
    def running(self) -> bool:
        return bool(self._threads) and not self._stop.is_set()

    def _create(self, first: bool = False):
        mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | (
            FILE_FLAG_FIRST_PIPE_INSTANCE if first else 0)
        h = self._k.CreateNamedPipeW(
            self.pipe_name, mode,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES, 4096, 64 * 1024, 0, ctypes.byref(self._sa))
        return None if not h or h == INVALID_HANDLE else h

    # --- ввод-вывод с ограничением по времени ---
    def _wait(self, h, ov: OVERLAPPED, timeout: float) -> tuple[bool, int, int]:
        """Дождаться операции: (успех, байт, код ошибки). Не дождались — отменить."""
        done = wintypes.DWORD()
        if self._k.WaitForSingleObject(ov.hEvent, max(0, int(timeout * 1000))) != 0:
            self._k.CancelIoEx(h, ctypes.byref(ov))
            self._k.GetOverlappedResult(h, ctypes.byref(ov), ctypes.byref(done), True)
            return False, 0, WAIT_TIMEOUT
        ok = self._k.GetOverlappedResult(h, ctypes.byref(ov), ctypes.byref(done), False)
        return bool(ok), done.value, 0 if ok else ctypes.get_last_error()

    def _io(self, h, write: bool, buf, size: int, timeout: float) -> tuple[bool, int, int]:
        ov = OVERLAPPED()
        ov.hEvent = self._k.CreateEventW(None, True, False, None)
        if not ov.hEvent:
            return False, 0, ctypes.get_last_error()
        try:
            fn = self._k.WriteFile if write else self._k.ReadFile
            if not fn(h, buf, size, None, ctypes.byref(ov)):
                err = ctypes.get_last_error()
                if err not in (ERROR_IO_PENDING, ERROR_MORE_DATA):
                    return False, 0, err
            return self._wait(h, ov, timeout)
        finally:
            self._k.CloseHandle(ov.hEvent)

    def _connect(self, h) -> bool:
        """Ждать подключения, проверяя раз в 0,5 с, не пора ли остановиться."""
        ov = OVERLAPPED()
        ov.hEvent = self._k.CreateEventW(None, True, False, None)
        try:
            if self._k.ConnectNamedPipe(h, ctypes.byref(ov)):
                return True
            err = ctypes.get_last_error()
            if err == ERROR_PIPE_CONNECTED:
                return True
            if err != ERROR_IO_PENDING:
                return False
            while not self._stop.is_set():
                if self._k.WaitForSingleObject(ov.hEvent, 500) == 0:
                    done = wintypes.DWORD()
                    return bool(self._k.GetOverlappedResult(h, ctypes.byref(ov),
                                                            ctypes.byref(done), False))
            self._k.CancelIoEx(h, ctypes.byref(ov))
            done = wintypes.DWORD()
            self._k.GetOverlappedResult(h, ctypes.byref(ov), ctypes.byref(done), True)
            return False
        finally:
            self._k.CloseHandle(ov.hEvent)

    def _read_message(self, h) -> bytes | None:
        """Сообщение целиком за READ_TIMEOUT; None — не успели, ошибка или слишком большое."""
        buf = ctypes.create_string_buffer(64 * 1024)
        parts, total = [], 0
        deadline = time.monotonic() + READ_TIMEOUT
        while True:
            ok, got, err = self._io(h, False, buf, len(buf), deadline - time.monotonic())
            if not ok and err != ERROR_MORE_DATA:
                return None
            parts.append(buf.raw[:got])
            total += got
            if total > MAX_MESSAGE:
                return None
            if ok:
                return b"".join(parts)

    def _admit(self, pid: int) -> bool:
        with self._clients_lock:
            if self._clients.get(pid, 0) >= PER_CLIENT:
                return False
            self._clients[pid] = self._clients.get(pid, 0) + 1
            return True

    def _release(self, pid: int) -> None:
        with self._clients_lock:
            left = self._clients.get(pid, 0) - 1
            if left > 0:
                self._clients[pid] = left
            else:
                self._clients.pop(pid, None)

    def _serve(self, handle) -> None:
        while not self._stop.is_set():
            h = handle or self._create()
            handle = None
            if h is None:
                time.sleep(0.5)
                continue
            pid, admitted = 0, False
            try:
                if not self._connect(h) or self._stop.is_set():
                    continue
                client = wintypes.ULONG()
                self._k.GetNamedPipeClientProcessId(h, ctypes.byref(client))
                pid = client.value
                admitted = self._admit(pid)
                if not admitted:
                    self.dropped += 1
                    continue
                msg = self._read_message(h)
                if msg is None:
                    self.dropped += 1
                    continue
                detected = self._handle(msg, pid)
                data = reply(detected)
                self._io(h, True, data, len(data), WRITE_TIMEOUT)
            except Exception:  # noqa: BLE001 — один запрос не должен остановить сервер
                from diag.log import swallowed
                swallowed("amsi: запрос")
            finally:
                if admitted:
                    self._release(pid)
                self._k.DisconnectNamedPipe(h)
                self._k.CloseHandle(h)

    def _own_child(self, pid: int) -> bool:
        try:
            import psutil
            return psutil.Process(pid).ppid() == os.getpid()
        except Exception:  # noqa: BLE001 — процесс вышел или нет доступа
            return False

    def _bases_now(self):
        if self._bases is None:
            from analyzer.folderview import rules_and_bases
            signatures, rules, _whitelist = rules_and_bases()
            self._bases = (signatures, rules)
        return self._bases

    def reload_bases(self) -> None:
        self._bases = None
        self._cache.clear()

    def _handle(self, msg: bytes, client_pid: int) -> bool:
        parsed = parse_request(msg)
        if parsed is None:
            return False
        _pid, flags, app, name, content, full = parsed
        pid = client_pid or _pid  # PID из ядра, а не из сообщения
        if self.skip_own and self._own_child(pid):
            return False
        self.scanned += 1
        sha = hashlib.sha256(content).hexdigest()
        verdict = self._cache.get(sha)
        if verdict is None:
            signatures, rules = self._bases_now()
            verdict = scan_content(content, name, signatures, rules)
            if len(self._cache) >= CACHE_SIZE:
                self._cache.clear()
            self._cache[sha] = verdict
        if verdict.level == "clean":
            return False
        blocked = verdict.level == "threat" and self.block
        self.blocked += blocked
        text = _decode(content)
        self.on_event({"pid": pid, "app": app, "name": name, "level": verdict.level,
                       "reason": verdict.reason, "blocked": blocked, "sha256": sha,
                       "size": full, "bits": 32 if flags & 1 else 64,
                       "trimmed": bool(flags & 2),
                       "excerpt": text[:EXCERPT] + ("\n..." if len(text) > EXCERPT else "")})
        return blocked


# ---------- регистрация ----------
def dll_sources(bin_dir: Path = BIN_DIR) -> dict[int, Path]:
    return {bits: bin_dir / name for bits, name in DLLS.items() if (bin_dir / name).is_file()}


def install_dir() -> Path:
    import trustseal
    if trustseal.is_admin():
        trustseal.ensure_root()  # корень закрыт от записи до того, как туда лягут библиотеки
    return trustseal.protected_dir() / "amsi"


def server_paths() -> list[str]:
    """Кому провайдер отдаёт содержимое: собранная программа или интерпретатор исходников."""
    return [os.path.normcase(os.path.abspath(sys.executable))]


def registered_servers() -> list[str]:
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SERVERS_KEY, 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            value, _ = winreg.QueryValueEx(key, "Servers")
            return [str(v) for v in value if v]
    except OSError:
        return []


def _reg(bits: int):
    import winreg
    view = winreg.KEY_WOW64_64KEY if bits == 64 else winreg.KEY_WOW64_32KEY
    return winreg, view


def registered() -> dict[int, str]:
    """{разрядность: путь библиотеки} по реестру; пусто — не зарегистрирован."""
    if sys.platform != "win32":
        return {}
    out = {}
    for bits in DLLS:
        winreg, view = _reg(bits)
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rf"{PROVIDERS_KEY}\{CLSID}", 0,
                                winreg.KEY_READ | view):
                pass
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rf"{CLASSES_KEY}\{CLSID}\InprocServer32",
                                0, winreg.KEY_READ | view) as key:
                out[bits] = winreg.QueryValueEx(key, "")[0]
        except OSError:
            continue
    return out


def _secure(folder: Path) -> None:
    import trustseal
    trustseal._icacls(str(folder), "/inheritance:r", "/grant:r", "*S-1-5-32-544:(OI)(CI)F",
                      "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX")


def place(folder: Path, sources: dict[int, Path]) -> dict[int, str]:
    """Копии библиотек в защищённой папке: {разрядность: путь}. Имя предсказуемо (хэш
    публичной сборки) — файл с ним мог подложить кто угодно, пока папка не была закрыта;
    поэтому берётся только файл с тем же содержимым, чужой заменяется."""
    placed = {}
    for bits, src in sources.items():
        digest = _sha256(src)
        target = folder / f"sbit_amsi{bits}-{digest[:12]}.dll"
        if target.exists() and _sha256(target) != digest:
            target.unlink()
        if not target.exists():
            shutil.copy2(src, target)
            if _sha256(target) != digest:
                target.unlink(missing_ok=True)
                raise OSError(f"копия {target.name} не совпала с {src}")
        placed[bits] = str(target)
    return placed


def install(bin_dir: Path = BIN_DIR) -> dict[int, str]:
    """Копирует библиотеки и регистрирует провайдер. PermissionError — нет прав."""
    import winreg
    sources = dll_sources(bin_dir)
    if 64 not in sources:
        raise FileNotFoundError(f"нет {DLLS[64]} в {bin_dir} (python native/amsi/build.py)")
    folder = install_dir()
    folder.mkdir(parents=True, exist_ok=True)
    _secure(folder)
    placed = place(folder, sources)
    previous = registered()
    for bits, dll in placed.items():
        _, view = _reg(bits)
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, rf"{CLASSES_KEY}\{CLSID}", 0,
                                winreg.KEY_WRITE | view) as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, "StretchBIT AMSI Provider")
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE,
                                rf"{CLASSES_KEY}\{CLSID}\InprocServer32", 0,
                                winreg.KEY_WRITE | view) as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, dll)
            winreg.SetValueEx(key, "ThreadingModel", 0, winreg.REG_SZ, "Both")
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, rf"{PROVIDERS_KEY}\{CLSID}", 0,
                                winreg.KEY_WRITE | view) as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, "StretchBIT")
    with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, SERVERS_KEY, 0,
                            winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY) as key:
        # провайдер общий у релизной и тестовой версии: список дополняется, а не заменяется
        servers = [s for s in registered_servers() if server_allowed(s)]
        servers += [s for s in server_paths() if s not in servers]
        winreg.SetValueEx(key, "Servers", 0, winreg.REG_MULTI_SZ, servers)
    if not previous:
        journal.log_action("AMSI: зарегистрирован провайдер проверки скриптов",
                           "amsi_unregister", {"clsid": CLSID})
    cleanup_old(set(placed.values()))
    return placed


def _sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def server_allowed(path: str) -> bool:
    """Оставить ли сервер в списке: файл есть, а у собранной программы — ещё и в папке, которую
    меняют только администраторы. Интерпретатор из venv разработки (папка пользователя) мог бы
    занять канал sbit-amsi, пока служба остановлена, и получать чужие скрипты."""
    if not os.path.isfile(path):
        return False
    if not getattr(sys, "frozen", False):
        return True
    import winacl
    return winacl.admin_only(Path(path))[0]


def registration_ok(bin_dir: Path = BIN_DIR) -> bool:
    """Зарегистрированные библиотеки на месте, в защищённой папке и совпадают с
    библиотеками этой версии, а эта программа — в списке серверов (иначе — зарегистрировать
    заново: после переезда установки провайдер отдавал бы скрипты прежнему пути)."""
    current = registered()
    sources = dll_sources(bin_dir)
    if 64 not in current or not sources:
        return False
    servers = registered_servers()
    known = {os.path.normcase(s) for s in servers}
    if any(os.path.normcase(s) not in known for s in server_paths()):
        return False
    if any(not server_allowed(s) for s in servers):
        return False  # в списке устаревший или небезопасный путь — install() его уберёт
    import trustseal
    folder = os.path.normcase(str(trustseal.protected_dir() / "amsi"))
    for bits, src in sources.items():
        dll = current.get(bits)
        if not dll or os.path.normcase(os.path.dirname(dll)) != folder or \
                not os.path.isfile(dll):
            return False
        try:
            if _sha256(Path(dll)) != _sha256(src):
                return False
        except OSError:
            return False
    return True


def _delete_tree(root, path: str, view: int) -> None:
    import winreg
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ | view) as key:
            subkeys = []
            i = 0
            while True:
                try:
                    subkeys.append(winreg.EnumKey(key, i))
                except OSError:
                    break
                i += 1
        for sub in subkeys:
            _delete_tree(root, rf"{path}\{sub}", view)
        winreg.DeleteKeyEx(root, path, view, 0)
    except FileNotFoundError:
        pass


def uninstall(forget: bool = True) -> None:
    """Снимает регистрацию и удаляет библиотеки (занятые — после перезагрузки).
    forget — убрать запись журнала (снято галочкой в настройках, а не отменой в журнале)."""
    import winreg
    own = set(server_paths())
    others = [s for s in registered_servers() if s not in own and os.path.isfile(s)]
    if others:  # провайдером пользуется и другая версия: убрать только себя из списка
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, SERVERS_KEY, 0,
                                winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY) as key:
            winreg.SetValueEx(key, "Servers", 0, winreg.REG_MULTI_SZ, others)
        if forget:
            journal.forget("amsi_unregister")
        return
    for bits in DLLS:
        _, view = _reg(bits)
        _delete_tree(winreg.HKEY_LOCAL_MACHINE, rf"{PROVIDERS_KEY}\{CLSID}", view)
        _delete_tree(winreg.HKEY_LOCAL_MACHINE, rf"{CLASSES_KEY}\{CLSID}", view)
    _delete_tree(winreg.HKEY_LOCAL_MACHINE, SERVERS_KEY, winreg.KEY_WOW64_64KEY)
    cleanup_old(set())
    if forget:
        journal.forget("amsi_unregister")


def cleanup_old(keep: set[str]) -> None:
    """Старые копии библиотеки: удалить, а загруженные в процессы — при перезагрузке."""
    folder = install_dir()
    if not folder.is_dir():
        return
    for dll in folder.glob("sbit_amsi*.dll"):
        if str(dll) in keep:
            continue
        try:
            dll.unlink()
        except OSError:
            ctypes.windll.kernel32.MoveFileExW(str(dll), None, 4)  # MOVEFILE_DELAY_UNTIL_REBOOT


@journal.undo_op("amsi_unregister")
def _undo_register(_data: dict) -> str:
    uninstall(forget=False)
    from ui import settings as cfg
    cfg.set_("protect/amsi", False)
    return "Провайдер AMSI снят"


@journal.active_check("amsi_unregister")
def _registered_still(_data: dict) -> bool:
    return bool(registered())
