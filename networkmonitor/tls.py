"""Начало TLS-соединений: имя сайта (SNI) и отпечаток клиента JA3 через WinDivert.

Содержимое HTTPS зашифровано, но первое сообщение клиента (ClientHello) идёт открытым:
в нём имя сайта (SNI) и набор шифров, расширений и кривых. JA3 — md5 от этих списков:
у одной и той же программы он одинаковый, а у многих вредоносов свой, узнаваемый
(список SSLBL). QUIC (HTTP/3 по UDP) шифрует даже начало соединения, его здесь не видно.

WinDivert открывается в режиме «только смотреть» (SNIFF | RECV_ONLY): пакеты не
задерживаются и не меняются, другие программы на WinDivert (например, zapret) не мешают.
Нужны права администратора и WinDivert.dll с драйвером WinDivert64.sys рядом.

Чья программа: у пакета (уровень NETWORK) процесса нет — как и в Wireshark, который видит
пакеты на уровне сетевой карты. Поэтому второй дескриптор WinDivert слушает уровень SOCKET
(фильтрующая платформа Windows, WFP): событие CONNECT приходит при вызове connect(), ещё до
первого пакета, и в нём PID программы. Локальный порт -> PID запоминается (SocketMap), и
ClientHello с этого порта получает программу наверняка, даже если соединение уже закрыто.
Запасной путь (старый WinDivert без уровня SOCKET) — таблица соединений psutil.
"""
import ctypes
import glob
import hashlib
import os
import struct
import sys
import threading
import time
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

import psutil

PROJECT_DIR = Path(__file__).resolve().parent.parent
# только исходящие TCP на 443 с данными, первый байт — TLS Handshake (22): это ClientHello
FILTER = b"outbound and tcp.DstPort == 443 and tcp.PayloadLength > 5 and tcp.Payload[0] == 22"
WINDIVERT_LAYER_NETWORK = 0
WINDIVERT_LAYER_SOCKET = 3
# connect() по TCP к порту 443 (и QUIC тоже не нужен: ClientHello только по TCP)
SOCKET_FILTER = b"event == CONNECT and tcp and remotePort == 443 and not loopback"
WINDIVERT_FLAG_SNIFF = 0x0001
WINDIVERT_FLAG_RECV_ONLY = 0x0004
ADDRESS_SIZE = 80          # WINDIVERT_ADDRESS (версия 2)
MAX_PACKET = 0xFFFF
GREASE = {0x0A0A + 0x1010 * i for i in range(16)}  # «мусорные» значения, в JA3 не входят


@dataclass(frozen=True)
class ClientHello:
    sni: str
    ja3: str          # md5
    ja3_text: str     # строка, из которой md5
    alpn: str = ""


@dataclass(frozen=True)
class TlsEvent:
    time: float
    pid: int
    name: str
    exe: str
    remote: str       # ip:443
    hello: ClientHello


# ---------- разбор ClientHello ----------
def parse_client_hello(data: bytes) -> ClientHello | None:
    """Полезная нагрузка TCP с началом TLS -> ClientHello. None — не ClientHello или
    сообщение разрезано на несколько пакетов (бывает при больших ClientHello)."""
    try:
        if len(data) < 9 or data[0] != 22 or data[5] != 1:  # Handshake, ClientHello
            return None
        pos = 9
        version = struct.unpack_from(">H", data, pos)[0]
        pos += 2 + 32                                 # версия, random
        pos += 1 + data[pos]                          # session id
        n = struct.unpack_from(">H", data, pos)[0]
        pos += 2
        ciphers = [c for c in struct.unpack_from(f">{n // 2}H", data, pos) if c not in GREASE]
        pos += n
        pos += 1 + data[pos]                          # методы сжатия
        if pos + 2 > len(data):
            return None
        end = pos + 2 + struct.unpack_from(">H", data, pos)[0]
        pos += 2
        if end > len(data):
            return None
        extensions, curves, formats, sni, alpn = [], [], [], "", ""
        while pos + 4 <= end:
            ext, size = struct.unpack_from(">HH", data, pos)
            body = data[pos + 4:pos + 4 + size]
            pos += 4 + size
            if ext in GREASE:
                continue
            extensions.append(ext)
            if ext == 0 and len(body) > 5:            # server_name
                name_len = struct.unpack_from(">H", body, 3)[0]
                sni = body[5:5 + name_len].decode("ascii", "replace").lower()
            elif ext == 10 and len(body) >= 2:        # supported_groups
                count = struct.unpack_from(">H", body, 0)[0] // 2
                curves = [c for c in struct.unpack_from(f">{count}H", body, 2) if c not in GREASE]
            elif ext == 11 and body:                  # ec_point_formats
                formats = list(body[1:1 + body[0]])
            elif ext == 16 and len(body) > 3:         # ALPN: первый протокол
                alpn = body[3:3 + body[2]].decode("ascii", "replace")
    except (struct.error, IndexError):
        return None
    text = ",".join([str(version), "-".join(map(str, ciphers)), "-".join(map(str, extensions)),
                     "-".join(map(str, curves)), "-".join(map(str, formats))])
    return ClientHello(sni, hashlib.md5(text.encode()).hexdigest(), text, alpn)


def tcp_payload(packet: bytes) -> tuple[str, int, int, bytes] | None:
    """IP-пакет -> (адрес назначения, порт источника, порт назначения, данные TCP)."""
    if not packet:
        return None
    version = packet[0] >> 4
    if version == 4:
        ihl = (packet[0] & 0x0F) * 4
        if packet[9] != 6:
            return None
        dst = ".".join(map(str, packet[16:20]))
        tcp = packet[ihl:]
    elif version == 6:
        if packet[6] != 6:  # заголовки-расширения IPv6 для простоты не разбираем
            return None
        import ipaddress
        dst = str(ipaddress.IPv6Address(packet[24:40]))
        tcp = packet[40:]
    else:
        return None
    if len(tcp) < 20:
        return None
    sport, dport = struct.unpack_from(">HH", tcp, 0)
    offset = (tcp[12] >> 4) * 4
    return dst, sport, dport, tcp[offset:]


# ---------- WinDivert ----------
def windivert_candidates(configured: str = "") -> list[Path]:
    """Где искать WinDivert.dll: настройка, защищённая копия программы, native/windivert,
    папки zapret."""
    candidates = []
    if configured:
        candidates.append(Path(configured) / "WinDivert.dll")
    try:
        import trustseal
        if trustseal.root_trusted():
            candidates.append(trustseal.protected_dir() / "windivert" / "WinDivert.dll")
    except Exception:  # noqa: S110 — без защищённой копии ищем дальше
        pass
    candidates.append(PROJECT_DIR / "native" / "windivert" / "WinDivert.dll")
    for drive_root in ("C:\\", os.environ.get("ProgramFiles", r"C:\Program Files")):
        candidates += [Path(p) for p in glob.glob(os.path.join(drive_root, "zapret*", "bin",
                                                               "WinDivert.dll"))]
    return candidates


def windivert_safe(dll: Path) -> tuple[bool, str]:
    """Библиотеку и драйвер рядом с ней меняют только администраторы: программа с правами
    загружает WinDivert.dll в себя — подменённая библиотека выполнила бы свой код с правами
    администратора (папки zapret в корне диска обычно открыты на запись пользователю)."""
    import winacl
    for item in (dll, dll.parent / "WinDivert64.sys"):
        ok, reason = winacl.admin_only(item)
        if not ok:
            return False, reason
    return True, ""


def find_windivert(configured: str = "") -> Path | None:
    """WinDivert.dll с драйвером рядом, который меняют только администраторы (см.
    windivert_safe); небезопасные находки — в find_windivert.unsafe."""
    find_windivert.unsafe = []
    for dll in windivert_candidates(configured):
        if not (dll.is_file() and (dll.parent / "WinDivert64.sys").is_file()):
            continue
        ok, reason = windivert_safe(dll)
        if ok:
            return dll
        find_windivert.unsafe.append((dll, reason))
    return None


find_windivert.unsafe = []


def trust_windivert(folder) -> Path:
    """Пользователь выбрал папку с WinDivert: копия WinDivert.dll и WinDivert64.sys в
    защищённую папку программы (%ProgramData%\\StretchBIT\\windivert, запись — только
    администраторам); дальше загружается копия. Нужны права администратора."""
    import shutil

    import trustseal
    src = Path(folder)
    if not (src / "WinDivert.dll").is_file() or not (src / "WinDivert64.sys").is_file():
        raise FileNotFoundError("в папке нет WinDivert.dll и WinDivert64.sys")
    target = trustseal.protected_subdir("windivert")
    if target is None:
        raise PermissionError("нужны права администратора")
    for name in ("WinDivert.dll", "WinDivert64.sys"):
        shutil.copy2(src / name, target / name)
    return target


def socket_event(addr: bytes) -> tuple[int, int, int] | None:
    """WINDIVERT_ADDRESS уровня SOCKET -> (PID, локальный порт, удалённый порт).
    Раскладка (windivert.h 2.x): Timestamp 8, битовые поля 4, Reserved2 4, затем
    WINDIVERT_DATA_SOCKET: EndpointId 8, ParentEndpointId 8, ProcessId 4, LocalAddr 16,
    RemoteAddr 16, LocalPort 2, RemotePort 2, Protocol 1 (числа — в порядке процессора)."""
    if len(addr) < 73:
        return None
    pid, = struct.unpack_from("<I", addr, 32)
    lport, rport = struct.unpack_from("<HH", addr, 68)
    return pid, lport, rport


class SocketMap:
    """Локальный порт -> (PID, имя, путь) по событиям CONNECT. Имя узнаётся сразу при
    событии: короткоживущая программа может завершиться раньше, чем уйдёт ClientHello."""
    MAX = 20000

    def __init__(self):
        self._ports: dict[int, tuple[int, float]] = {}
        self._names: dict[int, tuple[str, str, float]] = {}
        self._lock = threading.Lock()

    def add(self, port: int, pid: int) -> None:
        name = self._name(pid)
        with self._lock:
            if len(self._ports) > self.MAX:
                self._ports.clear()
            self._ports[port] = (pid, time.monotonic())
            self._names[pid] = (*name, time.monotonic())

    def get(self, port: int) -> tuple[int, str, str] | None:
        with self._lock:
            hit = self._ports.get(port)
            if not hit:
                return None
            name, exe, _ = self._names.get(hit[0], ("?", "", 0))
        return hit[0], name, exe

    def _name(self, pid: int) -> tuple[str, str]:
        with self._lock:
            cached = self._names.get(pid)
        if cached and time.monotonic() - cached[2] < 60:   # PID мог достаться другой программе
            return cached[0], cached[1]
        if pid == 4:
            return "System", ""
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            try:
                exe = proc.exe()
            except psutil.Error:
                exe = ""
            return name, exe
        except psutil.Error:
            return "?", ""


class _PortMap:
    """Локальный порт TCP -> процесс (обновляется, когда порт не найден)."""

    def __init__(self):
        self._ports: dict[int, int] = {}
        self._names: dict[int, tuple[str, str]] = {}
        self._updated = 0.0

    def refresh(self) -> None:
        try:
            conns = psutil.net_connections(kind="tcp")
        except psutil.Error:
            return
        self._ports = {c.laddr.port: c.pid for c in conns if c.laddr and c.pid}
        self._updated = time.monotonic()

    def process(self, port: int) -> tuple[int, str, str]:
        pid = self._ports.get(port)
        if pid is None and time.monotonic() - self._updated > 0.5:
            self.refresh()
            pid = self._ports.get(port)
        if not pid:
            return 0, "?", ""
        if pid not in self._names:
            try:
                proc = psutil.Process(pid)
                name = proc.name()
                try:
                    exe = proc.exe()
                except psutil.Error:
                    exe = ""
            except psutil.Error:
                name, exe = "?", ""
            self._names[pid] = (name, exe)
        return pid, *self._names[pid]


class TlsWatcher:
    """on_hello(TlsEvent) вызывается из своего потока."""

    def __init__(self, on_hello, on_status=None, dll_dir: str = ""):
        self.on_hello = on_hello
        self.on_status = on_status or (lambda text: None)
        self.dll_dir = dll_dir
        self.running = False
        self._stop = threading.Event()
        self._handle = None
        self._socket_handle = None
        self._dll = None
        self._thread: threading.Thread | None = None
        self._socket_thread: threading.Thread | None = None
        self.sockets = SocketMap()

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="tls-watch")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._handle and self._dll:
            self._dll.WinDivertShutdown(self._handle, 3)  # прерывает ожидание WinDivertRecv
        if self._socket_handle and self._dll:
            self._dll.WinDivertShutdown(self._socket_handle, 3)
        if self._thread:
            self._thread.join(timeout=5)
        if self._socket_thread:
            self._socket_thread.join(timeout=5)

    def _open(self) -> str:
        """Пустая строка — открыто, иначе причина."""
        if sys.platform != "win32":
            return "только Windows"
        dll_path = find_windivert(self.dll_dir)
        if dll_path is None:
            if find_windivert.unsafe:
                dll, reason = find_windivert.unsafe[0]
                return (f"WinDivert найден в {dll.parent}, но не загружен: {reason}. "
                        "Подменённая библиотека выполнилась бы с правами администратора. "
                        "Укажите эту папку кнопкой на вкладке «TLS» — программа сделает "
                        "защищённую копию")
            return ("не найден WinDivert.dll с драйвером WinDivert64.sys (укажите папку на "
                    "вкладке «TLS»)")
        try:
            dll = ctypes.WinDLL(str(dll_path), use_last_error=True)
        except OSError as e:
            return f"не загружен {dll_path}: {e}"
        dll.WinDivertOpen.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int16,
                                      ctypes.c_uint64]
        dll.WinDivertOpen.restype = ctypes.c_void_p
        dll.WinDivertRecv.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.UINT,
                                      ctypes.POINTER(wintypes.UINT), ctypes.c_void_p]
        dll.WinDivertRecv.restype = wintypes.BOOL
        dll.WinDivertShutdown.argtypes = [ctypes.c_void_p, ctypes.c_int]
        dll.WinDivertClose.argtypes = [ctypes.c_void_p]
        handle = dll.WinDivertOpen(FILTER, WINDIVERT_LAYER_NETWORK, 0,
                                   WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY)
        if not handle or handle == ctypes.c_void_p(-1).value:
            code = ctypes.get_last_error()
            if code == 5:
                return "нет прав администратора"
            return f"WinDivertOpen: ошибка {code}"
        self._dll, self._handle = dll, handle
        sock = dll.WinDivertOpen(SOCKET_FILTER, WINDIVERT_LAYER_SOCKET, 0,
                                 WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY)
        if sock and sock != ctypes.c_void_p(-1).value:
            self._socket_handle = sock
        return ""

    def _run_sockets(self) -> None:
        """Поток уровня SOCKET: каждое connect() к :443 — порт и PID в SocketMap."""
        addr = ctypes.create_string_buffer(ADDRESS_SIZE)
        try:
            while not self._stop.is_set():
                if not self._dll.WinDivertRecv(self._socket_handle, None, 0, None, addr):
                    if self._stop.is_set():
                        break
                    continue
                ev = socket_event(addr.raw)
                if ev and ev[0]:
                    self.sockets.add(ev[1], ev[0])
        finally:
            self._dll.WinDivertClose(self._socket_handle)
            self._socket_handle = None

    def _run(self) -> None:
        error = self._open()
        if error:
            self.on_status(f"TLS: перехват недоступен ({error})")
            return
        self.running = True
        if self._socket_handle:
            self._socket_thread = threading.Thread(target=self._run_sockets, daemon=True,
                                                   name="tls-sockets")
            self._socket_thread.start()
            who = "программа — по событиям connect() (WFP)"
        else:
            who = "программа — по таблице соединений (WinDivert без уровня SOCKET)"
        self.on_status(f"TLS: имена сайтов и отпечатки JA3 видны (WinDivert, только чтение; "
                       f"{who})")
        ports = _PortMap()
        buf = ctypes.create_string_buffer(MAX_PACKET)
        addr = ctypes.create_string_buffer(ADDRESS_SIZE)
        got = wintypes.UINT(0)
        try:
            while not self._stop.is_set():
                if not self._dll.WinDivertRecv(self._handle, buf, MAX_PACKET,
                                               ctypes.byref(got), addr):
                    if self._stop.is_set():
                        break
                    continue
                parsed = tcp_payload(buf.raw[:got.value])
                if parsed is None:
                    continue
                dst, sport, dport, payload = parsed
                hello = parse_client_hello(payload)
                if hello is None:
                    continue
                pid, name, exe = self.sockets.get(sport) or ports.process(sport)
                try:
                    self.on_hello(TlsEvent(time.time(), pid, name, exe, f"{dst}:{dport}", hello))
                except Exception:
                    from diag.log import swallowed
                    swallowed("tls: обработчик ClientHello")
        finally:
            self.running = False
            self._dll.WinDivertClose(self._handle)
            self._handle = None
