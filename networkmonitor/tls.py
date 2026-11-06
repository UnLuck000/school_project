"""Начало TLS-соединений: имя сайта (SNI) и отпечаток клиента JA3 через WinDivert.

Содержимое HTTPS зашифровано, но первое сообщение клиента (ClientHello) идёт открытым:
в нём имя сайта (SNI) и набор шифров, расширений и кривых. JA3 — md5 от этих списков:
у одной и той же программы он одинаковый, а у многих вредоносов свой, узнаваемый
(список SSLBL). QUIC (HTTP/3 по UDP) шифрует даже начало соединения, его здесь не видно.

WinDivert открывается в режиме «только смотреть» (SNIFF | RECV_ONLY): пакеты не
задерживаются и не меняются, другие программы на WinDivert (например, zapret) не мешают.
Нужны права администратора и WinDivert.dll с драйвером WinDivert64.sys рядом.
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
def find_windivert(configured: str = "") -> Path | None:
    """WinDivert.dll: из настройки, из native/windivert проекта или из папки zapret."""
    candidates = []
    if configured:
        candidates.append(Path(configured) / "WinDivert.dll")
    candidates.append(PROJECT_DIR / "native" / "windivert" / "WinDivert.dll")
    for drive_root in ("C:\\", os.environ.get("ProgramFiles", r"C:\Program Files")):
        candidates += [Path(p) for p in glob.glob(os.path.join(drive_root, "zapret*", "bin",
                                                               "WinDivert.dll"))]
    for dll in candidates:
        if dll.is_file() and (dll.parent / "WinDivert64.sys").is_file():
            return dll
    return None


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
        self._dll = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="tls-watch")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._handle and self._dll:
            self._dll.WinDivertShutdown(self._handle, 3)  # прерывает ожидание WinDivertRecv
        if self._thread:
            self._thread.join(timeout=5)

    def _open(self) -> str:
        """Пустая строка — открыто, иначе причина."""
        if sys.platform != "win32":
            return "только Windows"
        dll_path = find_windivert(self.dll_dir)
        if dll_path is None:
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
        return ""

    def _run(self) -> None:
        error = self._open()
        if error:
            self.on_status(f"TLS: перехват недоступен ({error})")
            return
        self.running = True
        self.on_status("TLS: имена сайтов и отпечатки JA3 видны (WinDivert, только чтение)")
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
                pid, name, exe = ports.process(sport)
                try:
                    self.on_hello(TlsEvent(time.time(), pid, name, exe, f"{dst}:{dport}", hello))
                except Exception:
                    pass
        finally:
            self.running = False
            self._dll.WinDivertClose(self._handle)
            self._handle = None
