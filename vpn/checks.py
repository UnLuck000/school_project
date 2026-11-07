"""Проверки VPN: отклик сайтов (YouTube, Telegram...) и подмена сертификатов.

Запрос идёт тем же путём, что и у обычных программ при выбранном режиме:
• TUN — напрямую (система сама отправит его в туннель);
• системный прокси — через HTTP-прокси Xray;
• только локальный прокси — через локальный SOCKS5 (или HTTP) прокси;
• VPN не подключён — напрямую.
Переменные HTTPS_PROXY и т. п. не используются (у пользователя они могут указывать на чужой
клиент).

Отклик — время до ответа сайта: соединение, TLS-рукопожатие и первая строка ответа HTTP.
Сертификат проверяется по хранилищу доверенных корневых сертификатов Windows (как браузером):
если цепочка не сходится к доверенному центру или имя не совпадает — сертификат подменён
(вмешательство провайдера, DPI, «прозрачный» прокси, вредонос в системе). Ограничение: если
злоумышленник добавил свой корневой сертификат в хранилище Windows, подмена этой проверкой не
видна.
"""
import socket
import ssl
import struct
import time
from dataclasses import dataclass

TARGETS = [("YouTube", "www.youtube.com"), ("Telegram", "telegram.org"),
           ("Google", "www.google.com"), ("Discord", "discord.com"),
           ("Cloudflare", "www.cloudflare.com"), ("Госуслуги", "www.gosuslugi.ru")]
CERT_HOSTS = ["www.youtube.com", "www.google.com", "telegram.org", "discord.com",
              "github.com", "www.wikipedia.org"]


@dataclass
class Probe:
    host: str
    ok: bool = False
    connect_ms: float = 0.0
    total_ms: float = 0.0
    status: str = ""          # строка ответа HTTP
    cert: str = "ok"          # ok | substituted | unknown
    issuer: str = ""          # издатель сертификата (если подменён — чей)
    error: str = ""


def _socks5(sock: socket.socket, host: str, port: int) -> None:
    sock.sendall(b"\x05\x01\x00")
    if sock.recv(2) != b"\x05\x00":
        raise OSError("SOCKS5: прокси не принял подключение")
    name = host.encode("idna")
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack(">H", port))
    reply = sock.recv(4)
    if len(reply) < 4 or reply[1] != 0:
        raise OSError(f"SOCKS5: отказ ({reply[1] if len(reply) > 1 else '?'})")
    rest = {1: 4, 4: 16}.get(reply[3])
    if rest is None:
        rest = sock.recv(1)[0]
    sock.recv(rest + 2)


def _http_connect(sock: socket.socket, host: str, port: int) -> None:
    sock.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(1024)
        if not chunk:
            raise OSError("HTTP-прокси закрыл соединение")
        data += chunk
    if b" 200" not in data.split(b"\r\n", 1)[0]:
        raise OSError("HTTP-прокси: " + data.split(b"\r\n", 1)[0].decode(errors="replace"))


def open_tcp(host: str, port: int, route: tuple, timeout: float = 10.0) -> socket.socket:
    """route: ("direct",) | ("socks", порт) | ("http", порт)."""
    if route[0] == "direct":
        return socket.create_connection((host, port), timeout=timeout)
    sock = socket.create_connection(("127.0.0.1", route[1]), timeout=timeout)
    try:
        (_socks5 if route[0] == "socks" else _http_connect)(sock, host, port)
    except Exception:
        sock.close()
        raise
    return sock


def _issuer(cert: dict) -> str:
    for part in cert.get("issuer", ()):
        for key, value in part:
            if key in ("organizationName", "commonName"):
                return value
    return ""


def probe(host: str, route: tuple, timeout: float = 10.0) -> Probe:
    result = Probe(host)
    t0 = time.perf_counter()
    try:
        sock = open_tcp(host, 443, route, timeout)
    except Exception as e:
        result.error = f"нет соединения: {str(e)[:80]}"
        result.cert = "unknown"
        return result
    result.connect_ms = (time.perf_counter() - t0) * 1000
    context = ssl.create_default_context()  # корневые сертификаты Windows
    try:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            result.issuer = _issuer(tls.getpeercert() or {})
            tls.sendall(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n"
                        "Connection: close\r\n\r\n".encode())
            line = tls.recv(256).split(b"\r\n", 1)[0].decode(errors="replace")
            result.status = line
            result.ok = line.startswith("HTTP/")
            result.total_ms = (time.perf_counter() - t0) * 1000
    except ssl.SSLCertVerificationError as e:
        result.cert = "substituted"
        result.error = f"сертификат не прошёл проверку: {e.verify_message}"
        result.issuer = _peek_issuer(host, route, timeout)
    except Exception as e:
        result.cert = "unknown"
        result.error = str(e)[:100]
    finally:
        sock.close()
    return result


def _peek_issuer(host: str, route: tuple, timeout: float) -> str:
    """Кто выдал подменённый сертификат (без проверки — только чтобы показать)."""
    try:
        sock = open_tcp(host, 443, route, timeout)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with context.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
        # разбор сертификата средствами самого ssl: без сторонних пакетов
        import os
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write(ssl.DER_cert_to_PEM_cert(der))
            path = f.name
        try:
            return _issuer(ssl._ssl._test_decode_cert(path)) or "неизвестен"
        finally:
            os.unlink(path)
    except Exception:
        return "неизвестен"


def route_for(backend) -> tuple:
    """Каким путём сейчас ходят программы (см. описание модуля)."""
    from vpn import backends, xray
    if backend is None or backend.state != backends.CONNECTED:
        return ("direct",)
    mode = getattr(backend, "mode", "")
    if isinstance(backend, backends.SingBoxBackend) or mode == "tun":
        return ("direct",)
    if mode == "local":
        ports = backend.local_ports
        return ("socks", ports["socks"]) if "socks" in ports else ("http", ports["http"])
    if mode == "proxy":
        return ("http", xray.HTTP_PORT)
    return ("direct",)
