"""TUN через sing-box: весь трафик системы — в локальный SOCKS Xray, Xray — к серверу VLESS.

Почему связка, а не один sing-box: сам sing-box (1.12 и 1.14) с частью серверов не проходит
проверку REALITY («reality verification failed»), а Xray с теми же ссылками работает. Так
устроены многие клиенты: TUN держит sing-box (адаптер, маршруты auto_route/strict_route,
перехват DNS hijack-dns, выбор настоящего адаптера auto_detect_interface — без PowerShell и
ручных маршрутов), протокол — Xray (поддерживает всё, включая xhttp). Собственные соединения
Xray к серверу sing-box пропускает напрямую (правило process_name), иначе была бы петля.
Настройки TUN — по образцу Throne (github.com/throneproj/Throne, src/configs/generate.cpp),
формат sing-box 1.12+. Нужны права администратора.
"""
import ipaddress
import os
import re
import shutil
import urllib.parse
from pathlib import Path

TUN_NAME = "sbit-tun"
TUN_ADDRESS = "172.19.0.1/30"
TUN_ADDRESS6 = "fdfe:dcba:9876::1/126"
TUN6_CANDIDATES = ("fdfe:dcba:9876::1/126", "fdfe:dcba:9877::1/126", "fdfe:dcba:9878::1/126",
                   "fdfe:dcba:9879::1/126")
# 172.19.0.1/30 — адрес sing-box по умолчанию, его же берут Throne, Hiddify, NekoBox: при их
# включённом TUN sing-box падал с «set ipv4 address: The object already exists»
TUN_CANDIDATES = ("172.19.0.1/30", "172.23.231.1/30", "10.211.97.1/30", "192.168.251.1/30")


def free_tun_address(used: list[str] | None = None, exclude: tuple = ()) -> str:
    """Первый адрес из TUN_CANDIDATES, чья подсеть не пересекается с адресами других
    адаптеров (used — для проверки; по умолчанию — адреса всех адаптеров Windows, и своего
    тоже: перед подключением его быть не должно, а остался — значит, от прежнего sing-box, и
    его адрес занят). exclude — адреса, на которых sing-box уже не запустился."""
    import ipaddress
    if used is None:
        import psutil
        used = [a.address for addrs in psutil.net_if_addrs().values()
                for a in addrs if a.family.name == "AF_INET"]
    taken = []
    for address in used:
        try:
            taken.append(ipaddress.ip_address(address))
        except ValueError:
            continue
    for candidate in TUN_CANDIDATES:
        net = ipaddress.ip_interface(candidate).network
        if candidate not in exclude and not any(ip in net for ip in taken):
            return candidate
    return next((c for c in reversed(TUN_CANDIDATES) if c not in exclude), TUN_CANDIDATES[-1])


def tun_address6(address4: str) -> str:
    """Адрес IPv6 в паре с выбранным IPv4: при смене адреса меняется и он (тот же «уже
    существует» бывает и у IPv6)."""
    index = TUN_CANDIDATES.index(address4) if address4 in TUN_CANDIDATES else 0
    return TUN6_CANDIDATES[index % len(TUN6_CANDIDATES)]


# DNS через VPN (vpn/dns_server): в списке окна — только эти; вручную — любой адрес вида
# 1.2.3.4, udp://, tcp://, tls:// (DoT), https://.../dns-query (DoH), quic://, h3://
DNS_PRESETS = ["1.1.1.1", "1.0.0.1", "8.8.8.8",
               "https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query",
               "https://8.8.8.8/dns-query",
               "tls://1.1.1.1", "tls://1.0.0.1", "tls://8.8.8.8"]
DNS_SCHEMES = {"udp": ("udp", 53), "tcp": ("tcp", 53), "tls": ("tls", 853),
               "https": ("https", 443), "quic": ("quic", 853), "h3": ("h3", 443)}
_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def parse_dns(text: str) -> dict:
    """Адрес DNS → {"type", "server", "server_port"[, "path"]} в виде sing-box. ValueError —
    адрес записан не так (текст ошибки — для окна)."""
    text = (text or "").strip()
    if not text:
        raise ValueError("DNS не указан")
    scheme, rest = (text.split("://", 1) if "://" in text else ("udp", text))
    scheme = scheme.lower()
    if scheme not in DNS_SCHEMES:
        raise ValueError(f"DNS: неизвестный вид «{scheme}://» — можно udp, tcp, tls, https, "
                         "quic, h3")
    kind, default_port = DNS_SCHEMES[scheme]
    parsed = urllib.parse.urlsplit("//" + rest)
    host = (parsed.hostname or "").lower()
    try:
        port = parsed.port or default_port
    except ValueError:
        raise ValueError("DNS: порт — число от 1 до 65535") from None
    if not host or not (_is_ip(host) or _HOST_RE.match(host)):
        raise ValueError(f"DNS: «{text}» — нужен IP-адрес или имя сервера")
    path = parsed.path
    if kind in ("https", "h3"):
        result = {"type": kind, "server": host, "server_port": port,
                  "path": path or "/dns-query"}
    else:
        if path not in ("", "/") or parsed.query:
            raise ValueError(f"DNS: у {scheme}:// не бывает пути — только адрес и порт")
        result = {"type": kind, "server": host, "server_port": port}
    return result


def dns_servers(text: str, tag: str, net: str = "udp", detour: str = "proxy") -> list[dict]:
    """Сервер DNS sing-box (через туннель) и, если он задан именем, сервер для этого имени.
    net — tcp, когда весь UDP заблокирован: обычный DNS переходит на TCP, QUIC — ошибка."""
    server = parse_dns(text)
    if net == "tcp" and server["type"] == "udp":
        server["type"] = "tcp"
    if net == "tcp" and server["type"] in ("quic", "h3"):
        raise ValueError("DNS по QUIC и HTTP/3 идёт по UDP, а в профиле маршрутизации весь UDP "
                         "заблокирован — выберите tls:// или https://")
    server = {"tag": tag, **server, "detour": detour}
    result = [server]
    if not _is_ip(server["server"]):
        result.append({"type": net, "tag": tag + "-boot", "server": "1.1.1.1",
                       "detour": detour})
        server["domain_resolver"] = tag + "-boot"
    return result


SEARCH = [r"%ProgramFiles%\sing-box", r"%ProgramFiles%\FlyFrogLLC\Happ\tun",
          r"%LOCALAPPDATA%\Programs\sing-box"]


def find_singbox() -> str:
    try:
        from ui import settings as cfg
        custom = cfg.get("vpn/singbox_path")
    except Exception:
        custom = ""
    candidates = [custom] if custom else []
    candidates.append(str(Path(__file__).resolve().parent / "bin" / "sing-box.exe"))
    found = shutil.which("sing-box.exe")
    if found:
        candidates.append(found)
    candidates += [str(Path(os.path.expandvars(d)) / "sing-box.exe") for d in SEARCH]
    return next((c for c in candidates if c and os.path.isfile(c)), "")


def build_config(socks_port: int, xray_exe: str, ip_mode: str = "ipv4",
                 direct_apps: list[str] | None = None, block_quic: bool = False,
                 block_udp: bool = False, dns_server: str = "1.1.1.1",
                 windows_dns: dict | None = None, strict_route: bool = True,
                 tun_address: str | None = None) -> dict:
    """TUN sing-box → SOCKS5 127.0.0.1:socks_port (Xray).

    xray_exe — полный путь: мимо туннеля пропускается только этот файл (не любой xray.exe).
    Локальная сеть идёт напрямую правилом ip_is_private. DNS-запросы к роутеру в туннель по
    маршрутам не попадают (маршрут к своей подсети точнее, а адрес шлюза sing-box в туннель
    не берёт) — поэтому на время подключения DNS адаптеров подменяется (vpn/dnsguard.py).
    ip_mode — ipv4: IPv6 тоже заходит в туннель, но отклоняется (иначе шёл бы мимо VPN),
    DNS отдаёт только IPv4; prefer_ipv6 и ipv6: IPv6 через туннель, DNS отдаёт IPv6, если он
    есть у сайта, иначе IPv4 (в режиме ipv6 ещё и до сервера VPN — по IPv6, см.
    xray.server_address).
    direct_apps — программы (полные пути), которые идут напрямую, мимо VPN.
    block_quic — UDP 443 отклоняется (браузер переходит на TCP); block_udp — весь UDP
    отклоняется, а DNS через сервер идёт по TCP (иначе он тоже был бы UDP).
    dns_server — адрес DNS через туннель (parse_dns: 1.1.1.1, tls://, https://...).
    strict_route — строгая маршрутизация sing-box (vpn/strict_route): фильтры WFP не дают
    программам обойти туннель и отправить DNS мимо него; без неё совместимее с другими
    программами, работающими с сетью (виртуальные машины, локальные серверы).
    windows_dns — DNS, заданный вручную в Windows 11 (vpn/windns.py): A-запросы — на его
    сервер IPv4, AAAA — на сервер IPv6 (тоже через туннель); dns_server — для остального."""
    net = "tcp" if block_udp else "udp"
    windows_dns = windows_dns or {}
    # по умолчанию — обычный DNS по UDP через сервер: DoH держит одно долгое соединение
    # HTTP/2, через туннель оно бывает обрывается, и все запросы на нём разом падают
    servers = [*dns_servers(dns_server, "dns-remote", net), {"type": "local", "tag": "dns-local"}]
    dns_rules = []
    for family, query, tag in (("v4", "A", "dns-win4"), ("v6", "AAAA", "dns-win6")):
        chosen = (windows_dns.get(family) or [None])[0]
        if chosen and not (family == "v6" and ip_mode == "ipv4"):  # IPv6 в туннеле закрыт
            servers.append({"type": net, "tag": tag, "server": chosen, "detour": "proxy"})
            dns_rules.append({"query_type": [query], "action": "route", "server": tag})
    address4 = tun_address or free_tun_address()
    address = [address4, tun_address6(address4)]
    extra = [] if ip_mode in ("prefer_ipv6", "ipv6") else [{"ip_version": 6, "action": "reject"}]
    if block_udp:
        extra.append({"network": "udp", "action": "reject"})
    elif block_quic:
        extra.append({"network": "udp", "port": 443, "action": "reject"})
    return {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": servers,
            **({"rules": dns_rules} if dns_rules else {}),
            "final": "dns-remote",
            "strategy": "ipv4_only" if ip_mode == "ipv4" else "prefer_ipv6",
        },
        "inbounds": [{
            "type": "tun", "tag": "tun-in", "interface_name": TUN_NAME,
            "address": address, "mtu": 9000,
            "auto_route": True, "strict_route": bool(strict_route),
            "route_exclude_address": ["127.0.0.0/8", "255.255.255.255/32", "::1/128"],
        }],
        "outbounds": [
            {"type": "socks", "tag": "proxy", "server": "127.0.0.1",
             "server_port": socks_port, "version": "5"},
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"process_path": [os.path.normpath(xray_exe)], "outbound": "direct"},
                *([{"process_path": [os.path.normpath(a) for a in direct_apps],
                    "outbound": "direct"}] if direct_apps else []),
                {"ip_is_private": True, "outbound": "direct"},
                *extra,
            ],
            "final": "proxy",
            "auto_detect_interface": True,
            "find_process": True,
            "default_domain_resolver": "dns-local",
        },
    }
