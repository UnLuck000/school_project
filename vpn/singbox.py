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
import os
import shutil
from pathlib import Path

TUN_NAME = "myav-tun"
TUN_ADDRESS = "172.19.0.1/30"
TUN_ADDRESS6 = "fdfe:dcba:9876::1/126"
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
                 block_udp: bool = False, dns_server: str = "1.1.1.1") -> dict:
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
    отклоняется, а DNS через сервер идёт по TCP (иначе он тоже был бы UDP)."""
    address = [TUN_ADDRESS, TUN_ADDRESS6]
    extra = [] if ip_mode in ("prefer_ipv6", "ipv6") else [{"ip_version": 6, "action": "reject"}]
    if block_udp:
        extra.append({"network": "udp", "action": "reject"})
    elif block_quic:
        extra.append({"network": "udp", "port": 443, "action": "reject"})
    return {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                # обычный DNS по UDP через сервер: DoH держит одно долгое соединение HTTP/2,
                # оно через туннель обрывается, и все запросы на нём разом падают
                {"type": "tcp" if block_udp else "udp", "tag": "dns-remote",
                 "server": dns_server, "detour": "proxy"},
                {"type": "local", "tag": "dns-local"},
            ],
            "final": "dns-remote",
            "strategy": "ipv4_only" if ip_mode == "ipv4" else "prefer_ipv6",
        },
        "inbounds": [{
            "type": "tun", "tag": "tun-in", "interface_name": TUN_NAME,
            "address": address, "mtu": 9000,
            "auto_route": True, "strict_route": True,
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
