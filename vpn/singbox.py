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
PRIVATE = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]
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


def build_config(socks_port: int, xray_exe: str) -> dict:
    """TUN sing-box → SOCKS5 127.0.0.1:socks_port (Xray). xray_exe — его соединения напрямую."""
    return {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {"type": "https", "tag": "dns-remote", "server": "1.1.1.1",
                 "detour": "proxy"},
                {"type": "local", "tag": "dns-local"},
            ],
            "final": "dns-remote",
            "strategy": "ipv4_only",
        },
        "inbounds": [{
            "type": "tun", "tag": "tun-in", "interface_name": TUN_NAME,
            "address": [TUN_ADDRESS], "mtu": 9000,
            "auto_route": True, "strict_route": True,
            "route_exclude_address": ["127.0.0.0/8", "255.255.255.255/32", *PRIVATE],
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
                {"process_name": [os.path.basename(xray_exe) or "xray.exe"],
                 "outbound": "direct"},
                {"ip_is_private": True, "outbound": "direct"},
            ],
            "final": "proxy",
            "auto_detect_interface": True,
            "find_process": True,
            "default_domain_resolver": "dns-local",
        },
    }
