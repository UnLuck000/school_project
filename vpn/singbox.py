"""VLESS в режиме TUN через sing-box (по умолчанию; Xray TUN — запасной вариант).

sing-box сам создаёт адаптер (wintun встроен), прописывает маршруты (auto_route,
strict_route), перехватывает DNS (hijack-dns) и находит настоящий адаптер для соединения с
сервером (auto_detect_interface) — без PowerShell и ручных маршрутов, как у Xray TUN.
Настройки — по образцу Throne (github.com/throneproj/Throne, src/configs/generate.cpp),
формат sing-box 1.12+ (новые DNS-серверы и действия маршрутов; подходит и для 1.14).

Транспорт xhttp sing-box не поддерживает: такие ссылки — через Xray (build_config бросает
ValueError с подсказкой). Нужны права администратора.
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


def outbound(v: dict) -> dict:
    """Ссылка vless:// (vpn.xray.parse_vless) → исходящее подключение sing-box."""
    out = {"type": "vless", "tag": "proxy", "server": v["address"],
           "server_port": int(v["port"]), "uuid": v["id"], "packet_encoding": "xudp"}
    if v["flow"]:
        out["flow"] = v["flow"]
    if v["security"] in ("tls", "reality"):
        tls = {"enabled": True, "server_name": v["sni"] or v["address"]}
        if v["fp"] or v["security"] == "reality":
            tls["utls"] = {"enabled": True, "fingerprint": v["fp"] or "chrome"}
        if v["alpn"]:
            tls["alpn"] = v["alpn"]
        if v["security"] == "reality":
            tls["reality"] = {"enabled": True, "public_key": v["pbk"], "short_id": v["sid"]}
        out["tls"] = tls
    network = v["network"]
    if network == "ws":
        transport = {"type": "ws", "path": v["path"] or "/"}
        if v["host"]:
            transport["headers"] = {"Host": v["host"]}
        out["transport"] = transport
    elif network == "grpc":
        out["transport"] = {"type": "grpc", "service_name": v["service"]}
    elif network == "httpupgrade":
        out["transport"] = {"type": "httpupgrade", "path": v["path"] or "/",
                            "host": v["host"]}
    elif network == "http" or (network == "tcp" and v["header"] == "http"):
        out["transport"] = {"type": "http", "path": v["path"] or "/",
                            "host": [v["host"]] if v["host"] else []}
    elif network in ("xhttp", "splithttp"):
        raise ValueError("транспорт xhttp sing-box не поддерживает — выберите режим "
                         "«TUN через Xray» или «Системный прокси»")
    elif network not in ("tcp", "raw", ""):
        raise ValueError(f"транспорт {network} sing-box не поддерживает")
    return out


def build_config(v: dict) -> dict:
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
        "outbounds": [outbound(v), {"type": "direct", "tag": "direct"}],
        "route": {
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"ip_is_private": True, "outbound": "direct"},
            ],
            "final": "proxy",
            "auto_detect_interface": True,
            "default_domain_resolver": "dns-local",  # адрес самого сервера — напрямую
        },
    }
