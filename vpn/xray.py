"""VLESS через Xray-core: разбор ссылки vless://, конфигурация Xray, системный прокси, TUN.

Режимы:
• proxy — Xray слушает 127.0.0.1:SOCKS_PORT (SOCKS5) и HTTP_PORT (HTTP); программа включает
  системный прокси Windows (HKCU\\...\\Internet Settings: ProxyEnable, ProxyServer,
  ProxyOverride) и сообщает о смене настроек (InternetSetOptionW). Прежние значения
  сохраняются: в журнал действий (откат) и в настройку vpn/proxy_backup — если программа
  упадёт с включённым прокси, при следующем запуске он вернётся (recover_proxy);
• tun — ЭКСПЕРИМЕНТАЛЬНО: входящий «tun» Xray (нужны wintun.dll рядом с xray.exe и права
  администратора), маршруты 0.0.0.0/1 и 128.0.0.0/1 через адаптер TUN_NAME, до самого
  сервера — через прежний шлюз (иначе соединение с сервером пошло бы в туннель).

xray.exe ищется: настройка vpn/xray_path, vpn/bin, PATH, установленный Happ.
Конфигурация с ключами пишется в cache/vpn/xray.json только на время подключения.
"""
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import time
import urllib.parse
from pathlib import Path

from recovery import journal

SOCKS_PORT = 10808
HTTP_PORT = 10809
TUN_NAME = "myav-tun"
TUN_ADDRESS = "172.19.0.1"
INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
BYPASS = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;192.168.*;<local>"
CREATE_NO_WINDOW = 0x08000000
SEARCH = [r"%ProgramFiles%\FlyFrogLLC\Happ\core", r"%ProgramFiles%\Xray",
          r"%LOCALAPPDATA%\Programs\Xray"]


def find_xray() -> str:
    try:
        from ui import settings as cfg
        custom = cfg.get("vpn/xray_path")
    except Exception:
        custom = ""
    candidates = [custom] if custom else []
    candidates.append(str(Path(__file__).resolve().parent / "bin" / "xray.exe"))
    found = shutil.which("xray.exe")
    if found:
        candidates.append(found)
    candidates += [str(Path(os.path.expandvars(d)) / "xray.exe") for d in SEARCH]
    return next((c for c in candidates if c and os.path.isfile(c)), "")


# ---------- ссылка vless:// ----------
def parse_vless(uri: str) -> dict:
    """vless://uuid@host:port?type=tcp&security=reality&pbk=...&sni=...#Название"""
    uri = uri.strip()
    parsed = urllib.parse.urlsplit(uri)
    if parsed.scheme.lower() != "vless" or not parsed.hostname or not parsed.username:
        raise ValueError("Ссылка должна иметь вид vless://UUID@адрес:порт?параметры#название")
    query = {k: v[-1] for k, v in urllib.parse.parse_qs(parsed.query).items()}
    return {
        "id": urllib.parse.unquote(parsed.username),
        "address": parsed.hostname,
        "port": parsed.port or 443,
        "name": urllib.parse.unquote(parsed.fragment) or parsed.hostname,
        "network": query.get("type", "tcp"),
        "security": query.get("security", "none"),
        "flow": query.get("flow", ""),
        "encryption": query.get("encryption", "none"),
        "sni": query.get("sni") or query.get("peer", ""),
        "fp": query.get("fp", ""),
        "pbk": query.get("pbk", ""),
        "sid": query.get("sid", ""),
        "spx": query.get("spx", ""),
        "alpn": [a for a in query.get("alpn", "").split(",") if a],
        "path": query.get("path", ""),
        "host": query.get("host", ""),
        "service": query.get("serviceName", ""),
        "mode": query.get("mode", ""),
        "header": query.get("headerType", ""),
    }


def outbound(v: dict, interface: str = "") -> dict:
    stream: dict = {"network": v["network"], "security": v["security"]}
    if v["security"] == "reality":
        stream["realitySettings"] = {"serverName": v["sni"], "fingerprint": v["fp"] or "chrome",
                                     "publicKey": v["pbk"], "shortId": v["sid"],
                                     "spiderX": v["spx"]}
    elif v["security"] == "tls":
        tls = {"serverName": v["sni"] or v["address"]}
        if v["fp"]:
            tls["fingerprint"] = v["fp"]
        if v["alpn"]:
            tls["alpn"] = v["alpn"]
        stream["tlsSettings"] = tls
    if v["network"] == "ws":
        stream["wsSettings"] = {"path": v["path"] or "/", "headers": {"Host": v["host"]}
                                if v["host"] else {}}
    elif v["network"] == "grpc":
        stream["grpcSettings"] = {"serviceName": v["service"]}
    elif v["network"] in ("xhttp", "splithttp"):
        stream["xhttpSettings"] = {"path": v["path"] or "/", "host": v["host"],
                                   "mode": v["mode"] or "auto"}
    elif v["network"] == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": v["path"] or "/", "host": v["host"]}
    elif v["network"] == "tcp" and v["header"] == "http":
        stream["tcpSettings"] = {"header": {"type": "http"}}
    if interface:  # TUN: соединение с сервером — через настоящий адаптер, не через туннель
        stream["sockopt"] = {"interface": interface}
    user = {"id": v["id"], "encryption": v["encryption"] or "none"}
    if v["flow"]:
        user["flow"] = v["flow"]
    return {"tag": "proxy", "protocol": "vless",
            "settings": {"vnext": [{"address": v["address"], "port": v["port"],
                                    "users": [user]}]},
            "streamSettings": stream}


def build_config(v: dict, mode: str, interface: str = "") -> dict:
    if mode == "tun":
        inbounds = [{"tag": "tun-in", "protocol": "tun",
                     "settings": {"name": TUN_NAME, "MTU": 1500}}]
    else:
        inbounds = [
            {"tag": "socks-in", "listen": "127.0.0.1", "port": SOCKS_PORT, "protocol": "socks",
             "settings": {"udp": True}, "sniffing": {"enabled": True,
                                                      "destOverride": ["http", "tls"]}},
            {"tag": "http-in", "listen": "127.0.0.1", "port": HTTP_PORT, "protocol": "http"}]
    direct = {"tag": "direct", "protocol": "freedom"}
    if interface:
        direct["streamSettings"] = {"sockopt": {"interface": interface}}
    return {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": [outbound(v, interface if mode == "tun" else ""), direct,
                      {"tag": "block", "protocol": "blackhole"}],
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": [
            {"type": "field", "ip": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
                                     "192.168.0.0/16", "169.254.0.0/16"],
             "outboundTag": "direct"}]},
    }


# ---------- системный прокси ----------
def _settings_key(path: str = INTERNET_SETTINGS):
    import winreg
    return winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0,
                              winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE)


def read_proxy(path: str = INTERNET_SETTINGS) -> dict:
    import winreg
    values = {}
    with _settings_key(path) as key:
        for name in ("ProxyEnable", "ProxyServer", "ProxyOverride"):
            try:
                values[name] = winreg.QueryValueEx(key, name)[0]
            except FileNotFoundError:
                values[name] = None
    return values


def write_proxy(values: dict, path: str = INTERNET_SETTINGS) -> None:
    import winreg
    with _settings_key(path) as key:
        for name, value in values.items():
            if value is None:
                try:
                    winreg.DeleteValue(key, name)
                except FileNotFoundError:
                    pass
            elif name == "ProxyEnable":
                winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, int(value))
            else:
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, str(value))
    if path == INTERNET_SETTINGS:
        _notify_proxy_changed()


def _notify_proxy_changed() -> None:
    """Браузеры и WinINet перечитывают прокси сразу, без перезапуска."""
    import ctypes
    wininet = ctypes.WinDLL("wininet")
    wininet.InternetSetOptionW(None, 39, None, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
    wininet.InternetSetOptionW(None, 37, None, 0)  # INTERNET_OPTION_REFRESH


def enable_system_proxy(path: str = INTERNET_SETTINGS) -> dict:
    """Включает прокси на Xray; возвращает прежние значения (для отката)."""
    old = read_proxy(path)
    _save_backup(old)
    write_proxy({"ProxyEnable": 1, "ProxyServer": f"127.0.0.1:{HTTP_PORT}",
                 "ProxyOverride": BYPASS}, path)
    if path == INTERNET_SETTINGS:
        journal.log_action("VPN: включён системный прокси 127.0.0.1:%d" % HTTP_PORT,
                           "vpn_proxy_restore", {"old": old})
    return old


def restore_system_proxy(old: dict, path: str = INTERNET_SETTINGS) -> None:
    write_proxy(old, path)
    _save_backup(None)


@journal.undo_op("vpn_proxy_restore")
def _undo_proxy(d: dict) -> str:
    restore_system_proxy(d["old"])
    return "Системный прокси возвращён к прежним настройкам"


def _save_backup(old: dict | None) -> None:
    try:
        from ui import settings as cfg
        cfg.set_("vpn/proxy_backup", json.dumps(old) if old is not None else "")
    except Exception:
        pass


def recover_proxy() -> bool:
    """Запуск программы: прокси остался включённым после сбоя — вернуть прежний."""
    try:
        from ui import settings as cfg
        raw = cfg.get("vpn/proxy_backup")
    except Exception:
        return False
    if not raw:
        return False
    try:
        restore_system_proxy(json.loads(raw))
        return True
    except (OSError, ValueError):
        return False


# ---------- TUN: маршруты ----------
def _powershell(script: str, env: dict) -> subprocess.CompletedProcess:
    """Значения — через переменные окружения, не подставляются в текст скрипта."""
    script = "[Console]::OutputEncoding = [Text.Encoding]::UTF8; " + script
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                          capture_output=True, text=True, encoding="utf-8", errors="replace",
                          env={**os.environ, **env}, creationflags=CREATE_NO_WINDOW)


def default_route() -> tuple[str, str]:
    """(шлюз, имя адаптера) текущего маршрута по умолчанию."""
    result = _powershell(
        "$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | "
        "Select-Object -First 1; if ($r) { $r.NextHop; (Get-NetAdapter -InterfaceIndex "
        "$r.ifIndex).Name }", {})
    lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
    return (lines[0], lines[1]) if len(lines) >= 2 else ("", "")


def server_ip(address: str) -> str:
    try:
        ipaddress.ip_address(address)
        return address
    except ValueError:
        return socket.gethostbyname(address)


def setup_tun_routes(server: str, gateway: str) -> str:
    """Адрес и маршруты адаптера TUN. Пустая строка — успех, иначе текст ошибки."""
    script = (
        "$ErrorActionPreference = 'Stop'; "
        "for ($i = 0; $i -lt 50 -and -not (Get-NetAdapter -Name $env:TUN -EA SilentlyContinue)); "
        "$i++) { Start-Sleep -Milliseconds 200 }; "
        "$a = Get-NetAdapter -Name $env:TUN; "
        "New-NetIPAddress -InterfaceIndex $a.ifIndex -IPAddress $env:ADDR -PrefixLength 30 "
        "-EA SilentlyContinue | Out-Null; "
        "Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses 1.1.1.1,8.8.8.8; "
        "route add $env:SERVER mask 255.255.255.255 $env:GW metric 1 | Out-Null; "
        "New-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceIndex $a.ifIndex -NextHop "
        "0.0.0.0 -RouteMetric 1 -PolicyStore ActiveStore | Out-Null; "
        "New-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceIndex $a.ifIndex -NextHop "
        "0.0.0.0 -RouteMetric 1 -PolicyStore ActiveStore | Out-Null")
    result = _powershell(script, {"TUN": TUN_NAME, "ADDR": TUN_ADDRESS, "SERVER": server,
                                  "GW": gateway})
    return "" if result.returncode == 0 else (result.stderr or result.stdout).strip()[-400:]


def remove_tun_routes(server: str) -> None:
    """Маршруты через TUN исчезают вместе с адаптером; маршрут до сервера — убираем сами."""
    if server:
        _powershell("route delete $env:SERVER | Out-Null", {"SERVER": server})


def write_config(config: dict, folder: Path) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = (folder / "xray.json").resolve()
    path.write_text(json.dumps(config, ensure_ascii=False, indent=1), encoding="utf-8")
    return path


def wait_port(port: int, timeout: float = 8.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False
