"""Обезличивание журналов и отчёта.

Убирается всё, что указывает на пользователя:
• имя учётной записи и компьютера, папки профиля (%USERPROFILE%, %APPDATA%...), профили
  других пользователей (%OTHERUSER%) — anonymize_user;
• IP-адреса этого компьютера (адаптеры, внешний адрес) → %MYIP%, адреса локальной сети
  (10/8, 172.16/12, 192.168/16, 100.64/10, fe80::, fc00::/7) → %LANIP%, MAC-адреса → %MAC%;
• VPN: адреса серверов (домен и IP) → %VPNSERVER1%..., имена профилей → %PROFILE1%...
Адреса сайтов, к которым идут запросы, остаются. Имена файлов не меняются.

Значения регистрируются по ходу работы (register_*): адреса адаптеров — при запуске,
профили VPN — при запуске и при подключении, внешний адрес — когда программа его узнала.
"""
import ipaddress
import os
import re
import threading

ANON_FOLDERS = ("LOCALAPPDATA", "APPDATA", "TEMP", "USERPROFILE", "PUBLIC")
OTHER_USER = "%OTHERUSER%"

_lock = threading.Lock()
_values: dict[str, str] = {}        # точное значение (в нижнем регистре) → метка
_order: dict[str, int] = {}         # вид метки → следующий номер
_pattern: re.Pattern | None = None


def anonymize_user(text: str, env: dict | None = None) -> str:
    """Папки профиля → %USERPROFILE% и т. п., имена → %USERNAME%, %COMPUTERNAME%,
    профили других пользователей → %OTHERUSER%."""
    env = os.environ if env is None else env
    pairs = []
    for name in ANON_FOLDERS:  # сначала длинные пути: %LOCALAPPDATA% внутри %USERPROFILE%
        value = (env.get(name) or "").rstrip("\\/")
        if len(value) > 3:
            pairs.append((value, f"%{name}%"))
    pairs.sort(key=lambda p: len(p[0]), reverse=True)
    for value, token in pairs:
        text = re.sub(re.escape(value) + r"(?=[\\/\s\"';:,)]|$)", lambda m: token, text,
                      flags=re.I | re.M)
    text = re.sub(r"(?i)\b([a-z]:\\users\\)(?!%|public\\|default\\|all users\\)[^\\\s\"]+",
                  lambda m: m.group(1) + OTHER_USER, text)
    names = [(env.get(n) or "", n) for n in ("USERNAME", "COMPUTERNAME", "USERDOMAIN")]
    for value, name in sorted(names, key=lambda p: len(p[0]), reverse=True):  # IVAN-PC до Ivan
        if len(value) >= 3:
            text = re.sub(r"(?<![\w%])" + re.escape(value) + r"(?![\w%])", f"%{name}%", text,
                          flags=re.I)
    return text


def _register(value: str, kind: str, numbered: bool = True) -> str:
    global _pattern
    value = (value or "").strip()
    if len(value) < 3:
        return value
    key = value.lower()
    with _lock:
        if key not in _values:
            if numbered:
                n = _order.get(kind, 1)
                _order[kind] = n + 1
                _values[key] = f"%{kind}{n}%"
            else:
                _values[key] = f"%{kind}%"
            _pattern = None
        return _values[key]


def register_vpn_profile(name: str, server: str = "") -> None:
    """Имя профиля → %PROFILEn%, сервер (host или host:port) → %VPNSERVERn%."""
    if name:
        _register(name, "PROFILE")
    host = (server or "").strip()
    if host:
        if host.startswith("[") and "]" in host:      # [IPv6]:порт
            host = host[1:host.index("]")]
        elif host.count(":") == 1:                     # домен или IPv4 с портом
            host = host.rsplit(":", 1)[0]
        _register(host, "VPNSERVER")


def register_vpn_server(address: str) -> None:
    """Адрес сервера, который стал известен позже (разрешённый IP) — та же метка, что у
    уже известного сервера, если он один, иначе новая."""
    _register(address, "VPNSERVER")


def register_own_ip(address: str) -> None:
    _register(address, "MYIP", numbered=False)


def register_adapters() -> None:
    """Адреса всех адаптеров этого компьютера (кроме loopback) — %MYIP%."""
    try:
        import psutil
        import socket
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family in (socket.AF_INET, socket.AF_INET6):
                    ip = a.address.split("%")[0]
                    if ip and not ip.startswith(("127.", "::1")):
                        register_own_ip(ip)
    except Exception:
        pass


def register_vpn_profiles() -> None:
    try:
        from vpn import profiles
        for p in profiles.load():
            register_vpn_profile(p.name, p.server)
    except Exception:
        pass


MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){2,7}(?::|[0-9A-Fa-f]{1,4})(?![\w:])"
                     r"|(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){1,6}:(?:[0-9A-Fa-f]{1,4}:?){0,6}"
                     r"(?![\w:])")
LAN_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
    "fe80::/10", "fc00::/7")]


def _mask_ip(match: re.Match) -> str:
    text = match.group(0)
    try:
        ip = ipaddress.ip_address(text.split("%")[0])
    except ValueError:
        return text
    if ip.is_loopback or ip.is_unspecified:
        return text
    if any(ip in net for net in LAN_NETS):
        return "%LANIP%"
    return text


def _compiled() -> re.Pattern | None:
    global _pattern
    with _lock:
        if _pattern is None and _values:
            keys = sorted(_values, key=len, reverse=True)
            _pattern = re.compile("|".join(
                r"(?<![\w.%-])" + re.escape(k) + r"(?![\w%-]|\.\w)" for k in keys), re.I)
        return _pattern


def scrub(text: str) -> str:
    """Полное обезличивание строки журнала или отчёта."""
    if not text:
        return text
    text = anonymize_user(text)
    pattern = _compiled()
    if pattern is not None:
        values = _values
        text = pattern.sub(lambda m: values.get(m.group(0).lower(), m.group(0)), text)
    text = MAC_RE.sub("%MAC%", text)
    text = IPV4_RE.sub(_mask_ip, text)
    text = IPV6_RE.sub(_mask_ip, text)
    return text


def reset() -> None:
    """Для тестов."""
    global _pattern
    with _lock:
        _values.clear()
        _order.clear()
        _pattern = None
