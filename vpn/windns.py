"""DNS, заданный вручную в Windows 11 («Параметры» → сеть → «Назначение DNS-сервера: вручную»).

Если пользователь сам выбрал DNS для IPv4 и/или IPv6, VPN в режиме TUN его не подменяет своим
(vpn/dns_server): A-запросы идут на DNS из настроек IPv4 Windows, AAAA — на DNS из настроек
IPv6, оба через туннель (singbox.build_config, windows_dns). Чего в Windows нет — то через
«DNS через VPN» клиента. Учитываются только публичные адреса: DNS в локальной сети (роутер) на
время VPN всё равно подменяется (vpn/dnsguard.py) — иначе запросы шли бы мимо туннеля.

Читается только реестр (быстро, без PowerShell): подключённые адаптеры (psutil), их GUID из
Control\\Network, статические NameServer из Tcpip и Tcpip6. В Windows 10 такой настройки в
«Параметрах» нет — там проверка не делается."""
import ipaddress
import sys
import winreg

NETWORK_KEY = (r"SYSTEM\CurrentControlSet\Control\Network"
               r"\{4D36E972-E325-11CE-BFC1-08002BE10318}")
TCPIP = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
TCPIP6 = r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces"
WINDOWS_11_BUILD = 22000


def _value(path: str, name: str) -> str:
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            value, _ = winreg.QueryValueEx(key, name)
    except OSError:
        return ""
    if isinstance(value, list):
        value = " ".join(str(v) for v in value)
    return str(value or "")


def _adapter_guids() -> dict[str, str]:
    """Имя подключения («Ethernet», «Беспроводная сеть») → GUID адаптера."""
    result = {}
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, NETWORK_KEY) as root:
            i = 0
            while True:
                try:
                    guid = winreg.EnumKey(root, i)
                except OSError:
                    break
                i += 1
                name = _value(rf"{NETWORK_KEY}\{guid}\Connection", "Name")
                if name and guid.startswith("{"):
                    result[name] = guid
    except OSError:
        pass
    return result


def _public(text: str) -> list[str]:
    servers = []
    for part in text.replace(",", " ").split():
        try:
            address = ipaddress.ip_address(part.split("%")[0])
        except ValueError:
            continue
        if address.is_global and part not in servers:
            servers.append(part)
    return servers


def supported() -> bool:
    return sys.platform == "win32" and sys.getwindowsversion().build >= WINDOWS_11_BUILD


def manual_dns() -> dict:
    """{"v4": [серверы], "v6": [серверы], "adapters": [имена]} — DNS, заданный вручную у
    подключённых адаптеров с основным шлюзом (не у туннеля myav-tun)."""
    result = {"v4": [], "v6": [], "adapters": []}
    if not supported():
        return result
    try:
        import psutil
        up = [name for name, st in psutil.net_if_stats().items() if st.isup]
    except Exception:
        return result
    guids = _adapter_guids()
    for name in up:
        guid = guids.get(name)
        if not guid or name.lower().startswith("myav-tun"):
            continue
        v4_key, v6_key = rf"{TCPIP}\{guid}", rf"{TCPIP6}\{guid}"
        gateway = (_value(v4_key, "DefaultGateway") or _value(v4_key, "DhcpDefaultGateway")
                   or _value(v6_key, "DefaultGateway"))
        if not gateway.strip():
            continue  # без шлюза (виртуальные адаптеры): через него в интернет не ходят
        v4, v6 = _public(_value(v4_key, "NameServer")), _public(_value(v6_key, "NameServer"))
        if v4 or v6:
            result["adapters"].append(name)
        result["v4"] += [s for s in v4 if s not in result["v4"]]
        result["v6"] += [s for s in v6 if s not in result["v6"]]
    return result


def describe(found: dict) -> str:
    """Текст для окна VPN: что берётся из Windows, что — из «DNS через VPN»."""
    if not supported():
        return ""
    if not found["v4"] and not found["v6"]:
        return "В Windows DNS вручную не задан: все запросы — через «DNS через VPN»."
    parts = []
    for family, servers in (("IPv4", found["v4"]), ("IPv6", found["v6"])):
        parts.append(f"{family} — {', '.join(servers)} (из Windows)" if servers
                     else f"{family} — DNS через VPN")
    return (f"DNS задан в Windows ({', '.join(found['adapters'])}): " + "; ".join(parts) +
            ". Запросы к нему тоже идут через туннель.")
