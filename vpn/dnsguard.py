"""DNS без утечки на время VPN: адаптерам с DNS в локальной сети (роутер) — публичный DNS.

DNS-сервер Windows обычно — роутер (частный адрес). Маршрут к своей подсети у Windows
точнее маршрутов туннеля, а адрес шлюза sing-box в туннель не берёт, поэтому запросы к роутеру
шли мимо туннеля — провайдер видел, какие сайты открываются (а с kill switch такие запросы
вообще блокировались бы, и сайты не открывались). На время подключения таким адаптерам
ставится PUBLIC_DNS: запросы к нему идут по маршрутам туннеля, sing-box их перехватывает
(hijack-dns) и отправляет через сервер.

Прежние значения: в журнал действий (откат) и в настройку vpn/dns_backup (возврат при
отключении и при запуске программы после сбоя — recover). Адаптер, получавший DNS по DHCP,
возвращается к DHCP. Значения в PowerShell — через переменные окружения.
"""
import json
import os
import subprocess

from recovery import journal

PUBLIC_DNS = ["1.1.1.1", "1.0.0.1"]
CREATE_NO_WINDOW = 0x08000000


def _powershell(script: str, env: dict | None = None) -> subprocess.CompletedProcess:
    script = "[Console]::OutputEncoding = [Text.Encoding]::UTF8; $ErrorActionPreference = " \
             "'Stop'; " + script
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                          capture_output=True, text=True, encoding="utf-8", errors="replace",
                          env={**os.environ, **(env or {})}, creationflags=CREATE_NO_WINDOW)


def private_dns_adapters() -> list[dict]:
    """[{"index", "alias", "servers", "dhcp"}] — адаптеры, где DNS в локальной сети."""
    script = (
        "Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | "
        "ForEach-Object { $i = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -EA "
        "SilentlyContinue; if ($i -and $i.Status -eq 'Up') { "
        "$guid = $i.InterfaceGuid; $static = (Get-ItemProperty -EA SilentlyContinue "
        "\"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\$guid\")"
        ".NameServer; '{0}|{1}|{2}|{3}' -f $_.InterfaceIndex, $_.InterfaceAlias, "
        "($_.ServerAddresses -join ','), [string]::IsNullOrEmpty($static) } }")
    result = _powershell(script)
    import ipaddress
    found = []
    for line in result.stdout.splitlines():
        parts = line.strip().split("|")
        if len(parts) != 4:
            continue
        servers = [s for s in parts[2].split(",") if s]
        try:
            private = any(ipaddress.ip_address(s).is_private for s in servers)
        except ValueError:
            continue
        if private and not parts[1].startswith("myav-tun"):
            found.append({"index": int(parts[0]), "alias": parts[1], "servers": servers,
                          "dhcp": parts[3] == "True"})
    return found


def protect() -> list[str]:
    """Поставить PUBLIC_DNS адаптерам с DNS в локальной сети. Возвращает их имена."""
    adapters = private_dns_adapters()
    if not adapters:
        return []
    for a in adapters:
        result = _powershell("Set-DnsClientServerAddress -InterfaceIndex $env:IDX "
                             "-ServerAddresses ($env:DNS -split ',')",
                             {"IDX": str(a["index"]), "DNS": ",".join(PUBLIC_DNS)})
        if result.returncode:
            _restore(adapters)
            raise OSError(f"DNS адаптера {a['alias']} не изменён: "
                          f"{(result.stderr or result.stdout).strip()[-200:]}")
    _powershell("Clear-DnsClientCache")
    _save_backup(adapters)
    journal.log_action("VPN: DNS адаптеров на время подключения — " + ", ".join(PUBLIC_DNS) +
                       " (" + ", ".join(a["alias"] for a in adapters) + ")",
                       "vpn_dns_restore", {"adapters": adapters})
    return [a["alias"] for a in adapters]


def _restore(adapters: list[dict]) -> None:
    for a in adapters:
        if a.get("dhcp"):
            _powershell("Set-DnsClientServerAddress -InterfaceIndex $env:IDX "
                        "-ResetServerAddresses", {"IDX": str(a["index"])})
        else:
            _powershell("Set-DnsClientServerAddress -InterfaceIndex $env:IDX "
                        "-ServerAddresses ($env:DNS -split ',')",
                        {"IDX": str(a["index"]), "DNS": ",".join(a["servers"])})
    _powershell("Clear-DnsClientCache")


def restore() -> bool:
    """Вернуть прежний DNS. False — нечего возвращать."""
    adapters = _load_backup()
    if not adapters:
        return False
    _restore(adapters)
    _save_backup(None)
    return True


@journal.undo_op("vpn_dns_restore")
def _undo(d: dict) -> str:
    _restore(d["adapters"])
    _save_backup(None)
    return "DNS адаптеров возвращён к прежнему"


def _save_backup(value) -> None:
    from ui import settings as cfg
    cfg.set_("vpn/dns_backup", json.dumps(value, ensure_ascii=False) if value else "")


def _load_backup() -> list | None:
    try:
        from ui import settings as cfg
        raw = cfg.get("vpn/dns_backup")
        return json.loads(raw) if raw else None
    except Exception:
        return None


def recover() -> bool:
    """Запуск программы: DNS остался подменённым после сбоя — вернуть."""
    return restore()
