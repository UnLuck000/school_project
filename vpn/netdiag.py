"""«Почему нет интернета?» и чужие VPN-клиенты с TUN.

Чужой клиент с TUN (Throne, Happ, Hiddify, v2rayN...) на sing-box со «строгой маршрутизацией»
ставит фильтры WFP (фильтрующая платформа Windows), которые блокируют всё мимо его
туннеля. Это не правила брандмауэра: выключение и сброс брандмауэра их не снимают, держатся
они, пока жив процесс клиента. 11.11.2026 после переключения на мобильный интернет у такого
клиента туннель перестал работать, а фильтры остались — браузер писал
ERR_NETWORK_ACCESS_DENIED, хотя наш VPN был отключён и всё вернул.

diagnose() — по шагам: связь, наш kill switch, блокировка исходящих в брандмауэре,
системный прокси на мёртвом порту, оставшаяся подмена DNS, чужие TUN-клиенты и их блокирующие
фильтры WFP (список фильтров — только с правами администратора). Ничего не меняет.
"""
import ctypes
import os
import re
import socket
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

CREATE_NO_WINDOW = 0x08000000
OK, WARN, BAD = "ok", "warn", "bad"
# процессы VPN-клиентов, которые поднимают свой TUN (имя файла в нижнем регистре)
TUN_CLIENTS = {
    "throne.exe": "Throne", "thronecore.exe": "Throne", "happ.exe": "Happ",
    "happd.exe": "Happ (служба)", "v2rayn.exe": "v2rayN", "nekoray.exe": "NekoRay",
    "nekobox.exe": "NekoBox", "hiddify.exe": "Hiddify", "hiddifycli.exe": "Hiddify",
    "clash-verge.exe": "Clash Verge", "verge-mihomo.exe": "Clash Verge (mihomo)",
    "mihomo.exe": "mihomo", "clash.exe": "Clash", "wireguard.exe": "WireGuard",
    "openvpn.exe": "OpenVPN", "outline.exe": "Outline", "amneziavpn.exe": "AmneziaVPN",
    "sing-box.exe": "sing-box", "xray.exe": "Xray",
}
PROBES = (("1.1.1.1", 443), ("8.8.8.8", 443))


@dataclass
class Finding:
    level: str      # ok | warn | bad
    title: str
    text: str = ""


def _our_dir() -> str:
    return os.path.normcase(str(Path(__file__).resolve().parent / "bin"))


def foreign_tunnels() -> list[str]:
    """Чужие VPN-клиенты и туннели: «Throne (thronecore.exe)», «адаптер throne-tun». Свои
    xray.exe и sing-box.exe (из vpn/bin) и свой адаптер не считаются."""
    found: list[str] = []
    try:
        from processmanager import ntsnap
        procs = ntsnap.list_processes()
    except Exception:
        procs = []
    seen, clients = set(), {}
    for p in procs:
        name = p.name.lower()
        if name not in TUN_CLIENTS or name in seen:
            continue
        if name in ("sing-box.exe", "xray.exe"):
            try:
                import psutil
                exe = psutil.Process(p.pid).exe()
            except Exception:
                exe = ""
            if not exe or os.path.normcase(os.path.dirname(exe)) == _our_dir():
                continue  # своё ядро (или не узнать чьё) — не предупреждаем
        seen.add(name)
        clients.setdefault(TUN_CLIENTS[name].split(" (")[0], []).append(p.name)
    found += [f"{client} ({', '.join(files)})" for client, files in clients.items()]
    try:
        import psutil

        from vpn import dnsguard, singbox
        for alias, stats in psutil.net_if_stats().items():
            if stats.isup and alias != singbox.TUN_NAME and dnsguard.is_tunnel(alias, ""):
                found.append(f"адаптер {alias}")
    except Exception:
        from diag.log import swallowed
        swallowed("netdiag: адаптеры")
    return found


def wfp_block_filters() -> list[tuple[str, int]]:
    """Блокирующие фильтры WFP чужих туннелей: [(имя, сколько)]. Нужны права
    администратора (netsh wfp show filters), иначе — пусто."""
    target = Path(tempfile.gettempdir()) / f"sbit-wfp-{os.getpid()}.xml"
    try:
        subprocess.run(["netsh", "wfp", "show", "filters", f"file={target}"],
                       capture_output=True, timeout=60, creationflags=CREATE_NO_WINDOW)
        text = target.read_text(encoding="utf-8", errors="ignore")
    except (OSError, subprocess.SubprocessError):
        return []
    finally:
        try:
            target.unlink()
        except OSError:
            pass
    return parse_wfp_blocks(text)


TUNNEL_FILTER_RE = re.compile(r"sing|tun|wireguard|wintun|throne|happ|clash|mihomo|xray|v2ray"
                              r"|hiddify|nekoray|outline|amnezia|openvpn|vpn", re.I)
SYSTEM_PROVIDERS = ("FWPM_PROVIDER_MPSSVC", "FWPM_PROVIDER_IKEEXT", "FWPM_PROVIDER_TCP")


def parse_wfp_blocks(xml: str) -> list[tuple[str, int]]:
    """Из вывода netsh wfp show filters — блокирующие фильтры, похожие на туннельные, не от
    служб Windows (брандмауэр сам ставит свои блокировки — они не наш случай)."""
    counts: dict[str, int] = {}
    for item in re.split(r"<item>\s*<filterKey>", xml)[1:]:
        name = re.search(r"<displayData>\s*<name>(.*?)</name>", item, re.S)
        action = re.search(r"<action>\s*<type>(.*?)</type>", item, re.S)
        provider = re.search(r"<providerKey>(.*?)</providerKey>", item)
        if not name or not action or "BLOCK" not in action.group(1):
            continue
        title = name.group(1).strip()
        if provider and provider.group(1).startswith(SYSTEM_PROVIDERS):
            continue
        own = title.lower().startswith(("sbit kill switch", "myav kill switch"))
        if TUNNEL_FILTER_RE.search(title) and not own:
            counts[title] = counts.get(title, 0) + 1
    return sorted(counts.items(), key=lambda kv: -kv[1])


def probe(host: str, port: int, timeout: float = 3.0) -> str:
    """Пустая строка — соединение открылось, иначе причина. Без прокси (обычный сокет)."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return ""
    except OSError as e:
        code = getattr(e, "winerror", None) or e.errno
        if code == 10013:
            return "доступ запрещён (соединение блокирует фильтр, код 10013)"
        if isinstance(e, socket.timeout) or code in (10060, 110):
            return "нет ответа (тайм-аут)"
        if code in (10051, 10065):
            return "нет маршрута в сеть"
        return str(e)


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _proxy() -> tuple[bool, str]:
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as k:
            enabled = winreg.QueryValueEx(k, "ProxyEnable")[0] == 1
            server = winreg.QueryValueEx(k, "ProxyServer")[0] if enabled else ""
        return enabled, str(server)
    except OSError:
        return False, ""


def _proxy_alive(server: str) -> bool:
    """«127.0.0.1:10809», «http=...;https=...» или «socks=127.0.0.1:2080» — открыт ли порт."""
    match = re.search(r"([\w.\-]+):(\d+)", server)
    if not match:
        return True
    return probe(match.group(1), int(match.group(2)), 1.0) == ""


def diagnose(vpn_connected: bool = False) -> list[Finding]:
    out: list[Finding] = []
    failures = [(f"{h}:{p}", probe(h, p)) for h, p in PROBES]
    broken = [f"{a} — {why}" for a, why in failures if why]
    if not broken:
        out.append(Finding(OK, "Связь есть", "соединения с 1.1.1.1 и 8.8.8.8 открываются"))
    else:
        out.append(Finding(BAD, "Связи нет", "; ".join(broken)))
    denied = any("10013" in why for _, why in failures)

    from vpn import killswitch
    if killswitch.active() and not vpn_connected:
        out.append(Finding(BAD, "Включён kill switch этой программы",
                           "VPN не подключён, а интернет перекрыт: кнопка «Снять блокировку» "
                           "в окне VPN"))
    try:
        blocked = [n for n, p in killswitch.profiles().items()
                   if p["enabled"] and p["outbound"] == "Block"]
    except OSError:
        blocked = []
    if blocked and not vpn_connected:
        out.append(Finding(BAD, "Брандмауэр блокирует исходящие соединения",
                           "профили: " + ", ".join(blocked) + ". Если это не наш kill switch — "
                           "так настроил брандмауэр кто-то другой"))

    enabled, server = _proxy()
    if enabled and not _proxy_alive(server):
        out.append(Finding(BAD, "Системный прокси указывает на закрытый порт",
                           f"{server}: программа-прокси не запущена, браузеры без связи. "
                           "«Параметры» → «Сеть и Интернет» → «Прокси»"))

    try:
        from ui import settings as cfg
        if cfg.get("vpn/dns_backup") and not vpn_connected:
            out.append(Finding(WARN, "DNS адаптеров ещё подменён этой программой",
                               "вернётся при следующем запуске программы"))
    except Exception:
        from diag.log import swallowed
        swallowed("netdiag: подмена DNS")

    tunnels = foreign_tunnels()
    if tunnels:
        out.append(Finding(WARN if not denied else BAD, "Работает другой VPN с туннелем",
                           ", ".join(tunnels) + ". Его фильтры могут блокировать всё мимо "
                           "его туннеля; выключение брандмауэра их не снимает — закройте "
                           "этот клиент полностью"))
    if _is_admin():
        filters = wfp_block_filters()
        if filters:
            names = "; ".join(f"{name} ×{n}" for name, n in filters[:6])
            out.append(Finding(BAD if denied else WARN,
                               "Блокирующие фильтры чужого туннеля (WFP)",
                               names + ". Пока его туннель работает, это нормально; если он "
                               "оборвался, они перекрывают весь интернет. Держатся, пока жив "
                               "процесс, который их поставил"))
    else:
        out.append(Finding(WARN, "Фильтры WFP не проверены", "нужны права администратора"))

    if broken and len(out) == 1:
        out.append(Finding(WARN, "Явной причины не найдено",
                           "проверьте Wi-Fi или кабель, роутер и баланс мобильного интернета"))
    return out


ICON = {OK: "✓", WARN: "!", BAD: "✗"}


def report(findings: list[Finding]) -> str:
    return "\n\n".join(f"{ICON[f.level]}  {f.title}" + (f"\n{f.text}" if f.text else "")
                       for f in findings)
