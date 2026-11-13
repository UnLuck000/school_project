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
import re
import shutil
import socket
import subprocess
import time
import urllib.parse
from pathlib import Path

from recovery import journal
import syscmd

SOCKS_PORT = 10808
HTTP_PORT = 10809
TUN_NAME = "sbit-tun"
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
# русские буквы, похожие на латинские: ссылку переписывали вручную, и Xray отвечал
# «unsupported "encryption": nоne» (с русской «о») — так же с None, NONE и пробелом в конце
_LOOKALIKE = str.maketrans("асеорхукмтвнАСЕОРХУКМТВН", "aceopxykmtbhACEOPXYKMTBH")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _token(value: str) -> str:
    """Слово из ссылки (имя параметра, tcp, reality, none...): без пробелов, латиницей,
    строчными — Xray различает регистр и не знает «None»."""
    return value.strip().translate(_LOOKALIKE).lower()


def parse_vless(uri: str) -> dict:
    """vless://uuid@host:port?type=tcp&security=reality&pbk=...&sni=...#Название

    Ссылки, набранные вручную, выправляются: имена параметров и слова-значения (type,
    security, flow, encryption, fp, mode, headerType) — латиницей и строчными, у UUID —
    похожие русские буквы на латинские. Ключи (pbk, sid), адреса и пути — как есть."""
    uri = uri.strip()
    parsed = urllib.parse.urlsplit(uri)
    if _token(parsed.scheme) != "vless" or not parsed.hostname or not parsed.username:
        raise ValueError("Ссылка должна иметь вид vless://UUID@адрес:порт?параметры#название")
    query = {_token(k): v[-1].strip() for k, v in urllib.parse.parse_qs(parsed.query).items()}
    uid = urllib.parse.unquote(parsed.username).strip()
    if UUID_RE.match(_token(uid)):
        uid = _token(uid)
    try:
        port = parsed.port or 443
    except ValueError:
        raise ValueError("Порт в ссылке — не число от 1 до 65535") from None
    word = lambda key, default="": _token(query.get(key, "")) or default  # noqa: E731
    return {
        "id": uid,
        "address": parsed.hostname,
        "port": port,
        "name": urllib.parse.unquote(parsed.fragment).strip() or parsed.hostname,
        "network": word("type", "tcp"),
        "security": word("security", "none"),
        "flow": word("flow"),
        "encryption": word("encryption", "none"),
        "sni": query.get("sni") or query.get("peer", ""),
        "fp": word("fp"),
        "pbk": query.get("pbk", ""),
        "sid": query.get("sid", ""),
        "spx": query.get("spx", ""),
        "alpn": [a.strip() for a in query.get("alpn", "").split(",") if a.strip()],
        "path": query.get("path", ""),
        "host": query.get("host", ""),
        "service": query.get("servicename", ""),
        "mode": word("mode"),
        "header": word("headertype"),
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


# маршрутизация (vpn/route_ru, vpn/block_ads), Mux (vpn/mux), фрагментация (vpn/fragment)
RU_DOMAINS = ["geosite:category-ru", r"regexp:\.ru$", r"regexp:\.xn--p1ai$", r"regexp:\.su$"]
ADS = ["geosite:category-ads-all"]
FRAGMENT = {"packets": "tlshello", "length": "100-200", "interval": "10-20"}
MUX = {"enabled": True, "concurrency": 8, "xudpConcurrency": 16, "xudpProxyUDP443": "reject"}


LOCAL_SOCKS_TAG, LOCAL_HTTP_TAG = "local-socks", "local-http"
IP_MODES = {"ipv4": "Только IPv4",
            "prefer_ipv6": "Предпочтительно IPv6 (IPv4, если у сайта нет IPv6)",
            "ipv6": "IPv6 и до сервера VPN тоже (IPv4 — только если IPv6 нет)"}


def _cfg(key: str, default=None):
    try:
        from ui import settings as cfg
        return cfg.get(key)
    except Exception:
        return default


def local_ports() -> dict[str, int]:
    """Локальные прокси для программ: {"socks": порт, "http": порт} — только включённые и
    допустимые (не внутренние порты связки и не одинаковые)."""
    ports = {}
    for kind in ("socks", "http"):
        if not _cfg(f"vpn/{kind}_enabled", False):
            continue
        try:
            port = int(_cfg(f"vpn/{kind}_port", 0))
        except (TypeError, ValueError):
            continue
        if 1024 <= port <= 65535 and port not in (SOCKS_PORT, HTTP_PORT) and \
                port not in ports.values():
            ports[kind] = port
    return ports


def port_owner(port: int) -> str | None:
    """Кто занял 127.0.0.1:port (имя процесса, «другая программа»); None — порт свободен."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            return None
        except OSError:
            pass
    try:
        import psutil
        for c in psutil.net_connections(kind="tcp"):
            if c.laddr and c.laddr.port == port and c.status == psutil.CONN_LISTEN and c.pid:
                return psutil.Process(c.pid).name()
    except Exception:
        from diag.log import swallowed
        swallowed("xray: кто занял порт")
    return "другая программа"


def ensure_free(*ports: int) -> None:
    """Внутренние порты связки должны быть свободны: иначе wait_port примет чужой Xray
    (второй экземпляр программы, другой клиент) за свой и подключение покажется удачным."""
    for port in ports:
        owner = port_owner(port)
        if owner:
            raise OSError(f"порт 127.0.0.1:{port} уже занят ({owner}) — возможно, VPN уже "
                          "подключён в другом окне или программе")


def add_local_inbound(config: dict, kind: str, port: int) -> None:
    """Локальный прокси для программ: SOCKS5 или HTTP, только 127.0.0.1 — снаружи к нему не
    подключиться. Трафик идёт по тем же правилам, что и туннель."""
    if kind == "socks":
        config["inbounds"].append({"tag": LOCAL_SOCKS_TAG, "listen": "127.0.0.1", "port": port,
                                   "protocol": "socks", "settings": {"udp": True}})
    else:
        config["inbounds"].append({"tag": LOCAL_HTTP_TAG, "listen": "127.0.0.1", "port": port,
                                   "protocol": "http", "settings": {}})


def options_from_settings(mode: str = "proxy", log=None, xray_exe: str = "") -> dict:
    """Настройки для apply_options: выбранный профиль маршрутизации (vpn/routing.py) и
    настройки клиента (Mux, фрагментация, подменённые сертификаты, DNS для WARP).
    mode — какие входящие есть в конфигурации: singbox (TUN sing-box → socks-in), tun
    (TUN Xray), proxy, local. xray_exe — для папки geo-файлов профиля (options["assets"])."""
    from vpn import routing
    profile = routing.active()
    options = routing.options(profile, log)
    options["profile"] = profile.name
    for key in ("mux", "fragment"):
        options[key] = bool(_cfg(f"vpn/{key}", False))
    options["cert_blocked"] = [h for h in str(_cfg("vpn/cert_blocked", "") or "").splitlines()
                               if h.strip()]
    options["mode"] = mode
    options["ip_mode"] = str(_cfg("vpn/ip_mode", "ipv4") or "ipv4")
    options["dns"] = str(_cfg("vpn/dns_server", "1.1.1.1") or "1.1.1.1")
    options["assets"] = routing.assets_dir(profile, Path(xray_exe).parent,
                                           options.get("adblock")) if xray_exe else ""
    if options["assets"] and options.get("adblock"):
        options["adblock_ext"] = routing.ADBLOCK_DAT  # список — файлом, не строками
    return options


DOMAIN_PREFIXES = ("domain", "full", "keyword", "regexp", "geosite", "dotless", "ext")


def domain_entry(entry: str) -> str:
    """Строка домена в виде Xray: с префиксом (domain:, full:, ...) как есть, иначе domain:."""
    entry = entry.strip()
    low = entry.lower()
    if ":" in entry and low.split(":", 1)[0] in DOMAIN_PREFIXES:
        prefix, rest = entry.split(":", 1)
        return prefix.lower() + ":" + rest
    return "domain:" + entry.strip(".").lstrip("*.")


def ip_entry(entry: str) -> str:
    low = entry.strip().lower()
    return low if low.startswith(("geoip:", "ext:")) else entry.strip()


def split_rule_entries(entries: list[str], ip_files=()) -> tuple[list[str], list[str]]:
    """Свои правила: строки → (домены, адреса). Адрес — IP, сеть CIDR, geoip:... или
    ext:файл.dat:метка, если файл — geoip (ip_files: имена строчными); домен — имя (как
    domain:, вместе с поддоменами), full:, keyword:, regexp:, geosite:, ext:..."""
    domains, ips = [], []
    for entry in entries:
        low = entry.lower()
        if low.startswith("geoip:"):
            ips.append(low)
            continue
        if low.startswith("ext:") and low.split(":")[1] in ip_files:
            ips.append(entry)
            continue
        try:
            ipaddress.ip_network(entry, strict=False)
            ips.append(entry)
            continue
        except ValueError:
            pass
        domains.append(domain_entry(entry))
    return domains, ips


# входящие для правил «Дополнительно»: имя в профиле → метки входящих в режиме подключения
INBOUND_TAGS = {"tun": {"singbox": ["socks-in"], "tun": ["tun-in"]},
                "proxy": {"proxy": ["socks-in", "http-in"]}}


def inbound_tags(name: str, mode: str) -> list[str]:
    if name == "local-socks":
        return [LOCAL_SOCKS_TAG]
    if name == "local-http":
        return [LOCAL_HTTP_TAG]
    return INBOUND_TAGS.get(name, {}).get(mode, [])


def advanced_rule(rule: dict, mode: str, tunnel: str = "proxy", ip_files=()) -> dict | None:
    """Правило «Дополнительно» → правило маршрутизации Xray (условия — через «И»).
    None — правило выключено или его входящих в этом режиме нет (без проверки входящего
    оно поймало бы весь трафик)."""
    if rule.get("enabled") is False:
        return None
    out: dict = {"type": "field"}
    if rule.get("inbound"):
        tags = sorted({t for name in rule["inbound"] for t in inbound_tags(name, mode)})
        if not tags:
            return None
        out["inboundTag"] = tags
    domains = [domain_entry(d) for d in rule.get("domain") or [] if d.strip()]
    if domains:
        out["domain"] = domains
    ips = [ip_entry(i) for i in rule.get("ip") or [] if i.strip()]
    if ips:
        out["ip"] = ips
    if rule.get("port"):
        out["port"] = str(rule["port"])
    if rule.get("source_port"):
        out["sourcePort"] = str(rule["source_port"])
    if rule.get("network"):
        out["network"] = rule["network"]
    if rule.get("protocol"):
        out["protocol"] = list(rule["protocol"])
    sources = [ip_entry(s) for s in rule.get("source") or [] if s.strip()]
    if sources:
        out["source"] = sources
    out["outboundTag"] = {"proxy": tunnel, "vpn": "proxy", "direct": "direct",
                          "block": "block"}.get(rule.get("outbound"), tunnel)
    return out


def _rules_for(entries: list[str], tag: str, ip_files=()) -> list[dict]:
    domains, ips = split_rule_entries(entries, ip_files)
    rules = []
    if domains:
        rules.append({"type": "field", "domain": domains, "outboundTag": tag})
    if ips:
        rules.append({"type": "field", "ip": ips, "outboundTag": tag})
    return rules


def apply_options(config: dict, v: dict, options: dict, log=None) -> dict:
    """Маршрутизация, блокировки, WARP, Mux и фрагментация в готовой конфигурации Xray.

    Порядок правил: DNS самого Xray (для WARP) → сертификат подменён (cert_blocked) →
    «Дополнительно» (advanced, по порядку) → свои «Блокировать» → «Туннель» → «Обход» →
    реклама и AdBlock → QUIC/UDP → российские сайты напрямую → остальное в туннель.
    • свои правила (rules_block/proxy/direct): домены (domain:, full:, keyword:, regexp:,
      geosite:, ext:файл:метка...) и адреса (IP, CIDR, geoip:..., ext: файла geoip);
    • route_ru — geosite:category-ru, зоны .ru/.рф/.su, geoip:ru напрямую;
    • block_ads — geosite:category-ads-all; adblock — домены списка AdBlock;
    • block_quic — UDP на порт 443 (браузеры переходят на TCP), block_udp — весь UDP: по UDP
      внутри VLESS VPN чаще распознают и режут;
    • warp — WireGuard Cloudflare (vpn/warp.py): over_vpn — «туннель» ведёт в warp, а warp
      подключается через VPN; under_vpn — сам VPN подключается через warp;
    • домен для правил — из трафика (sniffing routeOnly), сам Xray адреса не спрашивает (AsIs);
    • mux — не с flow=xtls-rprx-vision; fragment — ClientHello до сервера кусочками."""
    say = log or (lambda text: None)
    rules = config.setdefault("routing", {"domainStrategy": "AsIs", "rules": []})["rules"]
    w = options.get("warp")
    tunnel = "warp" if w and w.get("chain") == "over_vpn" else "proxy"
    ip_files = options.get("ip_files") or ()
    head = []
    if w:  # WireGuard до сервера WARP по имени — DNS Xray, и тот только через VPN
        head.append({"type": "field", "inboundTag": ["dns-internal"], "outboundTag": "proxy"})
    if options.get("cert_blocked"):
        head.append({"type": "field", "domain": ["full:" + h for h in options["cert_blocked"]],
                     "outboundTag": "block"})
    for rule in options.get("advanced", []):
        converted = advanced_rule(rule, options.get("mode", ""), tunnel, ip_files)
        if converted is not None:
            head.append(converted)
    head += _rules_for(options.get("rules_block", []), "block", ip_files)
    head += _rules_for(options.get("rules_proxy", []), tunnel, ip_files)
    head += _rules_for(options.get("rules_direct", []), "direct", ip_files)
    if options.get("block_ads"):
        head.append({"type": "field", "domain": list(ADS), "outboundTag": "block"})
    if options.get("adblock_ext"):
        head.append({"type": "field", "domain": [f"ext:{options['adblock_ext']}:adblock"],
                     "outboundTag": "block"})
    elif options.get("adblock"):
        head.append({"type": "field", "domain": ["domain:" + d for d in options["adblock"]],
                     "outboundTag": "block"})
    if options.get("block_udp"):
        head.append({"type": "field", "network": "udp", "outboundTag": "block"})
    elif options.get("block_quic"):
        head.append({"type": "field", "network": "udp", "port": "443", "outboundTag": "block"})
    rules[:0] = head
    if options.get("route_ru"):
        rules.append({"type": "field", "domain": list(RU_DOMAINS), "outboundTag": "direct"})
        rules.append({"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct"})
    if any(r.get("domain") or r.get("protocol") for r in rules):
        for inbound in config["inbounds"]:  # домен для правил — из трафика, без своего DNS
            if inbound["protocol"] in ("socks", "http", "mixed"):
                inbound["sniffing"] = {"enabled": True, "routeOnly": True,
                                       "destOverride": ["http", "tls", "quic"]}
    proxy = next(o for o in config["outbounds"] if o["tag"] == "proxy")
    if options.get("mux"):
        if v.get("flow"):
            say("Mux не включён: с flow=" + v["flow"] + " он несовместим")
        else:
            proxy["mux"] = dict(MUX)
    if options.get("fragment"):
        if w and w.get("chain") == "under_vpn":
            say("Фрагментация не включена: соединение с сервером VPN идёт через WARP")
        else:
            config["outbounds"].append({"tag": "fragment", "protocol": "freedom",
                                        "settings": {"fragment": dict(FRAGMENT)}})
            proxy.setdefault("streamSettings", {}).setdefault("sockopt", {})["dialerProxy"] = \
                "fragment"
    if w:
        _add_warp(config, proxy, w, options, say)
    return config


def _xray_dns(text: str) -> str:
    """DNS для самого Xray (WARP): DoH — как есть, tls:// и прочее — тот же адрес по UDP."""
    text = (text or "").strip()
    if text.lower().startswith("https://"):
        return text
    host = urllib.parse.urlsplit(text if "://" in text else "//" + text).hostname or ""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        return "1.1.1.1"


def _add_warp(config: dict, proxy: dict, w: dict, options: dict, say) -> None:
    from vpn import warp
    interface = options.get("interface", "")
    extra = warp.outbounds(w, interface, say)
    if w.get("chain") == "over_vpn":
        config["outbounds"].insert(0, extra[0])  # первое исходящее — для всего остального
        config["outbounds"] += extra[1:]
        say("WARP: VPN → WARP, сайты видят адрес Cloudflare")
    else:
        config["outbounds"] += extra
        proxy.setdefault("streamSettings", {}).setdefault("sockopt", {})["dialerProxy"] = "warp"
        say("WARP: WARP → VPN, провайдер видит только обмен с Cloudflare")
    ipv6 = options.get("ip_mode", "ipv4") != "ipv4" and bool(w.get("address_v6"))
    config["dns"] = {"servers": [_xray_dns(options.get("dns", ""))], "tag": "dns-internal",
                     "queryStrategy": "UseIP" if ipv6 else "UseIPv4"}


def server_address(host: str, ip_mode: str = "ipv4") -> str:
    """Адрес сервера VPN заранее (до туннеля). Режим «ipv6» — сначала IPv6, если он есть у
    сервера и у компьютера, иначе IPv4."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if ip_mode == "ipv6":
        try:
            infos = socket.getaddrinfo(host, 443, socket.AF_INET6, socket.SOCK_STREAM)
            for *_, addr in infos:
                with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
                    s.settimeout(3)
                    if s.connect_ex(addr[:2]) == 0:
                        return addr[0]
        except OSError:
            pass
    return socket.gethostbyname(host)


def build_config(v: dict, mode: str, interface: str = "", options: dict | None = None,
                 log=None) -> dict:
    """Конфигурация Xray: mode tun — входящее TUN, иначе SOCKS и HTTP на 127.0.0.1."""
    if mode == "tun":
        inbounds = [{"tag": "tun-in", "protocol": "tun",
                     "settings": {"name": TUN_NAME, "MTU": 1500}}]
    else:
        inbounds = [
            # routeOnly: имя сайта — только для правил, соединение идёт по исходному адресу
            {"tag": "socks-in", "listen": "127.0.0.1", "port": SOCKS_PORT, "protocol": "socks",
             "settings": {"udp": True}, "sniffing": {"enabled": True, "routeOnly": True,
                                                      "destOverride": ["http", "tls"]}},
            {"tag": "http-in", "listen": "127.0.0.1", "port": HTTP_PORT, "protocol": "http"}]
    direct = {"tag": "direct", "protocol": "freedom"}
    if interface:
        direct["streamSettings"] = {"sockopt": {"interface": interface}}
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": [outbound(v, interface if mode == "tun" else ""), direct,
                      {"tag": "block", "protocol": "blackhole"}],
        # AsIs: Xray не спрашивает IP сам. С IPIfNonMatch он узнавал адрес по своему DNS
        # (в связке с sing-box — по кругу через туннель, с обрывами), и часть соединений
        # к заблокированным сайтам уходила по правилу «частные адреса» напрямую
        "routing": {"domainStrategy": "AsIs", "rules": [
            {"type": "field", "ip": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
                                     "192.168.0.0/16", "169.254.0.0/16"],
             "outboundTag": "direct"}]},
    }
    return apply_options(config, v, options or {}, log)


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
        journal.log_action(f"VPN: включён системный прокси 127.0.0.1:{HTTP_PORT}",
                           "vpn_proxy_restore", {"old": old})
    return old


def restore_system_proxy(old: dict, path: str = INTERNET_SETTINGS) -> None:
    write_proxy(old, path)
    _save_backup(None)
    if path == INTERNET_SETTINGS:
        journal.forget("vpn_proxy_restore")


@journal.active_check("vpn_proxy_restore")
def _proxy_active(d: dict) -> bool:
    from ui import settings as cfg
    return bool(cfg.get("vpn/proxy_backup"))


@journal.undo_op("vpn_proxy_restore")
def _undo_proxy(d: dict) -> str:
    restore_system_proxy(d["old"])
    return "Системный прокси возвращён к прежним настройкам"


def _save_backup(old: dict | None) -> None:
    try:
        from ui import settings as cfg
        cfg.set_("vpn/proxy_backup", json.dumps(old) if old is not None else "")
    except Exception:
        from diag.log import swallowed
        swallowed("xray: копия настроек прокси")


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
    return subprocess.run(syscmd.PS_ARGS + [script],
                          capture_output=True, text=True, encoding="utf-8", errors="replace",
                          env={**os.environ, **env}, creationflags=CREATE_NO_WINDOW)


def default_route() -> tuple[str, str]:
    """(шлюз, имя адаптера) текущего маршрута по умолчанию."""
    result = _powershell(
        "$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | "
        "Select-Object -First 1; if ($r) { $r.NextHop; (Get-NetAdapter -InterfaceIndex "
        "$r.ifIndex).Name }", {})
    lines = [s.strip() for s in result.stdout.splitlines() if s.strip()]
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
