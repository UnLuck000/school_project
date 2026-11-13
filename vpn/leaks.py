"""Проверки VPN: время до серверов (TCP) и утечки DNS и IPv6.

ping_all — время установления TCP-соединения с адресом сервера каждого профиля (лучшее из
двух попыток). Это не скорость через VPN, а «жив ли сервер и насколько далеко»; при
подключённом TUN соединения идут через туннель — числа больше настоящих.

leak_test (режим TUN, VPN подключён):
  * IPv6 — запрос к api6.ipify.org (у него есть только адрес IPv6). В режиме «Только IPv4»
    ответ означает, что IPv6 идёт мимо туннеля (утечка); в режимах с IPv6 — показывается
    адрес, его стоит сверить с адресом сервера;
  * DNS — сервис bash.ws (как dnsleaktest.com): программа запрашивает десять случайных имён
    в его зоне, а он сообщает, какие DNS-серверы эти запросы ему передали и из какой они
    страны. DNS-сервер не в той стране, что внешний адрес VPN, — вероятная утечка (запросы
    уходят провайдеру). Сервису уходят только эти случайные имена.
Без прокси из переменных окружения: запрос должен идти тем же путём, что у обычных программ.
"""
import json
import secrets
import socket
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

OK, WARN, BAD, INFO = "ok", "warn", "bad", "info"


def server_address(server: str) -> tuple[str, int] | None:
    """«host:port» или «[IPv6]:port» из Profile.server."""
    server = server.strip()
    if server.startswith("["):
        host, _, rest = server[1:].partition("]")
        port = rest.lstrip(":")
    else:
        host, _, port = server.rpartition(":")
    if not host or not port.isdigit():
        return None
    return host, int(port)


def tcp_ping(host: str, port: int, timeout: float = 3.0, tries: int = 2) -> float | None:
    """Лучшее время соединения, мс; None — сервер не ответил."""
    best = None
    for _ in range(tries):
        start = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                ms = (time.perf_counter() - start) * 1000
        except OSError:
            continue
        best = ms if best is None else min(best, ms)
    return best


def ping_all(servers: list[str], workers: int = 8) -> list[float | None]:
    def one(server: str):
        address = server_address(server)
        return tcp_ping(*address) if address else None

    with ThreadPoolExecutor(workers) as pool:
        return list(pool.map(one, servers))


@dataclass
class Finding:
    level: str
    title: str
    detail: str = ""
    rows: list = field(default_factory=list)   # DNS: (адрес, страна, сеть, вид)


def _get(url: str, timeout: float = 10.0) -> bytes:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, headers={"User-Agent": "StretchBIT/1.0"})
    with opener.open(request, timeout=timeout) as response:
        return response.read(256 * 1024)


def ipv6_check(ip_mode: str, get=_get) -> Finding:
    try:
        address = get("https://api6.ipify.org", 8).decode("ascii", "replace").strip()
    except OSError:
        address = ""
    from vpn.window import mask_ip
    if not address:
        return Finding(OK, "IPv6: соединений нет", "Сайты, доступные только по IPv6, не "
                       "открываются — значит, и мимо туннеля IPv6 не идёт.")
    if ip_mode == "ipv4":
        return Finding(BAD, "IPv6 идёт мимо VPN", f"В режиме «Только IPv4» сайт ответил по "
                       f"IPv6 с адреса {mask_ip(address)}: этот трафик не проходит через "
                       "туннель. Проверьте, не работает ли другой VPN-клиент.")
    return Finding(INFO, "IPv6 через VPN", f"Адрес IPv6 для сайтов: {mask_ip(address)}. "
                   "Он должен принадлежать серверу VPN, а не провайдеру.")


def dns_check(get=_get, resolve=socket.getaddrinfo) -> Finding:
    try:
        test_id = get("https://bash.ws/id").decode("ascii", "replace").strip()
    except OSError as e:
        return Finding(WARN, "DNS: проверка не удалась", f"Сервис bash.ws недоступен: {e}")
    if not test_id.isdigit():
        return Finding(WARN, "DNS: проверка не удалась", "Сервис bash.ws ответил не так")
    for i in range(1, 11):
        try:
            resolve(f"{i}.{secrets.token_hex(3)}.{test_id}.bash.ws", 80)
        except OSError:
            pass  # имя и не должно существовать: важно, что запрос дошёл до DNS-сервера
    try:
        rows = json.loads(get(f"https://bash.ws/dnsleak/test/{test_id}?json").decode("utf-8"))
    except (OSError, ValueError) as e:
        return Finding(WARN, "DNS: проверка не удалась", f"Нет результата bash.ws: {e}")
    exit_rows = [r for r in rows if r.get("type") == "ip"]
    dns_rows = [r for r in rows if r.get("type") == "dns"]
    country = exit_rows[0].get("country_name", "") if exit_rows else ""
    table = [(r.get("ip", ""), r.get("country_name", ""), r.get("asn", ""), r.get("type", ""))
             for r in exit_rows + dns_rows]
    if not dns_rows:
        return Finding(WARN, "DNS: серверы не определены", "Запросы не дошли до сервиса — "
                       "возможно, DNS блокируется.", table)
    foreign = [r for r in dns_rows if country and r.get("country_name") != country]
    if foreign:
        names = ", ".join(f"{r.get('asn') or r.get('ip')} ({r.get('country_name')})"
                          for r in foreign[:3])
        return Finding(BAD, "Вероятная утечка DNS", f"Внешний адрес VPN — {country}, а "
                       f"запросы передали DNS-серверы из другой страны: {names}. Так "
                       "провайдер видит, какие сайты вы открываете.", table)
    return Finding(OK, "DNS через VPN", f"Все DNS-серверы ({len(dns_rows)}) в той же стране, "
                   f"что и внешний адрес VPN ({country or 'не определена'}).", table)


def leak_test(ip_mode: str) -> list[Finding]:
    with ThreadPoolExecutor(2) as pool:
        ipv6 = pool.submit(ipv6_check, ip_mode)
        dns = pool.submit(dns_check)
        return [dns.result(), ipv6.result()]


def report(findings: list[Finding]) -> str:
    marks = {OK: "✓", WARN: "!", BAD: "✗", INFO: "•"}
    parts = []
    for f in findings:
        text = f"{marks.get(f.level, '•')} {f.title}\n{f.detail}"
        if f.rows:
            from vpn.window import mask_ip
            text += "\n" + "\n".join(
                f"   {'внешний адрес' if kind == 'ip' else 'DNS-сервер'}: "
                f"{mask_ip(ip) if kind == 'ip' else ip} — {country}"
                f"{', ' + asn if asn else ''}" for ip, country, asn, kind in f.rows)
        parts.append(text)
    return "\n\n".join(parts)
