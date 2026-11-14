import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import psutil

from networkmonitor.beacon import Beacon, BeaconDetector
from networkmonitor.connections import LOLBINS, Alert, analyze, snapshot
from networkmonitor.dns_etw import DnsQuery, DnsWatcher
from networkmonitor.domains import load_domains, load_ja3, looks_generated, lookup_level
from networkmonitor.ioc import load_ip_blocklist
from networkmonitor.tls import TlsEvent, TlsWatcher
from scanner import exclusions
from scanner.engine import check_file, revocation_enabled
from scanner.hashing import load_all_signatures
from scanner.whitelist import trusted_hashes
from processmanager.memscan import shared_rules
from scanner.signature import VALID, check_revocation, describe, inspect_signature
from processmanager.story import STORY

# правила, срабатывание которых у своей или подписанной программы — не повод пугать
# пользователя: адрес или домен из списка (общие CDN и сервисы туда тоже попадают), DGA
QUIET_RULES = {"IOC", "DOMAIN", "SNI", "DGA"}
MAX_NAMES = 50000     # адрес -> домен из ответов DNS
def _domain_verdict(what: str, found: tuple[str, str, str]) -> tuple[str, str]:
    """Текст и уровень для совпадения со списком доменов (domains.lookup_level)."""
    domain, source, level = found
    text = f"{what} в списке вредоносных ({source}: {domain})"
    if level == "warning":
        text += "; в базе весь домен второго уровня — возможна ошибка базы"
    return text, level


DNS_STATUS = {0: "без адресов (другой тип записи)", 9003: "имя не существует",
              9501: "нет записей", 1460: "время ожидания истекло", 87: "отменён"}
BEACON_FORGET = 3 * 3600


@dataclass(frozen=True)
class DnsRecord:
    """Строка вкладки «DNS-запросы»."""
    time: str
    pid: int
    name: str           # процесс
    exe: str
    domain: str
    addresses: str
    verdict: str        # пусто — ничего не найдено
    level: str          # critical | warning | ""


@dataclass(frozen=True)
class TlsRecord:
    time: str
    pid: int
    name: str
    exe: str
    remote: str
    sni: str
    ja3: str
    alpn: str
    verdict: str
    level: str


# окно без прав со службой (service/remote.py RemoteSensors): DNS (ETW) и TLS (WinDivert)
# нужны права — события приходят от службы, разбор и оповещения остаются здесь
SENSORS = None


class NetworkMonitor:
    """Опрашивает соединения и сообщает о подозрительных; дополнительно смотрит DNS-запросы
    (ETW), начала TLS-соединений (WinDivert) и ищет маячки.

    on_event(kind, payload): kind = status | substatus | alert | dns | tls | beacon | error |
    stopped. dns и tls приходят пачками (списком) раз в interval.
    Вызывается из потоков монитора, поэтому GUI передаёт его через сигнал Qt.
    """

    def __init__(self, sig_dir: Path, rules_dir: Path, netfeeds_dir: Path,
                 on_event, interval: float = 2.0,
                 watch_dns: bool = True, watch_tls: bool = True):
        self.sig_dir = sig_dir
        self.rules_dir = rules_dir
        self.netfeeds_dir = netfeeds_dir
        self.on_event = on_event
        self.interval = interval

        self._stop = threading.Event()
        self._reload = threading.Event()
        self._thread: threading.Thread | None = None
        self._signatures = None
        self._rules = None
        self._reported: set[tuple] = set()
        self._verdicts: dict[tuple, str] = {}
        self._sigs: dict[tuple, tuple[str, bool, str | None]] = {}  # текст, действ., издатель
        self._digests: dict[tuple, str] = {}
        self._excl: tuple[float, dict] = (0.0, {})

        self._domains: dict[str, str] = {}
        self._ja3: dict[str, str] = {}
        self._names: dict[str, str] = {}          # адрес -> домен (из ответов DNS)
        self._addresses: dict[str, set[str]] = {}  # домен -> адреса из ответов DNS
        self._procs: dict[int, tuple[str, str, float]] = {}
        self._own: set[int] = {os.getpid()}       # сама программа и её рабочие процессы
        self._seen: set[tuple] = set()            # оповещения DNS/TLS: (pid, правило, значение)
        self._conns: set[tuple] = set()           # соединения прошлого снимка
        self._lock = threading.Lock()
        self._dns_batch: list[DnsRecord] = []
        self._tls_batch: list[TlsRecord] = []
        self.beacons = BeaconDetector()
        sensors = SENSORS
        dns_cls = sensors.dns if sensors is not None else DnsWatcher
        tls_cls = sensors.tls if sensors is not None else TlsWatcher
        self._dns = dns_cls(self._on_dns, self._substatus) if watch_dns else None
        self._tls = tls_cls(self._on_tls, self._substatus) if watch_tls else None

    def start(self):
        self._stop.clear()
        from processmanager.story import STORY
        STORY.sources.add("net")
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        from processmanager.story import STORY
        STORY.sources.discard("net")
        for watcher in (self._dns, self._tls):
            if watcher is not None:
                watcher.stop()
        if self._thread:
            self._thread.join(timeout=15)

    def reload_bases(self):
        """Базы обновились: перечитать их в потоке монитора."""
        self._reload.set()

    def _emit(self, kind: str, payload=""):
        try:
            self.on_event(kind, payload)
        except Exception:
            from diag.log import swallowed
            swallowed("netmon: обработчик события интерфейса")

    def _substatus(self, text: str) -> None:
        self._emit("substatus", text)

    def domain_of(self, ip: str) -> str:
        return self._names.get(ip, "")

    def addresses_of(self, domain: str) -> list[str]:
        with self._lock:
            return sorted(self._addresses.get(domain.lower(), ()))

    # ---------- файлы программ ----------
    def _verdict(self, exe: str) -> str:
        """Результат проверки exe (пустая строка: чисто или проверить нельзя)."""
        if not exe or self._signatures is None:
            return ""
        path = Path(exe)
        try:
            key = (exe, path.stat().st_mtime)
            if key in self._verdicts:
                return self._verdicts[key]
            reason = check_file(path, self._signatures, self._rules,
                                trusted_hashes()) or ""
        except OSError:
            return ""
        self._verdicts[key] = reason
        return reason

    def _signature(self, exe: str) -> tuple[str, bool]:
        """(текст о подписи, подпись действительна)."""
        if not exe:
            return "", False
        path = Path(exe)
        try:
            key = (exe, path.stat().st_mtime)
        except OSError:
            return "", False
        if key not in self._sigs:
            try:
                info = inspect_signature(path)
                if revocation_enabled():
                    info = check_revocation(path, info)
                valid = info.status == VALID
                self._sigs[key] = (describe(info), valid, info.publisher if valid else None)
            except Exception:
                self._sigs[key] = ("", False, None)
        return self._sigs[key][:2]

    def program_key(self, exe: str) -> str:
        """Ключ исключения программы (scanner.exclusions.program_key): издатель подписи
        или SHA-256 файла."""
        if not exe:
            return ""
        self._signature(exe)
        try:
            key = (exe, Path(exe).stat().st_mtime)
        except OSError:
            return ""
        publisher = self._sigs.get(key, ("", False, None))[2]
        if publisher:
            return exclusions.program_key(exe, publisher)
        if key not in self._digests:
            import hashlib
            digest = hashlib.sha256()
            try:
                with open(exe, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        digest.update(chunk)
            except OSError:
                return ""
            self._digests[key] = digest.hexdigest()
        return exclusions.program_key(exe, sha256=self._digests[key])

    def excluded(self, exe: str) -> bool:
        """Программа в исключениях мониторинга сети (перечитываются раз в 5 с)."""
        if not exe:
            return False
        stamp, data = self._excl
        if time.monotonic() - stamp > 5:
            data = exclusions.load().get("network", {})
            self._excl = (time.monotonic(), data)
        return bool(data) and self.program_key(exe) in data

    def _signature_text(self, exe: str) -> str:
        return self._signature(exe)[0]

    def _process(self, pid: int) -> tuple[str, str, float]:
        """(имя, путь, время запуска) процесса; кэш по PID."""
        info = self._procs.get(pid)
        if info is None:
            try:
                proc = psutil.Process(pid)
                name, created = proc.name(), proc.create_time()
                try:
                    exe = proc.exe()
                except psutil.Error:
                    exe = ""
                info = (name, exe, created)
            except psutil.Error:
                info = ("?", "", 0.0)
            if len(self._procs) > 5000:
                self._procs.clear()
            self._procs[pid] = info
        return info

    def _refresh_own(self) -> None:
        try:
            me = psutil.Process()
            self._own = {me.pid} | {c.pid for c in me.children(recursive=True)}
        except psutil.Error:
            self._own = {os.getpid()}

    def quiet_reason(self, pid: int, name: str, exe: str) -> str:
        """Почему по этой программе не нужно оповещение (пусто — нужно): сама программа
        (обновление баз, проверка отзыва) или программа с действительной подписью, кроме
        системных утилит, которыми пользуются вредоносы (powershell, mshta, certutil...).
        Файл программы, распознанный как угроза, оповещение получает всегда."""
        if pid in self._own:
            return "это сама программа StretchBIT"
        if not exe or (name or os.path.basename(exe)).lower() in LOLBINS or self._verdict(exe):
            return ""
        text, valid = self._signature(exe)
        return f"программа подписана: {text}" if valid else ""

    def _alert(self, level: str, rule: str, pid: int, remote: str, detail: str,
               name: str = "", exe: str = "") -> None:
        pname, pexe, created = self._process(pid) if pid else ("?", "", 0.0)
        name, exe = name or pname, exe or pexe
        if rule in QUIET_RULES and self.quiet_reason(pid, name, exe):
            return
        verdict = self._verdict(exe)
        if not verdict and self.excluded(exe):
            return  # исключена пользователем (кроме случая, когда файл распознан угрозой)
        if verdict:
            level = "critical"
            detail += f"; файл программы распознан: {verdict}"
        sig_text = self._signature_text(exe)
        if sig_text:
            detail += f"; подпись: {sig_text}"
        self._emit("alert", Alert(time=time.strftime("%H:%M:%S"), level=level, rule=rule,
                                  pid=pid, name=name, exe=exe, create_time=created,
                                  remote=remote, detail=detail))

    def _once(self, *key) -> bool:
        """True, если такое оповещение ещё не выдавалось."""
        with self._lock:
            if key in self._seen:
                return False
            if len(self._seen) > 20000:
                self._seen.clear()
            self._seen.add(key)
            return True

    # ---------- DNS ----------
    def _on_dns(self, q: DnsQuery) -> None:
        name, exe, _ = self._process(q.pid) if q.pid else ("?", "", 0.0)
        if q.results:
            with self._lock:
                if len(self._names) > MAX_NAMES:
                    self._names.clear()
                    self._addresses.clear()
                for ip in q.results:
                    self._names[ip] = q.name
                self._addresses.setdefault(q.name, set()).update(q.results)
        verdict, level = "", ""
        found = lookup_level(self._domains, q.name)
        if found:
            verdict, level = _domain_verdict("домен", found)
        else:
            dga = looks_generated(q.name)
            if dga:
                verdict, level = dga, "warning"
        if verdict:
            quiet = self.quiet_reason(q.pid, name, exe) if q.pid else ""
            if quiet:
                verdict, level = f"{verdict}; оповещения нет: {quiet}", "info"
            elif self._once(q.pid, "dns", q.name):
                self._alert(level, "DOMAIN" if found else "DGA", q.pid, q.name,
                            f"DNS-запрос: {verdict}", name, exe)
        if not q.final:  # начало запроса: одно обращение — одно событие для маячков
            beacon = self.beacons.feed(name, exe, q.name, q.time, "dns") if q.pid else None
            if beacon:
                self._on_beacon(beacon)
            return  # строка в список добавится с ответом (3008)
        answer = ", ".join(q.results) or DNS_STATUS.get(q.status, f"нет ответа (код {q.status})")
        if q.pid:
            STORY.contacted(q.pid, q.name, "dns", ", ".join(q.results[:3]), q.time)
        if not q.pid:
            answer = "из кэша DNS"
        record = DnsRecord(time.strftime("%H:%M:%S", time.localtime(q.time)), q.pid,
                           name if q.pid else "", exe, q.name, answer, verdict, level)
        with self._lock:
            self._dns_batch.append(record)

    # ---------- TLS ----------
    def _on_tls(self, ev: TlsEvent) -> None:
        h = ev.hello
        verdict, level = "", ""
        family = self._ja3.get(h.ja3)
        found = lookup_level(self._domains, h.sni) if h.sni else None
        if family:
            verdict, level = f"отпечаток JA3 вредоносного клиента: {family}", "critical"
        elif found:
            verdict, level = _domain_verdict("сайт", found)
        elif h.sni and looks_generated(h.sni):
            verdict, level = looks_generated(h.sni), "warning"
        rule = "JA3" if family else ("SNI" if found else "DGA")
        quiet = self.quiet_reason(ev.pid, ev.name, ev.exe) if verdict and rule != "JA3" else ""
        if quiet:
            verdict, level = f"{verdict}; оповещения нет: {quiet}", "info"
        elif verdict and self._once(ev.pid, "tls", h.ja3 + h.sni):
            self._alert(level, rule, ev.pid, h.sni or ev.remote,
                        f"TLS: {verdict}; JA3 {h.ja3}", ev.name, ev.exe)
        beacon = self.beacons.feed(ev.name, ev.exe, h.sni or ev.remote.rsplit(":", 1)[0],
                                   ev.time, "tls")
        if beacon:
            self._on_beacon(beacon)
        STORY.contacted(ev.pid, h.sni or ev.remote, "tls", ev.remote if h.sni else "", ev.time)
        record = TlsRecord(time.strftime("%H:%M:%S", time.localtime(ev.time)), ev.pid, ev.name,
                           ev.exe, ev.remote, h.sni, h.ja3, h.alpn, verdict, level)
        with self._lock:
            self._tls_batch.append(record)

    # ---------- маячки ----------
    def _on_beacon(self, b: Beacon) -> None:
        self._emit("beacon", b)
        _, signed = self._signature(b.exe)
        if signed:
            return  # обновления и телеметрия подписанных программ: только в списке
        pid = next((pid for pid, (_, exe, _) in list(self._procs.items())
                    if exe and exe.lower() == b.exe.lower()), 0)
        self._alert("warning", "BEACON", pid, b.target,
                    f"маячок: обращения к {b.target} каждые {b.period:.0f} с "
                    f"(разброс {b.cv:.0%}, событий {b.count}, источник {b.source})",
                    b.program, b.exe)

    def _flush(self) -> None:
        with self._lock:
            dns, tls = self._dns_batch, self._tls_batch
            self._dns_batch, self._tls_batch = [], []
        if dns:
            self._emit("dns", dns)
        if tls:
            self._emit("tls", tls)

    # ---------- основной цикл ----------
    def _load(self):
        blocklist = load_ip_blocklist(self.netfeeds_dir)
        self._signatures = load_all_signatures(self.sig_dir)
        self._rules = shared_rules(self.rules_dir)
        self._domains = load_domains(self.netfeeds_dir / "domains")
        self._ja3 = load_ja3(self.netfeeds_dir / "ja3")
        return blocklist

    def _run(self):
        self._emit("status", "Загружаю базы...")
        try:
            blocklist = self._load()
        except Exception as e:
            self._emit("error", f"Не удалось загрузить базы: {e}")
            self._emit("stopped")
            return

        self._emit("status", f"Мониторинг сети включён. Адресов C2: {len(blocklist)}, "
                             f"доменов: {len(self._domains)}, отпечатков JA3: {len(self._ja3)}")
        for watcher in (self._dns, self._tls):
            if watcher is not None:
                watcher.start()
        last_forget = time.monotonic()
        try:
            while not self._stop.wait(self.interval):
                self._flush()
                if self._reload.is_set():
                    self._reload.clear()
                    try:
                        blocklist = self._load()
                        self._verdicts.clear()
                    except Exception as e:
                        self._emit("error", f"Не удалось перечитать базы: {e}")
                if time.monotonic() - last_forget > 600:
                    self.beacons.forget_older(time.time() - BEACON_FORGET)
                    last_forget = time.monotonic()
                try:
                    conns = snapshot()
                except Exception as e:
                    self._emit("error", f"Ошибка чтения соединений: {e}")
                    continue

                now = time.time()
                self._refresh_own()
                current_conns = {(c.pid, c.rip, c.rport, c.lport) for c in conns}
                for c in conns:  # новые соединения — события для поиска маячков
                    if (c.pid, c.rip, c.rport, c.lport) not in self._conns and not c.inbound:
                        target = self._names.get(c.rip) or c.rip
                        STORY.contacted(c.pid, f"{c.rip}:{c.rport}", "tcp",
                                        self._names.get(c.rip, ""), now)
                        beacon = self.beacons.feed(c.name, c.exe, target, now, "tcp")
                        if beacon:
                            self._on_beacon(beacon)
                self._conns = current_conns

                current = set()
                for c in conns:
                    for level, rule, detail in analyze(c, blocklist):
                        key = (c.pid, c.create_time, c.rip, c.rport, rule)
                        current.add(key)
                        if key in self._reported:
                            continue
                        self._reported.add(key)
                        domain = self._names.get(c.rip)
                        if domain:
                            detail += f" (домен {domain})"
                        self._alert(level, rule, c.pid, f"{c.rip}:{c.rport}", detail,
                                    c.name, c.exe)
                # забываем соединения, которые закрылись: новое появление сработает снова
                self._reported &= current
        finally:
            self._flush()
            self._emit("stopped", "")
