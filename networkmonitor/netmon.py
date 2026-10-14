import threading
import time
from pathlib import Path

from networkmonitor.connections import Alert, analyze, snapshot
from networkmonitor.ioc import load_ip_blocklist
from scanner.engine import check_file
from scanner.hashing import load_all_signatures
from scanner.whitelist import load_whitelist
from scanner.yara_engine import load_rules


class NetworkMonitor:
    """Опрашивает соединения и сообщает о подозрительных.

    on_event(kind, payload): kind = status | alert | error | stopped.
    Вызывается из потока монитора, поэтому GUI передаёт его через сигнал Qt.
    """

    def __init__(self, sig_dir: Path, rules_dir: Path, netfeeds_dir: Path,
                 on_event, interval: float = 2.0):
        self.sig_dir = sig_dir
        self.rules_dir = rules_dir
        self.netfeeds_dir = netfeeds_dir
        self.on_event = on_event
        self.interval = interval

        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._signatures: set[str] = set()
        self._rules = None
        self._reported: set[tuple] = set()
        self._verdicts: dict[tuple, str] = {}

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=15)

    def _emit(self, kind: str, payload=""):
        try:
            self.on_event(kind, payload)
        except Exception:
            pass

    def _verdict(self, exe: str) -> str:
        """Результат проверки exe (пустая строка: чисто или проверить нельзя)."""
        if not exe:
            return ""
        path = Path(exe)
        try:
            key = (exe, path.stat().st_mtime)
            if key in self._verdicts:
                return self._verdicts[key]
            reason = check_file(path, self._signatures, self._rules,
                                set(load_whitelist())) or ""
        except OSError:
            return ""
        self._verdicts[key] = reason
        return reason

    def _run(self):
        self._emit("status", "Загружаю базы...")
        try:
            blocklist = load_ip_blocklist(self.netfeeds_dir)
            self._signatures = load_all_signatures(self.sig_dir)
            self._rules, _ = load_rules(self.rules_dir)
        except Exception as e:
            self._emit("error", f"Не удалось загрузить базы: {e}")
            self._emit("stopped")
            return

        self._emit("status", f"Мониторинг сети включён. "
                             f"Адресов C2 в списке: {len(blocklist)}")
        try:
            while not self._stop.wait(self.interval):
                try:
                    conns = snapshot()
                except Exception as e:
                    self._emit("error", f"Ошибка чтения соединений: {e}")
                    continue

                current = set()
                for c in conns:
                    for level, rule, detail in analyze(c, blocklist):
                        key = (c.pid, c.create_time, c.rip, c.rport, rule)
                        current.add(key)
                        if key in self._reported:
                            continue
                        self._reported.add(key)

                        verdict = self._verdict(c.exe)
                        if verdict:
                            level = "critical"
                            detail += f"; файл программы распознан: {verdict}"
                        self._emit("alert", Alert(
                            time=time.strftime("%H:%M:%S"), level=level, rule=rule,
                            pid=c.pid, name=c.name, exe=c.exe,
                            create_time=c.create_time,
                            remote=f"{c.rip}:{c.rport}", detail=detail,
                        ))
                # забываем соединения, которые закрылись: новое появление сработает снова
                self._reported &= current
        finally:
            self._emit("stopped", "")