"""Журнал блоков скриптов PowerShell (событие 4104) — вторая линия после AMSI.

AMSI можно отключить изнутри процесса (правкой памяти), и тогда скрипты дальше не
проверяются. Но PowerShell сам пишет блоки скриптов в журнал событий (ETW, событие 4104):
без политики — «подозрительные» блоки (Add-Type, отражение, обход AMSI...), с политикой
EnableScriptBlockLogging — все. Здесь — сеанс ETW реального времени (нужны права
администратора) на провайдеров Windows PowerShell 5.1 и PowerShell 7; длинный блок приходит
частями (MessageNumber из MessageTotal) — собирается по ScriptBlockId. Собранный текст
проверяется так же, как содержимое AMSI (scanner.amsi.scan_content): хэш, обход AMSI, YARA.

Выполнение уже идёт — остановить скрипт нельзя. Попытка отключить AMSI — признак атаки
наверняка: такой процесс завершается (kill), остальное — сообщение в журнале защиты.
Свои запуски PowerShell (дочерние процессы программы) не проверяются.

Политика «записывать все блоки» (set_policy) — HKLM\\SOFTWARE\\Policies, с откатом в журнале
действий; блоки скриптов попадают и в журнал событий Windows (Microsoft-Windows-PowerShell/
Operational) — вместе со всем, что в них написано.
"""
import hashlib
import os
import queue
import struct
import threading
import time

from processmanager.etw import EtwTrace, wstring
from networkmonitor.dns_etw import GUID
from recovery import journal

PROVIDERS = {"sbit-ps": GUID.parse("{A0C1853B-5C40-4B15-8766-3CF1C58F985A}"),     # 5.1
             "sbit-pwsh": GUID.parse("{F90714A8-5509-434A-BF6D-B1624C8A19A2}")}   # 7
EVENT_SCRIPT_BLOCK = 4104
POLICY_KEYS = (r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
               r"SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging")
PART_TIMEOUT = 30.0          # части одного блока, которые не дошли, — забыть
CACHE_SIZE = 4096
EXCERPT = 4000


def parse_4104(data: bytes) -> tuple[int, int, str, str, str] | None:
    """(номер части, всего частей, текст, ScriptBlockId, путь скрипта)."""
    if len(data) < 10:
        return None
    number, total = struct.unpack_from("<ii", data, 0)
    text, offset = wstring(data, 8)
    block_id, offset = wstring(data, offset)
    path, _ = wstring(data, offset)
    return number, total, text, block_id, path


class Assembler:
    """Части блока → целый блок (по процессу и ScriptBlockId)."""

    def __init__(self):
        self._parts: dict[tuple, tuple[float, int, dict[int, str], str]] = {}

    def add(self, pid: int, number: int, total: int, text: str, block_id: str,
            path: str) -> tuple[str, str] | None:
        now = time.monotonic()
        for key in [k for k, v in self._parts.items() if now - v[0] > PART_TIMEOUT]:
            del self._parts[key]
        if total <= 1:
            return text, path
        key = (pid, block_id)
        _, _, parts, first_path = self._parts.get(key, (now, total, {}, path))
        parts[number] = text
        if len(parts) < total:
            self._parts[key] = (now, total, parts, first_path or path)
            return None
        self._parts.pop(key, None)
        return "".join(parts[i] for i in sorted(parts)), first_path or path


class ScriptBlockWatch:
    def __init__(self, on_event, kill: bool = True, skip_own: bool = True):
        self.on_event = on_event
        self.kill = kill
        self.skip_own = skip_own
        self.scanned = 0
        self._assembler = Assembler()
        self._lock = threading.Lock()
        self._queue: queue.Queue = queue.Queue(maxsize=1000)
        self._traces: list[EtwTrace] = []
        self._cache: dict[str, object] = {}
        self._bases = None
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None

    def start(self) -> str:
        """"" — работает; иначе причина (нет прав администратора и т. п.)."""
        errors = []
        for name, provider in PROVIDERS.items():
            trace = EtwTrace(name, provider, 0, self._on_record, {EVENT_SCRIPT_BLOCK},
                             flush=1.0)
            err = trace.start()
            if err:
                errors.append(err)
            else:
                self._traces.append(trace)
        if not self._traces:
            return ("нужны права администратора" if 5 in errors else
                    f"сеанс ETW не открыт (код {errors[0] if errors else '?'})")
        self._stop.clear()
        self._worker = threading.Thread(target=self._work, daemon=True, name="pslog")
        self._worker.start()
        return ""

    def stop(self) -> None:
        self._stop.set()
        for trace in self._traces:
            trace.stop()
        self._traces = []
        self._queue.put(None)
        if self._worker is not None:
            self._worker.join(timeout=5)
            self._worker = None

    @property
    def running(self) -> bool:
        return bool(self._traces)

    def _on_record(self, event_id: int, pid: int, data: bytes) -> None:
        parsed = parse_4104(data)
        if parsed is None:
            return
        with self._lock:
            whole = self._assembler.add(pid, *parsed)
        if whole is not None:
            try:
                self._queue.put_nowait((pid, *whole))
            except queue.Full:  # noqa: S110 — поток ETW не ждёт: лавина блоков, часть пропускаем
                pass

    def _own_child(self, pid: int) -> bool:
        try:
            import psutil
            return psutil.Process(pid).ppid() == os.getpid()
        except Exception:  # noqa: BLE001 — процесс вышел или нет доступа
            return False

    def _bases_now(self):
        if self._bases is None:
            from analyzer.folderview import rules_and_bases
            signatures, rules, _whitelist = rules_and_bases()
            self._bases = (signatures, rules)
        return self._bases

    def check(self, pid: int, text: str, path: str) -> dict | None:
        """Проверить собранный блок; сведения для журнала защиты или None (чисто)."""
        from scanner import amsi
        if self.skip_own and self._own_child(pid):
            return None
        data = text.encode("utf-16-le")
        sha = hashlib.sha256(data).hexdigest()
        verdict = self._cache.get(sha)
        if verdict is None:
            signatures, rules = self._bases_now()
            verdict = amsi.scan_content(data, path or "scriptblock.ps1", signatures, rules)
            if len(self._cache) >= CACHE_SIZE:
                self._cache.clear()
            self._cache[sha] = verdict
        self.scanned += 1
        if verdict.level == "clean":
            return None
        killed = False
        if self.kill and verdict.level == "threat" and "AMSI" in verdict.reason:
            try:
                import psutil
                psutil.Process(pid).kill()
                killed = True
            except Exception:  # noqa: BLE001 — процесс уже вышел или нет доступа
                killed = False
        return {"pid": pid, "path": path, "level": verdict.level, "reason": verdict.reason,
                "sha256": sha, "killed": killed,
                "excerpt": text[:EXCERPT] + ("\n..." if len(text) > EXCERPT else "")}

    def _work(self) -> None:
        while not self._stop.is_set():
            item = self._queue.get()
            if item is None:
                return
            try:
                info = self.check(*item)
                if info is not None:
                    self.on_event(info)
            except Exception:  # noqa: BLE001 — один блок не должен остановить проверку
                from diag.log import swallowed
                swallowed("pslog: блок скрипта")


# ---------- политика «записывать все блоки» ----------
def policy_enabled() -> bool:
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, POLICY_KEYS[0]) as key:
            return winreg.QueryValueEx(key, "EnableScriptBlockLogging")[0] == 1
    except OSError:
        return False


def _read(path: str):
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            return winreg.QueryValueEx(key, "EnableScriptBlockLogging")[0]
    except OSError:
        return None


def _write(path: str, value) -> None:
    import winreg
    if value is None:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, "EnableScriptBlockLogging")
        except FileNotFoundError:
            pass
        return
    with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "EnableScriptBlockLogging", 0, winreg.REG_DWORD, int(value))


def set_policy(on: bool) -> None:
    """Включить (с записью в журнал действий) или вернуть как было. PermissionError — нет
    прав администратора."""
    if on:
        old = {path: _read(path) for path in POLICY_KEYS}
        for path in POLICY_KEYS:
            _write(path, 1)
        journal.log_action("PowerShell: включён журнал всех блоков скриптов (политика)",
                           "pslog_policy_restore", {"old": old})
        return
    restore = next((r for r in reversed(journal.read_all())
                    if r["op"] == "pslog_policy_restore" and not r["undone"]), None)
    old = restore["data"]["old"] if restore else {path: None for path in POLICY_KEYS}
    for path, value in old.items():
        _write(path, value)
    journal.forget("pslog_policy_restore")


@journal.undo_op("pslog_policy_restore")
def _undo_policy(d: dict) -> str:
    for path, value in d["old"].items():
        if path in POLICY_KEYS:  # только свои ключи, что бы ни было в записи
            _write(path, value)
    from ui import settings as cfg
    cfg.set_("protect/pslog_all", False)
    return "Журнал всех блоков скриптов PowerShell выключен (политика как была)"


@journal.active_check("pslog_policy_restore")
def _policy_still(_d: dict) -> bool:
    return policy_enabled()
