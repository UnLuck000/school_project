"""Контроль запуска процессов: каждая запущенная программа проверяется сразу.

Как узнаём о запуске:
• с правами администратора — ETW Microsoft-Windows-Kernel-Process (событие 1 ProcessStart):
  событие приходит в момент создания процесса, ловятся и процессы, живущие доли секунды;
• без прав — опрос списка процессов (ntsnap) раз в POLL_SECONDS: короткоживущий процесс
  можно пропустить.

Что делаем с новым процессом:
1. Файл программы проверяется всеми слоями (scanner.pool: хэши, YARA, эвристика; повторный
   запуск того же файла — ответ из кэша вердиктов без чтения файла).
2. Пока файл проверяется, процесс приостановлен (если файл не из папки Windows, не крупнее
   SUSPEND_LIMIT и его вердикта ещё нет в кэше): вредоносный код не успеет выполниться.
3. Угроза (хэш, правило YARA) — процесс и его дочерние процессы завершаются (_kill_tree;
   ВРЕМЕННО ЗАКОММЕНТИРОВАНО в _check_new: пока только уведомление, процесс продолжает
   работу), файл можно вручную отправить в карантин. Подозрительное (эвристика) —
   процесс продолжает работу, но о нём сообщается.
4. Интерпретаторы скриптов (powershell, wscript, mshta...): проверяется и файл скрипта из
   командной строки, закодированная команда PowerShell (-enc) — подозрительна.
5. Цепочки «документ → оболочка» (Word запускает PowerShell, Excel — cmd) — подозрительны:
   так работают макросы-загрузчики.

Процессы, запущенные до включения защиты, проверяются один раз без завершения: угроза
показывается в журнале защиты. Завершение процесса в журнал действий не пишется
(отменить его нельзя); пользователь видит его в журнале защиты и отчёте о работе.

LaunchGuard(on_event).start(); on_event(kind, info) из рабочего потока:
kind = status | blocked | threat | suspicious | error, info — dict (pid, name, exe, ...).
"""
import os
import queue
import re
import threading
from pathlib import Path

POLL_SECONDS = 0.3
SUSPEND_LIMIT = 64 * 1024 * 1024  # крупные программы (игры) не приостанавливаем: долго читать
SESSION_NAME = "sbit-proc"
EVENT_PROCESS_START = 1
KEYWORD_PROCESS = 0x10

SCRIPT_HOSTS = {"powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                "cmd.exe"}
SHELLS = SCRIPT_HOSTS | {"rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
                         "msiexec.exe", "schtasks.exe"}
DOCUMENT_APPS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
                 "mspub.exe", "onenote.exe", "visio.exe", "acrord32.exe", "acrobat.exe",
                 "foxitpdfreader.exe", "wordpad.exe", "hwp.exe"}
SCRIPT_EXTS = (".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta",
               ".bat", ".cmd")
ENCODED_RE = re.compile(r"(?:^|\s)[-/]e(?:nc(?:odedcommand)?|c)?\s+[A-Za-z0-9+/=]{20,}",
                        re.IGNORECASE)


def windows_dir() -> str:
    return os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows")) + os.sep


def _is_filetime(value: int) -> bool:
    return 0x01C0000000000000 < value < 0x0200000000000000  # годы примерно 1990–2190


def parse_process_start(data: bytes) -> tuple[int, int, str] | None:
    """Событие 1 Kernel-Process → (pid, ppid, путь ядра). Раскладка зависит от версии:
    • старая: ProcessID(4), CreateTime(8), ParentProcessID(4), SessionID, Flags, ImageName;
    • Windows 10/11 (версия 3+): ProcessID(4), ProcessSequenceNumber(8), CreateTime(8),
      ParentProcessID(4), ParentProcessSequenceNumber(8), SessionID, Flags, тип и признак
      повышения прав, SID метки целостности (переменной длины), ImageName.
    Версию отличаем по тому, где лежит время создания; путь ищем по «\\Device\\»."""
    if len(data) < 26:
        return None
    from processmanager.etw import wstring
    pid = int.from_bytes(data[0:4], "little")
    if _is_filetime(int.from_bytes(data[4:12], "little")):
        ppid, image_at = int.from_bytes(data[12:16], "little"), 24
    else:
        ppid, image_at = int.from_bytes(data[20:24], "little"), 32
    marker = data.find("\\Device\\".encode("utf-16-le"), image_at)
    if marker >= 0 and marker % 2 == 0:
        image_at = marker
    image, _ = wstring(data, image_at)
    return pid, ppid, image


def script_args(cmdline: list[str]) -> list[str]:
    """Файлы скриптов из командной строки интерпретатора (существующие)."""
    found = []
    for arg in cmdline[1:]:
        arg = arg.strip().strip('"')
        if arg.lower().endswith(SCRIPT_EXTS) and os.path.isfile(arg):
            found.append(os.path.abspath(arg))
    return found


def chain_reason(parent: str, child: str) -> str | None:
    """Подозрительная цепочка запуска: документ запускает оболочку."""
    if parent.lower() in DOCUMENT_APPS and child.lower() in SHELLS:
        return f"{parent} запустил {child}: так работают вредоносные макросы и документы"
    return None


# Удаление теневых копий и отключение восстановления: почти всегда — подготовка
# шифровальщика (после этого файлы не вернуть: recovery/shadow.py).
SHADOW_TOOLS = {"vssadmin.exe", "wmic.exe", "wbadmin.exe", "bcdedit.exe", "powershell.exe",
                "pwsh.exe"}
SHADOW_WIPE_RE = re.compile(
    r"vssadmin(\.exe)?\W.*(delete\s+shadows|resize\s+shadowstorage)"
    r"|wmic(\.exe)?\W.*shadowcopy\W.*delete"
    r"|wbadmin(\.exe)?\W.*delete\s+(catalog|systemstatebackup|backup)"
    r"|bcdedit(\.exe)?\W.*recoveryenabled\s+no"
    r"|win32_shadowcopy.*(delete|remove-ciminstance|remove-wmiobject)", re.I | re.S)


def shadow_wipe(cmdline: list[str]) -> bool:
    """Команда удаляет теневые копии Windows или отключает восстановление."""
    return bool(cmdline) and bool(SHADOW_WIPE_RE.search(" ".join(cmdline)))


def encoded_command(cmdline: list[str]) -> bool:
    if not cmdline or os.path.basename(cmdline[0]).lower() not in ("powershell.exe",
                                                                   "pwsh.exe"):
        return False
    return bool(ENCODED_RE.search(" ".join(cmdline[1:])))


# кто запустил PowerShell с -enc: от этих родителей это признак атаки даже при подписи
RISKY_PARENTS = SHELLS | DOCUMENT_APPS | {
    "explorer.exe", "wmiprvse.exe", "winrshost.exe",
    # интерпретаторы: подписаны, но ими пользуются загрузчики
    "python.exe", "pythonw.exe", "py.exe", "node.exe", "java.exe", "javaw.exe", "autoit3.exe"}
# промежуточные оболочки: смотрим, кто запустил их самих (Claude Code: claude.exe → cmd.exe →
# powershell -enc)
PASS_THROUGH = {"cmd.exe", "conhost.exe"}


def real_parent(ppid: int, hops: int = 3) -> tuple[str, str]:
    """(имя, путь) родителя, пропуская промежуточные cmd.exe; пустые — родитель завершился."""
    from processmanager import ntsnap
    for _ in range(hops):
        if not ppid:
            return "", ""
        exe = ntsnap.identity(ppid)[0]
        name = os.path.basename(exe).lower()
        if name not in PASS_THROUGH:
            return name, exe
        try:
            ppid = _psutil_process(ppid).ppid()
        except Exception:
            return name, exe
    return name, exe


def encoded_suspicious(parent_name: str, parent_signed: bool | None) -> bool:
    """-enc подозрителен, если PowerShell запустила неподписанная программа (или родитель
    уже завершился), оболочка, документ, Проводник (ярлык) или WMI. Подписанные программы
    (Claude Code, VS Code, установщики, Планировщик заданий) так передают длинные команды
    постоянно — без этого правила журнал защиты засыпан ложными тревогами."""
    name = parent_name.lower()
    if not name or parent_signed is None:
        return True
    return name in RISKY_PARENTS or not parent_signed


def decode_command(cmdline: list[str]) -> str:
    """Текст закодированной команды (Base64 от UTF-16) — первые 200 символов."""
    import base64
    match = ENCODED_RE.search(" ".join(cmdline[1:]))
    if not match:
        return ""
    blob = match.group(0).split()[-1]
    try:
        text = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-16-le", "replace")
    except ValueError:
        return ""
    text = " ".join(text.split())
    return text[:200] + ("..." if len(text) > 200 else "")


class LaunchGuard:
    def __init__(self, on_event):
        self.on_event = on_event
        self.mode = ""  # etw | poll
        self._stop = threading.Event()
        self._queue: queue.Queue = queue.Queue()
        self._threads: list[threading.Thread] = []
        self._trace = None
        self._seen: dict[int, float] = {}  # pid → время создания (опрос)
        self._names: dict[int, str] = {}   # pid → имя (для цепочек: родитель уже мог выйти)
        self.checked = 0
        self.blocked = 0
        self._reported: set[tuple[str, str]] = set()  # (родитель, команда): не повторять

    # ---------- управление ----------
    def start(self) -> None:
        self._stop.clear()
        worker = threading.Thread(target=self._work, daemon=True, name="launch-check")
        worker.start()
        self._threads = [worker]

    def stop(self) -> None:
        self._stop.set()
        from processmanager.story import STORY
        STORY.sources.discard("launch")
        if self._trace is not None:
            self._trace.stop()
            self._trace = None
        self._queue.put(None)
        for thread in self._threads:
            thread.join(timeout=5)
        self._threads = []

    @property
    def running(self) -> bool:
        return bool(self._threads) and not self._stop.is_set()

    def _emit(self, kind: str, info) -> None:
        try:
            self.on_event(kind, info)
        except Exception:
            from diag.log import swallowed
            swallowed("launchguard: обработчик события интерфейса")

    # ---------- источники событий ----------
    def _start_source(self) -> None:
        from processmanager import ntsnap
        from processmanager.story import STORY
        STORY.sources.add("launch")
        if ntsnap.AVAILABLE:  # уже запущенные: проверяются один раз, без завершения
            try:
                procs = ntsnap.list_processes()
            except OSError:
                procs = []
            for p in procs:
                self._seen[p.pid] = p.created
                self._names[p.pid] = p.name
                STORY.known(p.pid, p.ppid, p.name)
            self._queue.put(("existing", [p.pid for p in procs]))
        from processmanager.etw import EtwTrace, KERNEL_PROCESS
        trace = EtwTrace(SESSION_NAME, KERNEL_PROCESS, KEYWORD_PROCESS, self._on_etw,
                         {EVENT_PROCESS_START}, flush=0.1)
        if trace.start() == 0:
            self._trace = trace
            self.mode = "etw"
            self._emit("status", "Контроль запуска: события Windows (ETW), видны все запуски")
            return
        self.mode = "poll"
        self._emit("status", "Контроль запуска: опрос процессов раз в 0,3 с (без прав "
                             "администратора очень короткие процессы можно пропустить)")
        poller = threading.Thread(target=self._poll, daemon=True, name="launch-poll")
        poller.start()
        self._threads.append(poller)

    def _on_etw(self, event_id: int, _pid: int, data: bytes) -> None:
        parsed = parse_process_start(data)
        if parsed:
            pid, ppid, image = parsed
            from processmanager.etw import kernel_path
            exe = kernel_path(image)
            # командная строка интерпретатора — сразу: короткий скрипт успеет завершиться,
            # пока очередь дойдёт до проверки
            cmdline = _cmdline(pid) if os.path.basename(exe).lower() in SCRIPT_HOSTS else None
            from processmanager.story import STORY
            STORY.started(pid, ppid, exe, cmdline or "")
            self._queue.put(("new", pid, ppid, exe, cmdline))

    def _poll(self) -> None:
        from processmanager import ntsnap
        while not self._stop.wait(POLL_SECONDS):
            try:
                procs = ntsnap.list_processes()
            except OSError:
                continue
            alive = set()
            for p in procs:
                alive.add(p.pid)
                if self._seen.get(p.pid) != p.created:
                    self._seen[p.pid] = p.created
                    self._names[p.pid] = p.name
                    cmdline = _cmdline(p.pid) if p.name.lower() in SCRIPT_HOSTS else None
                    from processmanager.story import STORY
                    STORY.started(p.pid, p.ppid, "", cmdline or "", when=p.created, name=p.name)
                    self._queue.put(("new", p.pid, p.ppid, "", cmdline))
            for pid in set(self._seen) - alive:
                self._seen.pop(pid, None)

    # ---------- проверка ----------
    def _work(self) -> None:
        try:
            from analyzer.folderview import rules_and_bases
            self._bases = rules_and_bases()
        except Exception as e:
            self._emit("error", f"Контроль запуска: базы не загрузились: {e}")
            return
        self._start_source()
        while not self._stop.is_set():
            item = self._queue.get()
            if item is None:
                break
            try:
                if item[0] == "existing":
                    self._check_existing(item[1])
                else:
                    self._check_new(*item[1:])
            except Exception as e:  # один процесс не должен остановить контроль
                self._emit("error", f"Контроль запуска: {type(e).__name__}: {e}")

    def _own(self, pid: int, ppid: int) -> bool:
        from scanner import pool as scan_pool
        own = {0, 4, os.getpid()}
        if scan_pool._pool is not None:
            own.update(scan_pool._pool.pids())
        return pid in own or ppid == os.getpid()

    def _verdict(self, paths: list[str]) -> dict[str, str | None]:
        from scanner import pool as scan_pool
        signatures, rules, whitelist = self._bases
        result = {}
        for path, reason, error in scan_pool.check_files(paths, signatures, rules, whitelist):
            result[path] = None if error is not None else reason
        return result

    def _cached(self, exe: str) -> bool:
        """Вердикт файла уже есть в кэше: проверка займёт миллисекунды."""
        from scanner import verdict_cache
        from scanner.engine import cache_version
        signatures, rules, _ = self._bases
        try:
            p = Path(exe)
            return verdict_cache.get(p, p.stat(), cache_version(signatures, rules, True)) \
                is not None
        except (OSError, ValueError):
            return False

    def _check_existing(self, pids: list[int]) -> None:
        from analyzer.folderview import classify
        from processmanager import ntsnap
        exes: dict[str, list[int]] = {}
        for pid in pids:
            if self._own(pid, -1) or self._stop.is_set():
                continue
            exe, _ = ntsnap.identity(pid)
            if exe:
                exes.setdefault(exe, []).append(pid)
        for exe, reason in self._verdict(list(exes)).items():
            level, text = classify(reason)
            if level in ("threat", "suspicious"):
                self._emit(level, {"pid": exes[exe][0], "name": os.path.basename(exe),
                                   "exe": exe, "text": f"{text} (запущен до включения защиты)",
                                   "killed": False})

    def _check_new(self, pid: int, ppid: int, exe: str, cmdline: list[str] | None) -> None:
        from analyzer.folderview import classify
        from processmanager import ntsnap
        if self._own(pid, ppid):
            return
        if not exe or not os.path.isabs(exe):
            exe, _ = ntsnap.identity(pid)
        if not exe:
            return  # процесс уже завершился или защищён
        name = os.path.basename(exe)
        self._names[pid] = name
        parent = self._names.get(ppid, "")
        try:
            size = os.path.getsize(exe)
        except OSError:
            return
        hold = (not os.path.normcase(exe).startswith(windows_dir()) and size <= SUSPEND_LIMIT
                and not self._cached(exe))
        suspended = hold and _suspend(pid)
        killed = False
        try:
            if cmdline is None:
                cmdline = _cmdline(pid) if name.lower() in SCRIPT_HOSTS | SHADOW_TOOLS else []
            from processmanager.story import STORY
            STORY.identify(pid, exe, cmdline)
            targets = [exe] + script_args(cmdline)
            verdicts = self._verdict(targets)
            self.checked += 1
            for target in targets:
                level, text = classify(verdicts.get(target))
                if level == "threat":
                    # экстренное завершение: только уровень «угроза» (хэш или правило
                    # вредоноса у неподписанного файла); в карантин — вручную из журнала
                    killed = _kill_tree(pid)
                    self.blocked += killed
                    self._emit("blocked", {"pid": pid, "name": name, "exe": target,
                                           "text": text, "killed": killed,
                                           "parent": parent})
                    return
                if level == "suspicious":
                    self._emit("suspicious", {"pid": pid, "name": name, "exe": target,
                                              "text": text, "killed": False})
            if encoded_command(cmdline):
                origin, parent_exe = real_parent(ppid)
                signed = _signed(parent_exe) if parent_exe else None
                key = (origin, " ".join(cmdline))
                if encoded_suspicious(origin, signed) and key not in self._reported:
                    self._reported.add(key)
                    decoded = decode_command(cmdline)
                    self._emit("suspicious", {
                        "pid": pid, "name": name, "exe": exe, "killed": False,
                        "text": f"PowerShell с закодированной командой (-enc), запустил "
                                f"{origin or parent or 'неизвестный процесс'}: так прячут команды "
                                f"загрузчики" + (f". Команда: {decoded}" if decoded else "")})
            if shadow_wipe(cmdline):
                origin, _parent_exe = real_parent(ppid)
                key = ("shadow", origin, " ".join(cmdline))
                if key not in self._reported:
                    self._reported.add(key)
                    self._emit("suspicious", {
                        "pid": pid, "name": name, "exe": exe, "killed": False,
                        "text": f"Удаление теневых копий Windows (запустил "
                                f"{origin or parent or 'неизвестный процесс'}): так шифровальщики "
                                f"лишают возможности вернуть файлы. Команда: "
                                f"{' '.join(cmdline)[:200]}"})
            chain = chain_reason(parent, name)
            if chain:
                self._emit("suspicious", {"pid": pid, "name": name, "exe": exe, "text": chain,
                                          "killed": False})
        finally:
            if suspended and not killed:
                _resume(pid)


_signed_cache: dict[str, bool] = {}


def _signed(exe: str) -> bool:
    if exe not in _signed_cache:
        try:
            from scanner.signature import VALID, inspect_signature
            _signed_cache[exe] = inspect_signature(Path(exe)).status == VALID
        except Exception:
            _signed_cache[exe] = False
    return _signed_cache[exe]


def _psutil_process(pid: int):
    import psutil
    return psutil.Process(pid)


def _suspend(pid: int) -> bool:
    try:
        _psutil_process(pid).suspend()
        return True
    except Exception:
        return False  # нет прав (процесс администратора) или уже завершился


def _resume(pid: int) -> None:
    try:
        _psutil_process(pid).resume()
    except Exception:
        from diag.log import swallowed
        swallowed("launchguard: возобновление процесса")


def _cmdline(pid: int) -> list[str]:
    try:
        return _psutil_process(pid).cmdline()
    except Exception:
        return []


def _kill_tree(pid: int) -> bool:
    """Завершает процесс и всех его потомков (загрузчик мог успеть что-то запустить)."""
    try:
        proc = _psutil_process(pid)
        children = proc.children(recursive=True)
    except Exception:
        return False
    for child in children:
        try:
            child.kill()
        except Exception:
            from diag.log import swallowed
            swallowed("launchguard: завершение дочернего процесса")
    try:
        proc.kill()
        return True
    except Exception:
        return False
