"""Защита от стилеров (похитителей паролей): кто открывает пароли и cookies браузеров.

Стилер (RedLine, Lumma, Vidar...) не шифрует и не портит файлы: за секунды он копирует
базы браузеров (Login Data — пароли, Cookies — сеансы, Web Data — карты, Local State —
ключ расшифровки), профиль Firefox (logins.json, key4.db), папку tdata Telegram, токены
Discord и кошельки, а затем отправляет их на свой сервер. Поэтому следим не за записью,
а за открытием этих файлов:
• с правами администратора — ETW Microsoft-Windows-Kernel-File (событие 12 Create):
  видно каждое открытие файла и процесс, который его открыл;
• без прав — Restart Manager (RmGetList) раз в POLL_SECONDS (5 с): какие процессы держат файлы
  открытыми. Быстрое копирование так можно пропустить, долгое чтение — нет.

Кому можно: браузеру, которому принадлежит профиль (chrome.exe — профилю Chrome и т.д.),
программам с действительной подписью (поиск Windows, резервное копирование), кроме
интерпретаторов и системных утилит, которыми пользуются стилеры (powershell, python,
esentutl...), самой программе и программам, разрешённым пользователем (TRUST_FILE).
Остальные приостанавливаются; on_alarm(info) решает (завершить и в карантин, разрешить).
"""
import ctypes
import json
import os
import sys
import threading
import time
from ctypes import wintypes
from pathlib import Path

from recovery import journal

TRUST_FILE = journal.JOURNAL_DIR / "stealer_trust.json"
POLL_SECONDS = 5.0
SESSION_NAME = "sbit-files"
EVENT_CREATE = 12
KEYWORD_CREATE = 0x80 | 0x10  # KERNEL_FILE_KEYWORD_CREATE | FILENAME
DEVICE = "\\Device\\".encode("utf-16-le")

# что крадут: окончание пути (нижний регистр) → что это
SECRET_FILES = {
    "\\login data": "пароли",
    "\\login data for account": "пароли",
    "\\cookies": "cookies (вход на сайты)",
    "\\web data": "банковские карты и автозаполнение",
    "\\local state": "ключ расшифровки паролей",
    "\\logins.json": "пароли",
    "\\key4.db": "ключ расшифровки паролей",
    "\\cookies.sqlite": "cookies (вход на сайты)",
    "\\wallet.dat": "криптокошелёк",
}
SECRET_DIRS = {  # часть пути → что это (файлы внутри папки)
    "\\telegram desktop\\tdata\\": "сеанс Telegram",
    "\\discord\\local storage\\leveldb\\": "токен Discord",
    "\\exodus\\exodus.wallet\\": "криптокошелёк Exodus",
    "\\electrum\\wallets\\": "криптокошелёк Electrum",
    "\\local extension settings\\nkbihfbeogaeaoehlefnkodbefgpgknn\\": "кошелёк MetaMask",
}
# чей профиль: часть пути → (название, имена программ-владельцев)
OWNERS = [
    ("\\google\\chrome\\", "Google Chrome", {"chrome.exe", "elevation_service.exe"}),
    ("\\microsoft\\edge\\", "Microsoft Edge", {"msedge.exe", "msedgewebview2.exe",
                                               "elevation_service.exe", "identity_helper.exe"}),
    ("\\bravesoftware\\", "Brave", {"brave.exe", "elevation_service.exe"}),
    ("\\yandex\\yandexbrowser\\", "Яндекс Браузер", {"browser.exe", "service_update.exe"}),
    ("\\opera software\\", "Opera", {"opera.exe", "launcher.exe", "opera_crashreporter.exe"}),
    ("\\vivaldi\\", "Vivaldi", {"vivaldi.exe"}),
    ("\\chromium\\", "Chromium", {"chrome.exe"}),
    ("\\mozilla\\firefox\\", "Firefox", {"firefox.exe", "plugin-container.exe"}),
    ("\\telegram desktop\\", "Telegram", {"telegram.exe", "updater.exe"}),
    ("\\discord", "Discord", {"discord.exe", "update.exe"}),
    ("\\exodus\\", "Exodus", {"exodus.exe"}),
    ("\\electrum\\", "Electrum", {"electrum.exe"}),
    ("\\bitcoin\\", "Bitcoin Core", {"bitcoin-qt.exe", "bitcoind.exe"}),
]
# подписаны, но ими пользуются стилеры: подпись их не оправдывает
NOT_TRUSTED_SIGNED = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "python.exe", "pythonw.exe", "py.exe", "node.exe",
    "java.exe", "javaw.exe", "autoit3.exe", "certutil.exe", "esentutl.exe", "robocopy.exe",
    "xcopy.exe", "curl.exe", "tar.exe", "7z.exe", "winrar.exe", "rar.exe", "msbuild.exe",
    "installutil.exe", "regasm.exe", "regsvcs.exe", "aspnet_compiler.exe", "conhost.exe",
}
ALWAYS_TRUSTED = {"system", "registry", "memcompression", "searchindexer.exe",
                  "searchprotocolhost.exe", "searchfilterhost.exe", "msmpeng.exe",
                  "mssense.exe", "explorer.exe"}
# временные папки: там одноразовые профили (тесты, Selenium, Playwright), не секреты
# пользователя. Копию базы во временную папку стилер делает, открыв настоящую, — это видно.
TEMP_PARTS = ("\\appdata\\local\\temp\\", "\\windows\\temp\\")


def secret_kind(path: str) -> str | None:
    """Что лежит в файле (пароли, cookies...) или None, если это не секрет."""
    low = path.lower()
    if any(part in low for part in TEMP_PARTS):
        return None
    for end, kind in SECRET_FILES.items():
        if low.endswith(end):
            return kind
    for part, kind in SECRET_DIRS.items():
        if part in low:
            return kind
    return None


def owner_of(path: str) -> tuple[str, set[str]]:
    """(чей профиль, программы-владельцы)."""
    low = path.lower()
    for part, title, exes in OWNERS:
        if part in low:
            return title, exes
    return "", set()


def load_trust() -> set[str]:
    try:
        data = json.loads(TRUST_FILE.read_text(encoding="utf-8"))
        return {os.path.normcase(p) for p in data} if isinstance(data, list) else set()
    except (OSError, ValueError):
        return set()


def trust(exe: str) -> None:
    """Пользователь разрешил программе читать секреты (с откатом через журнал)."""
    items = load_trust()
    items.add(os.path.normcase(exe))
    _save_trust(items)
    journal.log_action(f"Стилер-защита: программе разрешён доступ к паролям браузеров: {exe}",
                       "stealer_untrust", {"exe": exe})


def _save_trust(items: set[str]) -> None:
    TRUST_FILE.parent.mkdir(parents=True, exist_ok=True)
    TRUST_FILE.write_text(json.dumps(sorted(items), ensure_ascii=False, indent=1),
                          encoding="utf-8")


@journal.active_check("stealer_untrust")
def _trust_active(d: dict) -> bool:
    return os.path.normcase(d["exe"]) in load_trust()


@journal.undo_op("stealer_untrust")
def _undo_trust(d: dict) -> str:
    items = load_trust()
    items.discard(os.path.normcase(d["exe"]))
    _save_trust(items)
    return f"Разрешение отозвано: {d['exe']}"


def secret_files() -> list[str]:
    """Существующие файлы-секреты текущего пользователя (для Restart Manager)."""
    local = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    roaming = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    roots = [local / "Google" / "Chrome" / "User Data", local / "Microsoft" / "Edge" / "User Data",
             local / "BraveSoftware" / "Brave-Browser" / "User Data",
             local / "Yandex" / "YandexBrowser" / "User Data", local / "Vivaldi" / "User Data",
             local / "Chromium" / "User Data", roaming / "Opera Software"]
    names = ("Login Data", "Web Data", "Cookies", os.path.join("Network", "Cookies"))
    found = []
    for root in roots:
        if not root.is_dir():
            continue
        if (root / "Local State").is_file():
            found.append(str(root / "Local State"))
        try:
            profiles = [p for p in root.iterdir() if p.is_dir()]
        except OSError:
            continue
        for profile in profiles:
            for name in names:
                if (profile / name).is_file():
                    found.append(str(profile / name))
    firefox = roaming / "Mozilla" / "Firefox" / "Profiles"
    if firefox.is_dir():
        for profile in firefox.iterdir():
            for name in ("logins.json", "key4.db", "cookies.sqlite"):
                if (profile / name).is_file():
                    found.append(str(profile / name))
    return found


class StealerGuard:
    def __init__(self, on_alarm, on_status=None):
        self.on_alarm = on_alarm
        self.on_status = on_status or (lambda text: None)
        self.mode = ""  # etw | rm
        self.events = 0  # сколько открытий файлов просмотрено (для отладки)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._trace = None
        self._alarmed: dict[int, float] = {}  # pid → когда тревожили
        self._decided: dict[tuple[int, str], bool] = {}  # (pid, exe) → можно ли
        self._lock = threading.Lock()
        self._trusted = load_trust()

    def start(self) -> None:
        self._stop.clear()
        self._trusted = load_trust()
        from processmanager.etw import EtwTrace, KERNEL_FILE
        trace = EtwTrace(SESSION_NAME, KERNEL_FILE, KEYWORD_CREATE, self._on_etw,
                         {EVENT_CREATE})
        if trace.start() == 0:
            self._trace = trace
            self.mode = "etw"
            from processmanager.story import STORY
            STORY.sources.add("files")  # то же событие Create — и для сводки по процессу
            self.on_status("Защита от стилеров: видно каждое открытие паролей и cookies (ETW)")
            return
        self.mode = "rm"
        self.on_status("Защита от стилеров: раз в 5 с проверяется, кто держит открытыми "
                       "пароли и cookies (без прав администратора)")
        self._thread = threading.Thread(target=self._poll, daemon=True, name="stealer-rm")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        from processmanager.story import STORY
        STORY.sources.discard("files")
        if self._trace is not None:
            self._trace.stop()
            self._trace = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    @property
    def running(self) -> bool:
        return self._trace is not None or self._thread is not None

    def reload_trust(self) -> None:
        self._trusted = load_trust()
        with self._lock:
            self._decided.clear()

    # ----- ETW -----
    def _on_etw(self, _event_id: int, pid: int, data: bytes) -> None:
        self.events += 1
        start = data.find(DEVICE)
        if start < 0:
            return
        if start % 2:
            start -= 1
        end = data.find(b"\0\0", start)
        while end > 0 and (end - start) % 2:
            end = data.find(b"\0\0", end + 1)
        path = data[start:end if end > 0 else len(data)].decode("utf-16-le", "replace")
        if start == 32 and len(data) >= 24:  # раскладка события известна (story.py)
            from processmanager import story
            if int.from_bytes(data[20:24], "little") >> 24 in story.WRITE_DISPOSITIONS and \
                    os.path.splitext(path)[1].lower() in story.WATCH_EXTS:
                from processmanager.etw import kernel_path
                story.STORY.file_written(pid, kernel_path(path))
        kind = secret_kind(path)
        if kind:
            from processmanager.etw import kernel_path
            self.check_access(pid, kernel_path(path), kind)

    # ----- Restart Manager -----
    def _poll(self) -> None:
        files, refreshed = [], 0.0
        while not self._stop.wait(POLL_SECONDS):
            if time.monotonic() - refreshed > 300:  # новые профили появляются редко
                files, refreshed = secret_files(), time.monotonic()
            for pid, path in holders(files, self._suspect):
                kind = secret_kind(path)
                if kind:
                    self.check_access(pid, path, kind)

    def _suspect(self, pid: int) -> bool:
        """Процесс не браузер и не доверенная программа (для опроса Restart Manager)."""
        from processmanager import ntsnap
        exe = ntsnap.identity(pid)[0] if ntsnap.AVAILABLE else ""
        name = os.path.basename(exe).lower()
        if any(name in owners for _, _, owners in OWNERS):
            return False  # свой ли это профиль, проверит check_access
        return not self.allowed(pid, exe, "")

    # ----- решение -----
    def allowed(self, pid: int, exe: str, path: str) -> bool:
        name = os.path.basename(exe).lower() if exe else ""
        if pid in (0, 4) or name in ALWAYS_TRUSTED:
            return True
        import ownproc
        if ownproc.is_program(pid, exe or None):
            return True  # сама программа: окно («Расширения»), служба, проверка дисков
        if not exe:
            return True  # защищённый системный процесс: путь не узнать
        if os.path.normcase(exe) in self._trusted:
            return True
        _, owners = owner_of(path)
        if name in owners:
            return True
        if name in NOT_TRUSTED_SIGNED:
            return False
        return _signed(exe)

    def check_access(self, pid: int, path: str, kind: str) -> None:
        from processmanager import ntsnap
        exe = ntsnap.identity(pid)[0] if ntsnap.AVAILABLE else ""
        key = (pid, os.path.normcase(exe))
        with self._lock:
            ok = self._decided.get(key)
        if ok is None:
            ok = self.allowed(pid, exe, path)
            with self._lock:
                self._decided[key] = ok
                if len(self._decided) > 5000:
                    self._decided.clear()
        if ok:
            return
        now = time.monotonic()
        with self._lock:
            if now - self._alarmed.get(pid, -1e9) < 60:
                return  # одно окно на процесс, не по окну на каждый файл
            self._alarmed[pid] = now
        owner, _ = owner_of(path)
        from toolbox.decoys import suspend
        info = {"pid": pid, "name": os.path.basename(exe) or f"PID {pid}", "exe": exe,
                "path": path, "kind": kind, "owner": owner or "программа",
                "suspended": suspend(pid)}
        try:
            self.on_alarm(info)
        except Exception:
            from diag.log import swallowed
            swallowed("stealerguard: обработчик тревоги")


def _signed(exe: str) -> bool:
    try:
        from scanner.signature import VALID, inspect_signature
        return inspect_signature(Path(exe)).status == VALID
    except Exception:
        return False


# ---------- Restart Manager ----------
CCH_RM_SESSION_KEY = 32
ERROR_MORE_DATA = 234


class RM_UNIQUE_PROCESS(ctypes.Structure):
    _fields_ = [("dwProcessId", wintypes.DWORD), ("ProcessStartTime", wintypes.FILETIME)]


class RM_PROCESS_INFO(ctypes.Structure):
    _fields_ = [("Process", RM_UNIQUE_PROCESS), ("strAppName", ctypes.c_wchar * 256),
                ("strServiceShortName", ctypes.c_wchar * 64), ("ApplicationType", ctypes.c_int),
                ("AppStatus", wintypes.ULONG), ("TSSessionId", wintypes.DWORD),
                ("bRestartable", wintypes.BOOL)]


def _rm_pids(files: list[str]) -> list[int]:
    """Процессы, которые держат открытым хоть один из файлов (один сеанс на все файлы)."""
    rm = ctypes.WinDLL("rstrtmgr")
    session = wintypes.DWORD()
    key = ctypes.create_unicode_buffer(CCH_RM_SESSION_KEY + 1)
    if rm.RmStartSession(ctypes.byref(session), 0, key):
        return []
    try:
        arr = (ctypes.c_wchar_p * len(files))(*files)
        if rm.RmRegisterResources(session, len(files), arr, 0, None, 0, None):
            return []
        needed, count, reasons = wintypes.UINT(), wintypes.UINT(0), wintypes.DWORD()
        err = rm.RmGetList(session, ctypes.byref(needed), ctypes.byref(count), None,
                           ctypes.byref(reasons))
        if err != ERROR_MORE_DATA or not needed.value:
            return []
        infos = (RM_PROCESS_INFO * needed.value)()
        count = wintypes.UINT(needed.value)
        if rm.RmGetList(session, ctypes.byref(needed), ctypes.byref(count), infos,
                        ctypes.byref(reasons)):
            return []
        return [infos[i].Process.dwProcessId for i in range(count.value)]
    finally:
        rm.RmEndSession(session)


def holders(files: list[str], suspect=None) -> list[tuple[int, str]]:
    """(pid, файл): какие процессы держат файлы открытыми. Права администратора не нужны.

    RmGetList перебирает открытые файлы всей системы (~0,2 с процессора на вызов), поэтому
    сначала один вызов на все файлы; какой именно файл открыт, выясняется по одному файлу
    только для процессов, которые suspect(pid) считает подозрительными (обычно — никого:
    базы держит открытыми сам браузер)."""
    if sys.platform != "win32" or not files:
        return []
    pids = [pid for pid in _rm_pids(files) if suspect is None or suspect(pid)]
    if not pids:
        return []
    result = []
    for path in files:
        result.extend((pid, path) for pid in _rm_pids([path]) if pid in pids)
    return result
