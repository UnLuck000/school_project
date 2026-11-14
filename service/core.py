r"""Ядро службы: защита файлов (monitor.RealtimeMonitor), карантин, журнал защиты и белый
список, защиты с правами (service/guards.py: контроль запуска, стилеры, AMSI, журнал
PowerShell, датчики DNS и TLS), брандмауэр, журнал действий службы с откатом и ядра VPN
(service/vpnhost.py) — с правами системы, по запросам интерфейса через канал
(service/pipeserver.py).

Данные службы — %ProgramData%\StretchBIT[-test]\service (запись только системе и
администраторам): config.json (включена ли защита, папки пользователей по SID, запрет
выключения), journal\threats.json (журнал защиты), whitelist.json. Карантин и базы — в папке
программы, как раньше. Папка конфигурации пользователя (%APPDATA%) не читается.

Права операций — service/protocol.py (OPS) и weakens(): ослабляющие защиту операции при
запрете (lock_protection) — только клиенту с правами администратора.
"""
import json
import os
import re
import sys
import threading
import time
import uuid
from collections import deque
from pathlib import Path

from service import protocol
from service.pipeserver import Client

EVENTS_KEEP = 2000
EVENTS_PER_CALL = 500
MAX_FOLDERS = 32
MAX_WAIT = 5.0
LISTEN_FRESH = 15.0   # с: окно опрашивало события не раньше — оно открыто и увидит тревогу
WAKE_PAUSE = 60.0     # с: не запускать окно в одном сеансе чаще
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
DATA_ENV = "STRETCHBIT_SERVICE_DIR"   # тесты: папка данных ядра (только из исходников)


class Refused(PermissionError):
    """Запрещено настройкой службы (ослабление защиты при lock_protection)."""


class NeedAdmin(PermissionError):
    """Операция только для клиента с правами администратора."""


def data_dir() -> Path:
    """Папка данных службы. Из исходников — cache/service-dev (или STRETCHBIT_SERVICE_DIR);
    в собранной программе — защищённая папка в ProgramData, закрытая от пользователей
    целиком (журнал защиты с путями файлов всех пользователей)."""
    if not getattr(sys, "frozen", False):
        if os.environ.get(DATA_ENV):
            return Path(os.environ[DATA_ENV])
        return Path("cache/service-dev").resolve()
    import trustseal
    folder = trustseal.ensure_root() / "service"
    folder.mkdir(exist_ok=True)
    trustseal._icacls(str(folder), "/inheritance:r", "/grant:r", "*S-1-5-32-544:(OI)(CI)F",
                      "*S-1-5-18:(OI)(CI)F")
    return folder


def user_profiles() -> list[Path]:
    """Папки профилей учётных записей людей (S-1-5-21-...) из реестра ProfileList."""
    if sys.platform != "win32":
        return []
    import winreg
    out = []
    key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            i = 0
            while True:
                try:
                    sid = winreg.EnumKey(key, i)
                except OSError:
                    break
                i += 1
                if not sid.startswith("S-1-5-21-"):
                    continue
                try:
                    with winreg.OpenKey(key, sid) as sub:
                        raw = winreg.QueryValueEx(sub, "ProfileImagePath")[0]
                except OSError:
                    continue
                folder = Path(os.path.expandvars(raw))
                if folder.is_dir():
                    out.append(folder)
    except OSError:
        return out
    return out


def service_system_folders() -> list[tuple[Path, bool, bool]]:
    """Системные папки защиты для службы: у LocalSystem %APPDATA% и %TEMP% — профиль
    системы, поэтому папки автозагрузки и AppData берутся у каждого профиля пользователя."""
    from monitor import system_folders
    windows = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows"))
    system_profile = os.path.join(windows, "system32", "config")
    result, seen = [], set()

    def add(folder: Path, recursive: bool, all_files: bool) -> None:
        key = os.path.normcase(str(folder))
        if key not in seen:
            seen.add(key)
            result.append((folder, recursive, all_files))

    for folder, recursive, all_files in system_folders():
        if not os.path.normcase(str(folder)).startswith(system_profile):
            add(folder, recursive, all_files)
    startup = Path("Microsoft", "Windows", "Start Menu", "Programs", "Startup")
    for profile in user_profiles():
        roaming, local = profile / "AppData" / "Roaming", profile / "AppData" / "Local"
        add(roaming / startup, True, True)
        add(roaming, True, False)
        add(local, True, False)
    return result


def _clean_folders(raw) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list) or len(raw) > MAX_FOLDERS:
        raise ValueError(f"папок — списком, не больше {MAX_FOLDERS}")
    out = []
    for item in raw:
        if not isinstance(item, str) or not item or len(item) > 1024 or "\0" in item:
            raise ValueError("неверная папка")
        path = os.path.normpath(item)
        if not os.path.isabs(path):
            raise ValueError(f"путь папки не полный: {item}")
        if path not in out:
            out.append(path)
    return out


class ServiceCore:
    """monitor_factory(folders, on_event) -> объект с start/stop/reload_bases — для тестов;
    по умолчанию RealtimeMonitor с системными папками всех профилей. auto_update —
    автообновление баз раз в сутки; по умолчанию только у настоящего монитора (тесты с
    подставным монитором не должны качать базы в папку проекта)."""

    def __init__(self, folder: Path | None = None, monitor_factory=None,
                 auto_update: bool | None = None, guard_factories: dict | None = None,
                 vpn_factory=None):
        self.folder = Path(folder or data_dir())
        self.folder.mkdir(parents=True, exist_ok=True)
        self.config_file = self.folder / "config.json"
        self.auto_update = monitor_factory is None if auto_update is None else auto_update
        self.monitor_factory = monitor_factory or self._default_monitor
        self.boot = uuid.uuid4().hex[:8]
        self.config = self._load_config()
        self._lock = threading.RLock()
        self._cond = threading.Condition()
        self._events: deque = deque(maxlen=EVENTS_KEEP)
        self._seq = 0
        self._monitor = None
        self._run = 0
        self._status = "Защита файлов выключена."
        self.server = None
        from diag.log import get
        self.log = get("service")
        from service.guards import GuardHost
        from service.vpnhost import VpnHost
        # подставной монитор (тесты) — и защиты подставные: настоящие ETW и AMSI не запускаются
        if guard_factories is None and monitor_factory is not None:
            guard_factories = {name: _NullGuard for name in
                               ("launch", "stealer", "amsi", "pslog", "dns", "tls")}
        self._listeners: dict[int, float] = {}   # сеанс Windows → когда окно опрашивало события
        self._woken: dict[int, float] = {}       # сеанс → когда служба запускала в нём окно
        self.window_launcher = _launch_window    # (сеанс) → PID окна; тесты подменяют
        self.guards = GuardHost(self.emit_data, guard_factories, wake=self.wake_window)
        self.vpn = VpnHost(self.emit_data, self.folder, vpn_factory)

    # ---------- настройки ----------
    def _load_config(self) -> dict:
        try:
            data = json.loads(self.config_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        if not isinstance(data, dict):
            data = {}
        folders = data.get("folders")
        from service.guards import DEFAULTS
        guards = data.get("guards") if isinstance(data.get("guards"), dict) else {}
        return {"enabled": bool(data.get("enabled", False)),
                "folders": folders if isinstance(folders, dict) else {},
                "lock_protection": bool(data.get("lock_protection", False)),
                "db_last_update": float(data.get("db_last_update", 0.0) or 0.0),
                "guards": {k: bool(guards.get(k, v)) for k, v in DEFAULTS.items()}}

    def _save_config(self) -> None:
        tmp = self.config_file.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self.config, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, self.config_file)

    def all_folders(self) -> list[str]:
        out = []
        for folders in self.config["folders"].values():
            for f in folders:
                if f not in out:
                    out.append(f)
        return out

    # ---------- работа ----------
    def start(self, pipe: bool = True) -> None:
        """Запуск службы: канал, базы (автообновление раз в сутки — у окна без прав
        администратора нет доступа к папке баз) и, если защита была включена, защита
        файлов."""
        if self.auto_update:  # настоящая служба (не тест с подставным монитором)
            # первым делом — сеть: блокировка kill switch могла остаться после сбоя или
            # выключения питания, а защита файлов (правила YARA) на слабом ПК грузится
            # десятки секунд и отнимала бы процессор у возврата сети
            threading.Thread(target=self._recover_vpn, daemon=True, name="svc-vpn-recover").start()
        if self.config["enabled"]:
            with self._lock:
                self._start_monitor()
        if self.auto_update:
            self._start_db_updates()
        if pipe:
            self.start_pipe()

    def _recover_vpn(self) -> None:
        """Служба перезапущена после сбоя с подключённым VPN: kill switch и подмена DNS
        (их копии — в настройках службы) возвращаются, иначе интернет остался бы перекрыт."""
        from vpn import dnsguard, killswitch
        for name, recover in (("kill switch", killswitch.recover), ("DNS", dnsguard.recover)):
            try:
                if recover():
                    self.log.warning("VPN: после сбоя службы возвращено: %s", name)
            except OSError:
                self.log.exception("VPN: не удалось вернуть %s после сбоя", name)

    DB_CHECK_INTERVAL = 15 * 60  # с: сама проверка update_due — не чаще раза в сутки
    DB_RETRY = 120               # с: обновление не удалось (сеть ещё не поднялась) — повтор
    DB_RETRIES = 5

    def _start_db_updates(self) -> None:
        self._db_stop = threading.Event()
        self._db_thread = threading.Thread(target=self._db_loop, daemon=True,
                                           name="svc-dbupdate")
        self._db_thread.start()

    def _db_loop(self) -> None:
        failed = 0
        while not self._db_stop.is_set():
            result = self.update_bases_if_due()
            # служба стартует раньше, чем Windows подключится к Wi-Fi: первая попытка при
            # загрузке или сразу после установки часто без сети (getaddrinfo failed, Windows 10
            # 14.11.2026) — повторить вскоре, а не через 15 минут
            failed = failed + 1 if result is False else 0
            retry = result is False and failed <= self.DB_RETRIES
            self._db_stop.wait(self.DB_RETRY if retry else self.DB_CHECK_INTERVAL)

    def update_bases_if_due(self, now: float | None = None) -> bool | None:
        """Одна проверка: прошли сутки — обновить базы. None — не пора или нет прав на папку
        баз; True/False — удалось ли (событие «db» уходит окнам)."""
        import contextlib
        import io

        import updater
        if not updater.needs_update(self.config.get("db_last_update", 0.0), now) or \
                not updater.can_update():
            return None
        self.log.info("Базы: начинаю автообновление%s",
                      " (баз на диске нет)" if updater.bases_missing() else "")
        output = io.StringIO()
        try:
            with contextlib.redirect_stdout(output):  # updater пишет итог каждого источника
                ok = updater.update_all()
        except Exception:  # noqa: BLE001 — сбой обновления не должен остановить службу
            ok = False
            self.log.exception("Базы: автообновление упало")
        for line in output.getvalue().splitlines():   # раньше — только в service-stdout.log
            if line.strip():
                self.log.info("Базы: %s", line.strip()[:300])
        if not ok:
            self.log.warning("Базы: автообновление не удалось — ни один источник не ответил "
                             "(причины — строками выше)")
            self.emit("db", "fail")
            return False
        with self._lock:
            self.config["db_last_update"] = time.time() if now is None else now
            self._save_config()
        try:
            from analyzer.folderview import reset_bases
            from processmanager.memscan import reset_cache
            reset_cache()
            reset_bases()
        except Exception:  # noqa: BLE001 — сброс кэша не должен мешать обновлению
            from diag.log import swallowed
            swallowed("служба: сброс кэша баз")
        with self._lock:
            if self._monitor is not None:
                self._monitor.reload_bases()
        self.log.info("Базы обновлены")
        self.emit("db", "ok")
        return True

    def start_pipe(self, name: str | None = None, allowed=None, sddl: str | None = None):
        from service import pipeserver, winapi
        import trustseal
        if allowed is None:
            images = [sys.executable]
            if not getattr(sys, "frozen", False):  # python.exe и pythonw.exe из исходников
                base = Path(sys.executable)
                images += [str(base.with_name("python.exe")), str(base.with_name("pythonw.exe"))]
            allowed = pipeserver.same_program(*images)
        if sddl is None:
            sddl = pipeserver.PIPE_SDDL if trustseal.is_admin() else \
                pipeserver.pipe_sddl(winapi.current_sid())
        server = pipeserver.PipeServer(name or protocol.pipe_name(), self.handle, allowed, sddl)
        if not server.start():
            raise OSError(server.error)
        self.server = server
        return server

    def stop(self) -> None:
        # сначала VPN: отключение снимает kill switch и подмену DNS. При выключении Windows
        # время ограничено — пусть его не съедят остановка защиты и ETW
        self.vpn.stop()
        if self.server is not None:
            self.server.stop()
            self.server = None
        if getattr(self, "_db_stop", None) is not None:
            self._db_stop.set()
            self._db_thread.join(timeout=3)
        with self._lock:
            self._stop_monitor()
        self.guards.stop_all()

    def _default_monitor(self, folders, on_event):
        from monitor import RealtimeMonitor
        from quarantine import QUARANTINE_DIR
        signatures = Path("signatures/hashes.txt")
        return RealtimeMonitor(folders, sig_dir=signatures.parent,
                               rules_dir=Path("signatures/rules"),
                               exclude=[QUARANTINE_DIR, signatures.parent.resolve(), self.folder],
                               on_event=on_event, system=service_system_folders())

    def _start_monitor(self) -> None:
        self._run += 1
        run = self._run
        self._monitor = self.monitor_factory(
            self.all_folders(), lambda kind, text="", r=run: self._on_monitor(r, kind, text))
        self._status = "Запускаю..."
        self._monitor.start()
        self.log.info("Защита файлов включена (запуск %s), папок пользователей: %s", run,
                      len(self.all_folders()))
        self.guards.apply(True, self.config["guards"])
        self.emit("state", "on", run)

    def _stop_monitor(self) -> None:
        monitor, self._monitor = self._monitor, None
        if monitor is not None:
            self.guards.apply(False, self.config["guards"])
            monitor.stop()
            self._status = "Защита файлов выключена."
            self.log.info("Защита файлов выключена (запуск %s)", self._run)
            self.emit("state", "off", self._run)

    def _on_monitor(self, run: int, kind: str, text: str) -> None:
        """События защиты файлов (поток монитора)."""
        if kind == "threat":
            path, reason, _action = (text.split("\t") + ["", ""])[:3]
            try:
                from recovery import threatlog
                threatlog.add(path, "threat", reason, "Защита файлов")
            except OSError:
                self.log.exception("Журнал защиты: запись не удалась")
            self.log.warning("Угроза: %s (%s)", path, reason)
        elif kind == "status":
            self._status = text
        elif kind == "stopped" and run == self._run and self._monitor is not None:
            self._monitor = None  # сам остановился (базы не загрузились)
            self._status = text or "Защита файлов остановлена."
        self.emit(kind, text, run)

    def emit(self, kind: str, text: str = "", run: int = 0, data=None) -> None:
        with self._cond:
            self._seq += 1
            event = {"seq": self._seq, "kind": kind, "text": text, "run": run,
                     "time": time.strftime("%H:%M:%S")}
            if data is not None:
                event["data"] = data
            self._events.append(event)
            self._cond.notify_all()

    def emit_data(self, kind: str, data) -> None:
        """События защит, датчиков сети и VPN (сведения — словарём в data)."""
        self.emit(kind, data=data, run=self._run)

    # ---------- окно ----------
    def listening(self, session: int) -> bool:
        """В этом сеансе открыто окно программы: оно недавно опрашивало события."""
        with self._cond:
            seen = self._listeners.get(session)
        return seen is not None and time.monotonic() - seen < LISTEN_FRESH

    def wake_window(self, pid: int) -> int | None:
        """Тревога, которую должен решить пользователь, а окна нет: запустить окно в сеансе
        того, чей процесс остановлен (процесс службы Windows — в сеансе, который на экране).
        Окно запускается от имени пользователя, без прав; тревоги оно получает при запуске
        (guards.state). Возвращает PID окна или None, если запуск не нужен или невозможен."""
        from service import winapi
        session = winapi.session_of(pid) if pid else -1
        if session <= 0:
            session = winapi.active_session()
        if session <= 0:
            self.log.info("Служба: тревога без окна — в систему никто не вошёл")
            return None
        if self.listening(session):
            return None
        now = time.monotonic()
        with self._cond:
            if now - self._woken.get(session, -1e9) < WAKE_PAUSE:
                return None
            self._woken[session] = now
        try:
            started = self.window_launcher(session)
        except OSError as e:
            self.log.warning("Служба: окно в сеансе %s не запущено: %s", session, e)
            return None
        if started:
            self.log.info("Служба: окно программы запущено в сеансе %s (PID %s) — тревога "
                          "ждёт решения", session, started)
        return started

    # ---------- запросы ----------
    def handle(self, client: Client, op: str, args: dict):
        level = protocol.OPS.get(op)
        if level is None:
            raise ValueError(f"неизвестная операция {op}")
        if level == protocol.ADMIN and not client.elevated:
            raise NeedAdmin("нужны права администратора у окна программы")
        if level == protocol.WEAKEN:
            self.check_weaken(client)
        return getattr(self, "op_" + op.replace(".", "_"))(client, args)

    def check_weaken(self, client: Client) -> None:
        if self.config["lock_protection"] and not client.elevated:
            raise Refused("выключение защиты запрещено в настройках службы: нужны права "
                          "администратора")

    def op_hello(self, client, args):
        import appinfo
        from diag import edition
        return {"version": appinfo.VERSION, "edition": edition.edition(),
                "protocol": protocol.PROTOCOL, "boot": self.boot, "sid": client.sid,
                "elevated": client.elevated}

    def op_status(self, client, args):
        with self._lock:
            return {"running": self._monitor is not None, "enabled": self.config["enabled"],
                    "run": self._run, "text": self._status,
                    "folders": self.config["folders"].get(client.sid or "?", []),
                    "watched": len(self.all_folders()),
                    "lock_protection": self.config["lock_protection"], "boot": self.boot,
                    "seq": self._seq, "db_last_update": self.config["db_last_update"]}

    def op_events(self, client, args):
        since = int(args.get("since", 0))
        wait = min(MAX_WAIT, max(0.0, float(args.get("wait", 0))))
        with self._cond:  # окно этого сеанса открыто (wake_window); ожидание ниже — ≤ 5 с
            self._listeners[client.session] = time.monotonic() + wait
        if args.get("boot") and args["boot"] != self.boot:
            since = 0  # служба перезапущена: всё нового запуска
        with self._cond:
            if since >= 0 and self._seq <= since and wait:
                self._cond.wait_for(lambda: self._seq > since, timeout=wait)
            events = list(self._events)
            seq = self._seq
        if since < 0:
            chosen = events[since:] if events else []   # последние |since| — для журнала
        else:
            chosen = [e for e in events if e["seq"] > since]
        chosen = chosen[-EVENTS_PER_CALL:]
        return {"boot": self.boot, "seq": seq, "events": chosen}

    def op_protection_set(self, client, args):
        on = bool(args.get("on"))
        sid = client.sid or "?"
        with self._lock:
            if not on:
                if self.config["enabled"] or self._monitor is not None:
                    self.check_weaken(client)
                self.config["enabled"] = False
                self._save_config()
                self._stop_monitor()
                return self.op_status(client, {})
            if "folders" in args:
                folders = _clean_folders(args.get("folders"))
                old = self.config["folders"].get(sid, [])
                if set(old) - set(folders):
                    self.check_weaken(client)
                before = self.all_folders()
                self.config["folders"][sid] = folders
                changed = set(before) != set(self.all_folders())
            else:
                changed = False
            self.config["enabled"] = True
            self._save_config()
            if self._monitor is not None and changed:
                self._stop_monitor()
            if self._monitor is None:
                self._start_monitor()
            return self.op_status(client, {})

    def op_bases_reload(self, client, args):
        with self._lock:
            if self._monitor is not None:
                self._monitor.reload_bases()
        return True

    # --- карантин: файлы пользователя — только через переданные дескрипторы ---
    def op_quarantine_list(self, client, args):
        from quarantine import list_quarantine
        return list_quarantine(bool(args.get("history")))

    def op_quarantine_add(self, client, args):
        import msvcrt
        import quarantine
        from service import winapi
        reason = str(args.get("reason") or "")[:500]
        h = winapi.take_handle(client.pid, int(args["handle"]))
        try:
            winapi.check_disk_file(h)
            path = winapi.final_path(h)
            fd = winapi.fd_from_handle(h, write=False)
        except BaseException:
            winapi.close(h)
            raise
        with os.fdopen(fd, "rb") as f:
            f.seek(0)
            qid = quarantine.quarantine_stream(
                f, path, reason,
                delete=lambda: winapi.delete_by_handle(msvcrt.get_osfhandle(f.fileno())))
        self.log.info("Карантин по запросу окна: %s", path)
        return {"id": qid, "path": path}

    def op_quarantine_restore(self, client, args):
        import quarantine
        from service import winapi
        h = winapi.take_handle(client.pid, int(args["handle"]))
        try:
            winapi.check_disk_file(h)
            dest = winapi.final_path(h)
            fd = winapi.fd_from_handle(h, write=True)
        except BaseException:
            winapi.close(h)
            raise
        with os.fdopen(fd, "wb") as f:
            f.seek(0)
            f.truncate()
            path = quarantine.restore_stream(str(args["id"]), f, dest,
                                             bool(args.get("whitelist", True)))
        self.log.info("Восстановлено из карантина по запросу окна: %s", path)
        return {"path": path}

    def op_quarantine_delete(self, client, args):
        from quarantine import delete_file
        return delete_file(str(args["id"]))

    # --- журнал защиты ---
    def op_threats_list(self, client, args):
        from recovery import threatlog
        return threatlog.merged(bool(args.get("include_done")))

    def op_threats_get(self, client, args):
        from recovery import threatlog
        return threatlog.get(str(args["id"]))

    def op_threats_add(self, client, args):
        from recovery import threatlog
        level = args.get("level")
        if level not in ("threat", "suspicious"):
            raise ValueError("уровень: threat или suspicious")
        return threatlog.add(str(args.get("path") or "")[:2048], level,
                             str(args.get("text") or "")[:2000],
                             str(args.get("source") or "")[:100],
                             str(args.get("story") or "")[:65536], int(args.get("pid") or 0))

    def op_threats_set_status(self, client, args):
        from recovery import threatlog
        status = str(args["status"])
        if status not in threatlog.STATUS_TEXT:
            raise ValueError("неизвестное состояние")
        threatlog.set_status(str(args["id"]), status, str(args.get("qid") or ""))
        return True

    def op_threats_mark_path(self, client, args):
        from recovery import threatlog
        status = str(args["status"])
        if status not in threatlog.STATUS_TEXT:
            raise ValueError("неизвестное состояние")
        threatlog.mark_path(str(args["path"]), status, str(args.get("qid") or ""))
        return True

    def op_threats_dismiss(self, client, args):
        from recovery import threatlog
        threatlog.dismiss(str(args["id"]))
        return True

    # --- белый список ---
    def op_whitelist_list(self, client, args):
        from scanner.whitelist import load_whitelist
        return load_whitelist()

    def op_whitelist_add(self, client, args):
        from scanner.whitelist import add_to_whitelist
        sha = str(args.get("sha256") or "").strip().lower()
        if not SHA_RE.match(sha):
            raise ValueError("нужен SHA-256")
        return add_to_whitelist(sha, str(args.get("path") or "")[:2048])

    def op_whitelist_remove(self, client, args):
        from scanner.whitelist import remove_from_whitelist
        return remove_from_whitelist(str(args.get("sha256") or ""))

    # --- настройки службы ---
    def op_config_set(self, client, args):
        with self._lock:
            if "lock_protection" in args:
                self.config["lock_protection"] = bool(args["lock_protection"])
            self._save_config()
            return {"lock_protection": self.config["lock_protection"]}

    # ---------- защиты с правами (service/guards.py) ----------
    def op_guards_state(self, client, args):
        with self._lock:
            return {**self.guards.state(), "wanted": dict(self.config["guards"])}

    def op_guards_set(self, client, args):
        from service.guards import GUARDS
        with self._lock:
            changes = {k: bool(v) for k, v in args.items() if k in GUARDS}
            if any(self.config["guards"].get(k) and not v for k, v in changes.items()):
                self.check_weaken(client)
            self.config["guards"].update(changes)
            self._save_config()
            self.guards.apply(self._monitor is not None, self.config["guards"])
            return self.op_guards_state(client, {})

    def op_stealer_decide(self, client, args):
        action = str(args.get("action") or "")
        if action == "allow":
            self.check_weaken(client)
        return self.guards.decide(str(args.get("alarm") or ""), action)

    def op_amsi_register(self, client, args):
        from scanner import amsi
        on = bool(args.get("on"))
        if on:
            if not amsi.dll_sources():
                raise ValueError("нет библиотеки провайдера (native/amsi/bin)")
            amsi.install()
            with self._lock:
                self.config["guards"]["amsi"] = True
                self._save_config()
        else:
            self.check_weaken(client)
            with self._lock:
                self.config["guards"]["amsi"] = False
                self._save_config()
                self.guards.apply(self._monitor is not None, self.config["guards"])
            if amsi.registered():
                amsi.uninstall()
        with self._lock:
            self.guards.apply(self._monitor is not None, self.config["guards"])
        return {"registered": bool(amsi.registered())}

    def op_pslog_policy(self, client, args):
        from scanner import pslog
        on = bool(args.get("on"))
        if not on:
            self.check_weaken(client)
        pslog.set_policy(on)
        with self._lock:  # перезапуск слежения: текст «все / подозрительные»
            self.guards._stop("pslog")
            self.guards.apply(self._monitor is not None, self.config["guards"])
        return {"enabled": pslog.policy_enabled()}

    def op_net_sensors(self, client, args):
        on = bool(args.get("on"))
        if not on:
            self.check_weaken(client)
        self.guards.set_net(on)
        return self.guards.state()

    def op_story_get(self, client, args):
        from service.guards import story_of
        return story_of(int(args.get("pid") or 0))

    # ---------- брандмауэр ----------
    def op_firewall_block_ip(self, client, args):
        from networkmonitor import firewall
        return firewall.block_ip(str(args.get("ip") or ""))

    def op_firewall_block_program(self, client, args):
        from networkmonitor import firewall
        exe = str(args.get("exe") or "")
        if not os.path.isabs(exe) or len(exe) > 1024 or any(c in exe for c in "\0\r\n"):
            raise ValueError("путь программы — полный")
        return firewall.block_program(exe)

    def op_firewall_unblock(self, client, args):
        from networkmonitor import firewall
        names = args.get("names")
        if not isinstance(names, list) or not names or len(names) > 64 or not all(
                isinstance(n, str) and re.fullmatch(r"[A-Za-z0-9-]{1,64}", n) and
                n.lower().startswith(firewall.OWN_PREFIXES) for n in names):
            raise ValueError("снимаются только правила программы (sbit-...)")
        firewall.unblock(names, str(args.get("target") or "")[:1024])
        return True

    # ---------- журнал действий службы ----------
    def op_journal_list(self, client, args):
        from recovery import journal
        return journal.read_all()

    def op_journal_undo(self, client, args):
        from recovery import journal
        return journal.undo(str(args.get("id") or ""))

    def op_journal_cleanup(self, client, args):
        from recovery import journal
        return journal.cleanup()

    # ---------- VPN (service/vpnhost.py) ----------
    def op_vpn_connect(self, client, args):
        profile = args.get("profile")
        if not isinstance(profile, dict):
            raise ValueError("нужен профиль")
        return self.vpn.connect(profile, args.get("settings") or {}, args.get("options"))

    def op_vpn_disconnect(self, client, args):
        return self.vpn.disconnect()

    def op_vpn_status(self, client, args):
        return self.vpn.status()

    def op_vpn_counters(self, client, args):
        return list(self.vpn.counters())

    def op_vpn_release_block(self, client, args):
        return self.vpn.release_block()


def _launch_window(session: int) -> int | None:
    """Окно программы в сеансе пользователя. Только собранная программа: из исходников
    (python -m service --console) служба — обычный процесс разработчика, окно он откроет сам."""
    if not getattr(sys, "frozen", False):
        return None
    from service import winapi
    return winapi.launch_in_session(session, sys.executable, "--alarm")  # без окна UAC


class _NullGuard:
    """Защита-заглушка ядра с подставным монитором (тесты): ничего не запускает."""

    def __init__(self, *callbacks, **_kw):
        self.callbacks = callbacks
        self.error = ""

    def start(self):
        return ""  # ScriptBlockWatch.start: пусто — запущено; AmsiServer.start → проверка ниже

    def stop(self):
        pass

    def reload_trust(self):
        pass

