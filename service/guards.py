r"""Защиты с правами в службе (шаги 2–4 service/DESIGN.md): контроль запуска (ETW
Kernel-Process), защита от стилеров (ETW Kernel-File), сервер AMSI, журнал блоков скриптов
PowerShell (ETW, событие 4104) и сетевые датчики — DNS (ETW DNS-Client) и TLS (WinDivert).

Работают в процессе службы, пока включена защита файлов (как раньше в окне), каждая — по своей
настройке (config.json службы, ключ guards). Находки служба пишет в журнал защиты сама
(сводка по процессу — из её STORY: процессы видит она), окну уходит событие «guard» с теми же
сведениями, что раньше получал обработчик окна, и пометкой logged. Тревога стилера ждёт решения
окна (stealer.decide); никто не ответил за ALARM_TIMEOUT — процесс отпускается, находка остаётся
в журнале защиты «подозрительной». Окно закрыто — служба сама запускает его в сеансе того
пользователя, чей процесс остановлен (ServiceCore.wake_window): при запуске окно получает
тревоги, которые ждут решения.

Сетевые датчики — только источники событий: разбор, таблицы и оповещения остаются в окне
(networkmonitor/netmon.py с датчиками службы — service/remote.py RemoteSensors).
"""
import dataclasses
import json
import os
import threading
import time
import uuid

GUARDS = ("launch", "stealer", "amsi", "pslog")
DEFAULTS = {"launch": True, "stealer": True, "amsi": False, "pslog": True}
ALARM_TIMEOUT = 600.0   # с: тревога стилера без ответа окна — процесс отпускается
ACTIONS = ("kill", "allow", "once")


def jsonable(obj):
    """Сведения защит — в JSON (Path, кортежи, множества, dataclass → строки и списки)."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        obj = dataclasses.asdict(obj)
    return json.loads(json.dumps(obj, ensure_ascii=False, default=lambda o: sorted(o)
                                 if isinstance(o, (set, frozenset)) else str(o)))


def story_of(pid: int) -> str:
    if not pid:
        return ""
    try:
        from processmanager import story
        return story.render(pid)
    except Exception:  # noqa: BLE001 — сводка не должна мешать записи находки
        from diag.log import swallowed
        swallowed("служба: сводка по процессу")
        return ""


# ---------- записи журнала защиты (раньше — обработчики окна mainwindow/protection.py) ----------
def log_launch(kind: str, info: dict) -> None:
    from recovery import threatlog
    exe, text = info.get("exe", ""), info.get("text", "")
    pid = int(info.get("pid") or 0)
    if kind == "blocked":
        threatlog.add(exe, "threat", text, "Контроль запуска", story_of(pid), pid)
    elif exe and kind in ("threat", "suspicious"):
        threatlog.add(exe, "threat" if kind == "threat" else "suspicious", text,
                      "Контроль запуска", story_of(pid), pid)


def log_amsi(info: dict) -> None:
    from recovery import threatlog
    pid = int(info.get("pid") or 0)
    story = story_of(pid)
    story = (story + "\n\n" if story else "") + "Начало проверенного содержимого:\n" + \
        str(info.get("excerpt", ""))
    level = "threat" if info.get("level") == "threat" else "suspicious"
    threatlog.add(info.get("name") or f"{info.get('app', '')} (PID {pid})", level,
                  f"AMSI: {info.get('reason', '')}", "AMSI (скрипты)", story, pid)


def log_pslog(info: dict) -> None:
    from recovery import threatlog
    pid = int(info.get("pid") or 0)
    story = story_of(pid)
    story = (story + "\n\n" if story else "") + "Блок скрипта (журнал 4104):\n" + \
        str(info.get("excerpt", ""))
    level = "threat" if info.get("level") == "threat" else "suspicious"
    threatlog.add(info.get("path") or f"PowerShell (PID {pid})", level,
                  f"Журнал PowerShell: {info.get('reason', '')}", "PowerShell (журнал 4104)",
                  story, pid)


class GuardHost:
    """emit(kind, payload) — событие окнам (ServiceCore.emit_data). factories — для тестов:
    {"launch": f(on_event), "stealer": f(on_alarm, on_status), "amsi": f(on_event),
    "pslog": f(on_event), "dns": f(on_query, on_status), "tls": f(on_hello, on_status)}."""

    def __init__(self, emit, factories: dict | None = None, wake=None):
        self.emit = emit
        self.factories = factories or {}
        self.wake = wake or (lambda pid: None)  # показать окно тому, чей процесс остановлен
        self.running: dict[str, object] = {}
        self.status: dict[str, str] = {}
        self.alarms: dict[str, dict] = {}
        self._lock = threading.RLock()
        from diag.log import get
        self.log = get("service")

    # ---------- включение ----------
    def apply(self, on: bool, wanted: dict) -> None:
        """on — работает ли защита файлов; wanted — настройки защит."""
        for name in GUARDS:
            want = on and bool(wanted.get(name, DEFAULTS[name]))
            with self._lock:
                have = name in self.running
            if want and not have:
                self._start(name)
            elif not want and have:
                self._stop(name)
                self.status[name] = "Выключена в настройках." if on else ""

    def stop_all(self) -> None:
        for name in list(self.running):
            self._stop(name)
        self.set_net(False)

    def _start(self, name: str) -> None:
        try:
            guard = getattr(self, "_make_" + name)()
        except Exception as e:  # noqa: BLE001 — одна защита не должна мешать остальным
            self.status[name] = f"Не запущена: {e}"
            self.log.exception("Служба: защита %s не запущена", name)
            return
        if guard is None:
            return
        with self._lock:
            self.running[name] = guard
        self.log.info("Служба: защита %s включена", name)

    def _stop(self, name: str) -> None:
        with self._lock:
            guard = self.running.pop(name, None)
        if guard is not None:
            try:
                guard.stop()
            except Exception:  # noqa: BLE001 — остановка одной не мешает остальным
                from diag.log import swallowed
                swallowed(f"служба: остановка {name}")
            self.log.info("Служба: защита %s выключена", name)

    def _status(self, name: str, text: str) -> None:
        self.status[name] = text
        self.emit("guard", {"guard": name, "kind": "status", "info": text})

    # ---------- контроль запуска ----------
    def _make_launch(self):
        factory = self.factories.get("launch")
        if factory is None:
            from scanner.launchguard import LaunchGuard as factory
        guard = factory(self._on_launch)
        guard.start()
        self.status["launch"] = "Загружаю базы..."
        return guard

    def _on_launch(self, kind: str, info) -> None:
        if kind == "status":
            self._status("launch", str(info))
            return
        info = jsonable(info)
        if isinstance(info, dict):
            try:
                log_launch(kind, info)
                info["logged"] = True
            except OSError:
                self.log.exception("Журнал защиты: запись не удалась")
        self.emit("guard", {"guard": "launch", "kind": kind, "info": info})

    # ---------- стилеры ----------
    def _make_stealer(self):
        factory = self.factories.get("stealer")
        if factory is None:
            from toolbox.stealerguard import StealerGuard as factory
        guard = factory(self._on_stealer, lambda text: self._status("stealer", text))
        threading.Thread(target=guard.start, daemon=True, name="svc-stealer").start()
        return guard

    def _on_stealer(self, info: dict) -> None:
        info = jsonable(info)
        alarm = uuid.uuid4().hex[:12]
        info["alarm"] = alarm
        with self._lock:
            self.alarms[alarm] = {"info": info, "time": time.monotonic()}
        self.log.warning("Стилер?: %s открыл %s", info.get("exe"), info.get("path"))
        self.emit("guard", {"guard": "stealer", "kind": "alarm", "info": info})
        timer = threading.Timer(ALARM_TIMEOUT, self._alarm_timeout, args=(alarm,))
        timer.daemon = True  # остановка службы не ждёт 10 минут незакрытую тревогу
        timer.start()
        try:
            # окно закрыто — решать некому, а процесс уже остановлен: открыть окно
            self.wake(int(info.get("pid") or 0))
        except Exception:  # noqa: BLE001 — тревога остаётся и без окна (отпуск по времени)
            self.log.exception("Служба: окно для тревоги не открыто")

    def _alarm_timeout(self, alarm: str) -> None:
        with self._lock:
            pending = self.alarms.pop(alarm, None)
        if pending is None:
            return
        info = pending["info"]
        if info.get("suspended"):
            from toolbox import decoys
            decoys.resume(int(info["pid"]))
        from recovery import threatlog
        try:
            threatlog.add(info.get("exe", ""), "suspicious",
                          f"Открыл {info.get('kind')} ({info.get('owner')}): {info.get('path')}. "
                          "Окно программы не ответило — процесс отпущен", "Защита от стилеров",
                          story_of(int(info.get("pid") or 0)), int(info.get("pid") or 0))
        except OSError:
            self.log.exception("Журнал защиты: запись не удалась")
        self.emit("guard", {"guard": "stealer", "kind": "expired", "info": info})

    def decide(self, alarm: str, action: str) -> str:
        """Решение окна по тревоге стилера: kill — завершить, allow — разрешить программе
        (с откатом в журнале службы), once — отпустить один раз."""
        if action not in ACTIONS:
            raise ValueError("действие: kill, allow или once")
        with self._lock:
            pending = self.alarms.pop(alarm, None)
        if pending is None:
            raise ValueError("тревога уже решена или истекла")
        info = pending["info"]
        pid, name = int(info.get("pid") or 0), info.get("name", "")
        from toolbox import decoys, stealerguard
        if action == "kill":
            import psutil
            try:
                psutil.Process(pid).kill()
            except Exception as e:  # noqa: BLE001 — причину получает окно
                return f"Не удалось завершить {name}: {e}"
            return f"{name} завершён. Файл можно отправить в карантин из журнала защиты " \
                   "(правый клик)."
        if info.get("suspended"):
            decoys.resume(pid)
        if action == "allow" and info.get("exe"):
            stealerguard.trust(info["exe"])
            with self._lock:
                guard = self.running.get("stealer")
            if guard is not None:
                guard.reload_trust()
            return f"{name}: доступ разрешён"
        return f"{name}: отпущен один раз"

    # ---------- AMSI ----------
    def _make_amsi(self):
        factory = self.factories.get("amsi")
        if factory is None:
            from scanner import amsi
            if not amsi.registration_ok():
                if not amsi.dll_sources():
                    self.status["amsi"] = "Нет библиотеки провайдера (native/amsi/bin)"
                    return None
                amsi.install()  # служба с правами: регистрирует и обновляет сама
            factory = amsi.AmsiServer
        server = factory(self._on_amsi)
        if not server.start():
            self.status["amsi"] = f"Не запущена: {server.error}"
            return None
        self.status["amsi"] = ("PowerShell, VBScript/JScript и макросы Office проверяются "
                               "перед выполнением; вредоносное блокируется.")
        return server

    def _on_amsi(self, info) -> None:
        info = jsonable(info)
        try:
            log_amsi(info)
            info["logged"] = True
        except OSError:
            self.log.exception("Журнал защиты: запись не удалась")
        self.emit("guard", {"guard": "amsi", "kind": "found", "info": info})

    # ---------- журнал PowerShell ----------
    def _make_pslog(self):
        factory = self.factories.get("pslog")
        if factory is None:
            from scanner.pslog import ScriptBlockWatch as factory
        watch = factory(self._on_pslog)
        error = watch.start()
        if error:
            self.status["pslog"] = f"Не запущен: {error}."
            return None
        from scanner import pslog
        everything = pslog.policy_enabled() if "pslog" not in self.factories else False
        self.status["pslog"] = ("Блоки скриптов PowerShell проверяются по журналу событий — "
                                + ("все" if everything else "подозрительные (все — галочкой в "
                                                            "дополнительных настройках)") + ".")
        return watch

    def _on_pslog(self, info) -> None:
        info = jsonable(info)
        try:
            log_pslog(info)
            info["logged"] = True
        except OSError:
            self.log.exception("Журнал защиты: запись не удалась")
        self.emit("guard", {"guard": "pslog", "kind": "found", "info": info})

    # ---------- сетевые датчики ----------
    def set_net(self, on: bool) -> None:
        for name in ("dns", "tls"):
            with self._lock:
                have = name in self.running
            if on and not have:
                self._start(name)
            elif not on and have:
                self._stop(name)

    def _make_dns(self):
        factory = self.factories.get("dns")
        if factory is None:
            from networkmonitor.dns_etw import DnsWatcher as factory
        watcher = factory(lambda q: self.emit("dns", jsonable(q)),
                          lambda text: self.emit("net_status", text))
        watcher.start()
        return watcher

    def _make_tls(self):
        factory = self.factories.get("tls")
        if factory is None:
            from networkmonitor.tls import TlsWatcher

            def factory(on_hello, on_status):
                # папка WinDivert из окна не берётся: только своя копия программы и защищённая
                # в ProgramData (tls.find_windivert проверяет права папок)
                return TlsWatcher(on_hello, on_status, "")
        watcher = factory(lambda ev: self.emit("tls", jsonable(ev)),
                          lambda text: self.emit("net_status", text))
        watcher.start()
        return watcher

    def state(self) -> dict:
        with self._lock:
            return {"running": sorted(self.running), "status": dict(self.status),
                    "alarms": [a["info"] for a in self.alarms.values()],
                    "pid": os.getpid()}
