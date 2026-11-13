"""Исправность функций: запуски, эталон «✓ Исправно» и отклонения от него.

Функция программы (FEATURES) — то, что пользователь может проверить: «Полная проверка
дисков», «VPN: подключение», окно «Диспетчер процессов»... У каждого запуска (Run) есть
шаги (step), факты (fact) и ошибки (error); исключения и окна об ошибках (QMessageBox
critical/warning), появившиеся во время запуска, тоже записываются в него.

Виды запусков:
• action — действие с началом и концом (проверка, подключение VPN, обновление баз);
• session — окно: от открытия до закрытия; исправно, если за это время не было ошибок.

Эталон (baseline.json рядом с модулем, входит в сборку): в тестовой версии кнопка
«✓ Исправно» сохраняет для функции последний успешный запуск на этом ПК — шаги и время.
На любом компьютере (и в релизной версии) запуск сверяется с эталоном; ошибка, пропавший
шаг или время намного дольше эталонного — запись ERROR/WARNING «отклонение от проверенной
версии» в журнал. Последние запуски — logs/feature_runs.json (для страницы «Тестирование»).
"""
import json
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from diag.log import get
import datadirs

log = get("feature")


@dataclass(frozen=True)
class Feature:
    id: str
    title: str
    area: str            # страница главного меню или класс окна — для панели в углу
    kind: str = "action"  # action | session
    # время зависит от объёма работы (размер папки, число файлов): сравнивать с эталоном
    # нельзя — 48 с на System32 против 0,8 с на маленькой папке давали ложное «ОТКЛОНЕНИЕ»
    timed: bool = True


_F = Feature
FEATURES: dict[str, Feature] = {f.id: f for f in [
    _F("app.start", "Запуск программы", "Главная"),
    _F("home.quick_scan", "Быстрая проверка (кнопка главной)", "Главная", timed=False),
    _F("db.update", "Обновление баз", "Главная", timed=False),
    _F("scan.file", "Проверка файла", "Сканирование папки/файла", timed=False),
    _F("scan.folder", "Проверка папки", "Сканирование папки/файла", timed=False),
    _F("analyzer.decompile", "Декомпилятор: разбор файла и проверка частей",
       "Сканирование папки/файла", timed=False),
    _F("protect.realtime", "Защита файлов: включение и выключение", "Защита"),
    _F("protect.full_scan", "Проверка дисков (полная и быстрая)", "Защита", timed=False),
    _F("protect.threat_actions", "Журнал защиты: карантин найденного", "Защита"),
    _F("protect.schedule", "Плановая проверка", "Защита"),
    _F("protect.decoys", "Ловушки для шифровальщиков", "Защита"),
    _F("net.monitor", "Мониторинг сети: включение и выключение", "Сеть"),
    _F("net.block", "Сеть: блокировка адреса или программы", "Сеть"),
    _F("journal.undo", "Журнал: отмена действий и переход к месту", "Журнал"),
    _F("journal.quarantine", "Журнал защиты: карантин, удаление, восстановление", "Журнал"),
    _F("journal.whitelist", "Белый список (через восстановление и отмену)", "Журнал"),
    _F("settings.change", "Изменение настроек", "Настройки"),
    _F("debug.bench", "Отчёт и графики ресурсов", "Отладка"),
    _F("win.autoruns", "Сканер автозапуска", "AutorunsWindow", "session"),
    _F("win.process_manager", "Диспетчер процессов", "ProcessWindow", "session"),
    _F("win.memory", "Память: RWX-регионы и модули", "MemoryDialog", "session"),
    _F("win.injection", "Поиск внедрённого кода", "InjectionScanDialog", "session"),
    _F("win.recovery", "Центр восстановления", "RecoveryWindow", "session"),
    _F("win.usb", "USB-накопители", "UsbWindow", "session"),
    _F("win.drivers", "Уязвимые драйверы", "DriversWindow", "session"),
    _F("win.extensions", "Расширения браузеров", "ExtensionsWindow", "session"),
    _F("win.link", "Проверка ссылок", "LinkCheckWindow", "session"),
    _F("win.password", "Проверка паролей по утечкам", "PasswordLeakWindow", "session"),
    _F("win.vpn", "Окно VPN", "VpnWindow", "session"),
    _F("vpn.connect", "VPN: подключение", "VpnWindow"),
    _F("vpn.checks", "VPN: проверка сайтов и сертификатов", "VpnWindow"),
    _F("vpn.netdiag", "VPN: «Почему нет интернета?»", "VpnWindow"),
    _F("vpn.routing", "VPN: импорт профилей маршрутизации (файлы, ссылка)", "VpnWindow",
       timed=False),
    _F("vpn.warp", "VPN: получение ключа WARP", "VpnWindow", timed=False),
    _F("settings.collect_info", "Сбор сведений о программе (.zip)", "Настройки"),
    _F("win.false_positives", "Ложные срабатывания", "FalsePositiveWindow", "session"),
    _F("win.resource_report", "Отчёт и графики (окно)", "ResourceReportWindow", "session"),
]}
WINDOW_FEATURES = {f.area: f.id for f in FEATURES.values() if f.kind == "session"}

BASELINE_FILE = Path(__file__).resolve().parent / "baseline.json"
RUNS_FILE = datadirs.LOGS / "feature_runs.json"
SLOW_FACTOR = 5.0      # во столько раз дольше эталона — предупреждение
SLOW_MIN_SEC = 30.0    # но не меньше, чем на столько секунд


@dataclass
class Run:
    feature: str
    kind: str = "action"
    started: float = field(default_factory=time.time)
    steps: list[str] = field(default_factory=list)
    facts: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    ok: bool | None = None
    duration: float = 0.0

    def step(self, name: str) -> None:
        if name not in self.steps:
            self.steps.append(name)
        log.debug("%s: шаг «%s»", self.feature, name)

    def fact(self, key: str, value) -> None:
        self.facts[key] = value

    def error(self, text: str) -> None:
        self.errors.append(str(text)[:500])
        log.error("%s: ошибка: %s", self.feature, text)

    def finish(self, ok: bool = True, **facts) -> None:
        if self.ok is not None:
            return
        self.facts.update(facts)
        self.ok = ok and not self.errors
        self.duration = time.time() - self.started
        with _lock:
            if self in _active:
                _active.remove(self)
        _remember(self)
        _compare(self)


_lock = threading.Lock()
_active: list[Run] = []
_runs: dict[str, dict] | None = None
_baseline: dict[str, dict] | None = None
listeners: list = []  # страница «Тестирование»: вызов при каждом завершённом запуске


def title(fid: str) -> str:
    f = FEATURES.get(fid)
    return f.title if f else fid


def begin(fid: str, kind: str | None = None) -> Run:
    f = FEATURES.get(fid)
    run = Run(fid, kind or (f.kind if f else "action"))
    with _lock:
        # незавершённый прежний запуск той же функции (действие запущено заново) — закрыть
        for old in [r for r in _active if r.feature == fid and r.kind == "action"]:
            _active.remove(old)
        _active.append(run)
    log.info("Начало: %s", title(fid))
    return run


def current(fid: str) -> Run | None:
    with _lock:
        return next((r for r in reversed(_active) if r.feature == fid), None)


def step(fid: str, name: str) -> None:
    run = current(fid)
    if run is not None:
        run.step(name)


def end(fid: str, ok: bool = True, error: str = "", **facts) -> None:
    run = current(fid) or begin(fid)
    if error:
        run.error(error)
    run.finish(ok, **facts)


class track:
    """with features.track("db.update") as run: ... — исключение = неисправность."""

    def __init__(self, fid: str):
        self.fid = fid
        self.run: Run | None = None

    def __enter__(self) -> Run:
        self.run = begin(self.fid)
        return self.run

    def __exit__(self, kind, value, tb):
        if value is not None and not isinstance(value, (KeyboardInterrupt, SystemExit)):
            self.run.error(f"{type(value).__name__}: {value}")
        self.run.finish(value is None)
        return False


def wrap_method(cls, name: str, fid: str) -> None:
    """Синхронный метод класса — запуск функции (исключение внутри — неисправность).

    Лишние позиционные аргументы отбрасываются: Qt передаёт слоту, например, checked у
    clicked, а исходный метод мог его не принимать (Qt смотрит число параметров исходного
    метода, у обёртки его не видно)."""
    import functools
    import inspect
    original = getattr(cls, name)
    params = list(inspect.signature(original).parameters.values())[1:]
    var = any(p.kind == p.VAR_POSITIONAL for p in params)
    limit = sum(p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD) for p in params)

    @functools.wraps(original)
    def wrapper(self, *args, **kwargs):
        if not var:
            args = args[:limit]
        with track(fid):
            return original(self, *args, **kwargs)

    setattr(cls, name, wrapper)


def end_if_active(fid: str, ok: bool = True, error: str = "", **facts) -> None:
    """Завершить запуск, только если он идёт (асинхронное действие с несколькими входами)."""
    run = current(fid)
    if run is not None:
        if error:
            run.error(error)
        run.finish(ok, **facts)


def on_exception(value: BaseException) -> None:
    """Необработанное исключение — во все идущие запуски."""
    with _lock:
        runs = list(_active)
    for run in runs:
        run.error(f"{type(value).__name__}: {value}")


def on_error_dialog(title_text: str, text: str) -> None:
    with _lock:
        runs = list(_active)
    for run in runs:
        run.error(f"окно ошибки «{title_text}»: {text}")


def window_shown(class_name: str) -> None:
    fid = WINDOW_FEATURES.get(class_name)
    if fid and current(fid) is None:
        begin(fid, "session")


def window_closed(class_name: str) -> None:
    fid = WINDOW_FEATURES.get(class_name)
    run = current(fid) if fid else None
    if run is not None:
        run.finish(True)


# --- хранение ---------------------------------------------------------------------------
def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def runs() -> dict[str, dict]:
    global _runs
    with _lock:
        if _runs is None:
            _runs = _load_json(RUNS_FILE)
        return dict(_runs)


def _remember(run: Run) -> None:
    global _runs
    item = {"time": run.started, "ok": run.ok, "duration": round(run.duration, 2),
            "steps": run.steps, "errors": run.errors[-5:],
            "facts": {k: str(v)[:200] for k, v in run.facts.items()}, "kind": run.kind}
    with _lock:
        if _runs is None:
            _runs = _load_json(RUNS_FILE)
        previous = _runs.get(run.feature, {})
        if run.ok:
            item["last_ok"] = {k: item[k] for k in ("time", "duration", "steps")}
            item["last_ok"]["variant"] = str((item.get("facts") or {}).get("kind", ""))
        elif previous.get("last_ok"):
            item["last_ok"] = previous["last_ok"]
        _runs[run.feature] = item
        try:
            RUNS_FILE.parent.mkdir(exist_ok=True)
            RUNS_FILE.write_text(json.dumps(_runs, ensure_ascii=False, indent=1), encoding="utf-8")
        except OSError:
            pass
    for listener in list(listeners):
        try:
            listener(run.feature)
        except Exception:  # noqa: S110 — слушатель (панель тестирования) не мешает учёту запусков
            pass


def baseline() -> dict[str, dict]:
    global _baseline
    with _lock:
        if _baseline is None:
            _baseline = _load_json(BASELINE_FILE)
        return dict(_baseline)


def mark_ok(fid: str, note: str = "") -> dict:
    """Кнопка «✓ Исправно»: эталон из последнего успешного запуска на этом ПК."""
    global _baseline
    import appinfo
    from diag import specs
    last = runs().get(fid, {}).get("last_ok") or {}
    entry = {"verified_at": time.strftime("%Y-%m-%d %H:%M:%S"), "version": appinfo.VERSION,
             "steps": last.get("steps", []), "duration": last.get("duration"),
             "variant": last.get("variant", ""),
             "pc": _pc_short(specs), "note": note, "had_run": bool(last)}
    with _lock:
        if _baseline is None:
            _baseline = _load_json(BASELINE_FILE)
        _baseline[fid] = entry
        BASELINE_FILE.write_text(json.dumps(_baseline, ensure_ascii=False, indent=1),
                                 encoding="utf-8")
    log.info("Отмечено исправным: %s (шаги: %s, время: %s с)%s", title(fid),
             ", ".join(entry["steps"]) or "нет", entry["duration"],
             "" if last else " — без успешного запуска в этом сеансе")
    return entry


def unmark(fid: str) -> None:
    global _baseline
    with _lock:
        if _baseline is None:
            _baseline = _load_json(BASELINE_FILE)
        if _baseline.pop(fid, None) is not None:
            BASELINE_FILE.write_text(json.dumps(_baseline, ensure_ascii=False, indent=1),
                                     encoding="utf-8")
    log.info("Отметка «исправно» снята: %s", title(fid))


def _pc_short(specs) -> str:
    try:
        d = specs.cached() or {}  # только из кэша: сбор занимает секунды, а это главный поток
        cpu = (d.get("cpu") or [{}])
        cpu = cpu[0] if isinstance(cpu, list) else cpu
        o = d.get("os") or {}
        return f"{(cpu.get('Name') or '').strip()}; Windows {o.get('build', '?')}"
    except Exception:
        return ""


def _compare(run: Run) -> None:
    ref = baseline().get(run.feature)
    name = title(run.feature)
    if not ref:
        if run.ok:
            log.info("Готово: %s за %.2f с%s", name, run.duration, _facts(run))
        else:
            log.error("Неисправно: %s за %.2f с — %s", name, run.duration,
                      "; ".join(run.errors) or "завершилось неудачно")
        return
    where = f"проверена исправной {ref.get('verified_at')} в версии {ref.get('version')}"
    if not run.ok:
        log.error("ОТКЛОНЕНИЕ от проверенной версии: %s (%s) — %s", name, where,
                  "; ".join(run.errors) or "завершилось неудачно")
        return
    variant = str((run.facts or {}).get("kind", ""))
    if variant and variant != ref.get("variant", ""):
        # эталон снят в другом режиме (VPN: TUN, а сейчас локальный прокси): шаги и время
        # у режимов разные, сравнение давало ложное «ОТКЛОНЕНИЕ»
        log.info("Готово: %s за %.2f с%s (эталон — для другого режима)", name, run.duration,
                 _facts(run))
        return
    missing = [s for s in ref.get("steps", []) if s not in run.steps]
    if missing and run.kind == "action":
        log.error("ОТКЛОНЕНИЕ от проверенной версии: %s (%s) — не пройдены шаги: %s",
                  name, where, ", ".join(missing))
    duration = ref.get("duration")
    feature = FEATURES.get(run.feature)
    timed = feature is None or feature.timed
    if run.kind == "action" and timed and duration and \
            run.duration > max(duration * SLOW_FACTOR, duration + SLOW_MIN_SEC):
        log.warning("ОТКЛОНЕНИЕ от проверенной версии: %s выполнялась %.1f с, эталон %.1f с (%s)",
                    name, run.duration, duration, where)
    elif not missing:
        log.info("Готово (как в проверенной версии): %s за %.2f с%s", name, run.duration,
                 _facts(run))


def _facts(run: Run) -> str:
    return (", " + ", ".join(f"{k}={v}" for k, v in run.facts.items())) if run.facts else ""


def install_dialog_hook() -> None:
    """Окна QMessageBox.critical/warning — в журнал и в идущие запуски."""
    from PySide6.QtWidgets import QMessageBox
    ui_log = get("ui")
    for level, name in (("error", "critical"), ("warning", "warning")):
        original = getattr(QMessageBox, name)

        def hooked(*args, _orig=original, _level=level, **kwargs):
            try:
                texts = [a for a in args if isinstance(a, str)]
                head = texts[0] if texts else ""
                body = texts[1] if len(texts) > 1 else ""
                getattr(ui_log, _level)("Окно «%s»: %s", head, body)
                if _level == "error":
                    on_error_dialog(head, body)
            except Exception:  # noqa: S110 — перехват окна сообщения не должен мешать самому окну
                pass
            return _orig(*args, **kwargs)

        setattr(QMessageBox, name, staticmethod(hooked))


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))
