"""Падения и зависания.

• Необработанные исключения главного потока и других потоков → журнал с трассировкой.
• Жёсткие падения (ошибка в C-модуле, Qt, нехватка памяти) — faulthandler пишет стеки
  всех потоков в logs/crash.log; он же по таймауту не срабатывает (только при падении).
• Сеанс: logs/session.json с PID и временем; если при запуске он остался от прошлого
  запуска, а процесса уже нет — «прошлый запуск завершился аварийно» (с последними строками
  crash.log). При обычном выходе файл удаляется (mark_clean_exit).
• Зависание интерфейса: таймер Qt раз в 0,1 с отмечается в главном потоке, сторожевой поток
  замечает паузу дольше FREEZE_SEC и пишет стек главного потока — место, где он стоит.
• Сообщения Qt (qWarning, qCritical) → журнал.
"""
import faulthandler
import json
import os
import sys
import threading
import time
import traceback

from diag.log import get
import datadirs

log = get("crash")
SESSION = datadirs.LOGS / "session.json"
CRASH_LOG = datadirs.LOGS / "crash.log"
FREEZE_SEC = 0.5
_crash_file = None


def install() -> None:
    global _crash_file
    sys.excepthook = _excepthook
    threading.excepthook = _thread_excepthook
    try:
        _crash_file = open(CRASH_LOG, "a", encoding="utf-8")
        _crash_file.write(f"\n--- запуск {time.strftime('%Y-%m-%d %H:%M:%S')} PID {os.getpid()}\n")
        _crash_file.flush()
        faulthandler.enable(_crash_file, all_threads=True)
    except OSError:
        pass


def start_session() -> None:
    """После того как этот экземпляр стал единственным (SingleInstance.listen): иначе
    второй запуск, который сразу выходит, затёр бы метку первого."""
    _check_previous_session()
    _write_session()


def _excepthook(kind, value, tb):
    log.critical("Необработанная ошибка: %s",
                 "".join(traceback.format_exception(kind, value, tb)).rstrip())
    try:
        from diag import features
        features.on_exception(value)
    except Exception:  # noqa: S110 — обработчик сбоя не должен падать сам
        pass


def _thread_excepthook(args):
    if args.exc_type is SystemExit:
        return
    name = args.thread.name if args.thread else "?"
    log.critical("Необработанная ошибка в потоке %s: %s", name, "".join(
        traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback)).rstrip())
    try:
        from diag import features
        features.on_exception(args.exc_value)
    except Exception:  # noqa: S110 — обработчик сбоя не должен падать сам
        pass


def _pid_alive(pid: int) -> bool:
    try:
        import psutil
        return psutil.pid_exists(pid)
    except Exception:
        return False


def _check_previous_session() -> None:
    try:
        old = json.loads(SESSION.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    pid = int(old.get("pid", 0))
    if pid and pid != os.getpid() and _pid_alive(pid):
        return  # другой экземпляр ещё работает (перезапуск с правами)
    started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(old.get("started", 0)))
    if _closed_by_setup(float(old.get("started", 0) or 0)):
        log.info("Прошлый запуск (с %s, PID %s) закрыт установщиком или удалением программы",
                 started, pid)
        return
    tail = ""
    try:
        lines = CRASH_LOG.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max((i for i, s in enumerate(lines[:-1]) if s.startswith("--- запуск")), default=0)
        tail = "\n".join(lines[start:-1][-40:])
    except OSError:
        pass
    log.error("Прошлый запуск (с %s, PID %s) завершился аварийно: не было обычного выхода "
              "(снятие задачи, сбой, выключение питания).%s", started, pid,
              f"\nПоследнее из crash.log:\n{tail}" if "Fatal" in tail or "Error" in tail else "")


def _closed_by_setup(started: float) -> bool:
    """Установщик и удаление закрывают программу принудительно и перед этим ставят метку
    cache/no_restart (selfguard): метка новее начала сеанса — это не сбой."""
    try:
        import selfguard
        return selfguard.NO_RESTART.stat().st_mtime >= started > 0
    except (OSError, ImportError):
        return False


def _write_session() -> None:
    try:
        SESSION.write_text(json.dumps({"pid": os.getpid(), "started": time.time()}),
                           encoding="utf-8")
    except OSError:
        pass


_exit_started: float | None = None  # время начала выхода: сторож зависаний молчит


def begin_exit() -> None:
    """Начался выход: остановка защиты и потоков ждёт их, это не зависание."""
    global _exit_started
    _exit_started = time.monotonic()


def mark_clean_exit() -> None:
    took = f" (остановка заняла {time.monotonic() - _exit_started:.1f} с)" if _exit_started else ""
    log.info("Обычный выход из программы%s", took)
    try:
        SESSION.unlink()
    except OSError:
        pass


class FreezeWatch:
    """Сторож главного потока. Создавать после QApplication."""

    def __init__(self):
        from PySide6.QtCore import QTimer
        self._beat = time.monotonic()
        self._main = threading.main_thread().ident
        self._timer = QTimer()
        self._timer.timeout.connect(self._tick)
        self._timer.start(100)
        threading.Thread(target=self._watch, name="diag-freeze", daemon=True).start()

    def _tick(self):
        self._beat = time.monotonic()

    def _watch(self):
        reported = 0.0
        last = time.monotonic()
        while True:
            time.sleep(0.1)
            if _exit_started is not None:
                return  # выход: ожидание потоков — не зависание
            now = time.monotonic()
            if now - last > 3.0:
                # сам сторож стоял: компьютер спал (или процесс был заморожен) — в журнале
                # это выглядело «зависанием на 72380 с»
                log.info("Пауза процесса %.0f с (сон компьютера) — не зависание", now - last)
                self._beat, reported = now, 0.0
            last = now
            lag = now - self._beat
            if lag > FREEZE_SEC and reported == 0.0:
                frame = sys._current_frames().get(self._main)
                stack = "".join(traceback.format_stack(frame, limit=12)) if frame else ""
                log.warning("Интерфейс не отвечает %.1f с, главный поток сейчас здесь:\n%s",
                            lag, stack.rstrip())
                reported = time.monotonic()
            elif lag <= FREEZE_SEC and reported:
                total = time.monotonic() - reported + FREEZE_SEC
                log.warning("Интерфейс снова отвечает (зависание ~%.1f с)", total)
                reported = 0.0


def install_qt_messages() -> None:
    from PySide6.QtCore import QtMsgType, qInstallMessageHandler
    qt_log = get("qt")
    levels = {QtMsgType.QtDebugMsg: qt_log.debug, QtMsgType.QtInfoMsg: qt_log.info,
              QtMsgType.QtWarningMsg: qt_log.warning, QtMsgType.QtCriticalMsg: qt_log.error,
              QtMsgType.QtFatalMsg: qt_log.critical}

    def handler(kind, context, message):
        levels.get(kind, qt_log.warning)("%s", message)

    qInstallMessageHandler(handler)
