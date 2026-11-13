"""Технический журнал logs/app.log.

Строка: «2026-11-08 18:20:31.123 +0900 INFO  [vpn] MainThread: текст». Всё проходит
обезличивание (diag.anon.scrub) перед записью. Файл сменяется при 5 МБ, хранится 5 прежних
(app.log.1 ... app.log.5). Тестовая версия пишет DEBUG, релизная — INFO и выше.

setup() вызывается в самом начале gui.py: журнал, перехват падений и внешних команд,
заголовок сеанса (версия, сборка, права); характеристики ПК и снимок настроек дописываются
из фонового потока (session_details), чтобы не задерживать запуск.
"""
import logging
import logging.handlers
import sys
import time
import datadirs

LOG_DIR = datadirs.LOGS
LOG_FILE = LOG_DIR / "app.log"
MAX_BYTES = 5 * 2 ** 20
BACKUPS = 5

log = logging.getLogger("sbit")
_ready = False


class _Formatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        t = time.localtime(record.created)
        return time.strftime("%Y-%m-%d %H:%M:%S", t) + f".{int(record.msecs):03d} " + \
            time.strftime("%z", t)

    def format(self, record):
        from diag import anon
        text = super().format(record)
        return anon.scrub(text)


FORMAT = "%(asctime)s %(levelname)-5s [%(name)s] %(threadName)s: %(message)s"


def swallowed(where: str) -> None:
    """Для «except Exception:», где ошибка намеренно не мешает работе: вместо молчаливого
    pass — строка в app.log (DEBUG), чтобы причину можно было найти."""
    try:
        import traceback
        last = traceback.format_exc(limit=2).strip().splitlines()[-1]
        get("swallow").debug("%s: %s", where, last)
    except Exception:  # noqa: BLE001, S110 — сам журнал недоступен: остаётся только молчать
        pass


def get(name: str) -> logging.Logger:
    """Журнал раздела: get("vpn") → «sbit.vpn» (в строке — [sbit.vpn])."""
    return log.getChild(name)


def setup(worker: bool = False) -> None:
    """worker=True — рабочий процесс проверки: пишет в тот же файл без заголовка сеанса."""
    global _ready
    if _ready:
        return
    from diag import edition
    LOG_DIR.mkdir(exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=MAX_BYTES, backupCount=BACKUPS, encoding="utf-8", delay=True)
    handler.setFormatter(_Formatter(FORMAT))
    log.addHandler(handler)
    log.setLevel(logging.DEBUG if edition.is_test() else logging.INFO)
    log.propagate = False
    _ready = True
    if worker:
        return
    from diag import anon, crash, proc
    anon.register_adapters()
    crash.install()
    proc.install()
    import appinfo
    from diag import specs
    log.info("=" * 70)
    log.info("Запуск %s %s, сборка: %s, %s, права администратора: %s, PID %s, аргументы: %s",
             appinfo.APP_NAME, appinfo.VERSION, edition.title(),
             "собранная программа" if getattr(sys, "frozen", False) else "из исходников",
             specs.is_admin(), _pid(), " ".join(sys.argv[1:]) or "нет")


def _pid() -> int:
    import os
    return os.getpid()


def session_details() -> None:
    """Характеристики ПК, снимок настроек и версий — в фоне после запуска."""
    import threading

    def work():
        from diag import anon, snapshot, specs
        anon.register_vpn_profiles()
        try:
            for line in specs.describe():
                log.info("ПК: %s", line)
        except Exception:
            log.exception("Характеристики ПК не собраны")
        try:
            for line in snapshot.lines():
                log.info("Снимок: %s", line)
        except Exception:
            log.exception("Снимок настроек не собран")

    threading.Thread(target=work, name="diag-session", daemon=True).start()


def tail(lines: int = 200, contains: str = "") -> list[str]:
    """Последние строки журнала (для комментария к функции)."""
    try:
        data = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    if contains:
        data = [s for s in data if contains in s]
    return data[-lines:]
