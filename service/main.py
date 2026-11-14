"""Точки входа службы (gui.py передаёт сюда ключи --service*, до Qt и userdata):

    --service           процесс службы (запускает диспетчер служб Windows)
    --service-console   то же ядро в консоли, без диспетчера служб (разработка)
    --service-install   создать или обновить службу и запустить её (установщик, с правами)
    --service-remove    остановить и удалить службу (удаление программы, с правами)
    --service-stop      остановить службу и дождаться (установщик перед заменой файлов)
"""
import sys
import time


def _prepare():
    """Папка данных службы вместо %APPDATA% и свой файл журнала — до импорта модулей,
    которые берут пути при импорте."""
    from service import core
    folder = core.data_dir()
    import userdata
    userdata.set_root(folder)
    from diag import log as diag_log
    diag_log.LOG_FILE = diag_log.LOG_DIR / "service.log"
    diag_log.setup(worker=True)
    log = diag_log.get("service")
    import wincerts
    wincerts.install()  # базы качает служба: на «чистой» Windows нет части корней
    import appinfo
    from diag import edition
    log.info("=" * 70)
    log.info("Служба %s %s (%s), PID %s, данные: %s", appinfo.APP_NAME, appinfo.VERSION,
             edition.title(), __import__("os").getpid(), folder)
    return folder, log


def _install() -> int:
    from service import protocol, scm
    if not getattr(sys, "frozen", False):
        print("Службу ставит только собранная программа (StretchBIT.exe), не исходники. "
              "Для разработки: python -m service --console")
        return 2
    name = protocol.service_name()
    what = scm.install(name, protocol.display_name(), protocol.DESCRIPTION,
                       scm.command_line())
    scm.start(name)
    print(f"Служба {name} {what} и запущена")
    return 0


def _console(folder, log) -> int:
    from service.core import ServiceCore
    core = ServiceCore(folder)
    core.start()
    print(f"Ядро службы работает в консоли (канал {core.server.name}). Ctrl+C — выход.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        core.stop()
    return 0


def entry(argv: list[str]) -> int:
    from service import protocol, scm
    name = protocol.service_name()
    if "--service-install" in argv:
        return _install()
    if "--service-remove" in argv:
        print("удалена" if scm.remove(name) else "службы не было")
        return 0
    if "--service-stop" in argv:
        print("остановлена" if scm.stop(name) else "не работала")
        return 0
    folder, log = _prepare()
    if "--service-console" in argv:
        return _console(folder, log)
    from service.core import ServiceCore
    holder = {}

    def start_core():
        holder["core"] = ServiceCore(folder)
        holder["core"].start()

    def stop_core():
        if "core" in holder:
            holder["core"].stop()
    code = scm.run_as_service(name, start_core, stop_core, log)
    if code == 1:
        log.error("--service: процесс запущен не диспетчером служб")
    return code
