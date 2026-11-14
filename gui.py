import os
import sys
import threading
import time
from pathlib import Path

# собранная программа: рабочая папка — app рядом с StretchBIT.exe (sys._MEIPASS), там же лежат
# модули, поэтому пути от __file__ (signatures, journal, cache) и относительные пути совпадают
os.chdir(Path(sys._MEIPASS) if getattr(sys, "frozen", False)
         else Path(__file__).resolve().parent)

if "--scan-worker" in sys.argv:  # собранная программа: рабочий процесс проверки (scanner.pool)
    from scanner.worker import main as _worker_main
    _worker_main()
    sys.exit(0)

if "--watchdog" in sys.argv:  # сторож: перезапуск после нештатного завершения (selfguard.py)
    import selfguard
    try:
        selfguard.watch(int(sys.argv[sys.argv.index("--watchdog") + 1]))
    except (ValueError, IndexError):
        pass
    sys.exit(0)

if any(a.startswith("--service") for a in sys.argv[1:]):
    # служба Windows и её установка (service/main.py): до Qt и папки конфигурации
    # пользователя — у службы свои данные в ProgramData
    if sys.stdout is None or sys.stderr is None:
        import datadirs
        datadirs.LOGS.mkdir(parents=True, exist_ok=True)
        _log = open(datadirs.LOGS / "service-stdout.log", "a", encoding="utf-8", buffering=1)
        sys.stdout = sys.stdout or _log
        sys.stderr = sys.stderr or _log
    from service.main import entry as _service_entry
    sys.exit(_service_entry(sys.argv[1:]))

if sys.stdout is None or sys.stderr is None:  # pythonw или exe без консоли
    import datadirs
    datadirs.LOGS.mkdir(parents=True, exist_ok=True)
    _log = open(datadirs.LOGS / "gui.log", "a", encoding="utf-8", buffering=1)
    sys.stdout = sys.stdout or _log
    sys.stderr = sys.stderr or _log

from diag import log as diag_log  # технический журнал logs/app.log (diag/log.py)
diag_log.setup()
_dlog = diag_log.get("app")
import wincerts  # noqa: E402 — HTTPS: недостающий корень Windows докачивается (wincerts.py)
wincerts.install()
from diag import features  # noqa: E402 — исправность функций (эталон «Исправно»)

import userdata  # noqa: E402 — настройки и журнал в %APPDATA%\StretchBitConfiguration
for _line in userdata.migrate():  # прежние данные из папки программы и реестра — туда
    _dlog.info("Конфигурация: %s", _line)


def _transfer_now() -> bool:
    """Перенос данных другой версии (service/transfer.py) — до первого чтения настроек.
    Ручной запуск без прав сейчас перезапустится через UAC: перенос сделает процесс с
    правами (ключ подписи журнала другой версии читают только администраторы)."""
    import trustseal
    if any(a in sys.argv for a in ("--uninstall", "--tool", "--undo")):
        return False
    elevating = not ({"--autostart", "--analyze", "--alarm"} & set(sys.argv))
    return trustseal.is_admin() or not elevating


if _transfer_now():
    from service import transfer as _transfer
    try:
        for _line in _transfer.window():
            _dlog.info("Конфигурация: %s", _line)
    except Exception:  # noqa: BLE001 — без переноса программа всё равно запустится
        _dlog.exception("Конфигурация: перенос данных другой версии не удался")

from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtWidgets import (
    QApplication, QFrame, QLabel, QMainWindow, QMessageBox, QScrollArea, QSystemTrayIcon,
    QTabWidget, QVBoxLayout, QWidget,
)

from scanner import heuristics, pool as scan_pool, verdict_cache
from scanner.whitelist import load_whitelist
from quarantine import list_quarantine
from monitor import RealtimeMonitor
from networkmonitor.netmon import NetworkMonitor

from processmanager.window import ProcessWindow
from processmanager.system import is_admin, relaunch_as_admin, allow_drops_from_lower_integrity

from ui import settings as cfg
from ui.pages import AboutPage, DashboardPage, SettingsPage, ToolsPage, DebugPage
from ui.shell import Shell
from ui.textutil import install_message_box_limits
from ui.theme import apply_theme
from ui.tray import TrayIcon, load_app_icon
from ui import access
from ui.debug_mode import ask_password, load_gate
from recovery import activity
from ui.single_instance import SingleInstance
from ui.exclusions_page import ExclusionsPage

import appinfo

from autoruns.window import AutorunsWindow

from analyzer.scanpage import ScanPage

from recovery.window import RecoveryWindow
from recovery.journal_page import JournalPage

from mainwindow.common import (
    NetBridge, MonitorBridge, SCAN_PAGE, LOG_PAGE,
)
from mainwindow.journal import JournalMixin
from mainwindow.tools import ToolsMixin
from mainwindow.usb import UsbMixin
from mainwindow.protection import ProtectionMixin
from mainwindow.scans import ScansMixin
from mainwindow.network import NetworkMixin
from mainwindow.databases import DatabasesMixin


class MainWindow(JournalMixin, ToolsMixin, UsbMixin, ProtectionMixin, ScansMixin,
                 NetworkMixin, DatabasesMixin, QMainWindow):
    """Главное окно. Методы по разделам — в mainwindow/* (классы-примеси); здесь
    сигналы Qt, устройство окна, трей, события и выход."""
    update_finished = Signal(str, bool, bool)  # вывод, успех, тихое (автообновление)
    update_progress = Signal(str)
    update_fraction = Signal(float)         # доля готовности обновления баз (шкала на главной)
    usb_checked = Signal(object, object)    # DriveReport автопроверки флешки, итог лечения
    usb_drives = Signal(object)             # [(корень, метка)] съёмных дисков (опрос в фоне)
    db_stats_ready = Signal(object)         # счётчики баз, посчитанные в фоне
    decoy_alarm = Signal(object, object)    # изменённые ловушки, виновник
    shadow_found = Signal(object, object, object)  # файлы, есть версии, снимки (shadow.py)
    full_progress = Signal(object)          # fullscan.Stats во время полной проверки
    full_found = Signal(str, str, str)      # путь, уровень, текст
    full_done = Signal(object, bool)        # итог, остановлена ли вручную
    launch_event = Signal(str, object)      # контроль запуска: вид, сведения
    stealer_event = Signal(object)          # защита от стилеров: сведения о доступе
    guard_status = Signal(str, str)         # launch | stealer, текст состояния
    amsi_event = Signal(object)             # AMSI: заблокированный или подозрительный скрипт
    pslog_event = Signal(object)            # журнал PowerShell 4104: опасный блок скрипта
    release_found = Signal(object, str, bool)  # updatecheck.Release | None, ошибка, вручную
    release_downloaded = Signal(object, str)   # путь установщика | None, ошибка
    systool_failed = Signal(object)         # diag.systool.Failure: системная программа не сработала
    service_event = Signal(object)          # событие службы Windows (service/client.EventPump)

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{appinfo.APP_NAME} {appinfo.VERSION}")
        self.settings = cfg.store()  # settings.ini в папке конфигурации (userdata.py)
        self._fit_to_screen()
        self.monitor: RealtimeMonitor | None = None  # или service.client.RemoteMonitor
        self.service = None  # service.client.ServiceClient: защита и карантин — в службе
        # защиту ведёт служба другой версии (релизной/тестовой): окно своих защит, сети и VPN
        # не запускает (service/editions.py); здесь — её название
        self.passive_other = ""
        self._service_pump = None
        self._service_db_last_update = 0.0  # db_last_update из последнего op_status службы
        self._service_db_progress = None    # служба обновляет базы: доля готовности
        self._db_fraction = 0.0             # окно само обновляет базы (без службы)
        self.bridge = MonitorBridge()
        self.bridge.event.connect(self.on_monitor_event)
        self.net_monitor: NetworkMonitor | None = None
        self.net_alerts: list = []  # порядок совпадает со строками таблицы
        self.net_bridge = NetBridge()
        self.net_bridge.event.connect(self.on_net_event)
        self.proc_window: ProcessWindow | None = None
        self.guard = None  # SingleInstance, задаётся при запуске
        self.tray: TrayIcon | None = None
        self._quitting = False
        self._session_ending = False
        QApplication.instance().commitDataRequest.connect(self._on_session_end)
        self._tray_hint_shown = False
        self.autoruns_window: AutorunsWindow | None = None
        self.recovery_window: RecoveryWindow | None = None
        self.usb_window = None
        self.tool_windows: dict = {}
        self._usb_known: set[str] = set()
        self._usb_pending: tuple | None = None   # флешка из последнего уведомления
        self.usb_checked.connect(self._on_usb_checked)
        from toolbox.decoys import DecoyWatcher
        self.decoy_watcher = DecoyWatcher(lambda changed, culprit:
                                          self.decoy_alarm.emit(changed, culprit))
        self.decoy_alarm.connect(self._on_decoy_alarm)
        self.shadow_found.connect(self._on_shadow_found)
        self.launch_guard = None   # scanner.launchguard.LaunchGuard, пока включена защита
        self.stealer_guard = None  # toolbox.stealerguard.StealerGuard
        self.amsi_server = None    # scanner.amsi.AmsiServer
        self.pslog_watch = None    # scanner.pslog.ScriptBlockWatch
        self.launch_event.connect(self._on_launch_event)
        self.amsi_event.connect(self._on_amsi_event)
        self.pslog_event.connect(self._on_pslog_event)
        self._systool_dialog = None
        self.systool_failed.connect(self._on_systool_failed)
        from diag import systool
        systool.add_listener(self.systool_failed.emit)  # из любого потока — через сигнал
        self.stealer_event.connect(self._on_stealer_event)
        self.guard_status.connect(self._on_guard_status)
        self._tray_target = ""     # что открыть по щелчку на уведомлении: usb | schedule
        from ui.notify import Notifier
        self.notifier = Notifier(self)  # уведомления Windows с кнопками
        self._schedule_due = 0.0   # когда начнётся объявленная плановая проверка
        self.recent_events: list[tuple[str, str, str]] = []  # для главной: время, текст, уровень
        self._db_stats: dict | None = None  # счётчики баз, пересчитываются после обновления
        self.db_stats_ready.connect(self._on_db_stats)
        self._updating = False
        self._update_silent = False
        self.auto_update_timer = QTimer(self)
        self.auto_update_timer.setInterval(30 * 60 * 1000)  # раз в полчаса: не пора ли
        self.auto_update_timer.timeout.connect(self.auto_update_check)

        self.setAcceptDrops(True)

        self.shell = Shell()
        self.dashboard = DashboardPage()
        self.tools_page = ToolsPage(self)
        self.debug_gate = load_gate()
        self.debug_page = DebugPage(self, self.debug_gate)
        self.journal_page = JournalPage(show_title=False)
        self.exclusions_page = ExclusionsPage(show_title=False)
        self.settings_page = SettingsPage()
        self.about_page = AboutPage()
        self.about_page.update_btn.clicked.connect(lambda: self.check_release(manual=True))
        self.release_found.connect(self._on_release_found)
        self.release_downloaded.connect(self._on_release_downloaded)

        # «Журнал»: найденное (журнал защиты, с карантином), действия программы и исключения.
        # Белый список вкладкой не показывается: он пополняется восстановлением из карантина,
        # а отмена этого действия во «Действиях» убирает файл из белого списка
        from ui.protect_journal import ProtectJournalPage
        self.protect_journal = ProtectJournalPage()
        self.protect_journal.changed.connect(self._on_protect_journal_changed)
        self.protect_journal.analyze.connect(lambda path: self.open_analyzer(path))
        self.protect_journal.false_positive.connect(lambda path: self.open_false_positives(path))
        log_page = QWidget()
        log_layout = QVBoxLayout(log_page)
        log_layout.setContentsMargins(16, 12, 16, 12)
        log_title = QLabel(LOG_PAGE)
        log_title.setStyleSheet("font-size: 20pt; font-weight: 600;")
        log_layout.addWidget(log_title)
        self.log_tabs = QTabWidget()
        self.log_tabs.addTab(self.protect_journal, "Журнал защиты")
        self.log_tabs.addTab(self.journal_page, "Действия")
        self.log_tabs.addTab(self.exclusions_page, "Исключения")
        # таблица для refresh_whitelist: вкладки нет, ссылку держим, иначе Qt удалит виджет
        self._whitelist_tab = self._build_whitelist_tab()
        self.log_tabs.currentChanged.connect(lambda _: self._refresh_log_tab())
        log_layout.addWidget(self.log_tabs, 1)

        self.shell.add_page("Главная", self.dashboard)
        self.scan_page = ScanPage()
        self.scan_page.status.connect(self._show_status)
        self.scan_page.quarantine_changed.connect(self.refresh_quarantine)
        self.scan_page.quarantine_changed.connect(self.refresh_whitelist)
        self.scan_page.quarantine_changed.connect(self.refresh_dashboard)
        self.scan_page.journal_changed.connect(lambda: self.journal_page.refresh())
        self.scan_page.folder_scanned.connect(self._on_folder_scanned)
        self.shell.add_page(SCAN_PAGE, self.scan_page)
        # карточек больше, чем помещается в низкое окно: прокрутка, а не наложение
        protection_scroll = QScrollArea()
        protection_scroll.setWidgetResizable(True)
        protection_scroll.setFrameShape(QFrame.Shape.NoFrame)
        protection_scroll.setWidget(self._build_protection_tab())
        self.shell.add_page("Защита", protection_scroll)
        self.shell.add_page("Сеть", self._build_network_tab())
        self.shell.add_page(LOG_PAGE, log_page)
        self.shell.add_page("Инструменты", self.tools_page)
        # с дополнительными разделами страница выше окна: прокрутка, а не сжатие текста
        settings_scroll = QScrollArea()
        settings_scroll.setWidgetResizable(True)
        settings_scroll.setFrameShape(QFrame.Shape.NoFrame)
        settings_scroll.setWidget(self.settings_page)
        self.shell.add_page("Настройки", settings_scroll)  # часть разделов — режим администратора
        self.shell.add_page("О программе", self.about_page)
        # режим администратора: пароль — в «Настройках», отчёт о работе — в «О программе»;
        # вкладка «Отладка» — только в тестовой версии
        self.settings_page.add_admin_group(self.debug_page.group_access)
        self.about_page.add_admin_group(self.debug_page.group_activity)
        self.shell.add_page("Отладка", self.debug_page, hidden=True)
        self.setCentralWidget(self.shell)

        self.debug_mode = False
        self.settings_page.advanced_requested.connect(self.open_advanced)
        self.debug_page.password_changed.connect(self._on_debug_password_changed)

        self.dashboard.quick_scan.connect(self.quick_scan)
        self.dashboard.toggle_protection.connect(self.toggle_protection)
        self.dashboard.check_updates.connect(self.check_updates)
        self.dashboard.open_processes.connect(self.open_process_manager)
        self.dashboard.open_scan.connect(lambda: self.shell.show_page(SCAN_PAGE))
        self.dashboard.open_journal.connect(lambda: self.show_log("Журнал защиты"))
        self.settings_page.changed.connect(self.on_setting_changed)
        self.update_finished.connect(self._on_update_finished)
        self.update_progress.connect(self._on_update_progress)
        self.update_fraction.connect(self._on_update_fraction)
        self.shell.page_changed.connect(self._on_page_changed)
        self.journal_page.undone.connect(self.on_undone)
        self.journal_page.goto.connect(self.goto_action_place)

        self._apply_tool_access()  # запреты инструментов действуют с запуска
        self.statusBar().showMessage("Готов к работе")
        self.refresh_quarantine()
        self.refresh_whitelist()
        self.refresh_dashboard()

    def install_test_ui(self):
        """Тестовая версия: страница «Тестирование» и панель «Исправно / Комментарий» в углу
        страниц главного окна (окна инструментов получают её сами — testpanel.WindowAttacher)."""
        from diag import testpanel
        self.testing_page = testpanel.TestingPage()
        self.shell.add_page("Тестирование", self.testing_page)
        row = self.shell.nav.currentRow()
        self.test_panel = testpanel.CornerPanel(self.shell.stack, self.shell._titles[max(row, 0)])
        self.shell.page_changed.connect(self.test_panel.set_area)

    def _on_page_changed(self, title: str):
        diag_log.get("ui").info("Страница «%s»", title)
        if title in ("Главная", "Отладка"):
            self.refresh_dashboard()
        elif title == "Защита":
            self.fill_drives()
        elif title == LOG_PAGE:
            self._refresh_log_tab()


    # ---------- центр восстановления ----------

    TAB_TOOLS = {0: "btnRestorePoint", 1: "btnSfcDism", 2: "btnSystemChecks"}


    # ---------- админ-права ----------

    def restart_as_admin(self):
        parent = self if self.isVisible() else None
        answer = QMessageBox.question(
            parent, "Права администратора",
            "Программа будет перезапущена с правами администратора. "
            "Защита и сканирование на время перезапуска остановятся. Продолжить?")
        if answer != QMessageBox.StandardButton.Yes:
            return
        if relaunch_as_admin():
            if self.guard is not None:
                self.guard.release()  # новый экземпляр сразу сможет занять имя
            self.quit_app(force=True)  # перезапуск разрешён и при запрете выхода
        else:
            QMessageBox.warning(parent, "Права администратора",
                                "Не удалось перезапустить (запрос UAC отклонён?)")

    # ---------- анализатор файлов ----------


    def _show_status(self, text: str, timeout: int):
        if text:
            self.statusBar().showMessage(text, timeout)
        else:
            self.statusBar().clearMessage()


    # ---------- дебаг мод ----------

    def _on_debug_password_changed(self, has_password: bool):
        pass  # пароль по умолчанию действует всегда: режим отладки остаётся как есть

    def open_advanced(self):
        """Кнопка в настройках: войти в режим администратора (с паролем) или выйти из него."""
        if self.debug_mode:
            self.toggle_debug_mode()
        elif ask_password(self, self.debug_gate):
            activity.record("access", "Режим администратора открыт по паролю")
            if not cfg.get("advanced/warned"):  # один раз за всё время, не за каждый запуск
                cfg.set_("advanced/warned", True)
                from toolbox.windows import info_dialog
                info_dialog(
                    self, "Режим администратора",
                    "Здесь собраны настройки, которые меняют работу защиты: автозапуск с "
                    "правами администратора, плановая проверка, слои проверки, контроль "
                    "запуска программ, запреты инструментов.\n\n"
                    "Меняйте их, только если понимаете, что делаете. Неверная настройка может "
                    "ослабить защиту компьютера или помешать работе программ. Если не уверены "
                    "— оставьте как есть: значения по умолчанию подобраны для обычной работы.")
            self.toggle_debug_mode()


    def toggle_debug_mode(self, quiet: bool = False):
        """Режим администратора (флаг debug_mode): разделы настроек, пароль, отчёт о работе
        в «О программе»; вкладка «Отладка» — только в тестовой версии."""
        from diag import edition
        self.debug_mode = not self.debug_mode
        self.shell.set_page_visible("Отладка", self.debug_mode and edition.is_test())
        self.settings_page.set_debug(self.debug_mode)
        self.about_page.set_admin(self.debug_mode)
        if self.debug_mode and not quiet:  # при запуске счётчики обновятся позже
            self.refresh_dashboard()
        title = f"{appinfo.APP_NAME} {appinfo.VERSION}"
        self.setWindowTitle(title + ("  [режим администратора]" if self.debug_mode else ""))
        if quiet:
            return
        extra = " Вкладка «Отладка» — в меню слева." if edition.is_test() else ""
        self.statusBar().showMessage(
            "Режим администратора включён." + extra
            if self.debug_mode else "Режим администратора выключен", 8000)

    # ---------- системный трей ----------
    def setup_tray(self, icon):
        self.tray = TrayIcon(self, icon)
        self.tray.apply_access(access.allowed)
        self.tray.set_exit_allowed(not cfg.get("general/block_exit"))
        self.tray.show()

    def show_main(self, page: str | None = None):
        if self.isMinimized():
            self.showNormal()
        else:
            self.show()
        self.raise_()
        self.activateWindow()
        if page:
            self.shell.show_page(page)

    def quit_app(self, force: bool = False):
        """force: выход без проверки запрета (перезапуск от администратора, конец сеанса)."""
        if not force and cfg.get("general/block_exit"):
            self._exit_blocked()
            return
        self._quitting = True
        self.close()

    def _exit_blocked(self):
        text = ("Закрытие программы запрещено в настройках, чтобы антивирус не выключили "
                "случайно. Программа продолжает работать в системном трее.")
        if self.tray is not None:
            self.tray.showMessage(appinfo.SHORT_NAME, text,
                                  QSystemTrayIcon.MessageIcon.Information, 4000)
        else:
            QMessageBox.information(self if self.isVisible() else None, appinfo.SHORT_NAME, text)

    def _on_session_end(self, *_):
        self._session_ending = True  # Windows завершает сеанс: выход разрешён всегда


    def _on_tray_message(self):
        if self._tray_target == "schedule":
            self._tray_target = ""
            self.show_main("Защита")  # там кнопки «Начать сейчас», «Отложить», «Пропустить»
            return
        if self._usb_pending:
            root, report = self._usb_pending
            self._usb_pending = None
            if access.allowed("btnUsb"):
                self.open_usb(root, report)
            else:
                self.show_log("Действия")

    # ---------- проверка ссылки, пароля, ловушки ----------
    TOOL_BUTTONS = {"link": "btnLinkCheck", "password": "btnPasswordLeak",
                    "drivers": "btnDrivers", "extensions": "btnExtensions", "vpn": "btnVpn"}


    def add_event(self, text: str, level: str = "info"):
        """Событие для списка «Последние события» на главной странице."""
        _dlog.log(40 if level in ("error", "threat") else 30 if level == "warning" else 20,
                  "Событие: %s", text)
        self.recent_events.insert(0, (time.strftime("%d.%m %H:%M"), text, level))
        del self.recent_events[8:]
        self.refresh_dashboard()

    def refresh_dashboard(self):
        protection_text = ""
        if self.monitor is not None:
            protection_text = self.protect_status.text()
        # базы обновляет служба (service/core.py), если она есть: окно без прав — не может
        db_updated = self._service_db_last_update if self.service is not None else \
            cfg.get("db/last_update")
        self.dashboard.refresh({
            "protection": self.monitor is not None,
            "network": self.net_monitor is not None,
            "quarantine": len(list_quarantine()),
            "whitelist": len(load_whitelist()),
            "last_scan": cfg.get("stats/last_scan"),
            "db_updated": db_updated,
            "db_updating": self._updating or self._service_db_progress is not None,
            "db_progress": (self._service_db_progress if self._service_db_progress is not None
                            else self._db_fraction),
            "protection_text": protection_text,
            "events": self.recent_events,
        })
        stats = self._database_stats() if self.debug_mode else None
        if stats is not None:  # подробные счётчики баз нужны только на вкладке отладки
            self.debug_page.refresh(stats["hashes"], stats["rules"], stats["rule_files"],
                                    stats["c2"], db_updated, stats["md5"])


    def on_setting_changed(self, key: str, value):
        activity.record("settings", f"{key} = {value}")
        if key == "general/on_top":
            self.apply_on_top(bool(value))
        elif key == "general/theme":
            apply_theme(QApplication.instance(), value)
        elif key == "scan/threshold":
            heuristics.set_threshold(int(value))
        elif key.startswith("lock/"):
            if key == "lock/protection" and self.service is not None:
                self.set_service_lock(bool(value))
            self.apply_access()
        elif key == "general/block_exit" and self.tray is not None:
            self.tray.set_exit_allowed(not value)
        elif key == "protect/decoys":
            self.apply_decoys()
        elif key in ("protect/launch", "protect/stealer"):
            self.apply_guards()
        elif key == "protect/amsi":
            self.set_amsi(bool(value))
        elif key == "protect/pslog":
            self.apply_guards()
        elif key == "protect/pslog_all":
            self.set_pslog_policy(bool(value))
        elif key.startswith("schedule/"):
            self.check_schedule()
        elif key in ("scan/mode", "scan/ecores_only", "scan/revocation"):
            scan_pool.apply_settings()

    def apply_on_top(self, on: bool):
        for window in (self, self.proc_window, self.autoruns_window, self.recovery_window,
                       *self.tool_windows.values(), getattr(self, "fp_window", None)):
            if window is not None:
                visible = window.isVisible()
                window.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, on)
                if visible:
                    window.show()  # смена флага скрывает окно, показываем заново

    # ---------- вкладка «Сеть» ----------
    NET_COLUMNS = [("Время", 70), ("Уровень", 100), ("Процесс", 130), ("PID", 60),
                   ("Адрес", 160), ("Правило", 80), ("Подробности", 420)]


    def _on_systool_failed(self, failure) -> None:
        """PowerShell или другая системная программа не выполнила работу (diag/systool):
        предупреждение без остановки работы; несколько сбоев — в одном окне."""
        from PySide6.QtWidgets import QDialog, QDialogButtonBox, QPlainTextEdit
        self.add_event(f"Сбой системной программы: {failure.tool_name}", "warning")
        self._show_status(f"{failure.tool_name}: {failure.title.lower()} — подробности в "
                          "журнале действий", 15000)
        dialog = self._systool_dialog
        if dialog is None or not dialog.isVisible():
            dialog = QDialog(self)
            dialog.setWindowTitle("Системная программа не сработала")
            dialog.resize(720, 420)
            box = QVBoxLayout(dialog)
            dialog.text = QPlainTextEdit()
            dialog.text.setReadOnly(True)
            box.addWidget(dialog.text, 1)
            buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
            journal_btn = buttons.addButton("Открыть журнал действий",
                                            QDialogButtonBox.ButtonRole.ActionRole)
            journal_btn.clicked.connect(lambda: (dialog.accept(), self.show_log("Действия")))
            buttons.accepted.connect(dialog.accept)
            box.addWidget(buttons)
            self._systool_dialog = dialog
        else:
            dialog.text.appendPlainText("\n" + "─" * 40 + "\n")
        dialog.text.appendPlainText(failure.short_text())
        dialog.show()
        dialog.raise_()


    # ---------- вкладка «Сканирование» ----------
    # ---------- вкладка «Карантин» ----------


    # ---------- закрытие окна ----------
    def _shutdown_all(self):
        if self._full_cancel is not None:
            self._full_cancel.set()
        verdict_cache.flush()
        scan_pool.shutdown()
        if self.recovery_window is not None:
            self.recovery_window.shutdown()
            self.recovery_window.close()
        self.scan_page.shutdown()
        if self.autoruns_window is not None:
            self.autoruns_window.shutdown()
            self.autoruns_window.close()
        if self.proc_window is not None:
            self.proc_window.shutdown()
            self.proc_window.close()
        if self.net_monitor is not None:
            self.net_monitor.stop()
        if self.monitor is not None and not getattr(self.monitor, "remote", False):
            self.monitor.stop()  # защита в службе работает и без окна
        if self._service_pump is not None:
            self._service_pump.stop()
        self.decoy_watcher.stop()
        for guard in (self.launch_guard, self.stealer_guard, self.amsi_server, self.pslog_watch):
            if guard is not None:
                guard.stop()
        vpn_window = self.tool_windows.get("vpn")
        if vpn_window is not None:
            vpn_window.shutdown()  # туннель не остаётся висеть после выхода

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        for url in event.mimeData().urls():
            if url.isLocalFile() and Path(url.toLocalFile()).exists():
                event.acceptProposedAction()
                self.open_analyzer(url.toLocalFile())  # файл или папка: страница сканирования
                break

    def showEvent(self, event):
        super().showEvent(event)
        if is_admin():
            allow_drops_from_lower_integrity(int(self.winId()))

    DEFAULT_SIZE = (1280, 860)
    MIN_SIZE = (1100, 720)  # меньше — карточки «Защиты» и «Инструментов» обрезают текст

    def _fit_to_screen(self):
        """Размер окна: прошлый, если он сохранён, иначе DEFAULT_SIZE; не больше экрана."""
        screen = QApplication.primaryScreen().availableGeometry()
        min_w = min(self.MIN_SIZE[0], screen.width())
        min_h = min(self.MIN_SIZE[1], screen.height() - 40)
        self.setMinimumSize(min_w, min_h)
        saved = self.settings.value("window/geometry")
        if saved is not None and self.restoreGeometry(saved):
            return
        self.resize(min(self.DEFAULT_SIZE[0], int(screen.width() * 0.9)),
                    min(self.DEFAULT_SIZE[1], int(screen.height() * 0.9)))

    def closeEvent(self, event):
        self.settings.setValue("window/geometry", self.saveGeometry())  # и при сворачивании в трей
        if (not self._quitting and not self._session_ending and cfg.get("general/block_exit")
                and self.tray is None):  # без трея окно просто сворачивается
            event.ignore()
            self.showMinimized()
            self._exit_blocked()
            return
        # закрытие окна всегда сворачивает в трей; выход — через меню значка
        to_tray = not self._quitting and self.tray is not None and not self._session_ending
        if to_tray:
            event.ignore()
            self.hide()
            if not self._tray_hint_shown:
                self._tray_hint_shown = True
                self.tray.showMessage(
                    appinfo.SHORT_NAME,
                    "Программа продолжает работать в системном трее. "
                    "Выход: правый клик по значку, «Выход».",
                    QSystemTrayIcon.MessageIcon.Information, 4000)
            return
        activity.record("program", "Программа завершена")
        from diag import crash
        crash.begin_exit()
        self._shutdown_all()
        crash.mark_clean_exit()
        import selfguard
        selfguard.stop()
        if self.tray is not None:
            self.tray.hide()  # иначе значок остаётся в трее до наведения мыши
        event.accept()
        QApplication.quit()


for _name, _fid in (("toggle_protection", "protect.realtime"), ("toggle_network", "net.monitor"),
                    ("restore_selected", "journal.quarantine"),
                    ("delete_selected", "journal.quarantine"),
                    ("remove_from_wl", "journal.whitelist"),
                    ("_quarantine_threats", "protect.threat_actions"),
                    ("on_setting_changed", "settings.change"),
                    ("open_resource_report", "debug.bench")):
    features.wrap_method(MainWindow, _name, _fid)


def elevate_on_start() -> bool:
    """Запуск пользователем без прав администратора: сразу окно UAC (без вопросов).
    True — новый процесс с правами запущен, этот нужно закрыть; False — UAC отклонён,
    программа работает без прав (часть защиты — в упрощённом режиме)."""
    if is_admin():
        return False
    return relaunch_as_admin()


def _argument(name: str) -> str | None:
    """Значение параметра командной строки вида: --name <значение>."""
    if name in sys.argv:
        index = sys.argv.index(name) + 1
        if index < len(sys.argv):
            return sys.argv[index]
    return None


if __name__ == "__main__":
    app = QApplication(sys.argv)
    from diag import crash, edition, resources, uiaudit
    crash.install_qt_messages()
    _freeze_watch = crash.FreezeWatch()
    uiaudit.install(app)
    features.install_dialog_hook()
    install_message_box_limits()  # длинные команды и пути не растягивают окна сообщений
    apply_theme(app, cfg.get("general/theme"))
    heuristics.set_threshold(cfg.get("scan/threshold"))
    scan_pool.apply_settings()  # режим проверки и «Только E-ядра»

    # окно со службой работает без прав: инструменты, меняющие систему, и отмена с правами —
    # отдельным процессом через окно UAC (service/elevate.py)
    if "--tool" in sys.argv or "--undo" in sys.argv:
        from service import elevate as _elevate
        app.setWindowIcon(load_app_icon())
        sys.exit(_elevate.run_tool(sys.argv) if "--tool" in sys.argv
                 else _elevate.run_undo(sys.argv))

    icon = load_app_icon()
    app.setWindowIcon(icon)
    tray_ok = QSystemTrayIcon.isSystemTrayAvailable()
    app.setQuitOnLastWindowClosed(not tray_ok)  # с треем программа живёт и после закрытия окна

    if "--uninstall" in sys.argv:  # удаление программы (uninstall.py): нужны права
        # из Inno Setup (--silent) права уже запрошены: перезапуск отдал бы управление
        # деинсталлятору раньше, чем шаги закончатся
        if not is_admin() and "--silent" not in sys.argv and relaunch_as_admin():
            sys.exit(0)
        import uninstall
        if "--silent" in sys.argv:  # деинсталлятор Inno Setup (installer.iss)
            sys.exit(uninstall.run_silent("--wipe" in sys.argv))
        sys.exit(0 if uninstall.run() else 1)

    autostart = "--autostart" in sys.argv
    analyze_path = _argument("--analyze")  # файл из меню Проводника
    # у релизной и тестовой — свои имена: иначе окно второй версии считало канал «занятым
    # чужой программой»
    guard = SingleInstance("StretchBIT-test" if edition.is_test() else "StretchBIT")
    wait = 10.0 if "--relaunched" in sys.argv else 0.0  # ждём закрытия прежнего экземпляра
    message = (b"open\n" + analyze_path.encode("utf-8")) if analyze_path else b"show"
    # уже запущена: передаём ей файл или просьбу показать окно и выходим
    if guard.already_running(notify=not autostart, wait=wait, message=message):
        sys.exit(0)

    # ручной запуск — сразу с запросом UAC, и при работающей службе: без прав инструменты
    # (диспетчер процессов, память, флешки, расширения, точки восстановления...) только
    # показывают (Windows 10, 14.11.2026). Без окна UAC: автозапуск (задание планировщика),
    # меню Проводника и окно, которое служба открыла по тревоге (--alarm): там важнее
    # показать тревогу сразу. Отказ в UAC — работа без прав, защита — в службе
    if not autostart and not analyze_path and "--alarm" not in sys.argv and elevate_on_start():
        sys.exit(0)
    # служба Windows установлена и отвечает: защита файлов, карантин и журнал защиты — в ней
    # (service/DESIGN.md)
    from service import client as _svc_client
    from service import editions as _editions
    if is_admin():
        # служба этой версии стоит в ручном запуске, а другой версии уже нет (удалили) —
        # вернуть свою, иначе окно запустило бы защиты у себя (service/editions.py)
        _editions.revive_own()
    service_client = _svc_client.connect()
    if service_client is not None:
        from service import remote as _svc_remote
        _svc_remote.install(service_client)  # до окна: оно сразу читает карантин и журнал
        _dlog.info("Служба защиты: подключено, окно без прав администратора: %s",
                   not is_admin())
    # своя служба не отвечает, а служба другой версии работает: две версии сразу мешают друг
    # другу (общие сеансы ETW, kill switch...) — окно пассивное (service/editions.py)
    passive = service_client is None and _editions.passive()
    if passive:
        _dlog.info("Защиту ведёт %s — окно без своих защит, сети и VPN",
                   _editions.other_title())
        if autostart:  # при входе в Windows запускается окно основной версии
            sys.exit(0)

    def _ensure_registration():
        # schtasks — до секунды на вызов (а с проверкой прежнего задания их три): в фоне
        if is_admin():
            cfg.ensure_autostart()  # задание планировщика (создаётся только с правами)
        cfg.ensure_explorer_menu()  # пункт «Проверить в ...» в меню файлов — всегда

    if not passive:  # задание и меню Проводника общие у версий — их ведёт основная
        threading.Thread(target=_ensure_registration, name="startup-registration",
                         daemon=True).start()
    if not guard.listen() and guard.squatted is None:  # другой экземпляр успел занять имя
        sys.exit(0)
    crash.start_session()  # метка сеанса: аварийный выход заметен при следующем запуске
    links = userdata.remove_links() if is_admin() else []  # см. userdata.remove_links
    import selfguard
    if cfg.get("protect/selfguard") and not passive:
        selfguard.start()  # сторож вернёт программу, если её снимут или она упадёт
        _guard_timer = QTimer()
        _guard_timer.timeout.connect(selfguard.start)  # сняли сторожа — запустить снова
        _guard_timer.start(30000)
    features.begin("app.start")

    window = MainWindow()
    window.guard = guard
    if passive:
        window.passive_other = _editions.other_title()
    if service_client is not None:
        window.attach_service(service_client)
    guard.activated.connect(lambda: window.show_main())
    guard.file_received.connect(lambda path: window.open_analyzer(path))
    if tray_ok:
        window.setup_tray(icon)
    window.apply_on_top(cfg.get("general/on_top"))
    if links:
        text = ("В папке настроек были ссылки на другие папки — убраны (так программу с "
                "правами можно заставить писать в чужие места): " + ", ".join(links[:5]))
        activity.record("trust", text)
        window.add_event(text, "warning")
    if guard.squatted is not None:
        pid, exe = guard.squatted
        text = (f"Имя канала программы заняла другая программа: {exe} (PID {pid}). Так можно "
                "помешать запуску защиты — проверьте эту программу.")
        activity.record("program", text)
        window.add_event(text, "warning")
    if "--restarted" in sys.argv:
        activity.record("program", "Программа была завершена не штатно и перезапущена сторожем")
        window.add_event("Программа была завершена не штатно — защита перезапущена", "warning")

    quiet_start = (autostart or bool(analyze_path)) and tray_ok
    if not quiet_start:
        window.show()
    if analyze_path:
        window.open_analyzer(analyze_path)
    if passive:
        window.show_passive()
    else:
        window.start_protection_on_launch()
        window.start_usb_watch()
        window.start_schedule()
        window.start_vpn_on_launch()
    window.start_activity_report()
    window.start_auto_update()
    if edition.is_test():
        from diag import testpanel
        testpanel.bridge()
        _attacher = testpanel.WindowAttacher(app)
        window.install_test_ui()
    features.end("app.start", True, окно="скрыто" if quiet_start else "показано")
    diag_log.session_details()
    resources.start()
    sys.exit(app.exec())
