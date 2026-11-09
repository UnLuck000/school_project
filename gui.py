import os
import sys
import threading
import time
from pathlib import Path
import json

# собранная программа: рабочая папка — app рядом с StretchBIT.exe (sys._MEIPASS), там же лежат
# модули, поэтому пути от __file__ (signatures, journal, cache) и относительные пути совпадают
os.chdir(Path(sys._MEIPASS) if getattr(sys, "frozen", False)
         else Path(__file__).resolve().parent)

if "--scan-worker" in sys.argv:  # собранная программа: рабочий процесс проверки (scanner.pool)
    from scanner.worker import main as _worker_main
    _worker_main()
    sys.exit(0)

if sys.stdout is None or sys.stderr is None:  # pythonw или exe без консоли
    Path("logs").mkdir(exist_ok=True)
    _log = open(Path("logs") / "gui.log", "a", encoding="utf-8", buffering=1)
    sys.stdout = sys.stdout or _log
    sys.stderr = sys.stderr or _log

from diag import log as diag_log  # технический журнал logs/app.log (diag/log.py)
diag_log.setup()
_dlog = diag_log.get("app")
from diag import features  # noqa: E402 — исправность функций (эталон «Исправно»)

from PySide6.QtCore import Qt, Signal, QObject, QSettings, QTimer, QUrl
from PySide6.QtGui import QBrush, QColor, QDesktopServices
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QHBoxLayout, QMainWindow, QMessageBox, QPushButton,
    QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget, QCheckBox, QLabel, QListWidgetItem,
    QMenu, QSystemTrayIcon, QScrollArea, QFrame,
)

from scanner import heuristics, pool as scan_pool, verdict_cache
from scanner.whitelist import load_whitelist, remove_from_whitelist
from scanner.hashing import load_all_signatures
from scanner.yara_engine import count_rules
import updater
from quarantine import QUARANTINE_DIR, list_quarantine
from recovery import threatlog
from monitor import RealtimeMonitor, system_folders
from networkmonitor.connections import LEVEL_TEXT, terminate_process
from networkmonitor.ioc import load_ip_blocklist
from networkmonitor.netmon import NetworkMonitor

from processmanager.window import ProcessWindow
from processmanager.system import is_admin, relaunch_as_admin, allow_drops_from_lower_integrity

from ui import settings as cfg
from ui.pages import AboutPage, DashboardPage, SettingsPage, ToolsPage, DebugPage, \
    run_feature as run_tool
from ui.shell import Shell
from ui.textutil import install_message_box_limits
from ui.theme import apply_theme
from ui.registry import FEATURES, HANDLERS
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
from ui.widgets import make_table


SIGNATURES = Path("signatures/hashes.txt")
RULES_DIR = Path("signatures/rules")
NETFEEDS_DIR = Path("signatures/netfeeds")
ID_ROLE = Qt.ItemDataRole.UserRole
DEFAULT_WATCH = [str(Path.home() / "Downloads")]


class NetBridge(QObject):
    event = Signal(str, object)


class MonitorBridge(QObject):
    """Передаёт события из потока монитора в главный поток."""
    event = Signal(str, str)


SCAN_PAGE = "Сканирование папки/файла"
LOG_PAGE = "Журнал"  # журнал защиты, действия, исключения


class MainWindow(QMainWindow):
    update_finished = Signal(str, bool, bool)  # вывод, успех, тихое (автообновление)
    update_progress = Signal(str)
    usb_checked = Signal(object, object)    # DriveReport автопроверки флешки, итог лечения
    decoy_alarm = Signal(object, object)    # изменённые ловушки, виновник
    full_progress = Signal(object)          # fullscan.Stats во время полной проверки
    full_found = Signal(str, str, str)      # путь, уровень, текст
    full_done = Signal(object, bool)        # итог, остановлена ли вручную
    launch_event = Signal(str, object)      # контроль запуска: вид, сведения
    stealer_event = Signal(object)          # защита от стилеров: сведения о доступе
    guard_status = Signal(str, str)         # launch | stealer, текст состояния

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{appinfo.APP_NAME} {appinfo.VERSION}")
        self.settings = QSettings("StudyAV", "myav")
        self._fit_to_screen()
        self.monitor: RealtimeMonitor | None = None
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
        self.launch_guard = None   # scanner.launchguard.LaunchGuard, пока включена защита
        self.stealer_guard = None  # toolbox.stealerguard.StealerGuard
        self.launch_event.connect(self._on_launch_event)
        self.stealer_event.connect(self._on_stealer_event)
        self.guard_status.connect(self._on_guard_status)
        self._tray_target = ""     # что открыть по щелчку на уведомлении: usb | schedule
        from ui.notify import Notifier
        self.notifier = Notifier(self)  # уведомления Windows с кнопками
        self._schedule_due = 0.0   # когда начнётся объявленная плановая проверка
        self.recent_events: list[tuple[str, str, str]] = []  # для главной: время, текст, уровень
        self._db_stats: dict | None = None  # счётчики баз, пересчитываются после обновления
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

    def _refresh_log_tab(self):
        widget = self.log_tabs.currentWidget()
        if widget is self.protect_journal:
            self.protect_journal.refresh()
        elif widget is self.journal_page:
            self.journal_page.refresh()
        elif widget is self.exclusions_page:
            self.exclusions_page.refresh()

    def show_log(self, tab: str = "Действия"):
        """Открывает страницу «Журнал» на нужной вкладке."""
        if tab == "Действия" and not access.allowed("btnUndoJournal"):
            tab = "Журнал защиты"  # журнал действий запрещён: остальные вкладки доступны
        self.show_main(LOG_PAGE)
        for i in range(self.log_tabs.count()):
            if self.log_tabs.tabText(i) == tab:
                self.log_tabs.setCurrentIndex(i)
        self._refresh_log_tab()

    def _on_protect_journal_changed(self):
        self.journal_page.refresh()
        self.refresh_whitelist()
        self.refresh_dashboard()

    def goto_action_place(self, place: str, record: dict):
        """«Перейти к месту действия» из журнала действий (recovery/journal_page.PLACES)."""
        data = record.get("data") or {}
        if place == "net_block":
            self.show_main("Сеть")
            self.net_tabs.setCurrentWidget(self.block_panel)
        elif place == "protect_journal":
            self.show_log("Журнал защиты")
        elif place == "autoruns":
            self.open_autoruns()
        elif place == "system_checks":
            self.open_recovery(2)
        elif place == "assoc":
            self.open_recovery(3)
        elif place == "false_positives":
            self.open_false_positives(data.get("path") or None)
        elif place in ("vpn_settings", "vpn_connect"):
            self.open_tool("vpn")
            window = self.tool_windows.get("vpn")
            if window is not None and hasattr(window, "show_section"):
                window.show_section("settings" if place == "vpn_settings" else "connect")
        elif place in ("drivers", "extensions"):
            self.open_tool(place)
        elif place == "usb":
            self.open_usb()
        elif place == "protection":
            self.show_main("Защита")
        elif place == "file":
            path = data.get("from") or data.get("to") or ""
            if path:
                self.open_analyzer(os.path.dirname(path))

    def on_undone(self, record: dict):
        """Действие отменено на странице журнала: обновляем окна, где оно было видно."""
        if self.autoruns_window is not None:
            self.autoruns_window.handle_undo(record)
        self.refresh_quarantine()
        self.refresh_dashboard()

    # ---------- центр восстановления ----------

    TAB_TOOLS = {0: "btnRestorePoint", 1: "btnSfcDism", 2: "btnSystemChecks"}

    def tool_blocked(self, button_id: str) -> bool:
        """Инструмент запрещён: сообщение вместо открытия (на случай ссылок из других окон)."""
        if access.allowed(button_id):
            return False
        QMessageBox.information(self if self.isVisible() else None,
                                FEATURES[button_id].title, access.LOCKED_TIP)
        return True

    def _apply_recovery_access(self):
        self.recovery_window.set_allowed(access.allowed("btnRestorePoint"),
                                         access.allowed("btnSfcDism"),
                                         access.allowed("btnSystemChecks"))

    def open_recovery_center(self):
        """Центр восстановления из трея: первая разрешённая вкладка, без действий."""
        for tab, button_id in self.TAB_TOOLS.items():
            if access.allowed(button_id):
                self.open_recovery(tab)
                return

    def open_recovery(self, tab: int = 0, action: str | None = None):
        if tab in self.TAB_TOOLS and self.tool_blocked(self.TAB_TOOLS[tab]):
            return
        if self.recovery_window is None:
            self.recovery_window = RecoveryWindow()
            self.recovery_window.restart_requested.connect(self.restart_as_admin)
            self._apply_recovery_access()
            self.apply_on_top(cfg.get("general/on_top"))
        self.recovery_window.show()
        self.recovery_window.raise_()
        self.recovery_window.activateWindow()
        self.recovery_window.show_tab(tab)
        if action == "create":
            self.recovery_window.create_restore_point()  # сначала запрос подтверждения
        elif action == "check":
            self.recovery_window.run_system_check()

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

    def open_analyzer(self, path: str | None = None):
        if self.tool_blocked("btnFileAnalyzer"):
            return
        """Файл или папка открываются на странице «Сканирование папки/файла»."""
        self.show_main(SCAN_PAGE)
        if path:
            self.scan_page.scan(path)

    def _show_status(self, text: str, timeout: int):
        if text:
            self.statusBar().showMessage(text, timeout)
        else:
            self.statusBar().clearMessage()

    def _on_folder_scanned(self):
        cfg.set_("stats/last_scan", time.strftime("%Y-%m-%d %H:%M"))
        self.refresh_dashboard()

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

    def apply_access(self):
        """Изменились запреты из дополнительных настроек (ui/access.py)."""
        self._apply_tool_access()
        # запрет выключения: то, что сейчас выключено, включается
        if access.protection_locked() and self.monitor is None:
            self.toggle_protection()
        if access.network_locked() and self.net_monitor is None:
            self.toggle_network()
        self._apply_off_locks()

    def _apply_tool_access(self):
        """Запреты инструментов: кнопки, страницы, пункты трея и вкладки (и при запуске)."""
        self.tools_page.apply_access()
        if self.proc_window is not None:
            self.proc_window.set_memory_allowed(access.allowed("btnMemoryDeep"))
        if self.recovery_window is not None:
            self._apply_recovery_access()
        if self.tray is not None:
            self.tray.apply_access(access.allowed)
        # пути к запрещённым инструментам скрываются, открытые окна закрываются
        scan_ok = access.allowed("btnFileAnalyzer")
        self.shell.set_page_visible(SCAN_PAGE, scan_ok)
        for name, button_id in (("btnScanPath", "btnFileAnalyzer"),
                                ("btnOpenProcesses", "btnProcessManager"),
                                ("btnOpenJournal", "btnUndoJournal")):
            self.dashboard.set_button_visible(name, access.allowed(button_id))
        self.log_tabs.setTabVisible(self.log_tabs.indexOf(self.journal_page),
                                    access.allowed("btnUndoJournal"))
        for window, button_id in ((self.usb_window, "btnUsb"),
                                  (self.autoruns_window, "btnAutoruns"),
                                  (self.proc_window, "btnProcessManager"),
                                  *((self.tool_windows.get(n), b)
                                    for n, b in self.TOOL_BUTTONS.items())):
            if window is not None and not access.allowed(button_id):
                window.hide()

    def _apply_off_locks(self):
        """Кнопки выключения защиты и сети неактивны, если выключать запрещено."""
        for buttons, running, locked in (
                ((self.protect_btn, self.dashboard.btn_protection), self.monitor is not None,
                 access.protection_locked()),
                ((self.net_btn,), self.net_monitor is not None, access.network_locked())):
            blocked = running and locked
            for button in buttons:
                button.setEnabled(not blocked)
                button.setToolTip(access.OFF_LOCKED_TIP if blocked else "")

    def _off_blocked(self, what: str) -> None:
        QMessageBox.information(self if self.isVisible() else None, appinfo.SHORT_NAME,
                                f"Выключать {what} запрещено в дополнительных настройках.")

    def show_beacons(self):
        self.show_main("Сеть")
        self.net_tabs.setCurrentWidget(self.beacon_panel)

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

    # ---------- USB-накопители ----------
    def open_usb(self, root: str | None = None, report=None):
        if self.tool_blocked("btnUsb"):
            return
        from usbguard.window import UsbWindow
        if self.usb_window is None:
            self.usb_window = UsbWindow()
            self.usb_window.journal_changed.connect(self.journal_page.refresh)
            self.usb_window.quarantine_changed.connect(self.refresh_quarantine)
            self.usb_window.quarantine_changed.connect(self.refresh_dashboard)
            self.apply_on_top(cfg.get("general/on_top"))
        self.usb_window.show()
        self.usb_window.raise_()
        self.usb_window.activateWindow()
        if root:
            self.usb_window.show_drive(root, report)

    def start_usb_watch(self):
        """Раз в 2 секунды: появилась ли новая флешка. Проверка — в фоне."""
        self._usb_timer = QTimer(self)
        self._usb_timer.timeout.connect(self._poll_usb)
        self._usb_timer.start(2000)
        if self.tray is not None:
            self.tray.messageClicked.connect(self._on_tray_message)
        self._poll_usb()  # флешки, вставленные до запуска, тоже проверяются

    def _poll_usb(self):
        from usbguard.scan import removable_drives
        drives = dict(removable_drives())
        new = set(drives) - self._usb_known
        self._usb_known = set(drives)
        if new and self.usb_window is not None and self.usb_window.isVisible():
            self.usb_window.refresh_drives()
        if self.monitor is None:  # защита флешек — часть защиты файлов
            return
        for root in sorted(new):
            threading.Thread(target=self._usb_job, args=(root, drives[root]),
                             daemon=True).start()

    def _usb_job(self, root: str, label: str):
        """Проверка флешки; вирус-ярлык лечится сразу (с откатом через журнал)."""
        from usbguard import repair
        from usbguard.window import auto_fixes, check_drive
        report = check_drive(root, label)
        cure = None
        fixes = auto_fixes(report)
        if fixes:
            done, errors = repair.apply(fixes, "Защита флешек: вирус-ярлык")
            cure = (done, errors, [f"{f.path}: {f.title}" for f in fixes])
        self.usb_checked.emit(report, cure)

    def _on_usb_checked(self, report, cure):
        from usbguard.window import summary
        problems = report.problems
        activity.record("usb", "Защита флешек: " + summary(report),
                        found=[f"{f.path}: {f.title}" for f in problems],
                        **({"cured": cure[2], "errors": cure[1]} if cure else {}))
        if not problems:
            self.statusBar().showMessage(summary(report), 8000)
            return
        if cure:
            done, errors, _ = cure
            text = (f"Флешка {report.root[:2]}: вирус-ярлык обезврежен — исправлено {done}"
                    + (f", не удалось {len(errors)}" if errors else "")
                    + ". Файлы возвращены на место. Отменить можно в «Журнале действий».")
            self.journal_page.refresh()
            self.refresh_quarantine()
            self.refresh_dashboard()
        else:
            text = summary(report) + ". Нажмите, чтобы посмотреть."
        self.add_event(text, "threat" if report.infected else "info")
        self._usb_pending = (report.root, report)
        if self.tray is not None:
            self.tray.showMessage(appinfo.SHORT_NAME, text,
                                  QSystemTrayIcon.MessageIcon.Warning, 10000)

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

    def open_tool(self, name: str):
        if self.tool_blocked(self.TOOL_BUTTONS[name]):
            return
        from toolbox import windows
        window = self.tool_windows.get(name)
        if window is None:
            # окна без владельца: не держатся поверх главного окна, его можно вывести вперёд
            if name == "link":
                window = windows.LinkCheckWindow()
                window.open_file.connect(self.open_analyzer)
            elif name == "password":
                window = windows.PasswordLeakWindow()
            elif name == "drivers":
                from toolbox.driverswindow import DriversWindow
                window = DriversWindow()
                window.journal_changed.connect(self.journal_page.refresh)
                window.exclusions_changed.connect(self.exclusions_page.refresh)
            elif name == "extensions":
                from toolbox.extwindow import ExtensionsWindow
                window = ExtensionsWindow()
                window.window_ref = self  # открыть папку в сканере
                window.journal_changed.connect(self.journal_page.refresh)
            else:
                from vpn.window import VpnWindow
                window = VpnWindow()
            self.tool_windows[name] = window
            self.apply_on_top(cfg.get("general/on_top"))
        window.show()
        window.raise_()
        window.activateWindow()

    def apply_decoys(self):
        """Ловушки работают вместе с защитой файлов (настройка protect/decoys)."""
        from toolbox import decoys
        self.decoy_watcher.stop()
        if not cfg.get("protect/decoys"):
            decoys.remove_all()
        elif self.monitor is not None:
            try:
                decoys.ensure()
            except OSError as e:
                self.statusBar().showMessage(f"Ловушки для шифровальщиков не созданы: {e}", 8000)
            self.decoy_watcher.start()
        self._refresh_decoys_info()

    def _refresh_decoys_info(self):
        from toolbox import decoys
        manifest = decoys.load_manifest()
        tip = ""
        if not cfg.get("protect/decoys"):
            text = "Выключены в дополнительных настройках."
        elif not manifest:
            text = "Появятся, когда включится защита."
        else:
            state = "следят за изменениями" if self.decoy_watcher.running else \
                "ждут включения защиты"
            text = f"{len(manifest)} файлов-приманок, {state}. Папки скрыты в Проводнике."
            tip = "\n".join(str(d) for d in decoys.decoy_dirs(manifest))
        self.decoys_label.setText(text)
        self.decoys_label.setToolTip(tip)
        self.decoys_btn.setToolTip(tip)
        self.decoys_btn.setEnabled(bool(manifest))
        if hasattr(self, "protection_page"):
            self.protection_page.refit()

    def _open_decoys(self):
        from toolbox import decoys
        dirs = decoys.decoy_dirs()
        if dirs:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(dirs[0])))

    def _on_decoy_alarm(self, changed, culprit):
        from toolbox.windows import decoy_alarm
        name = culprit["name"] if culprit else "неизвестная программа"
        self.add_event(f"Ловушка для шифровальщиков: {name}", "threat")
        self.show_main()
        decoy_alarm(self, changed, culprit, self.decoy_watcher)
        self.refresh_quarantine()
        self.journal_page.refresh()

    def start_activity_report(self):
        """Отчёт о работе: отсчёт периодов от первого запуска, проверка раз в час."""
        if not cfg.get("report/first_run"):
            cfg.set_("report/first_run", time.time())
        activity.record("program", f"Программа запущена ({appinfo.VERSION})")
        activity.trim()
        self.check_activity_report()
        self._report_timer = QTimer(self)
        self._report_timer.timeout.connect(self.check_activity_report)
        self._report_timer.start(3600 * 1000)

    def check_activity_report(self):
        first, last = cfg.get("report/first_run"), cfg.get("report/last_end")
        try:
            end = activity.prepare_outbox(first, last)
        except OSError:
            return
        if end != last:
            cfg.set_("report/last_end", end)
        self.debug_page.set_activity_state(first, end)

    def start_protection_on_launch(self):
        """Защита файлов и мониторинг сети включаются сразу при старте программы."""
        if self.monitor is None:
            self.toggle_protection()
        if self.net_monitor is None:
            self.toggle_network()

    def run_feature(self, button_id: str):
        """Запуск функции с кнопки «Инструменты» (из трея или со страницы)."""
        run_tool(self if self.isVisible() else None, self, FEATURES[button_id],
                 HANDLERS.get(button_id))

    def open_autoruns(self, journal: bool = False):
        if journal:  # журнал теперь отдельная страница главного меню
            if not self.tool_blocked("btnUndoJournal"):
                self.show_log()
            return
        if self.tool_blocked("btnAutoruns"):
            return
        if self.autoruns_window is None:
            self.autoruns_window = AutorunsWindow()
            self.autoruns_window.analyze_requested.connect(lambda path: self.open_analyzer(path))
            self.autoruns_window.quarantine_changed.connect(self.refresh_quarantine)
            self.autoruns_window.quarantine_changed.connect(self.refresh_dashboard)
            self.autoruns_window.journal_changed.connect(self.journal_page.refresh)
            self.autoruns_window.exclusions_changed.connect(self.exclusions_page.refresh)
            self.apply_on_top(cfg.get("general/on_top"))
        self.autoruns_window.show()
        self.autoruns_window.raise_()
        self.autoruns_window.activateWindow()
        if journal:
            self.autoruns_window.show_journal()

    def open_process_manager(self):
        if self.tool_blocked("btnProcessManager"):
            return
        if self.proc_window is None:
            self.proc_window = ProcessWindow()
            self.proc_window.analyze_requested.connect(lambda path: self.open_analyzer(path))
            self.proc_window.restart_requested.connect(self.restart_as_admin)
            self.proc_window.set_memory_allowed(access.allowed("btnMemoryDeep"))
            self.apply_on_top(cfg.get("general/on_top"))
        self.proc_window.show()
        self.proc_window.raise_()
        self.proc_window.activateWindow()

    # ---------- отладка: отчёт о ресурсах и ложные срабатывания ----------
    def open_resource_report(self):
        from bench.reportwindow import ResourceReportWindow
        if getattr(self, "report_window", None) is None:
            self.report_window = ResourceReportWindow(self._bench_prepare, self._bench_restore)
        self.report_window.show()
        self.report_window.raise_()
        self.report_window.activateWindow()

    def _bench_prepare(self) -> tuple[bool, bool]:
        """На время замера включаются защита файлов и мониторинг сети."""
        state = (self.monitor is not None, self.net_monitor is not None)
        if self.monitor is None:
            self.toggle_protection()
        if self.net_monitor is None:
            self.toggle_network()
        return state

    def _bench_restore(self, state):
        if not state:
            return
        protection, network = state
        if not protection and self.monitor is not None:
            self.toggle_protection(force=True)
        if not network and self.net_monitor is not None:
            self.toggle_network(force=True)

    def open_false_positives(self, path: str | None = None):
        """Окно «Ложные срабатывания» — только в тестовой версии: в релизной не открывается
        ни из меню, ни из «Перейти к месту действия» журнала."""
        from diag import edition
        if not edition.is_test():
            return
        from analyzer.fpwindow import FalsePositiveWindow
        if getattr(self, "fp_window", None) is None:
            self.fp_window = FalsePositiveWindow()
            self.fp_window.journal_changed.connect(lambda: self.journal_page.refresh())
        self.fp_window.show()
        self.fp_window.raise_()
        self.fp_window.activateWindow()
        if path:
            self.fp_window.start(path, False)

    # ---------- главная страница и настройки ----------
    def _database_stats(self) -> dict:
        """Счётчики баз. Считать их недёшево (тысячи файлов правил), поэтому кэш."""
        if self._db_stats is None:
            db = load_all_signatures(SIGNATURES.parent)
            rule_files, rules = count_rules(RULES_DIR)
            md5 = sum(p.stat().st_size // 16 for p in (SIGNATURES.parent / "feeds").glob("*.md5.bin"))
            self._db_stats = {"hashes": len(db), "md5": md5, "rules": rules,
                              "rule_files": rule_files,
                              "c2": len(load_ip_blocklist(NETFEEDS_DIR))}
        return self._db_stats

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
        self.dashboard.refresh({
            "protection": self.monitor is not None,
            "network": self.net_monitor is not None,
            "quarantine": len(list_quarantine()),
            "whitelist": len(load_whitelist()),
            "last_scan": cfg.get("stats/last_scan"),
            "db_updated": cfg.get("db/last_update"),
            "db_updating": self._updating,
            "protection_text": protection_text,
            "events": self.recent_events,
        })
        if self.debug_mode:  # подробные счётчики баз нужны только на вкладке отладки
            stats = self._database_stats()
            self.debug_page.refresh(stats["hashes"], stats["rules"], stats["rule_files"],
                                    stats["c2"], cfg.get("db/last_update"), stats["md5"])

    def check_updates(self):
        QDesktopServices.openUrl(QUrl(appinfo.RELEASES_URL))

    def quick_scan(self):
        """Кнопка главной: быстрая проверка (Windows, Users и программы на дисках)."""
        features.begin("home.quick_scan")
        self.shell.show_page("Защита")
        if self._full_cancel is None:
            self.toggle_full_scan("quick", all_drives=True)

    def start_auto_update(self):
        """Автообновление баз: при запуске и затем каждые полчаса проверяется, прошли ли
        сутки с последнего обновления (см. updater.update_due)."""
        self.auto_update_timer.start()
        QTimer.singleShot(5000, self.auto_update_check)  # окно успевает открыться

    def auto_update_check(self):
        if not self._updating and updater.update_due(cfg.get("db/last_update")):
            self.update_databases(silent=True)

    def update_databases(self, silent: bool = True):
        """Обновление баз. Вручную его не запускают: только автообновление (silent),
        без сообщения об успехе. silent=False оставлен для отладки из консоли."""
        if self._updating:
            return
        self._updating = True
        features.begin("db.update")
        self._update_silent = silent
        if not silent:
            self.statusBar().showMessage("Обновляю базы (хэши, правила YARA, адреса C2)...")
        self.refresh_dashboard()
        threading.Thread(target=self._update_job, args=(silent,), daemon=True).start()

    def _update_job(self, silent: bool):
        import contextlib
        import io

        buffer = io.StringIO()
        ok = False
        try:
            with contextlib.redirect_stdout(buffer):
                ok = updater.update_all(progress=self.update_progress.emit)
        except Exception as e:
            buffer.write(f"Ошибка: {e}\n")
        self.update_finished.emit(buffer.getvalue(), ok, silent)

    def _on_update_progress(self, text: str):
        if not self._update_silent:
            self.statusBar().showMessage(text)

    def _on_update_finished(self, text: str, ok: bool, silent: bool):
        from analyzer.folderview import reset_bases
        from processmanager.memscan import reset_cache

        self._updating = False
        if ok:
            cfg.set_("db/last_update", time.time())
        reset_cache()  # правила для памяти и файлов перекомпилируются при следующей проверке
        reset_bases()
        scan_pool.reset()  # рабочие процессы проверки перезапустятся с новыми правилами
        for monitor in (self.monitor, self.net_monitor):
            if monitor is not None:
                monitor.reload_bases()
        self._db_stats = None
        self.refresh_dashboard()
        activity.record("update", "Базы обновлены" if ok else "Обновление баз не удалось")
        features.end_if_active("db.update", ok, error="" if ok else text[-300:])
        if ok:
            self.add_event("Базы сигнатур обновлены")
        if silent:  # автообновление: сообщение об успехе не показывается
            if not ok:
                self.statusBar().showMessage(
                    "Не удалось обновить базы: нет сети. Повторю позже", 8000)
            return
        self.statusBar().showMessage("Обновление баз завершено", 8000)
        QMessageBox.information(self, "Обновление баз", text.strip() or "Готово")

    def on_setting_changed(self, key: str, value):
        activity.record("settings", f"{key} = {value}")
        if key == "general/on_top":
            self.apply_on_top(bool(value))
        elif key == "general/theme":
            apply_theme(QApplication.instance(), value)
        elif key == "scan/threshold":
            heuristics.set_threshold(int(value))
        elif key.startswith("lock/"):
            self.apply_access()
        elif key == "general/block_exit" and self.tray is not None:
            self.tray.set_exit_allowed(not value)
        elif key == "protect/decoys":
            self.apply_decoys()
        elif key in ("protect/launch", "protect/stealer"):
            self.apply_guards()
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

    def _build_network_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        row = QHBoxLayout()
        self.net_btn = QPushButton("Включить мониторинг сети")
        self.net_btn.clicked.connect(self.toggle_network)
        kill_btn = QPushButton("Завершить процесс")
        kill_btn.clicked.connect(self.kill_selected_process)
        clear_btn = QPushButton("Очистить")
        clear_btn.clicked.connect(self.clear_net_alerts)
        for w in (self.net_btn, kill_btn, clear_btn):
            row.addWidget(w)
        row.addStretch()
        layout.addLayout(row)

        self.net_status = QLabel("Мониторинг сети выключен")
        layout.addWidget(self.net_status)
        self.net_substatus = QLabel("")  # состояние DNS (ETW) и TLS (WinDivert)
        self.net_substatus.setWordWrap(True)
        self._net_sub: dict[str, str] = {}
        layout.addWidget(self.net_substatus)

        self.net_table = make_table(self.NET_COLUMNS)
        self.net_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.net_table.customContextMenuRequested.connect(self._net_alert_menu)

        from networkmonitor.panels import BeaconPanel, BlockPanel, DnsPanel, TlsPanel, NetBridgeSignals
        self.net_tabs = QTabWidget()
        self.net_tabs.addTab(self.net_table, "Оповещения")
        self.dns_panel = DnsPanel(lambda domain: self.net_monitor.addresses_of(domain)
                                  if self.net_monitor else [])
        self.tls_panel = TlsPanel()
        self.tls_panel.choose_dir.connect(self._set_windivert_dir)
        self.beacon_panel = BeaconPanel()
        self.block_panel = BlockPanel()
        for panel in (self.dns_panel, self.tls_panel):
            panel.blocked.connect(self.block_panel.refresh)
        self.net_tabs.addTab(self.dns_panel, "DNS-запросы")
        self.net_tabs.addTab(self.tls_panel, "TLS (SNI, JA3)")
        self.net_tabs.addTab(self.beacon_panel, "Маячки")
        self.net_tabs.addTab(self.block_panel, "Блокировки")
        self.net_tabs.currentChanged.connect(self._on_net_tab_changed)
        self._net_block_bridge = NetBridgeSignals()
        self._net_block_bridge.done.connect(self._on_net_blocked)
        layout.addWidget(self.net_tabs, 1)
        return tab

    def _on_net_tab_changed(self, index: int):
        if self.net_tabs.widget(index) is self.block_panel:
            self.block_panel.refresh()

    def _net_alert_menu(self, pos):
        row = self.net_table.rowAt(pos.y())
        if row < 0 or row >= len(self.net_alerts):
            return
        self.net_table.selectRow(row)
        alert = self.net_alerts[row]
        host = alert.remote.rsplit(":", 1)[0] if alert.remote.count(":") == 1 else alert.remote
        ips = [host] if host.replace(".", "").isdigit() or ":" in host else (
            self.net_monitor.addresses_of(host) if self.net_monitor else [])
        menu = QMenu(self)
        shown = f" ({', '.join(ips[:3])})" if ips else ""
        a_ip = menu.addAction("Заблокировать адрес брандмауэром" + shown)
        a_ip.setEnabled(bool(ips))
        a_exe = menu.addAction("Запретить программе выход в сеть")
        a_exe.setEnabled(bool(alert.exe))
        a_kill = menu.addAction("Завершить процесс")
        a_scan = menu.addAction("Открыть файл программы в сканере")
        a_scan.setEnabled(bool(alert.exe))
        menu.addSeparator()
        a_skip = menu.addAction("Не оповещать об этой программе (исключение)")
        a_skip.setEnabled(bool(alert.exe) and self.net_monitor is not None)
        chosen = menu.exec(self.net_table.viewport().mapToGlobal(pos))
        if chosen is a_skip:
            self._exclude_net_program(alert)
            return
        from networkmonitor.panels import run_block
        if chosen is a_ip:
            run_block(self, self._net_block_bridge, ips, [])
        elif chosen is a_exe:
            run_block(self, self._net_block_bridge, [], [alert.exe])
        elif chosen is a_kill:
            self.kill_selected_process()
        elif chosen is a_scan:
            self.open_analyzer(alert.exe)

    def _exclude_net_program(self, alert):
        """Исключение программы из оповещений мониторинга сети. В тестовой версии
        попадает в signatures/release_exclusions.json — и в релиз."""
        from diag import edition
        from scanner import exclusions
        key = self.net_monitor.program_key(alert.exe)
        if not key:
            QMessageBox.warning(self, "Сеть", "Файл программы недоступен")
            return
        how = ("по издателю подписи" if "|pub:" in key
               else "по SHA-256: после обновления файла оповещения вернутся")
        where = ("\n\nТестовая версия: исключение попадёт и в релизную."
                 if edition.is_test() else "")
        answer = QMessageBox.question(
            self, "Мониторинг сети",
            f"Не оповещать о сетевой активности {alert.name}?\n\n{alert.exe}\n\n"
            f"Исключение {how}. Если файл программы распознан как угроза, оповещения "
            f"будут всё равно. Убрать — «Журнал» → «Исключения».{where}")
        if answer != QMessageBox.StandardButton.Yes:
            return
        from diag.anon import anonymize_user  # файл может уйти в Git: без имени пользователя
        exclusions.add("network", key, alert.name, anonymize_user(alert.exe))
        activity.record("net_alert", f"Программа исключена из мониторинга сети: {alert.name}",
                        exe=alert.exe)
        self.exclusions_page.refresh()
        self.statusBar().showMessage(f"{alert.name}: оповещений сети больше не будет", 5000)

    def _on_net_blocked(self, text: str, ok: bool):
        (QMessageBox.information if ok else QMessageBox.warning)(self, "Блокировка", text)
        if ok:
            self.block_panel.refresh()
            self.journal_page.refresh()

    def _set_windivert_dir(self, folder: str):
        cfg.set_("net/windivert_dir", folder)
        QMessageBox.information(self, "WinDivert", "Папка сохранена. Выключите и снова "
                                                   "включите мониторинг сети.")

    def toggle_network(self, force: bool = False):
        """force: выключить и при запрете (возврат состояния после замера ресурсов)."""
        if self.net_monitor is not None:
            if access.network_locked() and not force:
                self._off_blocked("мониторинг сети")
                return
            self.net_btn.setEnabled(False)
            self.net_monitor.stop()
            self._net_stopped()
            return
        self.net_monitor = NetworkMonitor(
            sig_dir=SIGNATURES.parent, rules_dir=RULES_DIR, netfeeds_dir=NETFEEDS_DIR,
            on_event=lambda kind, payload: self.net_bridge.event.emit(kind, payload),
            windivert_dir=cfg.get("net/windivert_dir"),
        )
        self.net_monitor.start()
        self.net_btn.setText("Выключить мониторинг сети")
        self.net_status.setText("Запускаю...")
        self._apply_off_locks()
        self.refresh_dashboard()

    def _net_stopped(self):
        self.net_monitor = None
        self.net_btn.setEnabled(True)
        self.net_btn.setText("Включить мониторинг сети")
        self.net_status.setText("Мониторинг сети выключен")
        self._net_sub = {}
        self.net_substatus.setText("")
        self._apply_off_locks()
        self.refresh_dashboard()

    def on_net_event(self, kind: str, payload):
        if kind == "status":
            self.net_status.setText(payload)
        elif kind == "error":
            self.net_status.setText(f"Ошибка: {payload}")
        elif kind == "stopped":
            self._net_stopped()
        elif kind == "alert":
            self._add_net_alert(payload)
        elif kind == "substatus":
            self._net_sub[payload.split(":", 1)[0]] = payload
            self.net_substatus.setText("\n".join(self._net_sub.values()))
        elif kind == "dns":
            self.dns_panel.add(payload)
        elif kind == "tls":
            self.tls_panel.add(payload)
        elif kind == "beacon":
            self.beacon_panel.add(payload)

    def _add_net_alert(self, a):
        activity.record("net_alert", f"{a.name} (PID {a.pid}) → {a.remote}: {a.rule}",
                        detail=a.detail, exe=a.exe)
        row = self.net_table.rowCount()
        self.net_table.insertRow(row)
        values = [a.time, LEVEL_TEXT.get(a.level, a.level), a.name, str(a.pid),
                  a.remote, a.rule, a.detail]
        color = QColor("red") if a.level == "critical" else QColor("darkorange")
        for col, text in enumerate(values):
            item = QTableWidgetItem(text)
            item.setForeground(QBrush(color))
            self.net_table.setItem(row, col, item)
        self.net_alerts.append(a)
        if len(self.net_alerts) > 500:  # таблица и список обрезаются синхронно
            self.net_table.removeRow(0)
            self.net_alerts.pop(0)
        self.net_table.scrollToBottom()
        self.statusBar().showMessage(f"[Сеть] {a.name}: {a.detail}")

    def kill_selected_process(self):
        row = self.net_table.currentRow()
        if row < 0 or row >= len(self.net_alerts):
            QMessageBox.information(self, "Сеть", "Сначала выберите строку в списке")
            return
        alert = self.net_alerts[row]
        answer = QMessageBox.question(
            self, "Завершить процесс",
            f"Завершить {alert.name} (PID {alert.pid})?\n\n{alert.exe or 'путь неизвестен'}\n\n"
            "Несохранённые данные программы будут потеряны.")
        if answer == QMessageBox.StandardButton.Yes:
            message = terminate_process(alert)
            self.statusBar().showMessage(message)
            QMessageBox.information(self, "Сеть", message)

    def clear_net_alerts(self):
        self.net_table.setRowCount(0)
        self.net_alerts.clear()

    # ---------- вкладка «Защита» (мониторинг) ----------
    def _build_protection_tab(self) -> QWidget:
        from ui.protection_page import ProtectionPage
        page = ProtectionPage(system_folders())
        self.protection_page = page
        self.watch_list = page.watch_list
        for folder in self._load_watch_folders():
            self._add_watch_item(folder)
        self.watch_add_btn = page.watch_add_btn
        self.watch_add_btn.clicked.connect(self.add_watch_folder)
        self.watch_remove_btn = page.watch_remove_btn
        self.watch_remove_btn.clicked.connect(self.remove_watch_folder)
        self.protect_btn = page.protect_btn
        self.protect_btn.clicked.connect(self.toggle_protection)
        self.protect_status = page.protect_status
        self.decoys_label = page.decoys_label
        self.decoys_btn = page.decoys_btn
        self.decoys_btn.clicked.connect(self._open_decoys)
        self.protect_log = page.protect_log
        self.protect_log.customContextMenuRequested.connect(self._protect_log_menu)
        self._refresh_decoys_info()
        self._full_cancel: threading.Event | None = None
        self._full_mode = "full"
        page.full_btn.clicked.connect(lambda checked=False: self.toggle_full_scan("full"))
        page.quick_btn.clicked.connect(lambda checked=False: self.toggle_full_scan("quick"))
        page.full_drive.currentIndexChanged.connect(lambda i: self._update_quick_visible())
        self.full_progress.connect(self._on_full_progress)
        self.full_found.connect(self._on_full_found)
        self.full_done.connect(self._on_full_done)
        self.fill_drives()
        return page

    # ---------- контроль запуска и защита от стилеров ----------
    def apply_guards(self):
        """Работают вместе с защитой файлов, каждый — если включён в настройках."""
        on = self.monitor is not None
        page = self.protection_page
        want_launch = on and cfg.get("protect/launch")
        if want_launch and self.launch_guard is None:
            from scanner.launchguard import LaunchGuard
            self.launch_guard = LaunchGuard(lambda k, i: self.launch_event.emit(k, i))
            self.launch_guard.start()
            page.launch_label.setText("Загружаю базы...")
        elif not want_launch and self.launch_guard is not None:
            guard, self.launch_guard = self.launch_guard, None
            threading.Thread(target=guard.stop, daemon=True).start()
        if not want_launch and on:
            page.launch_label.setText("Выключен в дополнительных настройках.")
        want_stealer = on and cfg.get("protect/stealer")
        if want_stealer and self.stealer_guard is None:
            from toolbox.stealerguard import StealerGuard
            self.stealer_guard = StealerGuard(
                lambda info: self.stealer_event.emit(info),
                lambda text: self.guard_status.emit("stealer", text))
            threading.Thread(target=self.stealer_guard.start, daemon=True).start()
        elif not want_stealer and self.stealer_guard is not None:
            guard, self.stealer_guard = self.stealer_guard, None
            threading.Thread(target=guard.stop, daemon=True).start()
        if not want_stealer and on:
            page.stealer_label.setText("Выключена в дополнительных настройках.")
        page.refit()

    def _on_guard_status(self, which: str, text: str):
        label = (self.protection_page.launch_label if which == "launch"
                 else self.protection_page.stealer_label)
        label.setText(text.split(": ", 1)[-1][:1].upper() + text.split(": ", 1)[-1][1:])
        self.protection_page.refit()

    def _protect_line(self, text: str, path: str, color: str):
        item = QListWidgetItem(f"{time.strftime('%H:%M:%S')}  {text}")
        if path:
            item.setData(ID_ROLE, path)
            item.setToolTip("Правый клик: в карантин, открыть в сканере, показать в проводнике")
        item.setForeground(QBrush(QColor(color)))
        self.add_protect_item(item, threat=color == "red")

    def add_protect_item(self, item: QListWidgetItem, threat: bool = False) -> None:
        """Строка в журнал защиты, не мешая читать его.

        Журнал прокручивается вниз сам только при угрозе, или если он и так был внизу
        (смотрят новые события). Если пользователь листает выше, проверенные файлы его не
        двигают; удаление старых строк сверху (больше 500) не сдвигает видимую часть."""
        _dlog.log(30 if threat else 10, "Журнал защиты: %s", item.text())
        log = self.protect_log
        bar = log.verticalScrollBar()
        at_bottom = bar.value() >= bar.maximum() - 1
        log.addItem(item)
        if log.count() > 500:  # журнал не растёт бесконечно
            log.takeItem(0)
            if not at_bottom and not threat:
                bar.setValue(max(0, bar.value() - 1))  # строка сверху ушла: держим место
        if threat or at_bottom:
            log.scrollToBottom()

    def _on_launch_event(self, kind: str, info):
        if kind == "status":
            self._on_guard_status("launch", info)
            return
        if kind == "error":
            self._protect_line(f"[Запуск] {info}", "", "darkorange")
            return
        name, exe, text = info["name"], info["exe"], info["text"]
        if kind == "blocked":
            what = "завершён" if info.get("killed") else \
                "обнаружен (экстренное завершение отключено)"
            line = f"[Запуск] {name}: {text}. Процесс {what}"
            activity.record("launch", f"{exe}: {text}", killed=info.get("killed"),
                            parent=info.get("parent", ""))
            self.add_event(f"Угроза при запуске: {name}", "threat")
            threatlog.add(exe, "threat", text, "Контроль запуска")
            self.protect_journal.refresh()
            self._protect_line(line, exe, "red")
            if self.tray is not None:
                self.tray.showMessage(
                    "Обнаружен вирус", f"{name}: {text}\nПравый клик в журнале защиты: "
                    "«В карантин».", QSystemTrayIcon.MessageIcon.Critical, 10000)
            self.refresh_dashboard()
            return
        level = "red" if kind == "threat" else "darkorange"
        activity.record("launch", f"{exe}: {text}")
        self._protect_line(f"[Запуск] {name}: {text}", exe, level)
        if exe:
            threatlog.add(exe, "threat" if kind == "threat" else "suspicious", text,
                          "Контроль запуска")
        if kind == "threat":
            self.add_event(f"Угроза среди процессов: {name}", "threat")

    def _on_stealer_event(self, info):
        from toolbox.windows import stealer_alarm
        self.add_event(f"Доступ к паролям браузеров: {info['name']}", "threat")
        self._protect_line(f"[Стилер?] {info['name']} открыл {info['kind']} ({info['owner']})",
                           info.get("exe", ""), "red")
        self.show_main()
        stealer_alarm(self, info, self.stealer_guard)

    # ---------- VPN ----------
    def start_vpn_on_launch(self):
        """Прокси, оставшийся после сбоя, возвращается; VPN подключается, если включено
        «Подключать VPN при запуске программы» (vpn/autostart) и инструмент разрешён."""
        from vpn import dnsguard, killswitch, procguard, xray
        # ядра VPN от прошлого запуска (программу сняли в диспетчере задач до привязки к
        # заданию Windows): туннель и порты заняты, а управлять ими нечем
        orphans = procguard.kill_orphans()
        if orphans:
            text = "Завершены ядра VPN, оставшиеся от прошлого запуска: " + ", ".join(orphans)
            self.add_event(text, "info")
            activity.record("vpn", text)
        if xray.recover_proxy():
            self.add_event("Системный прокси возвращён (VPN был отключён аварийно)", "info")
        # программа закрылась с подключённым VPN или упала: интернет не должен остаться
        # перекрытым, DNS — подменённым
        if killswitch.recover():
            self.add_event("Kill switch снят: VPN был отключён аварийно", "info")
            activity.record("vpn", "Kill switch снят при запуске (VPN был отключён аварийно)")
        if dnsguard.recover():
            self.add_event("DNS адаптеров возвращён (VPN был отключён аварийно)", "info")
        if not cfg.get("vpn/autostart") or not access.allowed("btnVpn"):
            return
        from vpn.window import VpnWindow
        window = self.tool_windows.get("vpn")
        if window is None:
            window = VpnWindow()  # без владельца: не держится поверх главного окна
            self.tool_windows["vpn"] = window
            self.apply_on_top(cfg.get("general/on_top"))
        if window.autoconnect():
            activity.record("vpn", "VPN подключается вместе с программой")

    # ---------- плановая проверка ----------
    def start_schedule(self):
        page = self.protection_page
        page.schedule_now_btn.clicked.connect(lambda checked=False: self._schedule_now())
        page.schedule_postpone_btn.clicked.connect(lambda checked=False: self._schedule_postpone())
        page.schedule_skip_btn.clicked.connect(lambda checked=False: self._schedule_skip())
        self._schedule_timer = QTimer(self)
        self._schedule_timer.timeout.connect(self.check_schedule)
        self._schedule_timer.start(15 * 1000)
        QTimer.singleShot(15000, self.check_schedule)  # при запуске: не пропущена ли

    def check_schedule(self):
        from scanner import schedule
        now = time.time()
        if not cfg.get("schedule/enabled"):
            self.settings_page.set_schedule_text("Расписание выключено.")
            if self._schedule_due:  # выключили, пока шёл отсчёт
                self._schedule_due = 0.0
                self._hide_schedule_bar()
            return
        due = schedule.next_run(cfg.get("schedule/last_run"), cfg.get("schedule/period"),
                                cfg.get("schedule/time"), now, cfg.get("schedule/postponed"))
        kind = schedule.KINDS.get(cfg.get("schedule/kind"), "Полная проверка")
        self.settings_page.set_schedule_text(f"Следующая: {kind.lower()}, "
                                             f"{schedule.describe(due, now)}.")
        if self._full_cancel is not None:
            return  # проверка уже идёт
        if self._schedule_due:
            if now >= self._schedule_due:
                self._schedule_due = 0.0
                self._run_scheduled()
            else:
                self._show_schedule_bar(kind)
            return
        if now >= due - schedule.WARN_SECONDS:
            # пропущенная проверка (компьютер был выключен) тоже предупреждает за 10 минут
            self._schedule_due = max(due, now + schedule.WARN_SECONDS)
            self._remind(kind)

    def _remind(self, title: str):
        """Уведомление Windows с кнопками «Начать сейчас», «Отложить на час», «Пропустить»
        (ui/notify.py). Если оно недоступно — обычное уведомление через трей, щелчок по нему
        открывает «Защиту». Те же кнопки — в полосе на странице «Защита»."""
        shown = self.notifier.show(
            "Плановая проверка через 10 минут",
            f"Скоро начнётся {title.lower()}: она нагружает процессор и диск. Если вы играете "
            "или работаете в тяжёлой программе, сохраните работу.",
            [("Начать сейчас", "now"), ("Отложить на час", "postpone"),
             ("Пропустить", "skip")], self._on_schedule_toast)
        if not shown and self.tray is not None:
            self._tray_target = "schedule"
            self._usb_pending = None
            self.tray.showMessage(
                "Плановая проверка через 10 минут",
                f"Скоро начнётся {title.lower()}: она нагружает процессор и диск. Если вы "
                "играете или работаете в тяжёлой программе, сохраните работу. Нажмите, чтобы "
                "отложить или пропустить.",
                QSystemTrayIcon.MessageIcon.Information, 15000)
        self._show_schedule_bar(title)
        activity.record("schedule", f"Предупреждение: через 10 минут — {title.lower()}")

    def _on_schedule_toast(self, argument):
        """Кнопка в уведомлении Windows (None — закрыто без выбора: проверка начнётся)."""
        if not self._schedule_due:
            return  # уже решено кнопкой на странице «Защита»
        if argument == "now":
            self._schedule_now()
        elif argument == "postpone":
            self._schedule_postpone()
        elif argument == "skip":
            self._schedule_skip()
        elif argument == "":
            self.show_main("Защита")

    def _show_schedule_bar(self, title: str):
        page = self.protection_page
        minutes = max(1, round((self._schedule_due - time.time()) / 60))
        page.schedule_label.setText(f"Через {minutes} мин начнётся плановая "
                                    f"{title.lower()}.")
        page.schedule_bar.setVisible(True)

    def _hide_schedule_bar(self):
        self.protection_page.schedule_bar.setVisible(False)
        self._tray_target = ""

    def _schedule_now(self):
        self._schedule_due = 0.0
        self._hide_schedule_bar()
        self._run_scheduled()

    def _schedule_postpone(self, seconds: int = 3600):
        self._schedule_due = 0.0
        self._hide_schedule_bar()
        cfg.set_("schedule/postponed", time.time() + seconds)
        activity.record("schedule", "Плановая проверка отложена на час")
        self.check_schedule()

    def _schedule_skip(self):
        self._schedule_due = 0.0
        self._hide_schedule_bar()
        cfg.set_("schedule/last_run", time.time())  # следующая — через период
        cfg.set_("schedule/postponed", 0.0)
        activity.record("schedule", "Плановая проверка пропущена пользователем")
        self.check_schedule()

    def _run_scheduled(self):
        self._hide_schedule_bar()
        cfg.set_("schedule/last_run", time.time())
        cfg.set_("schedule/postponed", 0.0)
        kind = cfg.get("schedule/kind")
        activity.record("schedule", f"Плановая проверка начата ({kind})")
        self.add_event("Плановая проверка начата", "info")
        if self._full_cancel is None:
            self.toggle_full_scan("quick" if kind == "quick" else "full", all_drives=True)
        self.check_schedule()

    # ---------- полная проверка ----------
    def fill_drives(self):
        """Список дисков: заново при каждом показе страницы (флешку могли вставить)."""
        if self._full_cancel is not None:
            return
        from scanner import fullscan
        combo = self.protection_page.full_drive
        previous = combo.currentData()
        combo.clear()
        found = fullscan.drives()
        if len(found) > 1:
            combo.addItem(f"Все диски ({len(found)})", [d.root for d in found])
        for drive in found:
            combo.addItem(drive.title(), [drive.root])
        if not found:  # не Windows или диски не определились
            combo.addItem(os.path.abspath(os.sep), [os.path.abspath(os.sep)])
        index = combo.findData(previous)
        combo.setCurrentIndex(max(0, index))
        self._update_quick_visible()

    def _update_quick_visible(self):
        """Быстрая проверка — только системного диска: на других дисках кнопки и описания нет."""
        from scanner import fullscan
        page = self.protection_page
        roots = page.full_drive.currentData() or []
        visible = any(fullscan.is_system_drive(r) for r in roots)
        page.quick_btn.setVisible(visible)
        page.quick_hint.setVisible(visible)

    def toggle_full_scan(self, mode: str = "full", all_drives: bool = False):
        """mode: full | quick. all_drives — все локальные диски (плановая, с главной)."""
        page = self.protection_page
        if self._full_cancel is not None:
            self._full_cancel.set()
            button = page.quick_btn if self._full_mode == "quick" else page.full_btn
            button.setEnabled(False)
            button.setText("Останавливаю...")
            return
        from scanner import fullscan
        if mode == "quick":  # системный диск и папка пользователя (fullscan.quick_plan)
            roots = [item.path for item in fullscan.quick_plan()]
        elif all_drives:
            roots = [d.root for d in fullscan.drives() if not d.removable] or \
                [os.path.abspath(os.sep)]
        else:
            roots = page.full_drive.currentData() or []
        self._full_mode = mode
        features.begin("protect.full_scan").fact("режим", mode)
        cancel = self._full_cancel = threading.Event()
        active, other = ((page.quick_btn, page.full_btn) if mode == "quick"
                         else (page.full_btn, page.quick_btn))
        active.setText("Остановить проверку")
        other.setEnabled(False)
        page.full_drive.setEnabled(False)
        page.full_progress.setVisible(True)
        page.full_status.setVisible(True)
        page.full_status.setToolTip("")
        page.full_status.setText("Загружаю базы...")
        self._full_found_list: list[str] = []
        title = "Быстрая проверка" if mode == "quick" else "Полная проверка"
        activity.record("full_scan", f"{title} начата: " + ", ".join(roots))

        def job():
            try:
                stats = fullscan.run(roots, self.full_progress.emit,
                                     self.full_found.emit, cancel, mode)
            except Exception as e:  # базы не загрузились и т.п.
                stats = str(e)
            self.full_done.emit(stats, cancel.is_set())

        threading.Thread(target=job, daemon=True).start()

    @staticmethod
    def _full_text(stats) -> str:
        from analyzer.fileops import human_size
        text = (f"Проверено файлов: {stats.checked:,}. Пропущено: "
                f"{stats.skipped:,} ({human_size(stats.skipped_bytes)})"
                ).replace(",", " ")
        if stats.game_dirs:
            text += f", папок игр: {len(stats.game_dirs)}"
        extra = [f"записей автозапуска: {stats.autoruns}" if stats.autoruns else "",
                 "проверка системы выполнена" if stats.checks else "",
                 f"память процессов: {stats.processes}" if stats.processes else ""]
        if any(extra):
            text += ". Также: " + ", ".join(e for e in extra if e)
        text += f". Угроз: {stats.threats}, подозрительных: {stats.suspicious}."
        return text

    @staticmethod
    def _duration(started: float) -> str:
        seconds = int(time.time() - started)
        if seconds < 60:
            return f"{seconds} с"
        if seconds < 3600:
            return f"{seconds // 60} мин {seconds % 60} с"
        return f"{seconds // 3600} ч {seconds // 60 % 60} мин"

    def _on_full_progress(self, stats):
        if self._full_cancel is None or self._full_cancel.is_set():
            return
        self.protection_page.full_status.setText(
            f"{self._full_text(stats)} Идёт {self._duration(stats.started)}.\n"
            f"Сейчас: {stats.current}") 

    def _on_full_found(self, path: str, level: str, text: str):
        where = f"{path}: {text}" if path else text  # запись системы или процесс без файла
        self._full_found_list.append(where)
        title = "Быстрая проверка" if self._full_mode == "quick" else "Полная проверка"
        threatlog.add(path, level, text, title)
        item = QListWidgetItem(f"{time.strftime('%H:%M:%S')}  [{title}] {where}")
        if path:
            item.setData(ID_ROLE, path)
            item.setToolTip("Правый клик: в карантин, открыть в сканере, показать в проводнике")
        item.setForeground(QBrush(QColor("red" if level == "threat" else "darkorange")))
        self.add_protect_item(item, threat=level == "threat")
        if level == "threat":
            self.add_event(f"Угроза: {os.path.basename(path)} ({text})" if path else f"Угроза: {text}",
                           "threat")

    def _on_full_done(self, stats, stopped: bool):
        page = self.protection_page
        self._full_cancel = None
        for button, text in ((page.full_btn, "Полная проверка"),
                             (page.quick_btn, "Быстрая проверка")):
            button.setEnabled(True)
            button.setText(text)
        page.full_drive.setEnabled(True)
        page.full_progress.setVisible(False)
        if isinstance(stats, str):
            page.full_status.setText(f"Полная проверка не удалась: {stats}")
            for fid in ("protect.full_scan", "home.quick_scan"):
                features.end_if_active(fid, False, error=stats)
            return
        for fid in ("protect.full_scan", "home.quick_scan"):
            features.end_if_active(fid, True, stopped=stopped, files=stats.files,
                                   checked=stats.checked, errors=stats.errors,
                                   threats=stats.threats, suspicious=stats.suspicious)
        title = "Быстрая проверка" if self._full_mode == "quick" else "Полная проверка"
        head = (f"{title} остановлена" if stopped else
                f"{title} завершена за {self._duration(stats.started)}")
        text = f"{head}. {self._full_text(stats)}"
        page.full_status.setText(text)
        if stats.game_dirs:
            shown = stats.game_dirs[:30]
            page.full_status.setToolTip(
                "Папки игр (проверены только программы и библиотеки):\n" + "\n".join(shown)
                + (f"\n...и ещё {len(stats.game_dirs) - 30}" if len(stats.game_dirs) > 30
                   else ""))
        activity.record("full_scan", text, found=list(self._full_found_list))
        self.add_event(head, "threat" if stats.threats else "info")
        self.statusBar().showMessage(text, 15000)

    def _threat_paths(self) -> list[str]:
        paths = []
        for item in self.protect_log.selectedItems():
            path = item.data(ID_ROLE)
            if path and path not in paths:
                paths.append(path)
        return paths

    def _protect_log_menu(self, pos):
        paths = [p for p in self._threat_paths() if os.path.exists(p)]
        if not paths:
            return
        menu = QMenu(self)
        menu.addAction(f"В карантин ({len(paths)})" if len(paths) > 1 else "В карантин",
                       lambda: self._quarantine_threats(paths))
        menu.addAction("Открыть в сканере", lambda: self.open_analyzer(paths[0]))
        from analyzer import fileops
        menu.addAction("Показать в проводнике", lambda: fileops.show_in_explorer(paths[0]))
        from diag import edition
        if self.debug_mode and edition.is_test():  # разбор ложных — только в тестовой версии
            menu.addAction("Разобрать срабатывание (ложное?)",
                           lambda: self.open_false_positives(paths[0]))
        menu.exec(self.protect_log.viewport().mapToGlobal(pos))

    def _quarantine_threats(self, paths: list[str]):
        from analyzer import fileops
        done, failed = 0, []
        for path in paths:
            try:
                qid = fileops.quarantine(path, "Защита: перемещено пользователем")
                threatlog.mark_path(path, threatlog.QUARANTINED, qid)
                done += 1
            except OSError as e:
                failed.append(f"{os.path.basename(path)}: {e}")
        self.refresh_quarantine()
        self.journal_page.refresh()
        self.refresh_dashboard()
        text = f"Перемещено в карантин: {done}"
        if failed:
            text += "\n\nНе удалось:\n" + "\n".join(failed[:10])
        QMessageBox.information(self, "Карантин", text)

    def _load_watch_folders(self) -> list[str]:
        raw = self.settings.value("monitor/folders", None)
        if raw:
            try:
                folders = json.loads(raw)
                if isinstance(folders, list):
                    return [str(f) for f in folders]
            except (TypeError, ValueError):
                pass
        return list(DEFAULT_WATCH)

    def _save_watch_folders(self):
        folders = [self.watch_list.item(i).text() for i in range(self.watch_list.count())]
        self.settings.setValue("monitor/folders", json.dumps(folders, ensure_ascii=False))

    def _add_watch_item(self, folder: str):
        item = QListWidgetItem(folder)
        item.setToolTip(folder)  # в списке длинный путь сокращён посередине
        self.watch_list.addItem(item)

    def add_watch_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Папка для наблюдения")
        if folder and not self.watch_list.findItems(folder, Qt.MatchFlag.MatchExactly):
            self._add_watch_item(folder)
            self._save_watch_folders()

    def remove_watch_folder(self):
        row = self.watch_list.currentRow()
        if row >= 0:
            self.watch_list.takeItem(row)
            self._save_watch_folders()

    def toggle_protection(self, force: bool = False):
        """force: выключить и при запрете (возврат состояния после замера ресурсов)."""
        if self.monitor is not None:
            if access.protection_locked() and not force:
                self._off_blocked("защиту файлов")
                return
            self.protect_btn.setEnabled(False)
            self.monitor.stop()
            self._protection_stopped()
            return

        # список может быть пустым: системные папки наблюдаются всегда
        folders = [self.watch_list.item(i).text() for i in range(self.watch_list.count())]

        self.monitor = RealtimeMonitor(
            folders,
            sig_dir=SIGNATURES.parent,
            rules_dir=RULES_DIR,
            exclude=[QUARANTINE_DIR, SIGNATURES.parent.resolve()],
            on_event=lambda kind, text: self.bridge.event.emit(kind, text),
        )
        self.monitor.start()
        self._set_protection_ui(True)
        self.apply_decoys()  # ловушки для шифровальщиков — часть защиты
        self.apply_guards()  # контроль запуска и защита от стилеров — тоже

    def _set_protection_ui(self, running: bool):
        self.protect_btn.setEnabled(True)
        self.protection_page.set_running(running)
        for w in (self.watch_list, self.watch_add_btn, self.watch_remove_btn):
            w.setEnabled(not running)
        self.protect_status.setText("Запускаю..." if running else
                                    "Новые и изменённые файлы не проверяются.")
        self.refresh_dashboard()
        self._apply_off_locks()

    def _protection_stopped(self):
        self.monitor = None
        self.decoy_watcher.stop()
        self.apply_guards()
        self._refresh_decoys_info()
        self._set_protection_ui(False)

    def on_monitor_event(self, kind: str, text: str):
        if kind == "status":  # «Защита включена» уже в заголовке страницы
            self.protect_status.setText(text.removeprefix("Защита включена. "))
            self.refresh_dashboard()
            return
        if kind == "stopped":
            self._protection_stopped()
            return
        path = ""
        if kind == "threat":
            path, reason, action = (text.split("\t") + ["", ""])[:3]
            activity.record("threat", f"{path}: {reason}", action=action)
            threatlog.add(path, "threat", reason, "Защита файлов")
            text = f"[!] {path} ({reason}): {action}"
            self.refresh_quarantine()
            self.statusBar().showMessage(text)
            self.add_event(f"Угроза: {os.path.basename(path)} ({reason})", "threat")

        item = QListWidgetItem(f"{time.strftime('%H:%M:%S')}  {text}")
        if path:
            item.setData(ID_ROLE, path)
            item.setToolTip("Правый клик: в карантин, открыть в сканере, показать в проводнике")
        color = {"threat": "red", "error": "darkorange", "scanned": "gray"}.get(kind)
        if color:
            item.setForeground(QBrush(QColor(color)))
        self.add_protect_item(item, threat=kind == "threat")

    # ---------- вкладка «Белый список» ----------
    def _build_whitelist_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.wl_table = make_table([("Дата", 140), ("Путь при восстановлении", 380),
                                    ("SHA-256", 300)])
        layout.addWidget(self.wl_table)

        row = QHBoxLayout()
        remove_btn = QPushButton("Убрать из белого списка")
        remove_btn.clicked.connect(self.remove_from_wl)
        row.addWidget(remove_btn)
        row.addStretch()
        layout.addLayout(row)
        return tab

    def refresh_whitelist(self):
        self.wl_table.setRowCount(0)
        entries = sorted(load_whitelist().items(), key=lambda kv: kv[1].get("added_at", ""))
        for sha, info in entries:
            row = self.wl_table.rowCount()
            self.wl_table.insertRow(row)
            self.wl_table.setItem(row, 0, QTableWidgetItem(info.get("added_at", "")))
            self.wl_table.setItem(row, 1, QTableWidgetItem(info.get("path", "")))
            self.wl_table.setItem(row, 2, QTableWidgetItem(sha))

    def remove_from_wl(self):
        row = self.wl_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Белый список", "Сначала выберите запись в списке")
            return
        sha = self.wl_table.item(row, 2).text()
        answer = QMessageBox.question(
            self, "Белый список",
            "Файл с этим хэшем снова будет проверяться сканером. Продолжить?")
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            remove_from_whitelist(sha)
            self.statusBar().showMessage("Хэш убран из белого списка")
        except OSError as e:
            QMessageBox.critical(self, "Ошибка", str(e))
        self.refresh_whitelist()

    # ---------- вкладка «Сканирование» ----------
    # ---------- вкладка «Карантин» ----------


    # бывшая вкладка «Карантин» теперь часть журнала защиты (ui/protect_journal.py)
    def refresh_quarantine(self):
        self.protect_journal.refresh()

    def restore_selected(self):
        self.protect_journal.restore_selected()

    def delete_selected(self):
        self.protect_journal.delete_selected()

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
        if self.monitor is not None:
            self.monitor.stop()
        self.decoy_watcher.stop()
        for guard in (self.launch_guard, self.stealer_guard):
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

    icon = load_app_icon()
    app.setWindowIcon(icon)
    tray_ok = QSystemTrayIcon.isSystemTrayAvailable()
    app.setQuitOnLastWindowClosed(not tray_ok)  # с треем программа живёт и после закрытия окна

    if "--uninstall" in sys.argv:  # удаление программы (uninstall.py): нужны права
        if not is_admin() and relaunch_as_admin():
            sys.exit(0)
        import uninstall
        sys.exit(0 if uninstall.run() else 1)

    autostart = "--autostart" in sys.argv
    analyze_path = _argument("--analyze")  # файл из меню Проводника
    guard = SingleInstance("StudyAV-myav")
    wait = 10.0 if "--relaunched" in sys.argv else 0.0  # ждём закрытия прежнего экземпляра
    message = (b"open\n" + analyze_path.encode("utf-8")) if analyze_path else b"show"
    # уже запущена: передаём ей файл или просьбу показать окно и выходим
    if guard.already_running(notify=not autostart, wait=wait, message=message):
        sys.exit(0)

    # запуск пользователем — сразу с запросом UAC; из автозапуска (задание планировщика уже
    # с наивысшими правами) и из меню Проводника окно UAC не показываем
    if not autostart and not analyze_path and elevate_on_start():
        sys.exit(0)
    if is_admin():
        cfg.ensure_autostart()  # задание планировщика по умолчанию (создаётся только с правами)
    cfg.ensure_explorer_menu()  # пункт «Проверить в ...» в меню файлов — всегда
    if not guard.listen():  # другой экземпляр успел занять имя
        sys.exit(0)
    crash.start_session()  # метка сеанса: аварийный выход заметен при следующем запуске
    features.begin("app.start")

    window = MainWindow()
    window.guard = guard
    guard.activated.connect(lambda: window.show_main())
    guard.file_received.connect(lambda path: window.open_analyzer(path))
    if tray_ok:
        window.setup_tray(icon)
    window.apply_on_top(cfg.get("general/on_top"))

    quiet_start = (autostart or bool(analyze_path)) and tray_ok
    if not quiet_start:
        window.show()
    if analyze_path:
        window.open_analyzer(analyze_path)
    window.start_protection_on_launch()
    window.start_activity_report()
    window.start_usb_watch()
    window.start_auto_update()
    window.start_schedule()
    window.start_vpn_on_launch()
    if edition.is_test():
        from diag import testpanel
        testpanel.bridge()
        _attacher = testpanel.WindowAttacher(app)
        window.install_test_ui()
    features.end("app.start", True, окно="скрыто" if quiet_start else "показано")
    diag_log.session_details()
    resources.start()
    sys.exit(app.exec())