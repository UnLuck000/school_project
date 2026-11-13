"""Инструменты: окна инструментов, запреты (ui/access), режим администратора для окон, отчёт
ресурсов. Часть главного окна: методы MainWindow (gui.py)."""

from PySide6.QtWidgets import QMessageBox

from autoruns.window import AutorunsWindow
from processmanager.window import ProcessWindow
from recovery.window import RecoveryWindow
from ui import access, settings as cfg
from ui.pages import run_feature as run_tool
from ui.registry import FEATURES, HANDLERS
import appinfo
from mainwindow.common import SCAN_PAGE


class ToolsMixin:
    """Атрибуты и сигналы — у MainWindow (gui.py)."""

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

    def _open_elevated(self, name: str, tab: int = 0) -> bool:
        """Окно со службой без прав: инструмент — процессом с правами через UAC
        (service/elevate.py). False — открыть здесь (служба не нужна или UAC отклонён)."""
        from service import elevate
        if not elevate.wanted(name):
            return False
        try:
            if elevate.open_tool(name, tab):
                self.statusBar().showMessage("Инструмент открыт отдельным окном с правами "
                                             "администратора", 8000)
                return True
        except OSError as e:
            self.statusBar().showMessage(str(e), 8000)
        self.statusBar().showMessage("Без прав администратора: инструмент только показывает, "
                                     "изменения недоступны", 10000)
        return False

    def open_recovery(self, tab: int = 0, action: str | None = None):
        if tab in self.TAB_TOOLS and self.tool_blocked(self.TAB_TOOLS[tab]):
            return
        if self.recovery_window is None and action is None and \
                self._open_elevated("recovery", tab):
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

    def open_analyzer(self, path: str | None = None):
        if self.tool_blocked("btnFileAnalyzer"):
            return
        """Файл или папка открываются на странице «Сканирование папки/файла»."""
        self.show_main(SCAN_PAGE)
        if path:
            self.scan_page.scan(path)

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

    def open_tool(self, name: str):
        if self.tool_blocked(self.TOOL_BUTTONS[name]):
            return
        from toolbox import windows
        window = self.tool_windows.get(name)
        if window is None and name == "drivers" and self._open_elevated("drivers"):
            return
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
        if self.autoruns_window is None and self._open_elevated("autoruns"):
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
