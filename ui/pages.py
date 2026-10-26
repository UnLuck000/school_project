from PySide6.QtCore import QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QLabel, QMessageBox, QPushButton, QSpinBox, QVBoxLayout,
    QGroupBox, QWidget,
)

import appinfo
import ui.handlers  # noqa: F401  (регистрирует обработчики кнопок)
from ui import settings as cfg
from ui.loader import child, load_ui
from ui.registry import FEATURES, HANDLERS

THEMES = ["system", "light", "dark"]  # порядок совпадает с пунктами списка в Designer


class _UiPage(QWidget):
    """Страница, внешний вид которой загружается из .ui-файла."""
    UI_NAME = ""

    def __init__(self):
        super().__init__()
        self.ui = load_ui(self.UI_NAME, self)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.addWidget(self.ui)


class DashboardPage(_UiPage):
    UI_NAME = "dashboard_page"
    quick_scan = Signal()
    toggle_protection = Signal()
    update_databases = Signal()
    open_processes = Signal()

    def __init__(self):
        super().__init__()
        ui = self.ui
        names = {"protection": "lblProtection", "network": "lblNetwork", "hashes": "lblHashes",
                 "rules": "lblRules", "quarantine": "lblQuarantine",
                 "whitelist": "lblWhitelist", "last_scan": "lblLastScan"}
        self.labels = {key: child(ui, QLabel, name) for key, name in names.items()}
        self.btn_protection = child(ui, QPushButton, "btnStartProtection")

        child(ui, QPushButton, "btnQuickScan").clicked.connect(
            lambda checked=False: self.quick_scan.emit())
        self.btn_protection.clicked.connect(lambda checked=False: self.toggle_protection.emit())
        child(ui, QPushButton, "btnUpdateDatabases").clicked.connect(
            lambda checked=False: self.update_databases.emit())
        child(ui, QPushButton, "btnOpenProcesses").clicked.connect(
            lambda checked=False: self.open_processes.emit())

    def refresh(self, info: dict) -> None:
        def state(label: QLabel, on: bool) -> None:
            label.setText("включена" if on else "выключена")
            label.setStyleSheet("color: #2e9e4f; font-weight: 600;" if on
                                else "color: #c0392b; font-weight: 600;")

        state(self.labels["protection"], info["protection"])
        state(self.labels["network"], info["network"])
        self.labels["hashes"].setText(f"{info['hashes']:,}".replace(",", " "))
        self.labels["rules"].setText(str(info["rules"]))
        self.labels["quarantine"].setText(str(info["quarantine"]))
        self.labels["whitelist"].setText(str(info["whitelist"]))
        self.labels["last_scan"].setText(info["last_scan"] or "ещё не выполнялась")
        self.btn_protection.setText(
            "Выключить защиту" if info["protection"] else "Включить защиту")


class ToolsPage(_UiPage):
    UI_NAME = "tools_page"

    def __init__(self, window):
        super().__init__()
        self.window_ref = window
        for button_id, feature in FEATURES.items():
            button = self.ui.findChild(QPushButton, button_id)
            if button is None:  # кнопку убрали в Designer
                continue
            handler = HANDLERS.get(button_id)
            if handler is None:
                button.setText(f"{button.text()}   (скоро)")
            button.setToolTip(feature.plan)
            button.clicked.connect(
                lambda checked=False, f=feature, h=handler: self._run(f, h))
        self.group_research = child(self.ui, QGroupBox, "groupResearch")
        self.group_research.setVisible(False)

    def set_debug(self, on: bool) -> None:
        self.group_research.setVisible(on)

    def _run(self, feature, handler) -> None:
        if handler is None:
            QMessageBox.information(
                self, feature.title, f"Функция в разработке.\n\nПлан:\n{feature.plan}")
            return
        try:
            handler(self.window_ref)
        except Exception as e:  # ошибка в функции не должна ронять программу
            QMessageBox.critical(self, feature.title, f"Ошибка: {e}")


class SettingsPage(_UiPage):
    UI_NAME = "settings_page"
    changed = Signal(str, object)  # ключ, новое значение

    def __init__(self):
        super().__init__()
        ui = self.ui
        self.chk_autostart = child(ui, QCheckBox, "chkAutostart")
        self.chk_ask_admin = child(ui, QCheckBox, "chkAskAdmin")
        self.chk_auto_protect = child(ui, QCheckBox, "chkAutoProtect")
        self.chk_on_top = child(ui, QCheckBox, "chkOnTop")
        self.cmb_theme = child(ui, QComboBox, "cmbTheme")
        self.spn_threshold = child(ui, QSpinBox, "spnThreshold")
        self.spn_workers = child(ui, QSpinBox, "spnWorkers")
        self.spn_interval = child(ui, QSpinBox, "spnInterval")
        self.chk_tray = child(ui, QCheckBox, "chkTray")
        self._all = (self.chk_autostart, self.chk_ask_admin, self.chk_auto_protect,
                     self.chk_on_top, self.cmb_theme, self.spn_threshold,
                     self.spn_workers, self.spn_interval, self.chk_tray)
        self.load_values()

        self.chk_autostart.toggled.connect(self._on_autostart)
        self.chk_ask_admin.toggled.connect(lambda v: self._save("startup/ask_admin", v))
        self.chk_auto_protect.toggled.connect(lambda v: self._save("startup/auto_protect", v))
        self.chk_on_top.toggled.connect(lambda v: self._save("general/on_top", v))
        self.chk_tray.toggled.connect(lambda v: self._save("general/close_to_tray", v))
        self.cmb_theme.currentIndexChanged.connect(
            lambda i: self._save("general/theme", THEMES[i]))
        self.spn_threshold.valueChanged.connect(lambda v: self._save("scan/threshold", v))
        self.spn_workers.valueChanged.connect(lambda v: self._save("scan/workers", v))
        self.spn_interval.valueChanged.connect(lambda v: self._save("process/interval", v))
        child(ui, QPushButton, "btnReset").clicked.connect(lambda checked=False: self._reset())

    def load_values(self) -> None:
        for widget in self._all:
            widget.blockSignals(True)
        self.chk_autostart.setChecked(cfg.autostart_enabled())
        self.chk_ask_admin.setChecked(cfg.get("startup/ask_admin"))
        self.chk_auto_protect.setChecked(cfg.get("startup/auto_protect"))
        self.chk_on_top.setChecked(cfg.get("general/on_top"))
        self.chk_tray.setChecked(cfg.get("general/close_to_tray"))
        theme = cfg.get("general/theme")
        self.cmb_theme.setCurrentIndex(THEMES.index(theme) if theme in THEMES else 0)
        self.spn_threshold.setValue(cfg.get("scan/threshold"))
        self.spn_workers.setValue(cfg.get("scan/workers"))
        self.spn_interval.setValue(cfg.get("process/interval"))
        for widget in self._all:
            widget.blockSignals(False)

    def _save(self, key: str, value) -> None:
        cfg.set_(key, value)
        self.changed.emit(key, value)

    def _on_autostart(self, checked: bool) -> None:
        try:
            cfg.set_autostart(checked)
        except OSError as e:
            QMessageBox.warning(self, "Автозапуск", f"Не удалось изменить автозапуск: {e}")
            self.chk_autostart.blockSignals(True)
            self.chk_autostart.setChecked(not checked)
            self.chk_autostart.blockSignals(False)

    def _reset(self) -> None:
        answer = QMessageBox.question(self, "Настройки", "Вернуть все настройки по умолчанию?")
        if answer != QMessageBox.StandardButton.Yes:
            return
        cfg.reset()
        try:
            cfg.set_autostart(False)
        except OSError:
            pass
        self.load_values()
        for key in ("general/on_top", "general/theme", "scan/threshold"):
            self.changed.emit(key, cfg.get(key))


class AboutPage(_UiPage):
    UI_NAME = "about_page"

    def __init__(self):
        super().__init__()
        ui = self.ui
        child(ui, QLabel, "lblAppName").setText(appinfo.APP_NAME)
        child(ui, QLabel, "lblVersion").setText(f"Версия {appinfo.VERSION}")
        child(ui, QLabel, "lblDescription").setText(appinfo.DESCRIPTION)
        child(ui, QLabel, "lblThesis").setText(f"<b>Тема работы:</b> {appinfo.THESIS}")

        author = f"<b>Автор:</b> {appinfo.AUTHOR}"
        if appinfo.ORGANIZATION:
            author += f"<br>{appinfo.ORGANIZATION}"
        if appinfo.SUPERVISOR:
            author += f"<br><b>Руководитель:</b> {appinfo.SUPERVISOR}"
        author += f"<br>{appinfo.YEAR} год"
        child(ui, QLabel, "lblAuthor").setText(author)

        child(ui, QLabel, "lblComponents").setText(appinfo.COMPONENTS)
        child(ui, QLabel, "lblLicenses").setText(appinfo.LICENSES)
        child(ui, QLabel, "lblDisclaimer").setText(appinfo.DISCLAIMER)
        child(ui, QPushButton, "btnRepo").clicked.connect(
            lambda checked=False: QDesktopServices.openUrl(QUrl(appinfo.REPO_URL)))