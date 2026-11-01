from PySide6.QtCore import QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout, QLabel, QLineEdit,
    QMessageBox, QPushButton, QSpinBox, QVBoxLayout, QWidget,
)

import appinfo
import ui.handlers  # noqa: F401  (регистрирует обработчики кнопок)
from ui import settings as cfg
from ui.loader import child, load_ui
from ui.registry import FEATURES, HANDLERS

from processmanager.system import is_admin

from ui.debug_mode import MIN_LEN, PasswordGate
from ui.theme import THEMES as THEME_LIST, THEME_IDS as THEMES


def _run_feature(widget, window, feature, handler) -> None:
    if handler is None:
        QMessageBox.information(
            widget, feature.title, f"Функция в разработке.\n\nПлан:\n{feature.plan}")
        return
    try:
        handler(window)
    except Exception as e:  # ошибка в функции не должна ронять программу
        QMessageBox.critical(widget, feature.title, f"Ошибка: {e}")


def bind_features(widget, ui_root, window) -> None:
    """Привязывает кнопки из ui/registry.py, найденные на странице, к их обработчикам."""
    for button_id, feature in FEATURES.items():
        button = ui_root.findChild(QPushButton, button_id)
        if button is None:  # этой кнопки нет на данной странице
            continue
        handler = HANDLERS.get(button_id)
        if handler is None:
            button.setText(f"{button.text()}   (скоро)")
        button.setToolTip(feature.plan)
        button.clicked.connect(
            lambda checked=False, f=feature, h=handler: _run_feature(widget, window, f, h))


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
    check_updates = Signal()
    open_processes = Signal()

    def __init__(self):
        super().__init__()
        ui = self.ui
        names = {"protection": "lblProtection", "network": "lblNetwork",
                 "quarantine": "lblQuarantine", "whitelist": "lblWhitelist",
                 "last_scan": "lblLastScan"}
        self.labels = {key: child(ui, QLabel, name) for key, name in names.items()}
        self.btn_protection = child(ui, QPushButton, "btnStartProtection")

        child(ui, QPushButton, "btnQuickScan").clicked.connect(
            lambda checked=False: self.quick_scan.emit())
        self.btn_protection.clicked.connect(lambda checked=False: self.toggle_protection.emit())
        child(ui, QPushButton, "btnCheckUpdates").clicked.connect(
            lambda checked=False: self.check_updates.emit())
        child(ui, QPushButton, "btnOpenProcesses").clicked.connect(
            lambda checked=False: self.open_processes.emit())

    def refresh(self, info: dict) -> None:
        def state(label: QLabel, on: bool) -> None:
            label.setText("включена" if on else "выключена")
            label.setStyleSheet("color: #2e9e4f; font-weight: 600;" if on
                                else "color: #c0392b; font-weight: 600;")

        state(self.labels["protection"], info["protection"])
        state(self.labels["network"], info["network"])
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
        bind_features(self, self.ui, window)
        self.btn_admin = child(self.ui, QPushButton, "btnRelaunchAdmin")
        self.btn_admin.setVisible(not is_admin())  # с правами администратора кнопка не нужна
        if window is not None:
            self.btn_admin.clicked.connect(lambda checked=False: window.restart_as_admin())
        for button_id, feature in FEATURES.items():
            button = self.ui.findChild(QPushButton, button_id)
            if button is None:  # кнопку убрали в Designer
                continue
            # handler = HANDLERS.get(button_id)
            # if handler is None:
            #     button.setText(f"{button.text()}   (скоро)")
            # button.setToolTip(feature.plan)
            # button.clicked.connect(
            #     lambda checked=False, f=feature, h=handler: self._run(f, h))

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
        self.chk_block_exit = child(ui, QCheckBox, "chkBlockExit")
        self.chk_on_top = child(ui, QCheckBox, "chkOnTop")
        self.cmb_theme = child(ui, QComboBox, "cmbTheme")
        self.cmb_theme.clear()  # список тем задаётся в ui/theme.py
        self.cmb_theme.addItems([title for _, title in THEME_LIST])
        self.spn_threshold = child(ui, QSpinBox, "spnThreshold")
        self.spn_workers = child(ui, QSpinBox, "spnWorkers")
        self.spn_interval = child(ui, QSpinBox, "spnInterval")
        self.chk_tray = child(ui, QCheckBox, "chkTray")
        self.chk_explorer = child(ui, QCheckBox, "chkExplorerMenu")
        self._all = (self.chk_autostart, self.chk_ask_admin, self.chk_block_exit,
                     self.chk_on_top, self.cmb_theme, self.spn_threshold,
                     self.spn_workers, self.spn_interval, self.chk_tray,
                     self.chk_explorer,)
        self.load_values()

        self.chk_autostart.toggled.connect(self._on_autostart)
        self.chk_ask_admin.toggled.connect(lambda v: self._save("startup/ask_admin", v))
        self.chk_block_exit.toggled.connect(lambda v: self._save("general/block_exit", v))
        self.chk_on_top.toggled.connect(lambda v: self._save("general/on_top", v))
        self.chk_tray.toggled.connect(lambda v: self._save("general/close_to_tray", v))
        self.chk_explorer.toggled.connect(self._on_explorer_menu)
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
        self.chk_block_exit.setChecked(cfg.get("general/block_exit"))
        self.chk_on_top.setChecked(cfg.get("general/on_top"))
        self.chk_tray.setChecked(cfg.get("general/close_to_tray"))
        self.chk_explorer.setChecked(cfg.explorer_menu_enabled())
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

    def _on_explorer_menu(self, checked: bool) -> None:
        try:
            cfg.set_explorer_menu(checked)
        except OSError as e:
            QMessageBox.warning(self, "Проводник", f"Не удалось изменить меню: {e}")
            self.chk_explorer.blockSignals(True)
            self.chk_explorer.setChecked(not checked)
            self.chk_explorer.blockSignals(False)


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


class DebugPage(_UiPage):
    """Служебная страница: видна только в режиме отладки."""
    UI_NAME = "debug_page"
    update_databases = Signal()
    password_changed = Signal(bool)  # True: пароль задан

    def __init__(self, window, gate: PasswordGate | None = None):
        super().__init__()
        self.gate = gate
        self.lbl_hashes = child(self.ui, QLabel, "lblHashes")
        self.lbl_rules = child(self.ui, QLabel, "lblRules")
        self.lbl_password = child(self.ui, QLabel, "lblPasswordState")
        self.btn_set_password = child(self.ui, QPushButton, "btnSetPassword")
        self.btn_remove_password = child(self.ui, QPushButton, "btnRemovePassword")
        child(self.ui, QPushButton, "btnUpdateDatabases").clicked.connect(
            lambda checked=False: self.update_databases.emit())
        self.btn_set_password.clicked.connect(lambda checked=False: self.set_password())
        self.btn_remove_password.clicked.connect(lambda checked=False: self.remove_password())
        bind_features(self, self.ui, window)
        self.update_password_state()

    def update_password_state(self) -> None:
        has = self.gate is not None and self.gate.has_password()
        self.btn_set_password.setText("Сменить пароль" if has else "Установить пароль")
        self.btn_set_password.setEnabled(self.gate is not None)
        self.btn_remove_password.setEnabled(has)
        self.lbl_password.setText(
            "Пароль задан. Чтобы скрыть или открыть вкладку «Отладка», наберите его на "
            "клавиатуре в любом окне программы." if has else
            "Пароль не задан, поэтому режим отладки включён всегда. Задайте пароль, чтобы "
            "скрыть вкладку: после этого она открывается только набором пароля на клавиатуре.")

    def set_password(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle(self.btn_set_password.text())
        form = QFormLayout(dialog)
        first, second = QLineEdit(), QLineEdit()
        for edit in (first, second):
            edit.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow(QLabel(f"Не меньше {MIN_LEN} символов, регистр не учитывается. "
                           "Хранится только хэш пароля."))
        form.addRow("Пароль:", first)
        form.addRow("Ещё раз:", second)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                                   | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)
        while dialog.exec() == QDialog.DialogCode.Accepted:
            if first.text() != second.text():
                QMessageBox.warning(self, "Пароль", "Пароли не совпадают")
                continue
            try:
                self.gate.set_password(first.text())
            except (ValueError, OSError) as e:
                QMessageBox.warning(self, "Пароль", str(e))
                continue
            self.update_password_state()
            self.password_changed.emit(True)
            QMessageBox.information(
                self, "Пароль", "Пароль сохранён. Вкладка остаётся открытой до тех пор, "
                "пока вы не наберёте пароль ещё раз или не перезапустите программу.")
            return

    def remove_password(self) -> None:
        answer = QMessageBox.question(
            self, "Пароль", "Убрать пароль? Режим отладки будет включён всегда.")
        if answer == QMessageBox.StandardButton.Yes:
            try:
                self.gate.remove_password()
            except OSError as e:
                QMessageBox.warning(self, "Пароль", f"Не удалось удалить файл пароля: {e}")
                return
            self.update_password_state()
            self.password_changed.emit(False)

    def refresh(self, hashes: int, rules: int, rule_files: int) -> None:
        self.lbl_hashes.setText(f"{hashes:,}".replace(",", " "))
        self.lbl_rules.setText(f"{rules:,} (в {rule_files} файлах)".replace(",", " "))