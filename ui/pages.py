import time

from PySide6.QtCore import QSize, QTimer, QUrl, Signal
from PySide6.QtGui import QBrush, QColor, QDesktopServices
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout, QFrame,
    QGroupBox, QLabel, QLineEdit,
    QListWidget, QListWidgetItem, QMessageBox, QProgressBar, QPushButton, QSizePolicy,
    QSpinBox, QStyle,
    QVBoxLayout,
    QWidget,
)

import appinfo
import ui.handlers  # noqa: F401  (регистрирует обработчики кнопок)
from ui import settings as cfg
from ui.loader import child, load_ui
from ui.registry import FEATURES, HANDLERS

from processmanager.system import is_admin

from ui.debug_mode import MIN_LEN, PasswordGate
from ui.theme import THEMES as THEME_LIST, THEME_IDS as THEMES


def run_feature(widget, window, feature, handler) -> None:
    """Запуск инструмента: запрет, заглушка «в разработке», ошибка — сообщением."""
    from ui import access
    button_id = next((k for k, v in FEATURES.items() if v is feature), "")
    if not access.allowed(button_id):
        QMessageBox.information(widget, feature.title, access.LOCKED_TIP)
        return
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
            lambda checked=False, f=feature, h=handler: run_feature(widget, window, f, h))


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
    open_scan = Signal()
    open_journal = Signal()

    GOOD, BAD, WARN = "#2e9e4f", "#c0392b", "#d68910"
    STYLE = """
        QFrame[card="true"] { background: palette(base); border: 1px solid palette(mid);
                              border-radius: 8px; }
        QFrame[card="true"] QLabel { background: transparent; border: none; }
        QFrame[card="true"] QLabel[caption="true"] { color: palette(placeholder-text); }
        QPushButton[action="true"] { text-align: left; padding: 6px 12px; }
    """

    def __init__(self):
        super().__init__()
        ui = self.ui
        names = {"protection": "lblProtection", "network": "lblNetwork",
                 "quarantine": "lblQuarantine", "whitelist": "lblWhitelist",
                 "last_scan": "lblLastScan", "databases": "lblDatabases"}
        self.labels = {key: child(ui, QLabel, name) for key, name in names.items()}
        self.btn_protection = child(ui, QPushButton, "btnStartProtection")
        self.hero = child(ui, QFrame, "frameHero")
        self.hero_icon = child(ui, QLabel, "lblHeroIcon")
        self.hero_title = child(ui, QLabel, "lblHeroTitle")
        self.hero_text = child(ui, QLabel, "lblHeroText")
        self.events = child(ui, QListWidget, "listEvents")
        self.events.setWordWrap(True)
        ui.setStyleSheet(self.STYLE)
        for label in self.labels.values():
            label.setWordWrap(True)
            label.setStyleSheet("font-size: 13pt; font-weight: 600;")
        for name in ("captionProtection", "captionNetwork", "captionQuarantine",
                     "captionWhitelist", "captionLastScan", "captionDatabases"):
            child(ui, QLabel, name).setProperty("caption", True)

        style = self.style()
        icons = QStyle.StandardPixmap
        buttons = [("btnQuickScan", self.quick_scan, icons.SP_DirOpenIcon),
                   ("btnScanPath", self.open_scan, icons.SP_FileDialogContentsView),
                   ("btnOpenProcesses", self.open_processes, icons.SP_ComputerIcon),
                   ("btnOpenJournal", self.open_journal, icons.SP_FileDialogDetailedView),
                   ("btnCheckUpdates", self.check_updates, icons.SP_BrowserReload)]
        for name, signal, icon in buttons:
            button = child(ui, QPushButton, name)
            button.setIcon(style.standardIcon(icon))
            button.setIconSize(QSize(20, 20))
            button.setProperty("action", True)
            button.clicked.connect(lambda checked=False, s=signal: s.emit())
        self.btn_protection.clicked.connect(lambda checked=False: self.toggle_protection.emit())

        # обновление баз: текст «Обновляются» с бегущими точками и шкала под ним — видно, что
        # обновление идёт, а не стоит на месте
        self.db_bar = QProgressBar()
        self.db_bar.setRange(0, 1000)
        self.db_bar.setTextVisible(False)
        self.db_bar.setFixedHeight(8)
        self.db_bar.hide()
        card = child(ui, QFrame, "cardDatabases")
        card.layout().addWidget(self.db_bar)
        self._db_dots = 0
        self._db_timer = QTimer(self)
        self._db_timer.setInterval(450)
        self._db_timer.timeout.connect(self._tick_db_dots)

    def _tick_db_dots(self) -> None:
        self._db_dots = self._db_dots % 3 + 1
        self.labels["databases"].setText("Обновляются" + "." * self._db_dots)

    def set_db_progress(self, value: float) -> None:
        """Доля готовности обновления баз (0..1)."""
        self.db_bar.setValue(int(max(0.0, min(1.0, value)) * 1000))

    def _show_db_updating(self, on: bool, value: float = 0.0) -> None:
        self.db_bar.setVisible(on)
        if on:
            self.set_db_progress(value)
            if not self._db_timer.isActive():
                self._db_dots = 0
                self._tick_db_dots()
                self._db_timer.start()
        else:
            self._db_timer.stop()

    def set_button_visible(self, name: str, on: bool) -> None:
        """Кнопка быстрого действия (скрывается, если её инструмент запрещён)."""
        child(self.ui, QPushButton, name).setVisible(on)

    def _hero(self, color: str, icon, title: str, text: str) -> None:
        c = QColor(color)
        rgba = f"rgba({c.red()}, {c.green()}, {c.blue()}"
        self.hero.setStyleSheet(f"QFrame#frameHero {{ background: {rgba}, 0.13); "
                                f"border: 1px solid {rgba}, 0.55); border-radius: 10px; }}")
        self.hero_icon.setPixmap(self.style().standardIcon(icon).pixmap(48, 48))
        self.hero_title.setText(title)
        self.hero_title.setStyleSheet(f"font-size: 15pt; font-weight: 600; color: {color};"
                                      " background: transparent;")
        self.hero_text.setText(text)

    def refresh(self, info: dict) -> None:
        def state(label: QLabel, on: bool) -> None:
            label.setText("включена" if on else "выключена")
            label.setStyleSheet(f"font-size: 13pt; font-weight: 600; "
                                f"color: {self.GOOD if on else self.BAD};")

        state(self.labels["protection"], info["protection"])
        state(self.labels["network"], info["network"])
        self.labels["quarantine"].setText(str(info["quarantine"]))
        self.labels["whitelist"].setText(str(info["whitelist"]))
        self.labels["last_scan"].setText(info["last_scan"] or "ещё не выполнялась")
        self.btn_protection.setText(
            "Выключить защиту" if info["protection"] else "Включить защиту")

        updated = info.get("db_updated") or 0
        stale = not updated or time.time() - updated > 3 * 86400
        updating = bool(info.get("db_updating"))
        self._show_db_updating(updating, info.get("db_progress") or 0.0)
        if not updating:
            self.labels["databases"].setText(
                time.strftime("обновлены %d.%m.%Y %H:%M", time.localtime(updated)) if updated
                else "ещё не обновлялись")
        self.labels["databases"].setStyleSheet(
            "font-size: 11pt; font-weight: 600;" +
            (f" color: {self.WARN};" if stale and not updating else ""))

        icons = QStyle.StandardPixmap
        if not info["protection"]:
            self._hero(self.BAD, icons.SP_MessageBoxCritical, "Защита выключена",
                       "Новые и изменённые файлы не проверяются. Включите защиту, чтобы "
                       "следить за загрузками, автозагрузкой и системными папками.")
        elif stale and not info.get("db_updating"):
            self._hero(self.WARN, icons.SP_MessageBoxWarning, "Компьютер под защитой",
                       "Базы сигнатур давно не обновлялись: они обновятся автоматически, "
                       "как только будет доступна сеть.")
        else:
            details = info.get("protection_text") or "Файлы проверяются при появлении."
            self._hero(self.GOOD, icons.SP_DialogApplyButton, "Компьютер под защитой", details)

        self.events.clear()
        events = info.get("events") or []
        if not events:
            self.events.addItem("Событий пока нет")
        for when, text, level in events:
            item = QListWidgetItem(f"{when}  {text}")
            if level == "threat":
                item.setForeground(QBrush(QColor(self.BAD)))
            self.events.addItem(item)



class ToolsPage(_UiPage):
    UI_NAME = "tools_page"

    # группа: цвет значков; кнопка: значок и короткое описание на плитке
    GROUPS = {"groupDetect": "#d9534f", "groupAnalysis": "#2f7ed8", "groupRecovery": "#2e9e4f"}
    TILES = {
        "btnAutoruns": ("🚀", "Программы, которые запускаются вместе с Windows"),
        "btnMemoryDeep": ("🧠", "Внедрённый код в памяти процессов"),
        "btnFileAnalyzer": ("🔍", "Проверка файла или папки всеми слоями"),
        "btnProcessManager": ("⚙️", "Процессы, их подписи, сеть и память"),
        "btnRestorePoint": ("💾", "Снимок системы перед изменениями"),
        "btnSfcDism": ("🩹", "Восстановление системных файлов Windows"),
        "btnSystemChecks": ("🛡️", "Настройки, которые меняют вредоносы, с исправлением"),
        "btnUndoJournal": ("↩️", "Что сделала программа, и отмена действий"),
        "btnUsb": ("🔌", "Вирус-ярлык на флешке: найти и вернуть файлы"),
        "btnLinkCheck": ("🔗", "Ссылка и файл по ней — до того, как открыть"),
        "btnPasswordLeak": ("🔑", "Не утёк ли пароль — без отправки самого пароля"),
        "btnDrivers": ("🧩", "Уязвимые драйверы, через которые выключают защиту"),
        "btnExtensions": ("🧭", "Расширения браузеров, их права и уведомления сайтов"),
        "btnVpn": ("🌐", "Подключение к интернету через VPN-сервер"),
    }
    STYLE = """
        QGroupBox { background: palette(base); border: 1px solid palette(mid);
                    border-radius: 10px; margin-top: 16px; padding: 14px 8px 8px 8px;
                    font-size: 11pt; font-weight: 600; }
        QGroupBox::title { subcontrol-origin: margin; left: 14px; padding: 0 4px; }
        QPushButton[tile="true"] { border: 1px solid palette(mid); border-radius: 8px;
                                   background: palette(window); }
        QPushButton[tile="true"]:hover { border: 1px solid palette(highlight); }
        QPushButton[tile="true"]:pressed { background: palette(alternate-base); }
        QLabel { background: transparent; border: none; }
        QLabel[role="title"] { font-size: 10.5pt; font-weight: 600; }
        QLabel[role="desc"] { font-size: 9pt; font-weight: 400;
                              color: palette(placeholder-text); }
    """

    def __init__(self, window):
        super().__init__()
        self.window_ref = window
        bind_features(self, self.ui, window)
        self.ui.setStyleSheet(self.STYLE)
        self._titles: dict[str, tuple[QLabel, str]] = {}
        for group_name, color in self.GROUPS.items():
            group = child(self.ui, QGroupBox, group_name)
            for button in group.findChildren(QPushButton):
                self._make_tile(button, color)
            if isinstance(group.layout(), QVBoxLayout):
                group.layout().addStretch()  # плитки прижаты к верху группы
        self.btn_admin = child(self.ui, QPushButton, "btnRelaunchAdmin")
        self.btn_admin.setVisible(not is_admin())  # с правами администратора кнопка не нужна
        if window is not None:
            self.btn_admin.clicked.connect(lambda checked=False: window.restart_as_admin())
        self.apply_access()

    def _make_tile(self, button: QPushButton, color: str) -> None:
        """Плитка вместо плоской кнопки: значок в цветном квадрате, название, описание."""
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import QHBoxLayout
        icon, desc = self.TILES.get(button.objectName(), ("•", ""))
        title = button.text()
        button.setText("")
        button.setAccessibleName(title)
        button.setProperty("tile", True)
        button.setMinimumHeight(66)
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        row = QHBoxLayout(button)
        row.setContentsMargins(10, 8, 10, 8)
        row.setSpacing(12)
        badge = QLabel(icon)
        badge.setFixedSize(42, 42)
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        c = QColor(color)
        badge.setStyleSheet(f"background: rgba({c.red()}, {c.green()}, {c.blue()}, 0.18); "
                            f"border: 1px solid rgba({c.red()}, {c.green()}, {c.blue()}, 0.5); "
                            "border-radius: 9px; font-size: 17pt;")
        text = QVBoxLayout()
        text.setSpacing(1)
        name = QLabel(title)
        name.setProperty("role", "title")
        about = QLabel(desc)
        about.setProperty("role", "desc")
        about.setWordWrap(True)
        text.addWidget(name)
        text.addWidget(about)
        row.addWidget(badge)
        row.addLayout(text, 1)
        for label in (badge, name, about):
            label.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self._titles[button.objectName()] = (name, title)

    def apply_access(self) -> None:
        """Запрещённые инструменты неактивны, подсказка — где снять запрет."""
        from ui import access
        for button_id in access.TOOL_LOCKS:
            button = self.ui.findChild(QPushButton, button_id)
            if button is not None:
                allowed = access.allowed(button_id)
                button.setEnabled(allowed)
                button.setToolTip(FEATURES[button_id].plan if allowed else access.LOCKED_TIP)
                if button_id in self._titles:
                    label, title = self._titles[button_id]
                    label.setText(title if allowed else f"{title}   🔒")


class SettingsPage(_UiPage):
    UI_NAME = "settings_page"
    changed = Signal(str, object)  # ключ, новое значение
    advanced_requested = Signal()  # кнопка «Режим администратора»
    info_collected = Signal(str, str)  # путь к архиву, ошибка («» — успех)

    def __init__(self):
        super().__init__()
        ui = self.ui
        self.chk_autostart = child(ui, QCheckBox, "chkAutostart")
        # «Запуск» и «Плановая проверка» — только после пароля, как «Проверка» и «Запреты»
        self.group_startup = child(ui, QGroupBox, "groupStartup")
        self.group_schedule = child(ui, QGroupBox, "groupSchedule")
        self.group_startup.setVisible(False)
        self.group_schedule.setVisible(False)
        self.chk_block_exit = child(ui, QCheckBox, "chkBlockExit")
        self.chk_on_top = child(ui, QCheckBox, "chkOnTop")
        self.cmb_theme = child(ui, QComboBox, "cmbTheme")
        self.cmb_theme.clear()  # список тем задаётся в ui/theme.py
        self.cmb_theme.addItems([title for _, title in THEME_LIST])
        self.spn_threshold = child(ui, QSpinBox, "spnThreshold")
        self.spn_workers = child(ui, QSpinBox, "spnWorkers")
        self.spn_interval = child(ui, QSpinBox, "spnInterval")
        self.chk_decoys = child(ui, QCheckBox, "chkDecoys")
        self.chk_launch = child(ui, QCheckBox, "chkLaunchGuard")
        self.chk_stealer = child(ui, QCheckBox, "chkStealerGuard")
        self.chk_amsi = child(ui, QCheckBox, "chkAmsi")
        self.chk_pslog = child(ui, QCheckBox, "chkPsLog")
        self.chk_pslog_all = child(ui, QCheckBox, "chkPsLogAll")
        from PySide6.QtWidgets import QTimeEdit
        from scanner import schedule
        self.chk_schedule = child(ui, QCheckBox, "chkSchedule")
        self.cmb_schedule_kind = child(ui, QComboBox, "cmbScheduleKind")
        self.cmb_schedule_period = child(ui, QComboBox, "cmbSchedulePeriod")
        self.time_schedule = child(ui, QTimeEdit, "timeSchedule")
        self.lbl_schedule_next = child(ui, QLabel, "lblScheduleNext")
        self._kinds, self._periods = list(schedule.KINDS), list(schedule.PERIODS)
        self.cmb_schedule_kind.addItems(list(schedule.KINDS.values()))
        self.cmb_schedule_period.addItems(list(schedule.PERIODS.values()))
        self.group_scan = child(ui, QGroupBox, "groupScan")
        self.group_scan.setVisible(False)  # открывается паролем режима отладки
        self.group_locks = child(ui, QGroupBox, "groupLocks")
        self.group_locks.setVisible(False)
        from scanner import cpucores
        from scanner.pool import MODES
        self.cmb_scan_mode = child(ui, QComboBox, "cmbScanMode")
        self.cmb_scan_mode.clear()
        self._modes = list(MODES)
        for key in self._modes:
            count, title, _ = MODES[key]
            self.cmb_scan_mode.addItem(f"{title} ({count} процесса)" if count < 5
                                       else f"{title} ({count} процессов)")
        self.lbl_scan_mode = child(ui, QLabel, "lblScanModeHint")
        self.chk_ecores = child(ui, QCheckBox, "chkEcoresOnly")
        self.lbl_ecores = child(ui, QLabel, "lblEcoresHint")
        ecore_text = ("Если испытываете проблемы с производительностью, включите данный "
                      "параметр, чтобы все процессы проверки работали только на "
                      "энергоэффективных ядрах и не отнимали производительные у игр, "
                      "браузера и других программ. Проверка станет медленнее.")
        if cpucores.efficiency_cpus():
            self.lbl_ecores.setText(ecore_text + " " + cpucores.describe().capitalize() + ".")
        else:
            self.chk_ecores.setEnabled(False)
            self.lbl_ecores.setText("Недоступно: в этом процессоре нет энергоэффективных "
                                    "ядер (" + cpucores.describe() + ").")
        self.chk_ecores.setToolTip(ecore_text)
        self.chk_revocation = child(ui, QCheckBox, "chkRevocation")
        self.locks = {key: child(ui, QCheckBox, name) for key, name in (
            ("lock/protection", "chkLockProtection"), ("lock/network", "chkLockNetwork"),
            ("lock/restore_point", "chkLockRestorePoint"), ("lock/sfc_dism", "chkLockSfcDism"),
            ("lock/memory", "chkLockMemory"), ("lock/usb", "chkLockUsb"),
            ("lock/autoruns", "chkLockAutoruns"), ("lock/file_analyzer", "chkLockFileAnalyzer"),
            ("lock/process_manager", "chkLockProcessManager"),
            ("lock/link_check", "chkLockLinkCheck"), ("lock/password_leak", "chkLockPasswordLeak"),
            ("lock/system_checks", "chkLockSystemChecks"), ("lock/journal", "chkLockJournal"),
            ("lock/drivers", "chkLockDrivers"), ("lock/extensions", "chkLockExtensions"),
            ("lock/vpn", "chkLockVpn"))}
        self.btn_advanced = child(ui, QPushButton, "btnAdvanced")
        self.btn_advanced.clicked.connect(lambda checked=False: self.advanced_requested.emit())
        # «Сведения для разработчика» — видны всем (diag/bundle.py)
        self.lbl_support = child(ui, QLabel, "lblSupport")
        self.btn_collect = child(ui, QPushButton, "btnCollectInfo")
        self.btn_collect.clicked.connect(lambda checked=False: self.collect_info())
        self.info_collected.connect(self._on_info_collected)
        from diag import edition
        if edition.is_test():
            self.lbl_support.setText(self.lbl_support.text() + " В тестовой версии в архив "
                                     "входят ещё комментарии со снимками экрана и статусы "
                                     "проверенных функций.")
        self._all = (self.chk_autostart, self.chk_block_exit,
                     self.chk_on_top, self.cmb_theme, self.spn_threshold,
                     self.spn_workers, self.spn_interval,
                     self.chk_decoys, self.cmb_scan_mode, self.chk_ecores,
                     self.chk_revocation, self.chk_launch, self.chk_stealer, self.chk_amsi,
                     self.chk_pslog, self.chk_pslog_all,
                     self.chk_schedule, self.cmb_schedule_kind, self.cmb_schedule_period,
                     self.time_schedule, *self.locks.values())
        self.load_values()
        from ui.widgets import guard_wheel
        guard_wheel(ui)  # колесо над полем прокручивает страницу, значение — после щелчка

        self.chk_autostart.toggled.connect(self._on_autostart)
        self.chk_block_exit.toggled.connect(lambda v: self._save("general/block_exit", v))
        self.chk_on_top.toggled.connect(lambda v: self._save("general/on_top", v))
        self.chk_decoys.toggled.connect(lambda v: self._save("protect/decoys", v))
        self.chk_launch.toggled.connect(lambda v: self._save("protect/launch", v))
        self.chk_stealer.toggled.connect(lambda v: self._save("protect/stealer", v))
        self.chk_amsi.toggled.connect(lambda v: self._save("protect/amsi", v))
        self.chk_pslog.toggled.connect(lambda v: self._save("protect/pslog", v))
        self.chk_pslog_all.toggled.connect(lambda v: self._save("protect/pslog_all", v))
        self.chk_schedule.toggled.connect(self._on_schedule_enabled)
        self.cmb_schedule_kind.currentIndexChanged.connect(
            lambda i: self._save("schedule/kind", self._kinds[i]))
        self.cmb_schedule_period.currentIndexChanged.connect(self._on_schedule_period)
        self.time_schedule.timeChanged.connect(
            lambda t: self._save("schedule/time", t.toString("HH:mm")))
        self.cmb_theme.currentIndexChanged.connect(
            lambda i: self._save("general/theme", THEMES[i]))
        self.spn_threshold.valueChanged.connect(lambda v: self._save("scan/threshold", v))
        self.spn_workers.valueChanged.connect(lambda v: self._save("scan/workers", v))
        self.spn_interval.valueChanged.connect(lambda v: self._save("process/interval", v))
        self.cmb_scan_mode.currentIndexChanged.connect(self._on_scan_mode)
        self.chk_ecores.toggled.connect(lambda v: self._save("scan/ecores_only", v))
        self.chk_revocation.toggled.connect(lambda v: self._save("scan/revocation", v))
        for key, box in self.locks.items():
            box.toggled.connect(lambda v, k=key: self._save(k, v))
        # сброс снимает и запреты: только после пароля
        self.btn_reset = child(ui, QPushButton, "btnReset")
        self.btn_reset.clicked.connect(lambda checked=False: self._reset())
        self.btn_reset.setVisible(False)

    def collect_info(self) -> None:
        """Кнопка «Собрать сведения о программе»: куда сохранить — спросить, собрать в фоне
        (журналы до десятков МБ, снимок запускает ядра VPN за версиями)."""
        from pathlib import Path

        from PySide6.QtCore import QStandardPaths
        from PySide6.QtWidgets import QFileDialog

        from diag import bundle, features
        folder = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DesktopLocation)
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить сведения о программе",
                                              str(Path(folder) / bundle.default_name()),
                                              "Архив ZIP (*.zip)")
        if not path:
            return
        self.btn_collect.setEnabled(False)
        self.btn_collect.setText("Собираю сведения...")
        features.begin("settings.collect_info")

        def job():
            try:
                manifest = bundle.collect(Path(path))
                features.step("settings.collect_info", f"файлов: {manifest['files']}")
                self.info_collected.emit(path, "")
            except Exception as e:  # noqa: BLE001 — показать пользователю
                self.info_collected.emit(path, str(e))

        import threading
        threading.Thread(target=job, daemon=True, name="collect-info").start()

    def _on_info_collected(self, path: str, error: str) -> None:
        from diag import features
        from analyzer import fileops
        self.btn_collect.setEnabled(True)
        self.btn_collect.setText("Собрать сведения о программе (.zip)")
        features.end_if_active("settings.collect_info", not error, error=error)
        if error:
            QMessageBox.warning(self, "Сведения о программе", f"Не удалось собрать архив: {error}")
            return
        box = QMessageBox(QMessageBox.Icon.Information, "Сведения о программе",
                          f"Архив сохранён:\n{path}\n\nПередайте его разработчику.", parent=self)
        show = box.addButton("Показать в проводнике", QMessageBox.ButtonRole.ActionRole)
        box.addButton(QMessageBox.StandardButton.Ok)
        box.exec()
        if box.clickedButton() is show:
            fileops.show_in_explorer(path)

    def add_admin_group(self, group: QWidget) -> None:
        layout = self.group_locks.parentWidget().layout()
        layout.insertWidget(layout.indexOf(self.group_locks) + 1, group)
        group.setVisible(False)
        self._admin_extra = [*getattr(self, "_admin_extra", []), group]

    def set_debug(self, on: bool) -> None:
        """Разделы «Запуск», «Плановая проверка», «Проверка», «Запреты» и «Пароль
        администратора» видны только в режиме администратора."""
        for group in (self.group_startup, self.group_schedule, self.group_scan,
                      self.group_locks, self.btn_reset, *getattr(self, "_admin_extra", [])):
            group.setVisible(on)
        self.btn_advanced.setText("Выйти из режима администратора" if on
                                  else "Режим администратора")

    def load_values(self) -> None:
        for widget in self._all:
            widget.blockSignals(True)
        self.chk_autostart.setChecked(cfg.autostart_enabled())
        self.chk_block_exit.setChecked(cfg.get("general/block_exit"))
        self.chk_on_top.setChecked(cfg.get("general/on_top"))
        self.chk_decoys.setChecked(cfg.get("protect/decoys"))
        self.chk_launch.setChecked(cfg.get("protect/launch"))
        self.chk_stealer.setChecked(cfg.get("protect/stealer"))
        self.chk_amsi.setChecked(cfg.get("protect/amsi"))
        self.chk_pslog.setChecked(cfg.get("protect/pslog"))
        self.chk_pslog_all.setChecked(cfg.get("protect/pslog_all"))
        from PySide6.QtCore import QTime
        from scanner import schedule
        self.chk_schedule.setChecked(cfg.get("schedule/enabled"))
        kind, period = cfg.get("schedule/kind"), cfg.get("schedule/period")
        self.cmb_schedule_kind.setCurrentIndex(self._kinds.index(kind)
                                               if kind in self._kinds else 0)
        self.cmb_schedule_period.setCurrentIndex(self._periods.index(period)
                                                 if period in self._periods else 0)
        hours, minutes = schedule.parse_time(cfg.get("schedule/time"))
        self.time_schedule.setTime(QTime(hours, minutes))
        self._schedule_widgets(self.chk_schedule.isChecked())
        theme = cfg.get("general/theme")
        self.cmb_theme.setCurrentIndex(THEMES.index(theme) if theme in THEMES else 0)
        self.spn_threshold.setValue(cfg.get("scan/threshold"))
        self.spn_workers.setValue(cfg.get("scan/workers"))
        self.spn_interval.setValue(cfg.get("process/interval"))
        mode = cfg.get("scan/mode")
        self.cmb_scan_mode.setCurrentIndex(self._modes.index(mode) if mode in self._modes else 1)
        self._show_mode_hint()
        self.chk_ecores.setChecked(cfg.get("scan/ecores_only") and self.chk_ecores.isEnabled())
        self.chk_revocation.setChecked(cfg.get("scan/revocation"))
        for key, box in self.locks.items():
            box.setChecked(cfg.get(key))
        for widget in self._all:
            widget.blockSignals(False)

    def _schedule_widgets(self, on: bool) -> None:
        for w in (self.cmb_schedule_kind, self.cmb_schedule_period, self.time_schedule):
            w.setEnabled(on)

    def _restart_schedule(self) -> None:
        """Отсчёт заново: первая проверка — в ближайшее выбранное время."""
        cfg.set_("schedule/last_run", 0.0)
        cfg.set_("schedule/postponed", 0.0)

    def _on_schedule_enabled(self, on: bool) -> None:
        self._schedule_widgets(on)
        if on:
            self._restart_schedule()
        self._save("schedule/enabled", on)

    def _on_schedule_period(self, index: int) -> None:
        self._save("schedule/period", self._periods[index])

    def set_schedule_text(self, text: str) -> None:
        self.lbl_schedule_next.setText(text)

    def _show_mode_hint(self) -> None:
        from scanner.pool import MODES
        key = self._modes[max(0, self.cmb_scan_mode.currentIndex())]
        count, title, hint = MODES[key]
        self.lbl_scan_mode.setText(f"{title}: {hint[0].lower() + hint[1:]}. Каждый процесс "
                                   f"занимает одно ядро и около 70 МБ памяти на время проверки.")

    def _on_scan_mode(self, index: int) -> None:
        self._show_mode_hint()
        self._save("scan/mode", self._modes[index])

    def _save(self, key: str, value) -> None:
        cfg.set_(key, value)
        self.changed.emit(key, value)

    def _on_autostart(self, checked: bool) -> None:
        try:
            cfg.set_autostart(checked)
            cfg.set_("startup/autostart", checked)
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
            cfg.set_autostart(cfg.get("startup/autostart"))  # по умолчанию — выключен
        except OSError:
            pass
        self.load_values()
        for key in ("general/on_top", "general/theme", "scan/threshold", "scan/mode",
                    "protect/decoys", *self.locks):
            self.changed.emit(key, cfg.get(key))


class AboutPage(_UiPage):
    UI_NAME = "about_page"

    STYLE = """
        QFrame[card="true"] { background: palette(base); border: 1px solid palette(mid);
                              border-radius: 10px; }
        QFrame[card="true"] QLabel { background: transparent; border: none; }
        QLabel[role="cardTitle"] { font-size: 11pt; font-weight: 600; }
    """

    def __init__(self):
        super().__init__()
        ui = self.ui
        ui.setStyleSheet(self.STYLE)
        for name in ("cardAbout", "cardWork", "cardTech", "cardNote"):
            card = child(ui, QFrame, name)
            card.layout().setContentsMargins(14, 12, 14, 12)
            # высота по содержимому: свободное место остаётся внизу страницы
            card.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
            if name in ("cardWork", "cardTech"):  # у соседней карточки текст выше
                card.layout().addStretch()
        icon = QApplication.windowIcon()
        if not icon.isNull():
            child(ui, QLabel, "lblIcon").setPixmap(icon.pixmap(72, 72))
        child(ui, QLabel, "lblAppName").setText(appinfo.APP_NAME)
        child(ui, QLabel, "lblVersion").setText(f"Версия {appinfo.VERSION} · {appinfo.YEAR}")
        child(ui, QLabel, "lblDescription").setText(appinfo.DESCRIPTION)
        child(ui, QLabel, "lblFeatures").setText(
            "<br>".join(f"✔&nbsp;&nbsp;{line}" for line in appinfo.FEATURES))
        child(ui, QLabel, "lblThesis").setText(f"<b>Тема:</b> {appinfo.THESIS}")

        author = f"<b>Автор:</b> {appinfo.AUTHOR}"
        if appinfo.ORGANIZATION:
            author += f"<br>{appinfo.ORGANIZATION}"
        if appinfo.SUPERVISOR:
            author += f"<br><b>Руководитель:</b> {appinfo.SUPERVISOR}"
        author += f"<br><b>Год:</b> {appinfo.YEAR}"
        child(ui, QLabel, "lblAuthor").setText(author)

        child(ui, QLabel, "lblComponents").setText(appinfo.COMPONENTS)
        child(ui, QLabel, "lblDisclaimer").setText(appinfo.DISCLAIMER)
        repo = child(ui, QPushButton, "btnRepo")
        repo.clicked.connect(
            lambda checked=False: QDesktopServices.openUrl(QUrl(appinfo.REPO_URL)))
        # обновление программы (updatecheck.py): кнопка рядом со ссылкой на репозиторий
        self.update_btn = QPushButton("Проверить обновления")
        self.update_btn.setToolTip("Последний выпуск на GitHub: установщик проверяется по "
                                   "SHA256SUMS и подписи, запускается только с вашего согласия")
        repo.parentWidget().layout().addWidget(self.update_btn)
        self._admin_groups: list[QWidget] = []

    def add_admin_group(self, group: QWidget) -> None:
        """Раздел, видный только в режиме администратора (отчёт о работе программы)."""
        layout = self.ui.layout()  # сразу под карточками, до распорки внизу страницы
        layout.insertWidget(layout.indexOf(child(self.ui, QFrame, "cardNote")) + 1, group)
        group.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
        group.setVisible(False)
        self._admin_groups.append(group)

    def set_admin(self, on: bool) -> None:
        for group in self._admin_groups:
            group.setVisible(on)


class DebugPage(_UiPage):
    """Служебная страница: только в тестовой версии, в режиме администратора. Раздел
    «Пароль администратора» (group_access) создаётся здесь, а показывается на странице
    «Настройки» — во всех версиях, тоже только в режиме администратора."""
    UI_NAME = "debug_page"
    password_changed = Signal(bool)  # True: пароль задан

    def __init__(self, window, gate: PasswordGate | None = None):
        super().__init__()
        self.gate = gate
        self.lbl_hashes = child(self.ui, QLabel, "lblHashes")
        self.lbl_rules = child(self.ui, QLabel, "lblRules")
        self.lbl_c2 = child(self.ui, QLabel, "lblC2")
        self.lbl_updated = child(self.ui, QLabel, "lblUpdated")
        self.lbl_password = child(self.ui, QLabel, "lblPasswordState")
        self.btn_set_password = child(self.ui, QPushButton, "btnSetPassword")
        self.btn_remove_password = child(self.ui, QPushButton, "btnRemovePassword")
        self.btn_default_password = child(self.ui, QPushButton, "btnDefaultPassword")
        self.btn_set_password.clicked.connect(lambda checked=False: self.set_password())
        self.btn_remove_password.clicked.connect(lambda checked=False: self.remove_password())
        self.btn_default_password.clicked.connect(lambda checked=False: self.toggle_default())
        bind_features(self, self.ui, window)
        self.update_password_state()
        self.group_access = child(self.ui, QGroupBox, "groupAccess")

    def update_password_state(self) -> None:
        own = self.gate is not None and self.gate.has_own_password()
        default = self.gate is not None and self.gate.has_default()
        self.btn_set_password.setText("Сменить свой пароль" if own else "Добавить свой пароль")
        self.btn_set_password.setEnabled(self.gate is not None)
        self.btn_remove_password.setText("Убрать свой пароль")
        self.btn_remove_password.setEnabled(own and default)
        self.btn_default_password.setText("Убрать пароль по умолчанию" if default
                                          else "Вернуть пароль по умолчанию")
        self.btn_default_password.setEnabled(own or not default)
        text = ("Режим администратора открывается кнопкой «Режим администратора» на "
                "странице «Настройки» после ввода пароля. ")
        text += ("Пароль по умолчанию действует и показывается подсказкой в окне ввода. "
                 if default else "Пароль по умолчанию убран: подсказки в окне ввода нет. ")
        if own:
            text += ("Свой пароль задан: он хранится только на этом компьютере и в релизную "
                     "версию не попадает.")
        else:
            text += "Чтобы убрать пароль по умолчанию, сначала задайте свой."
        self.lbl_password.setText(text)

    def toggle_default(self) -> None:
        enable = not self.gate.has_default()
        if not enable and QMessageBox.question(
                self, "Пароль", "Убрать пароль по умолчанию? Останется только ваш пароль, "
                "подсказки в окне ввода не будет.") != QMessageBox.StandardButton.Yes:
            return
        try:
            self.gate.set_default_enabled(enable)
        except (ValueError, OSError) as e:
            QMessageBox.warning(self, "Пароль", str(e))
            return
        self.update_password_state()

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
            also = " Пароль по умолчанию тоже продолжает действовать." \
                if self.gate.has_default() else ""
            QMessageBox.information(self, "Пароль", "Пароль сохранён." + also)
            return

    def remove_password(self) -> None:
        answer = QMessageBox.question(
            self, "Пароль", "Убрать свой пароль? Останется пароль по умолчанию.")
        if answer == QMessageBox.StandardButton.Yes:
            try:
                self.gate.remove_password()
            except (OSError, ValueError) as e:
                QMessageBox.warning(self, "Пароль", f"Не удалось убрать пароль: {e}")
                return
            self.update_password_state()
            self.password_changed.emit(False)

    def refresh(self, hashes: int, rules: int, rule_files: int, c2: int = 0,
                updated: float = 0, md5: int = 0) -> None:
        text = f"{hashes:,}".replace(",", " ")
        if md5:
            text += f" (из них MD5 VirusShare: {md5:,})".replace(",", " ")
        self.lbl_hashes.setText(text)
        self.lbl_rules.setText(f"{rules:,} (в {rule_files} файлах)".replace(",", " "))
        self.lbl_c2.setText(f"{c2:,}".replace(",", " "))
        self.lbl_updated.setText(
            time.strftime("%d.%m.%Y %H:%M:%S", time.localtime(updated)) if updated else
            "ещё не обновлялись (обновятся при первом запуске с доступом к сети)")
