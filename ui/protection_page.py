"""Страница «Защита»: состояние сверху, ниже — что под защитой, внизу — журнал защиты.

Только внешний вид: запуск и остановка защиты, папки и журнал — в gui.MainWindow, которое
берёт отсюда виджеты (watch_list, protect_btn, protect_status, protect_log, decoys_label...).
"""
from PySide6.QtCore import QSize, Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QFrame, QGridLayout, QHBoxLayout, QLabel, QListWidget,
    QProgressBar, QPushButton, QStyle, QVBoxLayout, QWidget,
)

GOOD, BAD = "#2e9e4f", "#c0392b"

STYLE = """
    QFrame[card="true"] { background: palette(base); border: 1px solid palette(mid);
                          border-radius: 10px; }
    QFrame[card="true"] QLabel { background: transparent; border: none; }
    QLabel[role="cardTitle"] { font-size: 11pt; font-weight: 600; }
    QLabel[role="hint"] { color: palette(placeholder-text); }
    QLabel[role="itemTitle"] { font-weight: 600; }
    QLabel[role="badge"] { font-size: 16pt; border-radius: 8px; }
    QFrame[card="true"] QListWidget { border: 1px solid palette(mid); border-radius: 6px; }
"""


def _label(text: str = "", role: str = "", wrap: bool = True) -> QLabel:
    label = QLabel(text)
    label.setWordWrap(wrap)
    if role:
        label.setProperty("role", role)
    return label


def _card(title: str) -> tuple[QFrame, QVBoxLayout]:
    card = QFrame()
    card.setProperty("card", True)
    layout = QVBoxLayout(card)
    layout.setContentsMargins(14, 12, 14, 12)
    layout.setSpacing(8)
    layout.addWidget(_label(title, "cardTitle"))
    return card, layout


class ProtectionPage(QWidget):
    def __init__(self, system_folders: list):
        super().__init__()
        self.setStyleSheet(STYLE)
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 12, 16, 12)
        root.setSpacing(12)
        title = QLabel("Защита")
        title.setStyleSheet("font-size: 20pt; font-weight: 600;")
        root.addWidget(title)

        # ---------- состояние ----------
        self.hero = QFrame()
        self.hero.setObjectName("protectionHero")
        hero = QHBoxLayout(self.hero)
        hero.setContentsMargins(16, 12, 16, 12)
        hero.setSpacing(14)
        self.hero_icon = QLabel()
        self.hero_icon.setFixedSize(48, 48)
        texts = QVBoxLayout()
        texts.setSpacing(2)
        self.hero_title = QLabel()
        self.protect_status = _label("Защита выключена")  # подробности от монитора
        texts.addWidget(self.hero_title)
        texts.addWidget(self.protect_status)
        self.protect_btn = QPushButton("Включить защиту")
        self.protect_btn.setMinimumSize(QSize(170, 36))
        hero.addWidget(self.hero_icon)
        hero.addLayout(texts, 1)
        hero.addWidget(self.protect_btn, 0, Qt.AlignmentFlag.AlignVCenter)
        root.addWidget(self.hero)

        grid = QGridLayout()
        grid.setSpacing(12)
        self.grid = grid

        # ---------- свои папки ----------
        card, layout = _card("Папки под наблюдением")
        layout.addWidget(_label("Здесь проверяются все новые и изменённые файлы. Менять "
                                "список можно, когда защита выключена.", "hint"))
        self.watch_list = QListWidget()
        self.watch_list.setMinimumHeight(90)
        # длинный путь сокращается в середине, целиком — в подсказке
        self.watch_list.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        self.watch_list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        layout.addWidget(self.watch_list, 1)
        row = QHBoxLayout()
        self.watch_add_btn = QPushButton("Добавить папку...")
        self.watch_remove_btn = QPushButton("Убрать выбранную")
        row.addWidget(self.watch_add_btn)
        row.addWidget(self.watch_remove_btn)
        row.addStretch()
        layout.addLayout(row)
        grid.addWidget(card, 0, 0)

        # ---------- что ещё под защитой ----------
        card, layout = _card("Также под защитой")
        system_tip = "\n".join(
            f"{folder}{'' if recursive else '  (без подпапок)'}"
            f"{'  — все файлы' if all_files else ''}" for folder, recursive, all_files in
            system_folders)
        system_row, _, _ = self._item(
            "🖥️", f"Системные папки ({len(system_folders)})",
            "Windows, автозагрузка, AppData, Program Files: программы и скрипты. Список — "
            "при наведении.")
        system_row.setToolTip(system_tip)
        layout.addWidget(system_row)
        decoys_row, self.decoys_label, decoys_layout = self._item(
            "🪤", "Ловушки для шифровальщиков", "")
        self.decoys_btn = QPushButton("Открыть папку")
        decoys_layout.addWidget(self.decoys_btn, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(decoys_row)
        usb_row, self.usb_label, _ = self._item("🔌", "Флешки", "")
        layout.addWidget(usb_row)
        launch_row, self.launch_label, _ = self._item("🚦", "Запуск программ", "")
        layout.addWidget(launch_row)
        stealer_row, self.stealer_label, _ = self._item("🔐", "Пароли и cookies браузеров", "")
        layout.addWidget(stealer_row)
        amsi_row, self.amsi_label, _ = self._item("📜", "Скрипты и макросы (AMSI)", "")
        layout.addWidget(amsi_row)
        layout.addStretch()
        self.also_card = card
        grid.addWidget(card, 0, 1)

        # ---------- полная проверка ----------
        card, layout = _card("Проверка дисков")
        layout.addWidget(_label(
            "Полная — все папки и файлы выбранного диска; в папках игр (Steam, Epic, Unity, "
            "Unreal) проверяются только программы и библиотеки, текстуры и архивы ресурсов "
            "пропускаются; перед файлами — весь автозапуск, проверка системы и память "
            "запущенных процессов. Найденное появится в журнале защиты. Расписание — в "
            "настройках.",
            "hint"))
        # быстрая — только для системного диска: видна, когда он выбран (gui.fill_drives)
        self.quick_hint = _label(
            "Быстрая — системный диск: файлы в корне диска, в папках Windows, System32 и "
            "SysWOW64 (до 16 МБ, без вложенных папок), вся папка пользователя (файлы до "
            "32 МБ) и весь автозапуск.", "hint")
        layout.addWidget(self.quick_hint)
        row = QHBoxLayout()
        self.full_drive = QComboBox()
        self.full_drive.setMinimumWidth(320)
        self.full_btn = QPushButton("Полная проверка")
        self.full_btn.setMinimumHeight(32)
        self.quick_btn = QPushButton("Быстрая проверка")
        self.quick_btn.setMinimumHeight(32)
        row.addWidget(QLabel("Диск:"))
        row.addWidget(self.full_drive, 1)
        row.addWidget(self.quick_btn)
        row.addWidget(self.full_btn)
        layout.addLayout(row)
        self.full_progress = QProgressBar()
        self.full_progress.setRange(0, 0)  # сколько всего файлов, заранее неизвестно
        self.full_progress.setTextVisible(False)
        self.full_progress.setMaximumHeight(6)
        self.full_progress.setVisible(False)
        layout.addWidget(self.full_progress)
        self.full_status = _label("", "hint")
        self.full_status.setVisible(False)
        layout.addWidget(self.full_status)
        # плановая проверка скоро начнётся: видно 10 минут до начала
        self.schedule_bar = QFrame()
        self.schedule_bar.setObjectName("scheduleBar")
        self.schedule_bar.setStyleSheet(
            "QFrame#scheduleBar { background: rgba(214, 137, 16, 0.12); "
            "border: 1px solid rgba(214, 137, 16, 0.55); border-radius: 8px; }")
        bar = QHBoxLayout(self.schedule_bar)
        bar.setContentsMargins(12, 8, 12, 8)
        self.schedule_label = _label("")
        self.schedule_now_btn = QPushButton("Начать сейчас")
        self.schedule_postpone_btn = QPushButton("Отложить на час")
        self.schedule_skip_btn = QPushButton("Пропустить")
        bar.addWidget(self.schedule_label, 1)
        for button in (self.schedule_now_btn, self.schedule_postpone_btn,
                       self.schedule_skip_btn):
            bar.addWidget(button)
        self.schedule_bar.setVisible(False)
        layout.addWidget(self.schedule_bar)
        grid.addWidget(card, 1, 0, 1, 2)

        # ---------- журнал ----------
        card, layout = _card("Журнал защиты")
        head = layout.itemAt(0).widget()
        layout.removeWidget(head)
        top = QHBoxLayout()
        top.addWidget(head)
        top.addStretch()
        self.log_hint = _label("Правый клик по угрозе: карантин, сканер, Проводник", "hint",
                               wrap=False)
        self.clear_log_btn = QPushButton("Очистить")
        top.addWidget(self.log_hint)
        top.addWidget(self.clear_log_btn)
        layout.insertLayout(0, top)
        self.protect_log = QListWidget()
        self.protect_log.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.protect_log.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.protect_log.setAlternatingRowColors(True)
        self.protect_log.setMinimumHeight(160)
        layout.addWidget(self.protect_log, 1)
        self.clear_log_btn.clicked.connect(self.protect_log.clear)
        grid.addWidget(card, 2, 0, 1, 2)

        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        grid.setRowStretch(2, 1)  # верхние карточки — по содержимому, остальное — журналу
        root.addLayout(grid, 1)
        self.set_running(False)
        from ui.widgets import guard_wheel
        guard_wheel(self)  # список дисков: колесо прокручивает страницу

    def refit(self) -> None:
        """Высота карточки «Также под защитой» — по тексту с переносами: сетка сама не
        учитывает перенос строк и обрезает пояснения. Вызывать после смены текстов."""
        QTimer.singleShot(0, self._refit)

    def _refit(self) -> None:
        card = self.also_card
        if card.width() > 0:
            height = card.layout().totalHeightForWidth(card.width())
            card.setMinimumHeight(height)
            self.grid.setRowMinimumHeight(0, height)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.refit()

    def showEvent(self, event):
        super().showEvent(event)
        self.refit()

    @staticmethod
    def _item(icon: str, title: str, text: str) -> tuple[QWidget, QLabel, QHBoxLayout]:
        """Строка «значок — название — пояснение»: строка, пояснение (для обновления) и
        её раскладка (чтобы добавить кнопку)."""
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 2, 0, 2)
        layout.setSpacing(10)
        badge = _label(icon, "badge", wrap=False)
        badge.setFixedSize(36, 36)
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setStyleSheet("background: rgba(127, 127, 127, 0.15);")
        texts = QVBoxLayout()
        texts.setSpacing(1)
        detail = _label(text, "hint")
        texts.addWidget(_label(title, "itemTitle"))
        texts.addWidget(detail)
        layout.addWidget(badge, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(texts, 1)
        return row, detail, layout

    def set_running(self, running: bool) -> None:
        color = QColor(GOOD if running else BAD)
        rgba = f"rgba({color.red()}, {color.green()}, {color.blue()}"
        self.hero.setStyleSheet(f"QFrame#protectionHero {{ background: {rgba}, 0.13); "
                                f"border: 1px solid {rgba}, 0.55); border-radius: 10px; }}")
        icon = (QStyle.StandardPixmap.SP_DialogApplyButton if running
                else QStyle.StandardPixmap.SP_MessageBoxCritical)
        self.hero_icon.setPixmap(self.style().standardIcon(icon).pixmap(40, 40))
        self.hero_title.setText("Защита включена" if running else "Защита выключена")
        self.hero_title.setStyleSheet(f"font-size: 15pt; font-weight: 600; color: {color.name()};"
                                      " background: transparent;")
        self.protect_status.setStyleSheet("background: transparent;")
        self.protect_btn.setText("Выключить защиту" if running else "Включить защиту")
        self.usb_label.setText("Проверяются при подключении, вирус-ярлык лечится сразу."
                               if running else "Не проверяются: защита выключена.")
        if not running:
            self.launch_label.setText("Не проверяется: защита выключена.")
            self.stealer_label.setText("Не охраняются: защита выключена.")
            self.amsi_label.setText("Не проверяются: защита выключена.")
        self.refit()
