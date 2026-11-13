"""Окно VPN: профили, подключение, маршрутизация, проверки, настройки клиента, журнал.

Профиль — в выпадающем списке сверху, большая круглая кнопка подключения, плитки состояния,
разделы (строятся _page_*) — кнопками слева. Профили маршрутизации — vpn/routingwindow.py
(карточка в «Настройках клиента»). Внешний IP проверяется сам: после подключения и раз в
IP_INTERVAL, на плитке — только начало и конец адреса (mask_ip).
"""
import os
import threading
import time

from PySide6.QtCore import QObject, Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QButtonGroup, QCheckBox, QComboBox, QDialog,
    QDialogButtonBox, QFileDialog, QFormLayout, QFrame, QGridLayout, QHBoxLayout,
    QHeaderView, QInputDialog, QLabel, QLineEdit, QListWidget, QMessageBox,
    QPlainTextEdit, QPushButton, QScrollArea, QSpinBox, QStackedWidget, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from analyzer.fileops import human_size
from recovery import activity
from ui import settings as cfg
from vpn import backends, profiles
import re

GREEN, ORANGE, RED, GREY, ACCENT = "#2e9e4f", "#d68910", "#c0392b", "#8a8a8a", "#2f7ed8"
STATE_TEXT = {backends.DISCONNECTED: ("Не подключено", GREY),
              backends.CONNECTING: ("Подключение...", ORANGE),
              backends.CONNECTED: ("Подключено", GREEN),
              backends.DISCONNECTING: ("Отключение...", ORANGE),
              backends.ERROR: ("Ошибка", RED)}
SECURITY = {"reality": "REALITY", "tls": "TLS", "none": "без шифрования"}
NETWORK = {"tcp": "TCP", "raw": "TCP", "ws": "WebSocket", "grpc": "gRPC", "xhttp": "XHTTP",
           "httpupgrade": "HTTPUpgrade", "splithttp": "XHTTP"}
CERT_INTERVAL = 600  # проверка сертификатов во время подключения, с
IP_INTERVAL = 3 * 3600  # внешний IP во время подключения, с
ROUTING_UPDATE = 600    # проверка ссылок профилей маршрутизации и списков AdBlock, с

STYLE = """
QFrame[card="true"] { background: palette(base); border: 1px solid palette(mid);
                      border-radius: 12px; }
QFrame[card="true"] QLabel { background: transparent; border: none; }
QLabel[role="title"] { font-size: 11pt; font-weight: 600; }
QLabel[role="hint"] { color: palette(placeholder-text); }
QLabel[role="tileValue"] { font-size: 14pt; font-weight: 600; }
QLabel[role="tileName"] { color: palette(placeholder-text); font-size: 9pt; }
QPushButton[nav="true"] { text-align: left; padding: 10px 14px; border: none;
                          border-radius: 8px; font-size: 10.5pt; }
QPushButton[nav="true"]:checked { background: palette(highlight); color: palette(highlighted-text); }
QPushButton[nav="true"]:hover:!checked { background: palette(alternate-base); }
"""


def _label(text: str = "", role: str = "", wrap: bool = True) -> QLabel:
    label = QLabel(text)
    label.setWordWrap(wrap)
    if role:
        label.setProperty("role", role)
    return label


def _card() -> tuple[QFrame, QVBoxLayout]:
    card = QFrame()
    card.setProperty("card", True)
    layout = QVBoxLayout(card)
    layout.setContentsMargins(16, 14, 16, 14)
    layout.setSpacing(8)
    return card, layout


def mask_ip(ip: str) -> str:
    """Адрес на экране: первые 3 и последние 2 символа, остальное — «*»."""
    ip = ip.strip()
    if len(ip) <= 5:
        return "*" * len(ip)
    return ip[:3] + "*" * (len(ip) - 5) + ip[-2:]


def _lines(key: str) -> list[str]:
    return [line.strip() for line in str(cfg.get(key) or "").splitlines() if line.strip()]


def protocol_text(p: profiles.Profile | None) -> str:
    """«VLESS · REALITY · TCP · Vision» — только сам протокол, без режима подключения."""
    if p is None:
        return "—"
    if p.kind != "vless":
        return profiles.KINDS.get(p.kind, p.kind)
    try:
        from vpn import xray
        v = xray.parse_vless(p.config)
    except ValueError:
        return "VLESS"
    parts = ["VLESS", SECURITY.get(v["security"], v["security"].upper()),
             NETWORK.get(v["network"], v["network"])]
    if v["flow"]:
        parts.append("Vision" if "vision" in v["flow"] else v["flow"])
    return " · ".join(parts)


def mode_text(p: profiles.Profile | None, backend=None) -> str:
    if p is None or p.kind != "vless":
        return "—"
    from vpn import xray
    if p.mode == "local":
        ports = getattr(backend, "local_ports", None) or xray.local_ports()
        names = [f"{'SOCKS5' if k == 'socks' else 'HTTP'} 127.0.0.1:{v}" for k, v in ports.items()]
        return "Только локальный прокси: " + (", ".join(names) or "порты выключены")
    return profiles.MODES.get(p.mode, p.mode)


class _Bridge(QObject):
    log = Signal(str)
    ip = Signal(str)
    probes = Signal(object)          # список checks.Probe
    cert_alarm = Signal(object)      # checks.Probe с подменённым сертификатом
    apps = Signal(object)            # список apps.App
    apps_progress = Signal(str)
    netdiag = Signal(object)         # список netdiag.Finding
    routing = Signal(object)         # сообщения об обновлении профилей маршрутизации


# ================================ диалоги ================================
class PasteDialog(QDialog):
    """Профиль из текста конфигурации (вставить из буфера)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Новый профиль VPN")
        self.resize(680, 460)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Название профиля (необязательно — возьмётся из ссылки):"))
        self.name = QLineEdit()
        self.name.setPlaceholderText("Например: Дом, Работа")
        layout.addWidget(self.name)
        layout.addWidget(QLabel("Ссылка vless:// или конфигурация WireGuard / OpenVPN:"))
        self.text = QPlainTextEdit()
        self.text.setPlaceholderText("vless://UUID@адрес:порт?...#название\n\nили текст "
                                     "конфигурации WireGuard ([Interface] ... [Peer]) или "
                                     "OpenVPN (client, remote ...)")
        layout.addWidget(self.text, 1)
        clip = QApplication.clipboard().text().strip()  # ссылка в буфере — сразу в поле
        if clip.lower().startswith("vless://"):
            self.text.setPlainText(clip)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                   QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


class DirectAppsDialog(QDialog):
    """Программы напрямую, мимо VPN: поиск по «Пуску», запущенным процессам и папкам
    установки; поиск по названию; «Только приложения» убирает .dll и служебные .exe."""

    _cache: list | None = None  # найденное — на время работы программы

    def __init__(self, parent, chosen: list[str]):
        super().__init__(parent)
        self.setWindowTitle("Программы напрямую, мимо VPN")
        self.resize(1100, 680)
        self.chosen = {os.path.normcase(p) for p in chosen}
        self.found: list = []
        self.bridge = _Bridge()
        self.bridge.apps.connect(self._on_found)
        self.bridge.apps_progress.connect(lambda t: self.status.setText(t))
        layout = QVBoxLayout(self)
        hint = _label("Отмеченные программы идут напрямую, мимо сервера VPN (режим TUN). "
                      "Программы найдены по ярлыкам «Пуска», запущенным процессам и папкам "
                      "Program Files, Program Files (x86), %LOCALAPPDATA%\\Programs и "
                      "библиотекам игр.", "hint")
        layout.addWidget(hint)
        row = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Поиск: название, описание или путь")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._fill)
        self.only_apps = QPushButton("Только приложения")
        self.only_apps.setCheckable(True)
        self.only_apps.setChecked(True)
        self.only_apps.setToolTip("Скрыть .dll и служебные .exe (установщики, обновление, "
                                  "отчёты об ошибках, помощники) — оставить то, что запускают")
        self.only_apps.toggled.connect(self._fill)
        self.only_chosen = QCheckBox("Только отмеченные")
        self.only_chosen.toggled.connect(self._fill)
        add = QPushButton("Добавить файл вручную...")
        add.clicked.connect(self._add_manual)
        row.addWidget(self.search, 1)
        row.addWidget(self.only_apps)
        row.addWidget(self.only_chosen)
        row.addWidget(add)
        layout.addLayout(row)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["", "Название", "Описание", "Где найдена", "Путь"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        for col, width in enumerate((34, 230, 260, 150)):
            self.table.setColumnWidth(col, width)
        self.table.itemChanged.connect(self._on_check)
        layout.addWidget(self.table, 1)
        self.status = _label("Ищу программы...", "hint")
        layout.addWidget(self.status)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                   QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        if DirectAppsDialog._cache is not None:
            self._on_found(DirectAppsDialog._cache)
        else:
            threading.Thread(target=self._discover, daemon=True).start()

    def _discover(self) -> None:
        from vpn import apps
        try:
            found = apps.discover(self.bridge.apps_progress.emit)
        except Exception as e:
            self.bridge.apps_progress.emit(f"Поиск не удался: {e}")
            found = []
        self.bridge.apps.emit(found)

    def _on_found(self, found) -> None:
        from vpn import apps
        DirectAppsDialog._cache = found
        known = {os.path.normcase(a.path) for a in found}
        for path in self.chosen - known:  # добавленные вручную раньше
            found = found + [apps.App(path, os.path.basename(path), sources={"вручную"},
                                      is_app=True)]
        self.found = found
        self._fill()

    SOURCE = {"start": "Пуск", "running": "запущена", "folder": "папка", "вручную": "вручную"}

    def _fill(self) -> None:
        text = self.search.text().strip().lower()
        self.table.blockSignals(True)
        self.table.setRowCount(0)
        shown = 0
        for app in self.found:
            key = os.path.normcase(app.path)
            checked = key in self.chosen
            if self.only_chosen.isChecked() and not checked:
                continue
            if self.only_apps.isChecked() and not app.is_app and not checked:
                continue
            if text and text not in f"{app.name} {app.description} {app.path}".lower():
                continue
            row = self.table.rowCount()
            self.table.insertRow(row)
            box = QTableWidgetItem()
            box.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            box.setCheckState(Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)
            box.setData(Qt.ItemDataRole.UserRole, app.path)
            self.table.setItem(row, 0, box)
            where = ", ".join(self.SOURCE.get(s, s) for s in sorted(app.sources))
            for col, value in enumerate((app.name, app.description, where, app.path), start=1):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.table.setItem(row, col, item)
            shown += 1
            if shown >= 3000:
                break
        self.table.blockSignals(False)
        total = len(self.found)
        apps_count = sum(a.is_app for a in self.found)
        self.status.setText(f"Показано: {shown}. Найдено файлов: {total}, из них приложений: "
                            f"{apps_count}. Отмечено: {len(self.chosen)}.")

    def _on_check(self, item: QTableWidgetItem) -> None:
        if item.column() != 0:
            return
        key = os.path.normcase(item.data(Qt.ItemDataRole.UserRole))
        if item.checkState() == Qt.CheckState.Checked:
            self.chosen.add(key)
        else:
            self.chosen.discard(key)

    def _add_manual(self) -> None:
        from vpn import apps
        path, _ = QFileDialog.getOpenFileName(self, "Программа", "", "Программы (*.exe)")
        if not path:
            return
        key = os.path.normcase(os.path.normpath(path))
        self.chosen.add(key)
        if all(os.path.normcase(a.path) != key for a in self.found):
            self.found = [apps.App(key, os.path.basename(path), sources={"вручную"},
                                   is_app=True)] + self.found
        self._fill()

    def apps(self) -> list[str]:
        paths = {os.path.normcase(a.path): a.path for a in self.found}
        return [paths.get(k, k) for k in sorted(self.chosen)]


def builtin_rules() -> dict[str, list[str]]:
    """Встроенные правила выбранного профиля маршрутизации строками (см. routingwindow)."""
    from vpn import routing
    from vpn.routingwindow import builtin_lines
    return builtin_lines(routing.active())


# ================================ окно ================================
class VpnWindow(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("VPN")
        self.setWindowFlag(Qt.WindowType.Window)
        self.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint)
        self.setMinimumSize(1200, 760)
        self.resize(1460, 900)
        self.setStyleSheet(STYLE)
        self.profiles = profiles.load()
        if not self.profiles:
            self.profiles = [profiles.demo_profile()]
        self.backend: backends.Backend | None = None
        self.active: profiles.Profile | None = None
        self._last = (0, 0, time.monotonic())
        self._log_lines: list[str] = []
        self._probes: list = []
        self._cert_last = 0.0
        self.bridge = _Bridge()
        self._core_key, self._core_since, self._core_repeats = "", 0.0, 0
        self.bridge.log.connect(self._append_log)
        self.bridge.ip.connect(self._on_ip)
        self.bridge.netdiag.connect(self._on_netdiag)
        self.bridge.probes.connect(self._on_probes)
        self.bridge.cert_alarm.connect(self._on_cert_alarm)
        self.bridge.routing.connect(self._on_routing_update)
        self._ip_text = ""
        self._ip_backend = None   # подключение, для которого считается срок проверки IP
        self._ip_next = 0.0
        self._ip_busy = False
        self._routing_next = time.monotonic() + 30  # первая проверка ссылок — через 30 с
        self.root = QVBoxLayout(self)
        self.root.setContentsMargins(0, 0, 0, 0)
        self._build()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(1000)
        self._tick()

    # ---------------- построение ----------------
    def _build(self) -> None:
        self.body = QWidget()
        self.root.addWidget(self.body)
        self._build_modern(self.body)
        from ui.widgets import guard_wheel
        guard_wheel(self.body)
        self._fill_profiles()
        self._render_log()
        self._on_probes(self._probes)
        self._tick()

    def _header(self) -> QHBoxLayout:
        row = QHBoxLayout()
        title = QLabel("VPN")
        title.setStyleSheet("font-size: 18pt; font-weight: 700;")
        row.addWidget(title)
        row.addStretch()
        return row

    def _profile_buttons(self) -> QHBoxLayout:
        row = QHBoxLayout()
        for text, slot, tip in (("Вставить...", self._paste, "Ссылка vless:// или текст"),
                                ("Импорт файла...", self._import, ".conf или .ovpn"),
                                ("Переименовать", self._rename, ""),
                                ("Удалить", self._delete, "")):
            button = QPushButton(text)
            button.setToolTip(tip)
            button.clicked.connect(slot)
            row.addWidget(button)
        return row

    def _build_modern(self, body: QWidget) -> None:
        outer = QVBoxLayout(body)
        outer.setContentsMargins(18, 14, 18, 14)
        outer.setSpacing(12)
        outer.addLayout(self._header())
        # герой: кнопка и плитки
        hero, hl = _card()
        hrow = QHBoxLayout()
        hrow.setSpacing(24)
        self.connect_btn = QPushButton("Подключить")
        self.connect_btn.setFixedSize(150, 150)
        self.connect_btn.clicked.connect(self.toggle)
        hrow.addWidget(self.connect_btn, 0, Qt.AlignmentFlag.AlignVCenter)
        texts = QVBoxLayout()
        self.state_label = QLabel()
        texts.addWidget(self.state_label)
        self.protocol_label = _label("", "hint")
        self.protocol_label.setStyleSheet("font-size: 11pt;")
        texts.addWidget(self.protocol_label)
        self.mode_label_big = _label("", "hint")
        texts.addWidget(self.mode_label_big)
        self.error_label = _label("")
        self.error_label.setStyleSheet(f"color: {RED};")
        texts.addWidget(self.error_label)
        self.unblock_btn = QPushButton("Снять блокировку интернета (kill switch)")
        self.unblock_btn.setStyleSheet(f"color: {RED}; font-weight: 600;")
        self.unblock_btn.clicked.connect(self._release_block)
        texts.addWidget(self.unblock_btn, 0, Qt.AlignmentFlag.AlignLeft)
        self.netdiag_btn = QPushButton("Почему нет интернета?")
        self.netdiag_btn.setToolTip("Проверить связь, kill switch, брандмауэр, системный прокси "
                                    "и чужие VPN-клиенты с туннелем (ничего не меняет)")
        self.netdiag_btn.clicked.connect(self._run_netdiag)
        texts.addWidget(self.netdiag_btn, 0, Qt.AlignmentFlag.AlignLeft)
        texts.addStretch()
        hrow.addLayout(texts, 1)
        tiles = QGridLayout()
        tiles.setSpacing(10)
        self.tiles = {}
        for i, (key, name) in enumerate((("time", "Время"), ("speed", "Скорость"),
                                         ("rx", "Получено"), ("tx", "Отправлено"),
                                         ("server", "Сервер"), ("ip", "Внешний IP"))):
            tile, tl = _card()
            tl.setContentsMargins(12, 8, 12, 8)
            tl.setSpacing(2)
            tl.addWidget(_label(name, "tileName"))
            value = _label("—", "tileValue", wrap=False)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            tl.addWidget(value)
            tile.setMinimumWidth(190)
            tiles.addWidget(tile, i // 3, i % 3)
            self.tiles[key] = value
        hrow.addLayout(tiles)
        hl.addLayout(hrow)
        outer.addWidget(hero)
        # разделы
        lower = QHBoxLayout()
        nav = QVBoxLayout()
        nav.setSpacing(4)
        self.stack = QStackedWidget()
        group = QButtonGroup(self.body)
        self.section_index = {}
        for i, (key, title, page) in enumerate(self._pages()):
            button = QPushButton(title)
            button.setProperty("nav", True)
            button.setCheckable(True)
            button.setMinimumWidth(190)
            group.addButton(button, i)
            nav.addWidget(button)
            self.stack.addWidget(self._scroll(page))
            self.section_index[key] = i
        group.idClicked.connect(self.stack.setCurrentIndex)
        self.stack.currentChanged.connect(lambda i: group.button(i).setChecked(True))
        group.button(0).setChecked(True)
        nav.addStretch()
        lower.addLayout(nav)
        lower.addWidget(self.stack, 1)
        outer.addLayout(lower, 1)

    def show_section(self, key: str) -> None:
        """Раздел окна: connect | certs | settings | log (переход из журнала действий)."""
        if key in self.section_index:
            self.stack.setCurrentIndex(self.section_index[key])

    @staticmethod
    def _scroll(page: QWidget) -> QScrollArea:
        area = QScrollArea()
        area.setWidgetResizable(True)
        area.setFrameShape(QFrame.Shape.NoFrame)
        area.setWidget(page)
        return area

    def _pages(self) -> list[tuple[str, str, QWidget]]:
        return [("connect", "Подключение", self._page_connection()),
                ("certs", "Сертификаты", self._page_certs()),
                ("settings", "Настройки клиента", self._page_settings()),
                ("log", "Журнал", self._page_log())]

    # ---------------- разделы ----------------
    def _page_connection(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        # профиль: выбор, вставка, импорт, переименование, удаление
        card, cl = _card()
        cl.addWidget(_label("Профиль", "title"))
        prow = QHBoxLayout()
        self.cmb_profile = QComboBox()
        self.cmb_profile.setMinimumWidth(320)
        self.cmb_profile.currentIndexChanged.connect(self._on_select)
        prow.addWidget(self.cmb_profile, 1)
        prow.addLayout(self._profile_buttons())
        cl.addLayout(prow)
        self.chk_auto = QCheckBox("Этот профиль подключать при запуске программы (если "
                                  "включено «VPN при запуске» в настройках клиента)")
        self.chk_auto.toggled.connect(self._on_auto)
        cl.addWidget(self.chk_auto)
        self.engine_label = _label("", "hint")
        cl.addWidget(self.engine_label)
        layout.addWidget(card)
        # режим: галочки TUN и системного прокси; обе сняты — только локальный прокси
        card, cl = _card()
        cl.addWidget(_label("Режим подключения", "title"))
        self.chk_tun = QCheckBox("TUN: весь трафик компьютера через VPN (sing-box + Xray)")
        self.chk_proxy = QCheckBox("Системный прокси: программы, которые слушаются прокси "
                                   "Windows (браузеры)")
        for box in (self.chk_tun, self.chk_proxy):
            box.toggled.connect(lambda on, b=box: self._on_mode_box(b, on))
            cl.addWidget(box)
        self.mode_hint = _label("", "hint")
        cl.addWidget(self.mode_hint)
        layout.addWidget(card)
        # локальный прокси: виден, когда обе галочки сняты
        self.local_card, cl = _card()
        cl.addWidget(_label("Локальный прокси для программ", "title"))
        cl.addWidget(_label("Только с этого компьютера (127.0.0.1): через VPN пойдут лишь "
                            "программы с этим прокси (Telegram, браузер с настройкой прокси, "
                            "HTTPS_PROXY), остальное — как без VPN. Занятый порт (например, "
                            "Throne) — VPN подключится без этого прокси.", "hint"))
        form = QGridLayout()
        self.port_widgets = []
        for row, kind, title in ((0, "socks", "SOCKS5"), (1, "http", "HTTP")):
            box = QCheckBox(f"{title}-прокси, порт:")
            box.setChecked(cfg.get(f"vpn/{kind}_enabled"))
            box.toggled.connect(lambda on, k=kind: cfg.set_(f"vpn/{k}_enabled", on))
            spin = QSpinBox()
            spin.setRange(1024, 65535)
            spin.setValue(cfg.get(f"vpn/{kind}_port"))
            spin.valueChanged.connect(lambda v, k=kind: cfg.set_(f"vpn/{k}_port", v))
            form.addWidget(box, row, 0)
            form.addWidget(spin, row, 1)
            self.port_widgets += [box, spin]
        form.setColumnStretch(2, 1)
        cl.addLayout(form)
        layout.addWidget(self.local_card)
        # отклик сайтов (бывший раздел «Проверка»)
        card, cl = _card()
        cl.addWidget(_label("Отклик сайтов", "title"))
        cl.addWidget(_label("Время до ответа сайта тем же путём, каким сейчас ходят программы "
                            "(через VPN или напрямую), и проверка сертификата.", "hint"))
        row = QHBoxLayout()
        self.probe_btn = QPushButton("Проверить отклик")
        self.probe_btn.clicked.connect(self._run_probes)
        self.probe_host = QLineEdit()
        self.probe_host.setPlaceholderText("свой сайт, например example.com (необязательно)")
        row.addWidget(self.probe_btn)
        row.addWidget(self.probe_host, 1)
        cl.addLayout(row)
        self.probe_table = QTableWidget(0, 5)
        self.probe_table.setHorizontalHeaderLabels(["Сайт", "Соединение", "Ответ", "Сертификат",
                                                    "Подробности"])
        self.probe_table.verticalHeader().setVisible(False)
        self.probe_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.probe_table.horizontalHeader().setStretchLastSection(True)
        for col, width in enumerate((200, 110, 110, 230)):
            self.probe_table.setColumnWidth(col, width)
        self.probe_table.setMinimumHeight(240)
        cl.addWidget(self.probe_table)
        layout.addWidget(card)
        layout.addStretch()
        return page

    def _page_certs(self) -> QWidget:
        """Сайты с подменённым сертификатом (бывший раздел «Проверка»)."""
        page = QWidget()
        layout = QVBoxLayout(page)
        card, cl = _card()
        cl.addWidget(_label("Подмена сертификатов", "title"))
        cl.addWidget(_label("Сертификаты популярных сайтов сверяются с доверенными центрами "
                            "Windows. Если сертификат подменён (провайдер, DPI, вредонос), "
                            "трафик к сайту блокируется, пока вы не разрешите. Подмену не видно, "
                            "если злоумышленник добавил свой корневой сертификат в Windows.",
                            "hint"))
        self.chk_cert = QCheckBox("Проверять сертификаты сайтов во время подключения (раз в "
                                  "10 минут)")
        self.chk_cert.setChecked(cfg.get("vpn/cert_watch"))
        self.chk_cert.toggled.connect(lambda on: cfg.set_("vpn/cert_watch", on))
        cl.addWidget(self.chk_cert)
        cl.addWidget(_label("Заблокированы из-за подмены сертификата:", "hint"))
        self.cert_list = QListWidget()
        self.cert_list.setMinimumHeight(200)
        cl.addWidget(self.cert_list)
        allow = QPushButton("Разрешить выбранный сайт")
        allow.clicked.connect(self._allow_cert)
        cl.addWidget(allow, 0, Qt.AlignmentFlag.AlignLeft)
        self._fill_cert_list()
        layout.addWidget(card)
        layout.addStretch()
        return page

    def _page_settings(self) -> QWidget:
        from vpn import xray
        page = QWidget()
        layout = QVBoxLayout(page)
        # маршрутизация: профили (vpn/routingwindow.py)
        from vpn.routingwindow import RoutingCard
        card, cl = _card()
        cl.addWidget(_label("Маршрутизация", "title"))
        cl.addWidget(_label("Профиль маршрутизации решает, что идёт через туннель, что "
                            "напрямую и что блокируется (QUIC, UDP, российские сайты, реклама, "
                            "AdBlock, WARP, свои правила и файлы .dat). Действует во всех "
                            "режимах VLESS со следующего подключения.", "hint"))
        self.routing_card = RoutingCard(self.bridge.log.emit, self._busy)
        cl.addWidget(self.routing_card)
        row = QHBoxLayout()
        self.apps_btn = QPushButton()
        self.apps_btn.clicked.connect(self._edit_apps)
        row.addWidget(self.apps_btn)
        row.addStretch()
        cl.addLayout(row)
        self._apps_text()
        layout.addWidget(card)
        # защита и сеть
        card, cl = _card()
        cl.addWidget(_label("Защита и сеть", "title"))
        self.chk_kill = QCheckBox("Kill switch: при обрыве VPN интернет перекрыт до вашего "
                                  "решения")
        self.chk_kill.setToolTip(
            "TUN — брандмауэр Windows выпускает в интернет только через туннель. Системный "
            "прокси — прокси Windows остаётся на остановившемся Xray. Только локальный прокси "
            "— программы с прокси при обрыве просто теряют связь, мимо VPN они не уходят.")
        self.chk_kill.setChecked(cfg.get("vpn/killswitch"))
        self.chk_kill.toggled.connect(lambda on: cfg.set_("vpn/killswitch", on))
        cl.addWidget(self.chk_kill)
        f = QFormLayout()
        self.cmb_ip = QComboBox()
        self._ip_modes = list(xray.IP_MODES)
        self.cmb_ip.addItems(list(xray.IP_MODES.values()))
        mode = str(cfg.get("vpn/ip_mode") or "ipv4")
        self.cmb_ip.setCurrentIndex(self._ip_modes.index(mode) if mode in self._ip_modes else 0)
        self.cmb_ip.currentIndexChanged.connect(
            lambda i: cfg.set_("vpn/ip_mode", self._ip_modes[i]))
        self.cmb_ip.setToolTip(
            "Режим TUN. Только IPv4 — IPv6 перекрыт в туннеле, мимо VPN не идёт. Предпочтительно "
            "IPv6 — сайт с IPv6 открывается по IPv6, остальные по IPv4. IPv6 — так же, и "
            "соединение с самим сервером VPN тоже по IPv6, если он у сервера и у вас есть.")
        f.addRow("IP:", self.cmb_ip)
        from vpn import singbox
        self.cmb_dns = QComboBox()
        self.cmb_dns.setEditable(True)
        self.cmb_dns.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.cmb_dns.addItems(singbox.DNS_PRESETS)
        self.cmb_dns.setCurrentText(str(cfg.get("vpn/dns_server") or "1.1.1.1"))
        self.cmb_dns.currentTextChanged.connect(self._on_dns)
        self.cmb_dns.setToolTip(
            "DNS-сервер, к которому запросы идут через сервер VPN (TUN). Из списка или свой: "
            "IP (обычный DNS), tls://адрес (DNS over TLS), https://адрес/dns-query (DNS over "
            "HTTPS), tcp://, quic://, h3://")
        f.addRow("DNS через VPN:", self.cmb_dns)
        cl.addLayout(f)
        self.dns_error = _label("", "")
        self.dns_error.setStyleSheet(f"color: {RED};")
        self.dns_error.hide()
        cl.addWidget(self.dns_error)
        self.dns_hint = _label("", "hint")
        cl.addWidget(self.dns_hint)
        self.chk_strict = QCheckBox("Строгая маршрутизация (strict route)")
        self.chk_strict.setToolTip(
            "Режим TUN. Включена — фильтры Windows (WFP) не дают программам обойти туннель и "
            "отправить DNS-запросы мимо него. Выключите, если с VPN перестали работать "
            "виртуальные машины, локальные серверы или другие сетевые программы.")
        self.chk_strict.setChecked(cfg.get("vpn/strict_route") is not False)
        self.chk_strict.toggled.connect(lambda on: cfg.set_("vpn/strict_route", on))
        cl.addWidget(self.chk_strict)
        grid = QGridLayout()
        self.opt_boxes = {}
        for i, (key, text, tip) in enumerate((
                ("mux", "Mux (несколько соединений в одном)",
                 "Быстрее открываются сайты с множеством запросов. Не работает со ссылками "
                 "flow=xtls-rprx-vision (для них не включается)."),
                ("fragment", "Фрагментация (обход DPI)",
                 "Начало TLS-соединения с сервером режется на кусочки 100–200 байт с паузой "
                 "10–20 мс — если провайдер режет соединение с сервером VPN."))):
            box = QCheckBox(text)
            box.setToolTip(tip)
            box.setChecked(cfg.get(f"vpn/{key}"))
            box.toggled.connect(lambda on, k=key: cfg.set_(f"vpn/{k}", on))
            grid.addWidget(box, 0, i)
            self.opt_boxes[key] = box
        cl.addLayout(grid)
        layout.addWidget(card)
        card, cl = _card()
        cl.addWidget(_label("Запуск", "title"))
        self.chk_autostart = QCheckBox("Подключать VPN при запуске программы (профиль, "
                                       "отмеченный «подключать при запуске»)")
        self.chk_autostart.setChecked(cfg.get("vpn/autostart"))
        self.chk_autostart.toggled.connect(lambda on: cfg.set_("vpn/autostart", on))
        cl.addWidget(self.chk_autostart)
        cl.addWidget(_label(self._cores_text(), "hint"))
        layout.addWidget(card)
        layout.addWidget(_label("Настройки действуют со следующего подключения. Они относятся "
                                "только к VPN и не меняют настройки антивируса.", "hint"))
        layout.addStretch()
        self._show_builtin()
        return page

    def _on_dns(self, text: str) -> None:
        """DNS через VPN: сохраняется только правильно записанный адрес."""
        from vpn import singbox
        try:
            singbox.parse_dns(text)
        except ValueError as e:
            self.dns_error.setText(f"{e}. Сохранён прежний: {cfg.get('vpn/dns_server')}")
            self.dns_error.show()
            return
        self.dns_error.hide()
        cfg.set_("vpn/dns_server", text.strip())
        self._show_builtin()

    def _show_builtin(self) -> None:
        """Что зависит от режима: программы мимо VPN — только TUN (это правило sing-box);
        DNS через VPN — неактивно, если DNS для нужных адресов задан в Windows 11."""
        tun = self._mode_from_boxes() == "tun"
        busy = self._busy()
        self.apps_btn.setEnabled(tun and not busy)
        self.apps_btn.setToolTip("" if tun else "Только в режиме TUN: в режиме прокси через VPN "
                                                "идут лишь программы с прокси")
        from vpn import windns
        found = getattr(self, "_win_dns", None)
        if found is None:
            found = self._win_dns = windns.manual_dns()
        ipv4_only = str(cfg.get("vpn/ip_mode") or "ipv4") == "ipv4"
        covered = bool(found["v4"]) and (ipv4_only or bool(found["v6"]))
        self.cmb_dns.setEnabled(tun and not busy and not covered)
        self.chk_strict.setEnabled(tun and not busy)
        text = windns.describe(found) if tun else "DNS через VPN и строгая маршрутизация — " \
                                                  "только в режиме TUN."
        if covered and tun:
            text += " «DNS через VPN» не используется."
        elif tun and str(cfg.get("vpn/dns_server") or "").lower().startswith(("https", "tls",
                                                                               "h3", "quic")):
            text += (" DNS over HTTPS/TLS держит долгое соединение через туннель — если сайты "
                     "иногда не открываются по имени, выберите обычный 1.1.1.1.")
        self.dns_hint.setText(text)
        self.dns_hint.setVisible(bool(text))

    def _page_log(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        row = QHBoxLayout()
        self.chk_access = QCheckBox("Показывать каждое соединение (журнал доступа Xray)")
        self.chk_access.setChecked(True)
        self.chk_access.toggled.connect(lambda on: self._render_log())
        clear = QPushButton("Очистить")
        clear.clicked.connect(self._clear_log)
        row.addWidget(self.chk_access)
        row.addStretch()
        row.addWidget(clear)
        layout.addLayout(row)
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(2000)
        self.log_view.setMinimumHeight(360)
        layout.addWidget(self.log_view, 1)
        return page

    @staticmethod
    def _cores_text() -> str:
        from vpn import singbox, xray
        x, s = xray.find_xray(), singbox.find_singbox()
        return (f"Xray: {x or 'не найден'}\nsing-box: {s or 'не найден'}\n"
                "Версии и лицензии — vpn/bin/THIRD_PARTY.md")

    # ---------------- профили ----------------
    def _fill_profiles(self, select: int | None = None) -> None:
        if select is None:
            last = str(cfg.get("vpn/last_profile") or "")
            select = next((i for i, p in enumerate(self.profiles)
                           if f"{p.name}|{p.server}" == last), 0)
            if self.active in self.profiles:
                select = self.profiles.index(self.active)
        self.cmb_profile.blockSignals(True)
        self.cmb_profile.clear()
        for i, p in enumerate(self.profiles):
            self.cmb_profile.addItem(p.title)
            self.cmb_profile.setItemData(i, p.server, Qt.ItemDataRole.ToolTipRole)
        self.cmb_profile.blockSignals(False)
        if self.profiles:
            index = min(select, len(self.profiles) - 1)
            self.cmb_profile.setCurrentIndex(index)
            self._on_select(index)

    def _row(self) -> int:
        return self.cmb_profile.currentIndex()

    def _current(self) -> profiles.Profile | None:
        row = self._row()
        return self.profiles[row] if 0 <= row < len(self.profiles) else None

    def _on_select(self, _row: int) -> None:
        p = self._current()
        self.chk_auto.blockSignals(True)
        self.chk_auto.setChecked(bool(p and p.auto_connect))
        self.chk_auto.blockSignals(False)
        mode = (p.mode or "tun") if p and p.kind == "vless" else ""
        for box, on in ((self.chk_tun, mode in ("tun", "tun-xray")),
                        (self.chk_proxy, mode == "proxy")):
            box.blockSignals(True)
            box.setChecked(on)
            box.blockSignals(False)
        self._show_mode()
        self._tick()

    def _mode_from_boxes(self) -> str:
        """TUN, системный прокси или (обе галочки сняты) только локальный прокси."""
        if self.chk_tun.isChecked():
            return "tun"
        return "proxy" if self.chk_proxy.isChecked() else "local"

    def _on_mode_box(self, box: QCheckBox, on: bool) -> None:
        other = self.chk_proxy if box is self.chk_tun else self.chk_tun
        if on and other.isChecked():  # режимы взаимоисключающие
            other.blockSignals(True)
            other.setChecked(False)
            other.blockSignals(False)
        p = self._current()
        if p is not None and p.kind == "vless":
            p.mode = self._mode_from_boxes()
            self._save()
        self._show_mode()
        self._tick()

    def _show_mode(self) -> None:
        p = self._current()
        vless = bool(p and p.kind == "vless")
        mode = self._mode_from_boxes() if vless else ""
        self.local_card.setVisible(mode == "local")
        self.mode_hint.setText({
            "tun": "Весь трафик компьютера идёт через VPN: маршруты и DNS — sing-box, "
                   "соединение с сервером — Xray.",
            "proxy": "Через VPN идут программы, которые слушаются прокси Windows; остальные — "
                     "напрямую.",
            "local": "Обе галочки сняты: через VPN пойдут только программы с локальным прокси "
                     "(ниже), остальное — как без VPN.",
        }.get(mode, "Режим выбирается только у профилей VLESS."))

    def _save(self) -> None:
        try:
            profiles.save([p for p in self.profiles if p.kind != "demo"] +
                          [p for p in self.profiles if p.kind == "demo"])
        except OSError as e:
            QMessageBox.warning(self, "VPN", f"Профили не сохранены: {e}")

    def _add(self, profile: profiles.Profile) -> None:
        profile.name = profiles.unique_name(profile.name, [p.name for p in self.profiles])
        self.profiles.append(profile)
        self._save()
        self._fill_profiles(len(self.profiles) - 1)
        activity.record("vpn", f"Добавлен профиль {profile.name} ({profile.kind})")

    def _import(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Конфигурация VPN", "",
                                              "VPN (*.conf *.ovpn *.txt);;Все (*)")
        if not path:
            return
        try:
            self._add(profiles.import_file(path))
        except (OSError, ValueError) as e:
            QMessageBox.warning(self, "Импорт", str(e))

    def _paste(self) -> None:
        dialog = PasteDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        name, text = dialog.name.text().strip(), dialog.text.toPlainText().strip()
        if not text and name.lower().startswith(("vless://", "[interface]")):
            name, text = "", name  # ссылку вставили в поле названия
        try:
            self._add(profiles.from_text(name or "Профиль", text))
        except ValueError as e:
            QMessageBox.warning(self, "Профиль", str(e))

    def _rename(self) -> None:
        p = self._current()
        if p is None:
            return
        name, ok = QInputDialog.getText(self, "Переименовать", "Название:", text=p.name)
        if ok and name.strip() and name.strip() != p.name:
            p.name = profiles.unique_name(name, [o.name for o in self.profiles if o is not p])
            self._save()
            self._fill_profiles(self._row())

    def _delete(self) -> None:
        p = self._current()
        if p is None:
            return
        if p is self.active and self.backend is not None and \
                self.backend.state != backends.DISCONNECTED:
            QMessageBox.information(self, "VPN", "Сначала отключите этот профиль.")
            return
        if QMessageBox.question(self, "Удалить", f"Удалить профиль {p.name}?") != \
                QMessageBox.StandardButton.Yes:
            return
        self.profiles.remove(p)
        self._save()
        self._fill_profiles(0)

    def _on_auto(self, on: bool) -> None:
        p = self._current()
        if p is None:
            return
        for other in self.profiles:
            other.auto_connect = False
        p.auto_connect = on
        self._save()

    def autoconnect(self) -> bool:
        """VPN вместе с программой (vpn/autostart): профиль автоподключения или последний."""
        auto = next((p for p in self.profiles if p.auto_connect), None)
        if auto is None:
            self.bridge.log.emit("Автоподключение: не выбран профиль для подключения при "
                                 "запуске")
            return False
        self._fill_profiles(self.profiles.index(auto))
        self.toggle()
        return True

    # ---------------- подключение ----------------
    def showEvent(self, event):
        super().showEvent(event)
        self._win_dns = None  # DNS в Windows могли поменять, пока окно было закрыто
        self._show_builtin()
        # в QDialog у каждой кнопки autoDefault: Enter нажимал кнопку с фокусом или первую
        # («Подключить») — VPN включался от Enter в поле профиля
        for btn in self.findChildren(QPushButton):
            btn.setAutoDefault(False)
            btn.setDefault(False)

    def keyPressEvent(self, event):
        """Enter окно не обрабатывает: подключение — только щелчком (или пробелом на кнопке)."""
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            event.accept()
            return
        super().keyPressEvent(event)

    def toggle(self) -> None:
        self._win_dns = None
        if self.backend is not None and self.backend.state == backends.DISCONNECTING:
            return  # ядра ещё завершаются: их порты заняты (10808 — «уже занят»)
        if self.backend is not None and self.backend.state in (backends.CONNECTED,
                                                               backends.CONNECTING):
            backend = self.backend
            threading.Thread(target=backend.disconnect, daemon=True).start()
            activity.record("vpn", f"Отключение: {self.active.name if self.active else ''}")
            return
        p = self._current()
        if p is None:
            return
        backend = backends.backend_for(p.kind, self.bridge.log.emit, p.mode)
        if not backend.available:
            QMessageBox.information(self, "VPN", f"Для профиля {p.kind} нужен клиент: "
                                                 f"{backend.missing}.")
            return
        if not self._foreign_tunnels_ok(p):
            return
        self.backend, self.active = backend, p
        self._last = (0, 0, time.monotonic())
        self._ip_text = ""
        self._ip_backend = None
        self._cert_last = time.monotonic()  # первая проверка — через минуту после подключения
        self._cert_last -= CERT_INTERVAL - 60
        cfg.set_("vpn/last_profile", f"{p.name}|{p.server}")
        from diag import anon, features
        anon.register_vpn_profile(p.name, p.server)  # в журналах — %PROFILEn%, %VPNSERVERn%
        # адрес сервера в отчёт не пишется (п. 1.2): только профиль и вид
        activity.record("vpn", f"Подключение: {p.name} ({p.kind})")
        features.begin("vpn.connect").fact("kind", f"{p.kind}/{p.mode or 'tun'}")
        self.show_section("log")  # ход подключения — в журнале
        threading.Thread(target=backend.connect, args=(p,), daemon=True).start()

    def _reconnect(self) -> None:
        """Переподключиться с новыми правилами (после блокировки или разрешения сайта)."""
        backend, profile = self.backend, self.active
        if backend is None or profile is None or backend.state != backends.CONNECTED:
            return

        from diag import features
        features.begin("vpn.connect").fact("kind", "переподключение")

        def job():
            backend.disconnect()
            time.sleep(1)
            fresh = backends.backend_for(profile.kind, self.bridge.log.emit, profile.mode)
            self.backend = fresh
            fresh.connect(profile)

        threading.Thread(target=job, daemon=True).start()

    def _busy(self) -> bool:
        backend = self.backend
        return bool(backend) and backend.state in (backends.CONNECTED, backends.CONNECTING)

    def _tick(self) -> None:
        if not hasattr(self, "connect_btn"):
            return
        backend = self.backend
        state = backend.state if backend else backends.DISCONNECTED
        text, color = STATE_TEXT[state]
        busy = state in (backends.CONNECTED, backends.CONNECTING)
        self.state_label.setText(f"● {text}")
        self.state_label.setStyleSheet(f"font-size: 20pt; font-weight: 700; color: {color};")
        stopping = state == backends.DISCONNECTING
        self.connect_btn.setText("Отключаю..." if stopping else
                                 ("Отключить" if busy else "Подключить"))
        self.connect_btn.setEnabled(not stopping)
        ring = GREEN if state == backends.CONNECTED else (ORANGE if busy else ACCENT)
        self.connect_btn.setStyleSheet(
            f"QPushButton {{ border-radius: 75px; border: 4px solid {ring}; "
            f"font-size: 13pt; font-weight: 700; background: palette(base); }}"
            f"QPushButton:hover {{ background: palette(alternate-base); }}")
        self.error_label.setText(backend.error if backend and state == backends.ERROR else "")
        self.error_label.setVisible(bool(self.error_label.text()))
        blocked = bool(backend and getattr(backend, "blocked", False))
        from vpn import killswitch
        self.unblock_btn.setVisible(not busy and (blocked or killswitch.active()))
        for w in (self.chk_tun, self.chk_proxy, self.chk_kill, self.cmb_ip, self.cmb_dns,
                  self.chk_strict, self.apps_btn, self.cmb_profile,
                  *self.opt_boxes.values(), *self.port_widgets):
            w.setEnabled(not busy and not stopping)  # действуют со следующего подключения
        self.routing_card.set_busy(busy or stopping)
        if not busy and not stopping:
            p = self._current()
            for box in (self.chk_tun, self.chk_proxy):
                box.setEnabled(bool(p and p.kind == "vless"))
        key = (self._mode_from_boxes(), self._busy())
        if key != getattr(self, "_builtin_key", None):  # раз в секунду читались настройки
            self._builtin_key = key
            self._show_builtin()  # программы мимо VPN — только TUN, DNS — по настройкам Windows
        p = self.active if busy else self._current()
        self.protocol_label.setText(protocol_text(p))
        self.mode_label_big.setText(mode_text(p, backend if busy else None))
        engine = backend if busy else (self._engine(p) if p else None)
        self.engine_label.setText(
            "Клиент: " + ("—" if engine is None else getattr(engine, "exe", "") or (
                "встроенная имитация" if p and p.kind == "demo"
                else f"не найден: {engine.missing}")))
        self.tiles["server"].setText(p.server if p else "—")
        self._maybe_check_ip(backend if state == backends.CONNECTED else None)
        self.tiles["ip"].setText(mask_ip(self._ip_text) if self._ip_text else
                                 ("проверяю..." if self._ip_busy else "—"))
        self._maybe_update_routing()
        if state == backends.CONNECTED:
            seconds = int(time.time() - backend.since)
            self.tiles["time"].setText(f"{seconds // 3600:02d}:{seconds // 60 % 60:02d}:"
                                       f"{seconds % 60:02d}")
            rx, tx = self._counters(backend)
            last_rx, last_tx, last_t = self._last
            dt = max(0.5, time.monotonic() - last_t)
            if last_rx or last_tx:
                self.tiles["speed"].setText(f"↓ {human_size(int((rx - last_rx) / dt))}/с  "
                                            f"↑ {human_size(int((tx - last_tx) / dt))}/с")
            self._last = (rx, tx, time.monotonic())
            self.tiles["rx"].setText(human_size(rx))
            self.tiles["tx"].setText(human_size(tx))
            self._maybe_check_certs()
        else:
            for key in ("time", "speed", "rx", "tx"):
                self.tiles[key].setText("—")

    def _counters(self, backend) -> tuple[int, int]:
        """Принято/отправлено через туннель — в фоне: psutil.net_io_counters перебирает все
        адаптеры и бывал по 0,5 с (зависание окна VPN в журнале 10.11.2026). Значение
        отстаёт на один такт — для плиток скорости это не заметно."""
        if getattr(self, "_counter_backend", None) is not backend:
            self._counter_backend, self._counter_value = backend, (0, 0)
        if not getattr(self, "_counting", False):
            self._counting = True

            def job():
                try:
                    value = backend.counters()
                    if self._counter_backend is backend:
                        self._counter_value = value
                finally:
                    self._counting = False

            threading.Thread(target=job, daemon=True, name="vpn-counters").start()
        return self._counter_value

    def _engine(self, p: profiles.Profile):
        key = (p.kind, p.mode)
        if getattr(self, "_engine_key", None) != key:
            self._engine_key = key
            self._engine_cache = backends.backend_for(p.kind, lambda t: None, p.mode)
        return self._engine_cache

    # ---------------- журнал ----------------
    def _append_log(self, text: str) -> None:
        from diag.log import get
        # строки ядер (Xray, sing-box) — подробности, их сотни; свои сообщения — INFO
        core = text.startswith(("Xray: ", "sing-box: "))
        if not core:
            get("vpn").log(20, "%s", text)
        elif " accepted " not in text:  # куда ходит пользователь — только в окне, не в файле
            # одна и та же ошибка ядра (тайм-аут до сервера) шла сотнями строк подряд
            key = re.sub(r"\d+", "N", text)
            now = time.monotonic()
            if key == self._core_key and now - self._core_since < 300:
                self._core_repeats += 1
            else:
                if self._core_repeats:
                    get("vpn").log(10, "…такая же строка ядра ещё %d раз", self._core_repeats)
                self._core_key, self._core_since, self._core_repeats = key, now, 0
                get("vpn").log(10, "%s", text)
        line = f"{time.strftime('%H:%M:%S')}  {text}"
        self._log_lines.append(line)
        del self._log_lines[:-2000]
        if self._show_line(line):
            self.log_view.appendPlainText(line)

    def _show_line(self, line: str) -> bool:
        return self.chk_access.isChecked() or " accepted " not in line

    def _render_log(self) -> None:
        if not hasattr(self, "log_view"):
            return
        self.log_view.setPlainText("\n".join(s for s in self._log_lines if self._show_line(s)))
        self.log_view.verticalScrollBar().setValue(self.log_view.verticalScrollBar().maximum())

    def _clear_log(self) -> None:
        self._log_lines.clear()
        self.log_view.clear()

    # ---------------- проверки ----------------
    def _maybe_check_ip(self, backend) -> None:
        """Внешний IP: через 3 с после подключения, потом раз в IP_INTERVAL; кнопки нет."""
        if backend is None:
            self._ip_backend, self._ip_text = None, ""
            return
        now = time.monotonic()
        if backend is not self._ip_backend:
            self._ip_backend, self._ip_next, self._ip_text = backend, now + 3, ""
        if now >= self._ip_next and not self._ip_busy:
            self._ip_next = now + IP_INTERVAL
            self._check_ip()

    def _on_ip(self, text: str) -> None:
        self._ip_busy = False
        if not text.startswith("Внешний IP: "):
            self.bridge.log.emit(f"Внешний IP не определён: {text}")
            self._ip_next = time.monotonic() + 60  # повторить через минуту
            return
        import ipaddress
        ip = (text.removeprefix("Внешний IP: ").split() or [""])[0]
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            self.bridge.log.emit("Внешний IP не определён: сервис ответил не адресом")
            self._ip_next = time.monotonic() + 60
            return
        if ip:
            from diag import anon
            anon.register_own_ip(ip)  # внешний адрес — не в журналы
            self._ip_text = ip
            self.bridge.log.emit(f"Внешний IP: {mask_ip(ip)}")
        self._tick()

    def _check_ip(self) -> None:
        self._ip_busy = True
        from vpn import checks
        route = checks.route_for(self.backend)

        def job():
            try:
                sock = checks.open_tcp("api.ipify.org", 443, route)
                import ssl
                with ssl.create_default_context().wrap_socket(
                        sock, server_hostname="api.ipify.org") as tls:
                    tls.sendall(b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close"
                                b"\r\n\r\n")
                    data = b""
                    while chunk := tls.recv(4096):
                        data += chunk
                self.bridge.ip.emit("Внешний IP: " + data.split(b"\r\n\r\n", 1)[-1].decode()
                                    .strip())
            except Exception as e:
                self.bridge.ip.emit(f"Не удалось: {e}")

        threading.Thread(target=job, daemon=True).start()

    def _maybe_update_routing(self) -> None:
        """Ссылки профилей маршрутизации и списки AdBlock — в фоне, раз в ROUTING_UPDATE."""
        if time.monotonic() < self._routing_next:
            return
        self._routing_next = time.monotonic() + ROUTING_UPDATE

        def job():
            from vpn import routing
            try:
                notes = routing.update_due()
            except Exception as e:  # noqa: BLE001 — сообщить в журнал окна
                notes = [f"Профили маршрутизации не обновлены: {e}"]
            if notes:
                self.bridge.routing.emit(notes)

        threading.Thread(target=job, daemon=True, name="vpn-routing-update").start()

    def _on_routing_update(self, notes) -> None:
        for note in notes:
            self.bridge.log.emit(note)
            activity.record("vpn", note)
        if self._busy():
            self.bridge.log.emit("Обновлённые профили маршрутизации подействуют со следующего "
                                 "подключения")
        self.routing_card.reload()

    def _run_probes(self) -> None:
        from vpn import checks
        hosts = list(checks.TARGETS)
        own = self.probe_host.text().strip().removeprefix("https://").split("/")[0]
        if own:
            hosts.insert(0, (own, own))
        route = checks.route_for(self.backend)
        self.probe_btn.setEnabled(False)
        self.probe_btn.setText("Проверяю...")

        def job():
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(6) as pool:
                results = list(pool.map(lambda h: (h[0], checks.probe(h[1], route)), hosts))
            self.bridge.probes.emit(results)

        threading.Thread(target=job, daemon=True).start()

    def _on_probes(self, results) -> None:
        self._probes = results
        if not hasattr(self, "probe_table"):
            return
        self.probe_btn.setEnabled(True)
        self.probe_btn.setText("Проверить отклик")
        self.probe_table.setRowCount(0)
        for name, r in results:
            row = self.probe_table.rowCount()
            self.probe_table.insertRow(row)
            cert = {"ok": "настоящий", "substituted": "ПОДМЕНЁН", "unknown": "—"}[r.cert]
            values = (f"{name} ({r.host})" if name != r.host else r.host,
                      f"{r.connect_ms:.0f} мс" if r.connect_ms else "—",
                      f"{r.total_ms:.0f} мс" if r.ok else "нет ответа",
                      cert + (f" ({r.issuer})" if r.issuer else ""),
                      r.error or r.status)
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                if col == 2 and r.ok:
                    item.setForeground(Qt.GlobalColor.darkGreen if r.total_ms < 800
                                       else Qt.GlobalColor.darkYellow)
                if (col == 2 and not r.ok) or (col == 3 and r.cert == "substituted"):
                    item.setForeground(Qt.GlobalColor.red)
                self.probe_table.setItem(row, col, item)
        for _name, r in results:
            if r.cert == "substituted":
                self.bridge.cert_alarm.emit(r)

    def _maybe_check_certs(self) -> None:
        if not cfg.get("vpn/cert_watch") or time.monotonic() - self._cert_last < CERT_INTERVAL:
            return
        self._cert_last = time.monotonic()
        from vpn import checks
        route = checks.route_for(self.backend)

        def job():
            for host in checks.CERT_HOSTS:
                r = checks.probe(host, route)
                if r.cert == "substituted":
                    self.bridge.cert_alarm.emit(r)

        threading.Thread(target=job, daemon=True).start()

    def _on_cert_alarm(self, r) -> None:
        blocked = _lines("vpn/cert_blocked")
        if r.host in blocked:
            return
        blocked.append(r.host)
        cfg.set_("vpn/cert_blocked", "\n".join(blocked))
        self._fill_cert_list()
        text = (f"Сертификат сайта {r.host} подменён (выдал: {r.issuer or 'неизвестно'}): "
                f"{r.error}. Трафик к сайту заблокирован, пока вы не разрешите.")
        self._append_log(text)
        activity.record("vpn", text)
        self._reconnect()  # правило блокировки — в новую конфигурацию
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Подменён сертификат")
        box.setText(text + "\n\nТак бывает при вмешательстве провайдера или DPI, «прозрачном» "
                    "прокси или вредоносе в системе. Данные, отправленные на такой сайт, может "
                    "прочитать тот, кто подменил сертификат.")
        allow = box.addButton("Разрешить сайт", QMessageBox.ButtonRole.DestructiveRole)
        box.addButton("Оставить заблокированным", QMessageBox.ButtonRole.AcceptRole)
        box.exec()
        if box.clickedButton() is allow:
            self._allow_host(r.host)

    def _fill_cert_list(self) -> None:
        if hasattr(self, "cert_list"):
            self.cert_list.clear()
            self.cert_list.addItems(_lines("vpn/cert_blocked"))

    def _allow_cert(self) -> None:
        item = self.cert_list.currentItem()
        if item is not None:
            self._allow_host(item.text())

    def _allow_host(self, host: str) -> None:
        cfg.set_("vpn/cert_blocked", "\n".join(h for h in _lines("vpn/cert_blocked")
                                               if h != host))
        self._fill_cert_list()
        self._append_log(f"Сайт {host} разрешён пользователем")
        activity.record("vpn", f"Подмена сертификата: сайт {host} разрешён пользователем")
        self._reconnect()

    # ---------------- прочее ----------------
    def _apps_text(self) -> None:
        self.apps_btn.setText(f"Программы напрямую, мимо VPN ({len(_lines('vpn/direct_apps'))})"
                              "...")

    def _edit_apps(self) -> None:
        dialog = DirectAppsDialog(self, _lines("vpn/direct_apps"))
        if dialog.exec() == QDialog.DialogCode.Accepted:
            cfg.set_("vpn/direct_apps", "\n".join(dialog.apps()))
            self._apps_text()
            self._show_builtin()

    def _run_netdiag(self) -> None:
        """Проверка в фоне: соединения ждут до 3 с, список фильтров WFP — несколько секунд."""
        from diag import features
        self.netdiag_btn.setEnabled(False)
        self.netdiag_btn.setText("Проверяю...")
        features.begin("vpn.netdiag")
        connected = bool(self.backend and self.backend.state == backends.CONNECTED)

        def job():
            from vpn import netdiag
            try:
                found = netdiag.diagnose(connected)
            except Exception as e:  # noqa: BLE001 — показать, а не упасть
                found = [netdiag.Finding(netdiag.BAD, "Проверка не удалась", str(e))]
            self.bridge.netdiag.emit(found)

        threading.Thread(target=job, daemon=True, name="vpn-netdiag").start()

    def _on_netdiag(self, found) -> None:
        from diag import features
        from toolbox.windows import info_dialog
        from vpn import netdiag
        self.netdiag_btn.setEnabled(True)
        self.netdiag_btn.setText("Почему нет интернета?")
        bad = [f.title for f in found if f.level == netdiag.BAD]
        features.end_if_active("vpn.netdiag", True, problems=len(bad))
        self.bridge.log.emit("Проверка сети: " + ("; ".join(bad) if bad else "явных проблем нет"))
        info_dialog(self, "Почему нет интернета?", netdiag.report(found), 720)

    def _foreign_tunnels_ok(self, p) -> bool:
        """Перед подключением TUN: другой VPN-клиент со своим туннелем мешает нашему (два
        набора маршрутов и фильтров), а при сбое его фильтры перекрывают весь интернет."""
        mode = p.mode or "tun"
        if p.kind != "vless" or mode not in ("tun", "tun-xray"):
            return True
        from vpn import netdiag
        found = netdiag.foreign_tunnels()
        if not found:
            return True
        self.bridge.log.emit("Работает другой VPN с туннелем: " + ", ".join(found))
        answer = QMessageBox.question(
            self, "VPN",
            "Уже работает другой VPN-клиент со своим туннелем:\n" + "\n".join(found) +
            "\n\nДва туннеля мешают друг другу: часть соединений обрывается, а при сбое "
            "фильтры другого клиента перекрывают весь интернет — и выключение брандмауэра "
            "этого не снимает. Лучше закрыть его полностью (из трея).\n\nПодключить всё равно?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        return answer == QMessageBox.StandardButton.Yes

    def _release_block(self) -> None:
        from vpn import dnsguard, killswitch
        dns = dnsguard.restore()
        done = killswitch.disable()
        if self.backend is not None:
            if hasattr(self.backend, "release_block"):
                done = self.backend.release_block() or done
            self.backend.blocked = False
            if hasattr(self.backend, "dns_changed"):
                self.backend.dns_changed = False
        text = "Блокировка снята, интернет без VPN" if done else "Блокировки не было"
        if dns:
            text += "; DNS адаптеров возвращён"
        self._append_log(text)
        activity.record("vpn", text)
        self._tick()

    def closeEvent(self, event):
        # окно скрывается, подключение остаётся (как у обычных VPN-клиентов)
        if self.backend is not None and self.backend.state == backends.CONNECTED:
            self.bridge.log.emit("Окно закрыто, VPN остаётся подключённым")
        super().closeEvent(event)

    def shutdown(self) -> None:
        if self.backend is not None and self.backend.state != backends.DISCONNECTED:
            self.backend.disconnect()
