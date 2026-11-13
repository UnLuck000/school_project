"""Окно VPN, «Настройки клиента»: профили маршрутизации (vpn/routing.py) и их редактор.

RoutingCard — карточка раздела: выбор профиля, «Создать», «Дублировать», «Редактировать»,
«Удалить», «Импорт» (файлы или ссылка), «Экспорт». RoutingEditor — вкладки «Основное»
(встроенные правила, AdBlock, WARP, ссылка профиля), «Туннель», «Обход», «Блокировать»
(встроенные строки — только просмотр, свои — правка), «Дополнительно» (правила с полями Xray,
RuleDialog, «Как JSON»), «Файлы» (свои .dat с ссылками и автообновлением; у Default нет).
Скачивание и регистрация WARP — в потоке (run_job), окно не замирает.
"""
import json
import threading
import time

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QFrame,
    QGridLayout, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QMenu, QMessageBox,
    QPlainTextEdit, QPushButton, QSpinBox, QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget,
)

from analyzer.fileops import human_size
from recovery import activity
from ui.widgets import make_table
from vpn import routing, warp


def _hint(text: str = "") -> QLabel:
    label = QLabel(text)
    label.setWordWrap(True)
    label.setProperty("role", "hint")
    label.setStyleSheet("color: palette(placeholder-text);")
    return label


def _title(text: str) -> QLabel:
    label = QLabel(text)
    label.setStyleSheet("font-size: 11pt; font-weight: 600;")
    return label


def _buttons(dialog: QDialog, ok: str = "Сохранить") -> QDialogButtonBox:
    box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                           QDialogButtonBox.StandardButton.Cancel)
    box.button(QDialogButtonBox.StandardButton.Ok).setText(ok)
    box.button(QDialogButtonBox.StandardButton.Cancel).setText("Отмена")
    box.accepted.connect(dialog.accept)
    box.rejected.connect(dialog.reject)
    return box


def _when(ts: float) -> str:
    return time.strftime("%d.%m.%Y %H:%M", time.localtime(ts)) if ts else "ещё не загружено"


# ---------------- фоновые задачи ----------------
class _Job(QObject):
    finished = Signal(object, object)

    def __init__(self, owner: QObject, done):
        super().__init__(owner)
        self._done = done
        self.finished.connect(self._deliver)  # слот объекта в потоке окна — вызов в нём

    def _deliver(self, result, error) -> None:
        try:
            self._done(result, error)
        finally:
            self.deleteLater()


def run_job(owner: QObject, fn, done) -> None:
    """fn() — в потоке, done(результат, ошибка) — в потоке окна."""
    job = _Job(owner, done)

    def work():
        try:
            result = fn()
        except Exception as e:  # noqa: BLE001 — ошибку покажет окно
            job.finished.emit(None, e)
            return
        job.finished.emit(result, None)

    threading.Thread(target=work, daemon=True, name="vpn-routing").start()


# ---------------- период обновления ----------------
class IntervalPicker(QWidget):
    """Каждый час / 12 часов / 24 часа / своё (часы)."""

    def __init__(self, hours: int = 24):
        super().__init__()
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        self.combo = QComboBox()
        for value, text in routing.INTERVALS.items():
            self.combo.addItem(text, value)
        self.combo.addItem("Своё время (в часах)", 0)
        self.spin = QSpinBox()
        self.spin.setRange(1, 24 * 365)
        self.spin.setSuffix(" ч")
        row.addWidget(self.combo)
        row.addWidget(self.spin)
        row.addStretch()
        self.combo.currentIndexChanged.connect(self._sync)
        self.set_hours(hours)

    def _sync(self) -> None:
        self.spin.setVisible(self.combo.currentData() == 0)

    def set_hours(self, hours: int) -> None:
        hours = max(1, int(hours or 24))
        index = self.combo.findData(hours)
        if index < 0:
            index = self.combo.findData(0)
            self.spin.setValue(hours)
        self.combo.setCurrentIndex(index)
        self._sync()

    def hours(self) -> int:
        return int(self.combo.currentData() or self.spin.value())


# ---------------- диалоги ----------------
class LinkDialog(QDialog):
    """Импорт по ссылке: адрес, период автообновления, куда добавить файл .dat."""

    def __init__(self, parent, current: routing.RoutingProfile | None):
        super().__init__(parent)
        self.setWindowTitle("Импорт по ссылке")
        self.resize(720, 0)
        layout = QVBoxLayout(self)
        layout.addWidget(_hint(
            "Ссылка на профиль маршрутизации (.json или .zip, экспортированный StretchBIT) или "
            "на файл .dat (geosite/geoip Xray). Ссылку на страницу файла GitHub (…/blob/…) "
            "можно вставить как есть — она заменится на прямую. Скачанное обновляется само "
            "с выбранным периодом; ссылку и период потом можно поменять в профиле."))
        form = QFormLayout()
        self.url = QLineEdit()
        self.url.setPlaceholderText("https://github.com/…/geosite.dat")
        form.addRow("Ссылка:", self.url)
        self.interval = IntervalPicker(24)
        form.addRow("Обновлять:", self.interval)
        self.target = QComboBox()
        self.target.addItem("Новый профиль", True)
        if current is not None and not current.is_default:
            self.target.addItem(f"В профиль «{current.name}»", False)
            self.target.setCurrentIndex(1)
        self.target.setToolTip("Только для файла .dat; профиль по ссылке всегда новый")
        form.addRow("Файл .dat:", self.target)
        layout.addLayout(form)
        layout.addWidget(_buttons(self, "Загрузить"))

    def values(self) -> tuple[str, int, bool]:
        return self.url.text().strip(), self.interval.hours(), bool(self.target.currentData())


class RuleDialog(QDialog):
    """Правило «Дополнительно»: условия (все сразу — «И») и действие."""

    def __init__(self, parent, rule: dict | None = None, warp_on: bool = False):
        super().__init__(parent)
        self.setWindowTitle("Правило маршрутизации")
        self.resize(760, 760)
        r = routing.normalize_rule(rule or {})
        layout = QVBoxLayout(self)
        layout.addWidget(_hint(
            "Правило срабатывает, когда выполнены ВСЕ заполненные условия; пустые поля не "
            "проверяются. Правила «Дополнительно» проверяются раньше остальных, сверху вниз."))
        form = QFormLayout()
        self.name = QLineEdit(r["name"])
        self.name.setPlaceholderText("необязательно")
        form.addRow("Название:", self.name)
        self.enabled = QCheckBox("Включено")
        self.enabled.setChecked(r["enabled"])
        form.addRow("", self.enabled)
        self.outbound = QComboBox()
        for key, text in routing.OUTBOUNDS.items():
            self.outbound.addItem(text, key)
        self.outbound.setCurrentIndex(max(0, self.outbound.findData(r["outbound"])))
        self.outbound.setToolTip("«Туннель» — через VPN (а с WARP «VPN → WARP» — через WARP); "
                                 "«Только VPN, без WARP» — мимо WARP" +
                                 ("" if warp_on else " (WARP в профиле выключен — как «Туннель»)"))
        form.addRow("Действие:", self.outbound)
        inbound_row = QHBoxLayout()
        self.inbound = {}
        for key, text in routing.INBOUNDS.items():
            box = QCheckBox(text)
            box.setChecked(key in r["inbound"])
            inbound_row.addWidget(box)
            self.inbound[key] = box
        inbound_row.addStretch()
        form.addRow("Входящее (inbound):", inbound_row)
        self.domain = QPlainTextEdit("\n".join(r["domain"]))
        self.domain.setPlaceholderText("example.com\nfull:a.example.com\nkeyword:video\n"
                                       "regexp:\\.ru$\ngeosite:youtube\next:файл.dat:метка")
        self.domain.setMaximumHeight(110)
        form.addRow("Домены (domain):", self.domain)
        self.ip = QPlainTextEdit("\n".join(r["ip"]))
        self.ip.setPlaceholderText("1.2.3.4\n10.0.0.0/8\ngeoip:ru\next:файл.dat:метка")
        self.ip.setMaximumHeight(90)
        form.addRow("Адреса (ip):", self.ip)
        self.port = QLineEdit(r["port"])
        self.port.setPlaceholderText("443 или 1000-2000,8080")
        form.addRow("Порт (port):", self.port)
        self.source_port = QLineEdit(r["source_port"])
        form.addRow("Порт источника:", self.source_port)
        self.network = QComboBox()
        for key, text in routing.NETWORKS.items():
            self.network.addItem(text, key)
        self.network.setCurrentIndex(max(0, self.network.findData(r["network"])))
        form.addRow("Сеть (network):", self.network)
        proto_row = QHBoxLayout()
        self.protocol = {}
        for key in routing.PROTOCOLS:
            box = QCheckBox(key)
            box.setChecked(key in r["protocol"])
            proto_row.addWidget(box)
            self.protocol[key] = box
        proto_row.addStretch()
        form.addRow("Протокол (protocol):", proto_row)
        self.source = QPlainTextEdit("\n".join(r["source"]))
        self.source.setPlaceholderText("192.168.1.10\n192.168.1.0/24")
        self.source.setMaximumHeight(70)
        form.addRow("Адрес источника:", self.source)
        layout.addLayout(form)
        self.error = QLabel()
        self.error.setWordWrap(True)
        self.error.setStyleSheet("color: #c0392b;")
        self.error.hide()
        layout.addWidget(self.error)
        layout.addStretch()
        layout.addWidget(_buttons(self, "Готово"))

    def rule(self) -> dict:
        return routing.normalize_rule({
            "name": self.name.text(), "enabled": self.enabled.isChecked(),
            "outbound": self.outbound.currentData(),
            "inbound": [k for k, b in self.inbound.items() if b.isChecked()],
            "domain": self.domain.toPlainText(), "ip": self.ip.toPlainText(),
            "port": self.port.text(), "source_port": self.source_port.text(),
            "network": self.network.currentData(),
            "protocol": [k for k, b in self.protocol.items() if b.isChecked()],
            "source": self.source.toPlainText()})

    def accept(self) -> None:
        problems = routing.rule_problems(self.rule())
        if problems:
            self.error.setText("\n".join(problems))
            self.error.show()
            return
        super().accept()


class JsonRulesDialog(QDialog):
    """Все правила «Дополнительно» одним списком JSON (поля — как в RuleDialog)."""

    def __init__(self, parent, rules: list[dict]):
        super().__init__(parent)
        self.setWindowTitle("Дополнительные правила — JSON")
        self.resize(860, 640)
        layout = QVBoxLayout(self)
        layout.addWidget(_hint(
            "Список правил. Поля: name, enabled, outbound (proxy | direct | block | vpn), "
            "inbound (tun, proxy, local-socks, local-http), domain, ip, port, source_port, "
            "network (tcp, udp, \"tcp,udp\"), protocol (http, tls, quic, bittorrent), source."))
        self.text = QPlainTextEdit(json.dumps(rules, ensure_ascii=False, indent=1))
        self.text.setStyleSheet("font-family: Consolas, monospace;")
        layout.addWidget(self.text, 1)
        self.error = QLabel()
        self.error.setStyleSheet("color: #c0392b;")
        self.error.setWordWrap(True)
        self.error.hide()
        layout.addWidget(self.error)
        layout.addWidget(_buttons(self, "Применить"))
        self.result: list[dict] = []

    def accept(self) -> None:
        try:
            data = json.loads(self.text.toPlainText() or "[]")
            if not isinstance(data, list) or not all(isinstance(r, dict) for r in data):
                raise ValueError("нужен список [ {...}, ... ]")
        except ValueError as e:
            self.error.setText(f"Не JSON-список правил: {e}")
            self.error.show()
            return
        rules = [routing.normalize_rule(r) for r in data]
        problems = [f"Правило {i + 1}: {p}" for i, r in enumerate(rules)
                    for p in routing.rule_problems(r)]
        if problems:
            self.error.setText("\n".join(problems[:10]))
            self.error.show()
            return
        self.result = rules
        super().accept()


class WarpDialog(QDialog):
    """Настройки WARP: протокол, цепочка, ключ (получить или из конфигурации), шум."""

    def __init__(self, parent, w: dict):
        super().__init__(parent)
        self.setWindowTitle("WARP (Cloudflare)")
        self.resize(760, 0)
        self.w = warp.normalize(w)
        layout = QVBoxLayout(self)
        layout.addWidget(_hint(
            "WARP — бесплатный WireGuard-сервер Cloudflare в цепочке с VPN. Ключ можно получить "
            "здесь (регистрируется новое устройство WARP; закрытый ключ создаётся на этом "
            "компьютере и никуда не отправляется) или вставить готовую конфигурацию WireGuard "
            "/ AmneziaWG."))
        form = QFormLayout()
        self.protocol = QComboBox()
        for key, text in warp.PROTOCOLS.items():
            self.protocol.addItem(text, key)
        self.protocol.setCurrentIndex(max(0, self.protocol.findData(self.w["protocol"])))
        form.addRow("Протокол:", self.protocol)
        self.chain = QComboBox()
        for key, text in warp.CHAINS.items():
            self.chain.addItem(text, key)
        self.chain.setCurrentIndex(max(0, self.chain.findData(self.w["chain"])))
        form.addRow("Цепочка:", self.chain)
        keys = QHBoxLayout()
        self.register_btn = QPushButton("Получить ключ WARP")
        self.register_btn.clicked.connect(self._register)
        paste = QPushButton("Вставить конфигурацию WireGuard / AmneziaWG...")
        paste.clicked.connect(self._paste)
        keys.addWidget(self.register_btn)
        keys.addWidget(paste)
        keys.addStretch()
        form.addRow("Ключ:", keys)
        self.private = QLineEdit(self.w["private_key"])
        self.private.setEchoMode(QLineEdit.EchoMode.Password)
        self.private.setPlaceholderText("закрытый ключ WireGuard (base64)")
        form.addRow("Закрытый ключ:", self.private)
        self.peer = QLineEdit(self.w["peer_public_key"])
        form.addRow("Ключ сервера:", self.peer)
        self.endpoint = QLineEdit(self.w["endpoint"])
        form.addRow("Адрес сервера:", self.endpoint)
        self.v4 = QLineEdit(self.w["address_v4"])
        form.addRow("Адрес IPv4:", self.v4)
        self.v6 = QLineEdit(self.w["address_v6"])
        self.v6.setPlaceholderText("необязательно")
        form.addRow("Адрес IPv6:", self.v6)
        self.reserved = QLineEdit(",".join(str(x) for x in self.w["reserved"]))
        self.reserved.setToolTip("Reserved — три байта из регистрации WARP (client_id)")
        form.addRow("Reserved:", self.reserved)
        self.mtu = QSpinBox()
        self.mtu.setRange(576, 1500)
        self.mtu.setValue(int(self.w["mtu"]))
        form.addRow("MTU:", self.mtu)
        layout.addLayout(form)
        self.noise_box = QFrame()
        noise = QHBoxLayout(self.noise_box)
        noise.setContentsMargins(0, 0, 0, 0)
        self.jc, self.jmin, self.jmax = QSpinBox(), QSpinBox(), QSpinBox()
        for spin, title, value, top in ((self.jc, "Jc (пакетов)", self.w["jc"], 128),
                                        (self.jmin, "Jmin (байт)", self.w["jmin"], 1280),
                                        (self.jmax, "Jmax (байт)", self.w["jmax"], 1280)):
            spin.setRange(1, top)
            spin.setValue(int(value))
            noise.addWidget(QLabel(title))
            noise.addWidget(spin)
        noise.addStretch()
        layout.addWidget(_title("Шум AmneziaWG"))
        layout.addWidget(_hint("Перед рукопожатием WireGuard уходят Jc пакетов случайной длины "
                               "Jmin–Jmax: провайдер не узнаёт WireGuard по первому пакету. "
                               "Действует в цепочке «WARP → VPN». S1, S2, H1–H4 сервер WARP "
                               "не поддерживает."))
        layout.addWidget(self.noise_box)
        self.status = _hint()
        layout.addWidget(self.status)
        layout.addWidget(_buttons(self, "Готово"))
        self.protocol.currentIndexChanged.connect(self._sync)
        for edit in (self.private, self.endpoint, self.v4, self.v6):
            edit.textChanged.connect(self._sync)
        self._sync()

    def _sync(self) -> None:
        self.noise_box.setEnabled(self.protocol.currentData() == "amneziawg")
        problems = warp.problems(self.value())
        self.status.setText("Готово к подключению" if not problems else
                            "Не хватает: " + "; ".join(problems))

    def _apply(self, values: dict) -> None:
        for key, widget in (("private_key", self.private), ("peer_public_key", self.peer),
                            ("endpoint", self.endpoint), ("address_v4", self.v4),
                            ("address_v6", self.v6)):
            if key in values:
                widget.setText(str(values[key]))
        if "reserved" in values:
            self.reserved.setText(",".join(str(x) for x in values["reserved"]))
        for key, spin in (("mtu", self.mtu), ("jc", self.jc), ("jmin", self.jmin),
                          ("jmax", self.jmax)):
            if key in values:
                spin.setValue(int(values[key]))
        if values.get("protocol"):
            self.protocol.setCurrentIndex(max(0, self.protocol.findData(values["protocol"])))
        self._sync()

    def _register(self) -> None:
        if self.private.text().strip() and QMessageBox.question(
                self, "WARP", "Ключ уже есть. Получить новый (будет новое устройство WARP)?") \
                != QMessageBox.StandardButton.Yes:
            return
        from diag import features
        features.begin("vpn.warp")
        self.register_btn.setEnabled(False)
        self.status.setText("Регистрирую устройство WARP...")

        def done(result, error):
            self.register_btn.setEnabled(True)
            if error is not None:
                features.end_if_active("vpn.warp", False, error=str(error))
                self.status.setText(f"Ключ не получен: {error}. Если api.cloudflareclient.com "
                                    "недоступен — подключите VPN и повторите или вставьте "
                                    "готовую конфигурацию.")
                return
            features.end_if_active("vpn.warp", True)
            activity.record("vpn", "WARP: получен ключ нового устройства")
            self._apply(result)

        run_job(self, warp.register, done)

    def _paste(self) -> None:
        text, ok = QInputDialog.getMultiLineText(
            self, "Конфигурация WireGuard / AmneziaWG",
            "Текст .conf: [Interface] PrivateKey, Address ... [Peer] PublicKey, Endpoint:")
        if not ok or not text.strip():
            return
        try:
            self._apply(warp.parse_conf(text))
        except ValueError as e:
            QMessageBox.warning(self, "WARP", str(e))

    def value(self) -> dict:
        reserved = [p for p in self.reserved.text().replace(" ", "").split(",") if p]
        try:
            reserved_list = [int(p) % 256 for p in reserved][:3] if len(reserved) == 3 else [0, 0, 0]
        except ValueError:
            reserved_list = [0, 0, 0]
        return warp.normalize(dict(
            self.w, protocol=self.protocol.currentData(), chain=self.chain.currentData(),
            private_key=self.private.text().strip(), peer_public_key=self.peer.text().strip(),
            endpoint=self.endpoint.text().strip(), address_v4=self.v4.text().strip(),
            address_v6=self.v6.text().strip(), reserved=reserved_list, mtu=self.mtu.value(),
            jc=self.jc.value(), jmin=self.jmin.value(), jmax=self.jmax.value()))


# ---------------- редактор профиля ----------------
def builtin_lines(p: routing.RoutingProfile) -> dict[str, list[str]]:
    """Встроенные правила профиля строками (для вкладок «Туннель», «Обход», «Блокировать»)."""
    from vpn import xray
    result = {"rules_direct": [], "rules_proxy": [], "rules_block": []}
    if p.route_ru:
        result["rules_direct"] += ["# российские сайты (встроенное правило)", *xray.RU_DOMAINS,
                                   "geoip:ru"]
    result["rules_direct"].append("geoip:private  # локальная сеть (всегда)")
    if p.block_ads:
        result["rules_block"] += ["# реклама и трекеры (встроенное правило)", *xray.ADS]
    if p.adblock:
        result["rules_block"].append(f"# AdBlock: домены списка {p.adblock_url}")
    if p.block_udp:
        result["rules_block"].append("# весь UDP (встроенное правило)")
    elif p.block_quic:
        result["rules_block"].append("# QUIC — UDP 443 (встроенное правило)")
    w = p.warp
    if w.get("enabled") and w.get("chain") == "over_vpn":
        result["rules_proxy"].append("# туннель: VPN → WARP (сайты видят адрес Cloudflare)")
    elif w.get("enabled"):
        result["rules_proxy"].append("# туннель: WARP → VPN")
    result["rules_proxy"].append("# всё, что не попало в правила, — в туннель")
    return result


class RoutingEditor(QDialog):
    """Профиль маршрутизации: правка копии, «Сохранить» записывает. Файлы и ссылки на них
    меняются сразу (на диске), остальное — по «Сохранить»."""

    TABS = (("rules_proxy", "Туннель", "Через VPN, даже если иначе пошло бы напрямую."),
            ("rules_direct", "Обход", "Напрямую, мимо VPN."),
            ("rules_block", "Блокировать", "Соединение отклоняется. Главнее «Туннеля» и "
                                           "«Обхода»."))

    def __init__(self, parent, profile: routing.RoutingProfile, names: list[str],
                 busy: bool = False):
        super().__init__(parent)
        self.setWindowTitle(f"Профиль маршрутизации: {profile.name}")
        self.resize(1080, 780)
        self.p = routing.from_dict(routing.to_dict(profile), profile.id)
        self.names = [n for n in names if n != profile.name]
        layout = QVBoxLayout(self)
        if busy:
            layout.addWidget(_hint("VPN подключён: изменения подействуют со следующего "
                                   "подключения."))
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)
        self.tabs.addTab(self._tab_main(), "Основное")
        self.rule_edits = {}
        self.builtin_views = {}
        for key, title, hint in self.TABS:
            self.tabs.addTab(self._tab_rules(key, hint), title)
        self.tabs.addTab(self._tab_advanced(), "Дополнительно")
        self.tabs.addTab(self._tab_files(), "Файлы")
        layout.addWidget(_buttons(self))
        self._load()

    # --- вкладки ---
    def _tab_main(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        form = QFormLayout()
        self.name = QLineEdit()
        form.addRow("Название:", self.name)
        layout.addLayout(form)
        layout.addWidget(_title("Встроенные правила"))
        grid = QGridLayout()
        self.boxes = {}
        for i, (key, text, tip) in enumerate((
                ("block_quic", "Блокировать QUIC (UDP 443)",
                 "Браузеры переходят на обычный TCP. QUIC через VPN часто тормозит и его проще "
                 "распознать."),
                ("block_udp", "Блокировать весь UDP",
                 "По UDP внутри VLESS VPN чаще распознают и режут. Игры, звонки и Discord "
                 "голосом могут перестать работать. DNS через сервер пойдёт по TCP."),
                ("route_ru", "Российские сайты напрямую",
                 "Зоны .ru, .рф, .su, список российских сайтов и российские адреса — без сервера "
                 "VPN: Госуслуги, банки, маркетплейсы."),
                ("block_ads", "Блокировать рекламу",
                 "Встроенный список рекламных и следящих доменов (geosite:category-ads-all)."),
                ("adblock", "Включить AdBlock",
                 "Фильтр AdGuard DNS (десятки тысяч доменов рекламы и слежки): скачивается и "
                 "обновляется раз в сутки. Шире, чем «Блокировать рекламу»."))):
            box = QCheckBox(text)
            box.setToolTip(tip)
            box.toggled.connect(self._refresh_builtin)
            grid.addWidget(box, i // 2, i % 2)
            self.boxes[key] = box
        layout.addLayout(grid)
        row = QHBoxLayout()
        row.addWidget(QLabel("Список AdBlock:"))
        self.adblock_url = QLineEdit()
        self.adblock_url.setToolTip("Список в формате AdBlock (||домен^), hosts или по домену "
                                    "на строке")
        row.addWidget(self.adblock_url, 1)
        self.adblock_btn = QPushButton("Обновить список")
        self.adblock_btn.clicked.connect(self._refresh_adblock)
        row.addWidget(self.adblock_btn)
        layout.addLayout(row)
        self.adblock_status = _hint()
        layout.addWidget(self.adblock_status)
        layout.addWidget(_title("WARP"))
        row = QHBoxLayout()
        self.warp_box = QCheckBox("Включить WARP")
        self.warp_box.setToolTip("Цепочка с WireGuard-сервером Cloudflare (WireGuard или "
                                 "AmneziaWG) — «Настройки WARP...»")
        self.warp_box.toggled.connect(self._warp_toggled)
        warp_btn = QPushButton("Настройки WARP...")
        warp_btn.clicked.connect(self._edit_warp)
        row.addWidget(self.warp_box)
        row.addWidget(warp_btn)
        row.addStretch()
        layout.addLayout(row)
        self.warp_status = _hint()
        layout.addWidget(self.warp_status)
        self.source_frame = QFrame()
        sl = QVBoxLayout(self.source_frame)
        sl.setContentsMargins(0, 0, 0, 0)
        sl.addWidget(_title("Ссылка профиля"))
        sl.addWidget(_hint("Профиль загружен по ссылке: при обновлении его правила и настройки "
                           "заменяются присланными (название, ключ WARP и ссылки на файлы "
                           "остаются)."))
        form = QFormLayout()
        self.source_url = QLineEdit()
        form.addRow("Ссылка:", self.source_url)
        self.source_interval = IntervalPicker()
        form.addRow("Обновлять:", self.source_interval)
        sl.addLayout(form)
        row = QHBoxLayout()
        self.source_btn = QPushButton("Обновить сейчас")
        self.source_btn.clicked.connect(self._update_profile_source)
        row.addWidget(self.source_btn)
        self.source_status = _hint()
        row.addWidget(self.source_status, 1)
        sl.addLayout(row)
        layout.addWidget(self.source_frame)
        layout.addStretch()
        return page

    def _tab_rules(self, key: str, hint: str) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(_hint(
            hint + " По одному на строку. Домен: example.com (с поддоменами), full:example.com "
            "(точно), keyword:слово, regexp:выражение, geosite:категория, ext:файл.dat:метка. "
            "Адрес: 1.2.3.4, 10.0.0.0/8, geoip:страна. # — комментарий. Свои правила главнее "
            "встроенных."))
        layout.addWidget(_hint("Встроенные (включаются на вкладке «Основное»):"))
        fixed = QPlainTextEdit()
        fixed.setReadOnly(True)
        fixed.setMaximumHeight(170)
        fixed.setStyleSheet("QPlainTextEdit { background: palette(alternate-base); }")
        layout.addWidget(fixed)
        layout.addWidget(_hint("Свои:"))
        edit = QPlainTextEdit()
        edit.setPlaceholderText("example.com\ngeosite:youtube\n1.2.3.0/24")
        layout.addWidget(edit, 1)
        self.builtin_views[key] = fixed
        self.rule_edits[key] = edit
        return page

    def _tab_advanced(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(_hint(
            "Правила с полями маршрутизации Xray, как в Throne: входящее (inbound), домены, "
            "адреса, порты, сеть, протокол, адрес источника. Проверяются раньше всех остальных, "
            "сверху вниз; первое подошедшее решает. Двойной щелчок — изменить."))
        self.adv_table = make_table([("Вкл.", 50), ("Название", 200), ("Действие", 170),
                                     ("Условие", 400)])
        self.adv_table.cellDoubleClicked.connect(lambda *_: self._edit_rule())
        self.adv_table.itemChanged.connect(self._adv_check)
        layout.addWidget(self.adv_table, 1)
        row = QHBoxLayout()
        for text, slot in (("Добавить...", self._add_rule), ("Изменить...", self._edit_rule),
                           ("Удалить", self._delete_rule), ("Выше", lambda: self._move_rule(-1)),
                           ("Ниже", lambda: self._move_rule(1)), ("Как JSON...", self._json_rules)):
            button = QPushButton(text)
            button.clicked.connect(slot)
            row.addWidget(button)
        row.addStretch()
        layout.addLayout(row)
        return page

    def _tab_files(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        if self.p.is_default:
            layout.addWidget(_hint("В профиль Default файлы не добавляются. Создайте свой "
                                   "профиль («Создать» или «Дублировать») — в него можно "
                                   "добавить свои файлы маршрутизации .dat."))
            layout.addStretch()
            return page
        layout.addWidget(_hint(
            "Свои файлы маршрутизации .dat (geosite или geoip Xray, например списки "
            "runetfreedom). В правилах: ext:имя.dat:метка. Файлы geosite.dat и geoip.dat "
            "заменяют встроенные (тогда geosite:/geoip: берутся из них). Добавление и удаление "
            "— сразу, без «Сохранить»."))
        self.file_table = make_table([("Файл", 200), ("Вид", 80), ("Меток", 70),
                                      ("Размер", 90), ("Обновлено", 130), ("Ссылка", 300)])
        self.file_table.itemSelectionChanged.connect(self._file_selected)
        layout.addWidget(self.file_table, 1)
        row = QHBoxLayout()
        for text, slot in (("Добавить файлы...", self._add_files),
                           ("По ссылке...", self._add_link), ("Удалить", self._remove_file),
                           ("Обновить сейчас", self._update_file)):
            button = QPushButton(text)
            button.clicked.connect(slot)
            row.addWidget(button)
        row.addStretch()
        layout.addLayout(row)
        self.file_detail = QFrame()
        dl = QVBoxLayout(self.file_detail)
        dl.setContentsMargins(0, 0, 0, 0)
        form = QFormLayout()
        self.file_url = QLineEdit()
        self.file_url.setPlaceholderText("ссылка для автообновления (необязательно)")
        form.addRow("Ссылка:", self.file_url)
        self.file_interval = IntervalPicker()
        form.addRow("Обновлять:", self.file_interval)
        dl.addLayout(form)
        row = QHBoxLayout()
        save = QPushButton("Сохранить ссылку")
        save.clicked.connect(self._save_file_source)
        row.addWidget(save)
        self.file_status = _hint()
        row.addWidget(self.file_status, 1)
        dl.addLayout(row)
        self.file_tags = QPlainTextEdit()
        self.file_tags.setReadOnly(True)
        self.file_tags.setMaximumHeight(120)
        dl.addWidget(_hint("Метки в файле:"))
        dl.addWidget(self.file_tags)
        layout.addWidget(self.file_detail)
        self.file_detail.setEnabled(False)
        return page

    # --- заполнение ---
    def _load(self) -> None:
        p = self.p
        self.name.setText(p.name)
        self.name.setReadOnly(p.is_default)
        if p.is_default:
            self.name.setToolTip("Название профиля Default не меняется")
        for key, box in self.boxes.items():
            box.blockSignals(True)
            box.setChecked(bool(getattr(p, key)))
            box.blockSignals(False)
        self.adblock_url.setText(p.adblock_url)
        path = routing.adblock_file(p.adblock_url)
        self.adblock_status.setText(
            f"Список загружен {_when(path.stat().st_mtime)}" if path.is_file() else
            "Список ещё не загружен — загрузится при подключении или кнопкой")
        self.warp_box.blockSignals(True)
        self.warp_box.setChecked(bool(p.warp.get("enabled")))
        self.warp_box.blockSignals(False)
        for key, edit in self.rule_edits.items():
            edit.setPlainText("\n".join(getattr(p, key)))
        src = p.sources.get("")
        self.source_frame.setVisible(bool(src))
        if src:
            self.source_url.setText(src.get("url", ""))
            self.source_interval.set_hours(src.get("interval", 24))
            self._source_text(src)
        self._fill_rules()
        self._fill_files()
        self._refresh_builtin()
        self._warp_text()

    def _source_text(self, src: dict) -> None:
        text = f"Обновлён: {_when(float(src.get('updated') or 0))}"
        if src.get("error"):
            text += f". Последняя ошибка: {src['error']}"
        self.source_status.setText(text)

    def _collect(self) -> None:
        """Поля окна → self.p (кроме файлов: они уже на диске)."""
        p = self.p
        if not p.is_default:
            p.name = routing.unique_name(self.name.text(), self.names)
        for key, box in self.boxes.items():
            setattr(p, key, box.isChecked())
        p.adblock_url = self.adblock_url.text().strip() or routing.ADBLOCK_URL
        p.warp["enabled"] = self.warp_box.isChecked()
        for key, edit in self.rule_edits.items():
            setattr(p, key, [s for s in edit.toPlainText().splitlines() if s.strip()])
        if p.sources.get("") is not None:
            url, hours = self.source_url.text().strip(), self.source_interval.hours()
            old = p.sources[""]
            p.sources[""] = dict(old, url=url, interval=hours,
                                 updated=old.get("updated", 0) if old.get("url") == url else 0.0)

    def _refresh_builtin(self) -> None:
        probe = routing.from_dict(routing.to_dict(self.p), self.p.id)
        for key, box in self.boxes.items():
            setattr(probe, key, box.isChecked())
        probe.warp = dict(probe.warp, enabled=self.warp_box.isChecked())
        probe.adblock_url = self.adblock_url.text().strip() or routing.ADBLOCK_URL
        lines = builtin_lines(probe)
        for key, view in self.builtin_views.items():
            view.setPlainText("\n".join(lines[key]))

    def _warp_toggled(self, on: bool) -> None:
        self.p.warp["enabled"] = on
        if on and warp.problems(self.p.warp):
            self._edit_warp()
        self._refresh_builtin()
        self._warp_text()

    def _warp_text(self) -> None:
        w = self.p.warp
        problems = warp.problems(w)
        text = (f"{warp.PROTOCOLS[w['protocol']]}; {warp.CHAINS[w['chain']]}. " +
                ("Ключ есть." if not problems else "Не хватает: " + "; ".join(problems)))
        self.warp_status.setText(text if w.get("enabled") else "Выключен. " + text)

    def _edit_warp(self) -> None:
        dialog = WarpDialog(self, self.p.warp)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.p.warp = dict(dialog.value(), enabled=self.warp_box.isChecked())
        self._refresh_builtin()
        self._warp_text()

    def _refresh_adblock(self) -> None:
        url = self.adblock_url.text().strip() or routing.ADBLOCK_URL
        self.adblock_btn.setEnabled(False)
        self.adblock_status.setText("Загружаю список...")

        def done(count, error):
            self.adblock_btn.setEnabled(True)
            self.adblock_status.setText(f"Список не загружен: {error}" if error else
                                        f"Список загружен: {count} доменов")

        run_job(self, lambda: routing.refresh_adblock(url), done)

    def _update_profile_source(self) -> None:
        if QMessageBox.question(
                self, "Обновить профиль", "Скачать профиль по ссылке заново? Правила и настройки "
                "заменятся присланными, несохранённые изменения в окне пропадут.") != \
                QMessageBox.StandardButton.Yes:
            return
        url, hours = self.source_url.text().strip(), self.source_interval.hours()
        fresh = routing.get(self.p.id) or self.p
        routing.set_source(fresh, "", url, hours)
        self.source_btn.setEnabled(False)
        self.source_status.setText("Загружаю...")

        def done(text, error):
            self.source_btn.setEnabled(True)
            updated = routing.get(self.p.id)
            if updated is not None:
                self.p = updated
                self._load()
            if error is not None:
                self.source_status.setText(f"Не обновлён: {error}")

        run_job(self, lambda: routing.update_source(fresh, ""), done)

    # --- «Дополнительно» ---
    def _fill_rules(self) -> None:
        self.adv_table.blockSignals(True)
        self.adv_table.setRowCount(0)
        for rule in self.p.advanced:
            row = self.adv_table.rowCount()
            self.adv_table.insertRow(row)
            check = QTableWidgetItem()
            check.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled |
                           Qt.ItemFlag.ItemIsSelectable)
            check.setCheckState(Qt.CheckState.Checked if rule.get("enabled", True)
                                else Qt.CheckState.Unchecked)
            self.adv_table.setItem(row, 0, check)
            for col, text in enumerate((rule.get("name") or "—",
                                        routing.OUTBOUNDS.get(rule.get("outbound"), "Туннель"),
                                        routing.rule_text(rule)), start=1):
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                self.adv_table.setItem(row, col, item)
        self.adv_table.blockSignals(False)

    def _adv_check(self, item: QTableWidgetItem) -> None:
        if item.column() == 0 and 0 <= item.row() < len(self.p.advanced):
            self.p.advanced[item.row()]["enabled"] = item.checkState() == Qt.CheckState.Checked

    def _selected_rule(self) -> int:
        row = self.adv_table.currentRow()
        return row if 0 <= row < len(self.p.advanced) else -1

    def _add_rule(self) -> None:
        dialog = RuleDialog(self, None, self.warp_box.isChecked())
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.p.advanced.append(dialog.rule())
            self._fill_rules()
            self.adv_table.selectRow(len(self.p.advanced) - 1)

    def _edit_rule(self) -> None:
        row = self._selected_rule()
        if row < 0:
            return
        dialog = RuleDialog(self, self.p.advanced[row], self.warp_box.isChecked())
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.p.advanced[row] = dialog.rule()
            self._fill_rules()
            self.adv_table.selectRow(row)

    def _delete_rule(self) -> None:
        row = self._selected_rule()
        if row >= 0:
            del self.p.advanced[row]
            self._fill_rules()

    def _move_rule(self, step: int) -> None:
        row = self._selected_rule()
        target = row + step
        if row < 0 or not 0 <= target < len(self.p.advanced):
            return
        rules = self.p.advanced
        rules[row], rules[target] = rules[target], rules[row]
        self._fill_rules()
        self.adv_table.selectRow(target)

    def _json_rules(self) -> None:
        dialog = JsonRulesDialog(self, self.p.advanced)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.p.advanced = dialog.result
            self._fill_rules()

    # --- файлы ---
    def _fill_files(self) -> None:
        if self.p.is_default:
            return
        selected = self._selected_file()
        self.file_table.setRowCount(0)
        for f in self.p.files():
            try:
                kind, tags = routing.dat_info(f)
                kind_text, count = kind, str(len(tags))
            except (OSError, ValueError) as e:
                kind_text, count = "ошибка", str(e)
            src = self.p.sources.get(f.name) or {}
            row = self.file_table.rowCount()
            self.file_table.insertRow(row)
            values = (f.name, kind_text, count, human_size(f.stat().st_size),
                      _when(f.stat().st_mtime), src.get("url", "") + (
                          f" (ошибка: {src['error']})" if src.get("error") else ""))
            for col, text in enumerate(values):
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                item.setData(Qt.ItemDataRole.UserRole, f.name)
                self.file_table.setItem(row, col, item)
            if f.name == selected:
                self.file_table.selectRow(row)

    def _selected_file(self) -> str:
        if self.p.is_default:
            return ""
        item = self.file_table.item(self.file_table.currentRow(), 0) \
            if self.file_table.currentRow() >= 0 else None
        return item.data(Qt.ItemDataRole.UserRole) if item is not None else ""

    def _file_selected(self) -> None:
        name = self._selected_file()
        self.file_detail.setEnabled(bool(name))
        if not name:
            return
        src = self.p.sources.get(name) or {}
        self.file_url.setText(src.get("url", ""))
        self.file_interval.set_hours(src.get("interval", 24))
        self.file_status.setText((f"Обновлён: {_when(float(src.get('updated') or 0))}" +
                                  (f". Ошибка: {src['error']}" if src.get("error") else ""))
                                 if src.get("url") else "Ссылки нет — файл добавлен вручную")
        try:
            kind, tags = routing.dat_info(self.p.files_dir / name)
            shown = tags[:400]
            self.file_tags.setPlainText(
                f"{kind}: " + ", ".join(shown) + (f" … и ещё {len(tags) - 400}"
                                                  if len(tags) > 400 else ""))
        except (OSError, ValueError) as e:
            self.file_tags.setPlainText(f"Файл не прочитан: {e}")

    def _fresh(self) -> routing.RoutingProfile:
        """Профиль с диска (для операций с файлами: несохранённые поля окна не пишутся)."""
        return routing.get(self.p.id) or self.p

    def _after_files(self, fresh: routing.RoutingProfile) -> None:
        self.p.sources = fresh.sources
        self._fill_files()
        self._file_selected()

    def _add_files(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(self, "Файлы маршрутизации", "",
                                                "Файлы .dat (*.dat);;Все (*)")
        if not paths:
            return
        fresh = self._fresh()

        def done(added, error):
            if error is not None:
                QMessageBox.warning(self, "Файлы", str(error))
            self._after_files(fresh)

        run_job(self, lambda: routing.add_files(fresh, paths), done)

    def _add_link(self) -> None:
        dialog = LinkDialog(self, self.p)
        dialog.target.setEnabled(False)  # из окна профиля — только в этот профиль
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        url, hours, _ = dialog.values()
        fresh = self._fresh()
        self.file_status.setText("Загружаю...")

        def done(result, error):
            if error is not None:
                QMessageBox.warning(self, "По ссылке", str(error))
            else:
                self.file_status.setText(result[1])
            self._after_files(routing.get(self.p.id) or fresh)

        run_job(self, lambda: routing.import_url(url, hours, fresh, [], to_new=False), done)

    def _remove_file(self) -> None:
        name = self._selected_file()
        if not name or QMessageBox.question(self, "Удалить", f"Удалить файл {name} из профиля?") \
                != QMessageBox.StandardButton.Yes:
            return
        fresh = self._fresh()
        routing.remove_file(fresh, name)
        self._after_files(fresh)

    def _save_file_source(self) -> None:
        name = self._selected_file()
        if not name:
            return
        fresh = self._fresh()
        url = self.file_url.text().strip()
        if url:
            routing.set_source(fresh, name, url, self.file_interval.hours())
        else:
            fresh.sources.pop(name, None)
            routing.save(fresh)
        self._after_files(fresh)

    def _update_file(self) -> None:
        name = self._selected_file()
        fresh = self._fresh()
        if not name or not (fresh.sources.get(name) or {}).get("url"):
            QMessageBox.information(self, "Обновить", "У выбранного файла нет ссылки.")
            return
        self.file_status.setText("Загружаю...")

        def done(text, error):
            self._after_files(routing.get(self.p.id) or fresh)
            if error is not None:
                self.file_status.setText(f"Не обновлён: {error}")

        run_job(self, lambda: routing.update_source(fresh, name), done)

    def accept(self) -> None:
        self._collect()
        if self.p.warp.get("enabled") and warp.problems(self.p.warp) and QMessageBox.question(
                self, "WARP", "WARP включён, но ключа нет — подключение с этим профилем не "
                "получится. Сохранить всё равно?") != QMessageBox.StandardButton.Yes:
            return
        fresh = routing.get(self.p.id)
        if fresh is not None:  # файлы и их ссылки могли поменяться в окне — с диска
            self.p.sources = {k: v for k, v in fresh.sources.items() if k != ""} | (
                {"": self.p.sources[""]} if "" in self.p.sources else {})
        routing.save(self.p)
        super().accept()


# ---------------- карточка в «Настройках клиента» ----------------
class RoutingCard(QWidget):
    """Выбор профиля маршрутизации и действия с профилями."""

    changed = Signal()

    def __init__(self, log=None, busy=None):
        super().__init__()
        self.log = log or (lambda text: None)
        self.busy = busy or (lambda: False)
        self.profiles: list[routing.RoutingProfile] = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        row = QHBoxLayout()
        row.addWidget(QLabel("Профиль:"))
        self.combo = QComboBox()
        self.combo.setMinimumWidth(260)
        self.combo.currentIndexChanged.connect(self._on_select)
        row.addWidget(self.combo, 1)
        layout.addLayout(row)
        row = QHBoxLayout()
        self.buttons = {}
        for key, text, slot in (("create", "Создать", self._create),
                                ("duplicate", "Дублировать", self._duplicate),
                                ("edit", "Редактировать", self._edit),
                                ("delete", "Удалить", self._delete)):
            button = QPushButton(text)
            button.clicked.connect(slot)
            row.addWidget(button)
            self.buttons[key] = button
        imp = QPushButton("Импорт")
        menu = QMenu(imp)
        menu.addAction("Из файлов (профили .json/.zip и файлы .dat)...", self._import_files)
        menu.addAction("По ссылке...", self._import_url)
        imp.setMenu(menu)
        row.addWidget(imp)
        export = QPushButton("Экспорт...")
        export.clicked.connect(self._export)
        row.addWidget(export)
        row.addStretch()
        layout.addLayout(row)
        self.summary = _hint()
        layout.addWidget(self.summary)
        self.reload()

    def reload(self, select: str | None = None) -> None:
        self.profiles = routing.load_all()
        select = select or routing.active().id
        self.combo.blockSignals(True)
        self.combo.clear()
        for p in self.profiles:
            self.combo.addItem(p.name, p.id)
        index = max(0, self.combo.findData(select))
        self.combo.setCurrentIndex(index)
        self.combo.blockSignals(False)
        self._on_select(index)

    def current(self) -> routing.RoutingProfile | None:
        index = self.combo.currentIndex()
        return self.profiles[index] if 0 <= index < len(self.profiles) else None

    def names(self) -> list[str]:
        return [p.name for p in self.profiles]

    def set_busy(self, busy: bool) -> None:
        self.combo.setEnabled(not busy)
        self.combo.setToolTip("Профиль меняется, когда VPN отключён" if busy else "")
        p = self.current()
        self.buttons["delete"].setEnabled(bool(p and not p.is_default) and not (
            busy and p.id == routing.active().id))

    def _on_select(self, _index: int) -> None:
        p = self.current()
        if p is None:
            return
        if not self.busy():
            routing.set_active(p.id)
        self.summary.setText(p.summary())
        self.set_busy(self.busy())
        self.changed.emit()

    def _create(self) -> None:
        name, ok = QInputDialog.getText(self, "Новый профиль маршрутизации", "Название:",
                                        text="Новый профиль")
        if not ok:
            return
        p = routing.create(name, self.names())
        activity.record("vpn", f"Создан профиль маршрутизации {p.name}")
        self.reload(p.id)
        self._edit()

    def _duplicate(self) -> None:
        p = self.current()
        if p is None:
            return
        copy = routing.duplicate(p, self.names())
        activity.record("vpn", f"Профиль маршрутизации {p.name} скопирован как {copy.name}")
        self.reload(copy.id)

    def _edit(self) -> None:
        p = self.current()
        if p is None:
            return
        dialog = RoutingEditor(self.window(), p, self.names(), self.busy())
        dialog.exec()
        self.reload(p.id)

    def _delete(self) -> None:
        p = self.current()
        if p is None or p.is_default:
            return
        if QMessageBox.question(self, "Удалить", f"Удалить профиль маршрутизации «{p.name}» "
                                "вместе с его файлами?") != QMessageBox.StandardButton.Yes:
            return
        routing.delete(p)
        activity.record("vpn", f"Удалён профиль маршрутизации {p.name}")
        self.reload(routing.DEFAULT_ID)

    def _import_files(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Импорт маршрутизации", "",
            "Профили и файлы (*.json *.zip *.dat);;Все (*)")
        if not paths:
            return
        from diag import features
        features.begin("vpn.routing").fact("kind", "файлы")
        current, names = self.current(), self.names()

        def done(result, error):
            if error is not None:
                features.end_if_active("vpn.routing", False, error=str(error))
                QMessageBox.warning(self, "Импорт", str(error))
                return
            profile, notes = result
            features.end_if_active("vpn.routing", True)
            for note in notes:
                self.log(note)
                activity.record("vpn", note)
            self.reload(profile.id)
            QMessageBox.information(self, "Импорт", "\n".join(notes))

        run_job(self, lambda: routing.import_paths(paths, current, names), done)

    def _import_url(self) -> None:
        dialog = LinkDialog(self.window(), self.current())
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        url, hours, to_new = dialog.values()
        if not url:
            return
        from diag import features
        features.begin("vpn.routing").fact("kind", "ссылка")
        current, names = self.current(), self.names()
        self.summary.setText("Загружаю по ссылке...")

        def done(result, error):
            if error is not None:
                features.end_if_active("vpn.routing", False, error=str(error))
                self.reload()
                QMessageBox.warning(self, "Импорт по ссылке", str(error))
                return
            profile, text = result
            features.end_if_active("vpn.routing", True)
            self.log(text)
            activity.record("vpn", text)
            self.reload(profile.id)

        run_job(self, lambda: routing.import_url(url, hours, current, names, to_new), done)

    def _export(self) -> None:
        p = self.current()
        if p is None:
            return
        has_files = bool(p.files())
        suggested = p.name + (".zip" if has_files else ".json")
        path, _ = QFileDialog.getSaveFileName(
            self, "Экспорт профиля маршрутизации", suggested,
            "Архив с файлами (*.zip)" if has_files else
            "Профиль маршрутизации (*.json);;Архив (*.zip)")
        if not path:
            return
        keys = False
        if p.warp.get("private_key"):
            keys = QMessageBox.question(
                self, "Экспорт", "Включить в файл закрытый ключ WARP? Без него тот, кому вы "
                "передадите профиль, получит свой ключ сам.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes
        try:
            saved = routing.export(p, path, keys)
        except OSError as e:
            QMessageBox.warning(self, "Экспорт", str(e))
            return
        self.log(f"Профиль маршрутизации {p.name} сохранён: {saved.name}")
        activity.record("vpn", f"Экспорт профиля маршрутизации {p.name}")
