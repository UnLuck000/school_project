"""Окно VPN (прототип): профили, подключение, состояние, трафик, журнал."""
import threading
import time

from PySide6.QtCore import QObject, Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFrame, QGridLayout, QHBoxLayout,
    QInputDialog, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMessageBox,
    QPlainTextEdit, QPushButton, QVBoxLayout,
)

from analyzer.fileops import human_size
from recovery import activity
from vpn import backends, profiles

STATE_TEXT = {backends.DISCONNECTED: ("Не подключено", "#c0392b"),
              backends.CONNECTING: ("Подключение...", "#d68910"),
              backends.CONNECTED: ("Подключено", "#2e9e4f"),
              backends.ERROR: ("Ошибка", "#c0392b")}


class _Bridge(QObject):
    log = Signal(str)
    ip = Signal(str)


class PasteDialog(QDialog):
    """Профиль из текста конфигурации (вставить из буфера)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Новый профиль VPN")
        self.resize(640, 460)
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
        # ссылка в буфере обмена — сразу в поле
        from PySide6.QtWidgets import QApplication
        clip = QApplication.clipboard().text().strip()
        if clip.lower().startswith("vless://"):
            self.text.setPlainText(clip)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                   QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


class DirectAppsDialog(QDialog):
    """Программы, которые идут напрямую, мимо VPN (режим TUN): игры, торренты, банки."""

    def __init__(self, parent, apps: list[str]):
        super().__init__(parent)
        self.setWindowTitle("Программы напрямую, мимо VPN")
        self.resize(640, 380)
        layout = QVBoxLayout(self)
        hint = QLabel("Трафик этих программ не идёт через сервер VPN (только в режиме TUN). "
                      "Программа узнаётся по полному пути к файлу.")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        self.list = QListWidget()
        self.list.addItems(apps)
        layout.addWidget(self.list, 1)
        row = QHBoxLayout()
        add = QPushButton("Добавить программу...")
        add.clicked.connect(self._add)
        remove = QPushButton("Убрать выбранную")
        remove.clicked.connect(lambda: self.list.takeItem(self.list.currentRow()))
        row.addWidget(add)
        row.addWidget(remove)
        row.addStretch()
        layout.addLayout(row)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                   QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _add(self) -> None:
        import os
        path, _ = QFileDialog.getOpenFileName(self, "Программа", "", "Программы (*.exe)")
        if path:
            path = os.path.normpath(path)
            if not self.list.findItems(path, Qt.MatchFlag.MatchFixedString):
                self.list.addItem(path)

    def apps(self) -> list[str]:
        return [self.list.item(i).text() for i in range(self.list.count())]


class VpnWindow(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("VPN")
        self.setWindowFlag(Qt.WindowType.Window)
        self.resize(980, 640)
        self.profiles = profiles.load()
        if not self.profiles:
            self.profiles = [profiles.demo_profile()]
        self.backend: backends.Backend | None = None
        self.active: profiles.Profile | None = None
        self._last = (0, 0, time.monotonic())
        self.bridge = _Bridge()
        self.bridge.log.connect(self._append_log)
        self.bridge.ip.connect(lambda text: self.ip_label.setText(text))

        root = QHBoxLayout(self)
        # ----- профили -----
        left = QVBoxLayout()
        left.addWidget(QLabel("Профили"))
        self.list = QListWidget()
        self.list.currentRowChanged.connect(self._on_select)
        left.addWidget(self.list, 1)
        row = QHBoxLayout()
        for text, slot in (("Импорт файла...", self._import), ("Вставить...", self._paste),
                           ("Переименовать", self._rename), ("Удалить", self._delete)):
            button = QPushButton(text)
            button.clicked.connect(slot)
            row.addWidget(button)
        left.addLayout(row)
        root.addLayout(left, 2)

        # ----- состояние -----
        right = QVBoxLayout()
        card = QFrame()
        card.setObjectName("vpnCard")
        card.setStyleSheet("QFrame#vpnCard { border: 1px solid palette(mid); border-radius: 10px;"
                           " background: palette(base); }")
        grid = QGridLayout(card)
        self.state_label = QLabel()
        self.state_label.setStyleSheet("font-size: 18pt; font-weight: 600;")
        grid.addWidget(self.state_label, 0, 0, 1, 2)
        self.connect_btn = QPushButton("Подключить")
        self.connect_btn.setMinimumHeight(40)
        self.connect_btn.clicked.connect(self.toggle)
        grid.addWidget(self.connect_btn, 0, 2)
        self.info = {}
        for i, (key, title) in enumerate((("server", "Сервер"), ("kind", "Протокол"),
                                          ("time", "Время подключения"),
                                          ("traffic", "Получено / отправлено"),
                                          ("speed", "Скорость"), ("engine", "Клиент"))):
            grid.addWidget(QLabel(title + ":"), i + 1, 0)
            value = QLabel("—")
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            grid.addWidget(value, i + 1, 1, 1, 2)
            self.info[key] = value
        right.addWidget(card)

        ip_row = QHBoxLayout()
        self.ip_btn = QPushButton("Проверить внешний IP")
        self.ip_btn.clicked.connect(self._check_ip)
        self.ip_label = QLabel("")
        ip_row.addWidget(self.ip_btn)
        ip_row.addWidget(self.ip_label, 1)
        right.addLayout(ip_row)

        mode_row = QHBoxLayout()
        self.mode_label = QLabel("Режим VLESS:")
        self.cmb_mode = QComboBox()
        self._modes = list(profiles.MODES)
        self.cmb_mode.addItems(list(profiles.MODES.values()))
        self.cmb_mode.setToolTip(
            "TUN: sing-box + Xray — весь трафик через виртуальный адаптер: маршруты и DNS "
            "настраивает sing-box, соединение с сервером ведёт Xray (нужны права "
            "администратора). Системный прокси — "
            "браузеры и программы, которые слушаются прокси Windows (Xray). TUN через Xray — "
            "запасной вариант (wintun.dll рядом с xray.exe, экспериментально). Только "
            "локальный прокси — через VPN идут лишь программы с прокси 127.0.0.1:порт "
            "(Telegram, переменная HTTPS_PROXY), остальное — как без VPN.")
        self.cmb_mode.currentIndexChanged.connect(self._on_mode)
        mode_row.addWidget(self.mode_label)
        mode_row.addWidget(self.cmb_mode, 1)
        right.addLayout(mode_row)
        self.chk_auto = QCheckBox("Профиль для автоподключения (при запуске программы — если "
                                  "включено в настройках)")
        self.chk_auto.toggled.connect(self._on_auto)
        right.addWidget(self.chk_auto)
        from ui import settings as cfg
        self.chk_kill = QCheckBox("Kill switch: интернет только через VPN, при обрыве — "
                                  "блокировка")
        self.chk_kill.setToolTip(
            "Режим TUN: пока VPN подключён, брандмауэр Windows разрешает выход в интернет "
            "только через туннель (локальная сеть — можно). Если VPN оборвётся, интернет "
            "останется перекрытым, пока вы не снимете блокировку. Включение и снятие — в "
            "журнале действий с откатом.")
        self.chk_kill.setChecked(cfg.get("vpn/killswitch"))
        self.chk_kill.toggled.connect(lambda on: cfg.set_("vpn/killswitch", on))
        right.addWidget(self.chk_kill)
        self.chk_ipv6 = QCheckBox("IPv6 через VPN")
        self.chk_ipv6.setToolTip(
            "Режим TUN. Включено — IPv6 идёт через туннель (если сервер его поддерживает). "
            "Выключено — IPv6 перекрыт, программы работают по IPv4; мимо VPN он не идёт ни в "
            "каком случае.")
        self.chk_ipv6.setChecked(cfg.get("vpn/ipv6"))
        self.chk_ipv6.toggled.connect(lambda on: cfg.set_("vpn/ipv6", on))
        right.addWidget(self.chk_ipv6)
        self.unblock_btn = QPushButton("Снять блокировку интернета (kill switch)")
        self.unblock_btn.setStyleSheet("color: #c0392b; font-weight: 600;")
        self.unblock_btn.clicked.connect(self._release_block)
        self.unblock_btn.setVisible(False)
        right.addWidget(self.unblock_btn)

        # ----- маршрутизация, Mux, фрагментация -----
        route = QGridLayout()
        route.setContentsMargins(0, 4, 0, 4)
        self.route_boxes = {}
        for i, (key, text, tip) in enumerate((
                ("route_ru", "Российские сайты напрямую",
                 "Сайты в зонах .ru, .рф, .su, из списка российских сайтов и с российскими "
                 "адресами идут напрямую, без сервера VPN: Госуслуги, банки и маркетплейсы "
                 "работают быстрее и не ругаются на зарубежный IP."),
                ("block_ads", "Блокировать рекламу и трекеры",
                 "Список рекламных и следящих доменов (geosite:category-ads-all) — "
                 "соединения к ним не устанавливаются."),
                ("mux", "Mux (несколько соединений в одном)",
                 "Меньше рукопожатий с сервером — быстрее открываются сайты с множеством "
                 "запросов. Не работает со ссылками flow=xtls-rprx-vision (для них не "
                 "включается). Минус: одна потеря пакета тормозит все соединения внутри."),
                ("fragment", "Фрагментация (обход DPI)",
                 "Начало TLS-соединения с сервером режется на кусочки 100–200 байт с паузой "
                 "10–20 мс, чтобы DPI провайдера не распознал его. Нужно, если провайдер "
                 "режет или тормозит соединение с сервером VPN."))):
            box = QCheckBox(text)
            box.setToolTip(tip)
            box.setChecked(cfg.get(f"vpn/{key}"))
            box.toggled.connect(lambda on, k=key: cfg.set_(f"vpn/{k}", on))
            route.addWidget(box, i // 2, i % 2)
            self.route_boxes[key] = box
        local_row = QHBoxLayout()
        self.chk_local = QCheckBox("Локальный прокси для программ (SOCKS5 и HTTP), порт:")
        self.chk_local.setToolTip(
            "Пока VPN подключён, программы с настройкой прокси 127.0.0.1:порт (Telegram, "
            "браузеры, переменная HTTPS_PROXY) ходят через VPN — по тем же правилам "
            "маршрутизации. Доступен только с этого компьютера. Если порт занят другой "
            "программой (например, Throne), VPN подключится без локального прокси.")
        self.chk_local.setChecked(cfg.get("vpn/local_proxy"))
        self.chk_local.toggled.connect(lambda on: cfg.set_("vpn/local_proxy", on))
        from PySide6.QtWidgets import QSpinBox
        self.spn_port = QSpinBox()
        self.spn_port.setRange(1024, 65535)
        self.spn_port.setValue(cfg.get("vpn/local_port"))
        self.spn_port.valueChanged.connect(lambda v: cfg.set_("vpn/local_port", v))
        local_row.addWidget(self.chk_local)
        local_row.addWidget(self.spn_port)
        local_row.addStretch()
        route.addLayout(local_row, 3, 0, 1, 2)
        self.apps_btn = QPushButton()
        self.apps_btn.setToolTip("Программы, которые идут напрямую, мимо VPN (режим TUN)")
        self.apps_btn.clicked.connect(self._edit_apps)
        route.addWidget(self.apps_btn, 2, 0, 1, 2)
        right.addLayout(route)
        self._apps_text()
        from ui.widgets import guard_wheel
        guard_wheel(self)  # порт и режим меняются колесом только после щелчка

        right.addWidget(QLabel("Журнал"))
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(500)
        right.addWidget(self.log_view, 1)
        root.addLayout(right, 3)

        self._fill()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(1000)
        self._tick()

    def autoconnect(self) -> bool:
        """VPN вместе с программой (настройка vpn/autostart): профиль автоподключения."""
        auto = next((p for p in self.profiles if p.auto_connect), None)
        if auto is None:
            self.bridge.log.emit("Автоподключение: не выбран профиль для автоподключения")
            return False
        self.list.setCurrentRow(self.profiles.index(auto))
        self.toggle()
        return True

    # ----- профили -----
    def _fill(self, select: int = 0) -> None:
        self.list.clear()
        for p in self.profiles:
            item = QListWidgetItem(p.title)
            item.setToolTip(p.server)
            self.list.addItem(item)
        if self.profiles:
            self.list.setCurrentRow(min(select, len(self.profiles) - 1))

    def _current(self) -> profiles.Profile | None:
        row = self.list.currentRow()
        return self.profiles[row] if 0 <= row < len(self.profiles) else None

    def _on_select(self, _row: int) -> None:
        p = self._current()
        self.chk_auto.blockSignals(True)
        self.chk_auto.setChecked(bool(p and p.auto_connect))
        self.chk_auto.blockSignals(False)
        vless = bool(p and p.kind == "vless")
        self.mode_label.setVisible(vless)
        self.cmb_mode.setVisible(vless)
        if vless:
            self.cmb_mode.blockSignals(True)
            self.cmb_mode.setCurrentIndex(self._modes.index(p.mode) if p.mode in self._modes
                                          else 0)
            self.cmb_mode.blockSignals(False)
        self._tick()

    def _on_mode(self, index: int) -> None:
        p = self._current()
        if p is not None and p.kind == "vless":
            p.mode = self._modes[index]
            self._save()

    def _save(self) -> None:
        try:
            profiles.save([p for p in self.profiles if p.kind != "demo"] +
                          [p for p in self.profiles if p.kind == "demo"])
        except OSError as e:
            QMessageBox.warning(self, "VPN", f"Профили не сохранены: {e}")

    def _add(self, profile: profiles.Profile) -> None:
        self.profiles.append(profile)
        self._save()
        self._fill(len(self.profiles) - 1)
        activity.record("vpn", f"Добавлен профиль {profile.name} ({profile.kind})")

    def _import(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Конфигурация VPN", "",
                                              "WireGuard и OpenVPN (*.conf *.ovpn);;Все (*)")
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
        if ok and name.strip():
            p.name = name.strip()
            self._save()
            self._fill(self.list.currentRow())

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
        self._fill()

    def _on_auto(self, on: bool) -> None:
        p = self._current()
        if p is None:
            return
        for other in self.profiles:
            other.auto_connect = False
        p.auto_connect = on
        self._save()

    # ----- подключение -----
    def toggle(self) -> None:
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
        self.backend, self.active = backend, p
        self._last = (0, 0, time.monotonic())
        activity.record("vpn", f"Подключение: {p.name} ({p.kind}, {p.server})")
        threading.Thread(target=backend.connect, args=(p,), daemon=True).start()

    def _tick(self) -> None:
        backend = self.backend
        state = backend.state if backend else backends.DISCONNECTED
        text, color = STATE_TEXT[state]
        if state == backends.ERROR and backend.error:
            text = "Ошибка"
            self.connect_btn.setToolTip(backend.error)
        self.state_label.setText(f"● {text}")
        self.state_label.setStyleSheet(f"font-size: 18pt; font-weight: 600; color: {color};")
        busy = state in (backends.CONNECTED, backends.CONNECTING)
        self.connect_btn.setText("Отключить" if busy else "Подключить")
        from vpn import killswitch
        self.unblock_btn.setVisible(not busy and killswitch.active())
        for box in (self.chk_kill, self.chk_ipv6, self.apps_btn, self.chk_local, self.spn_port,
                    *self.route_boxes.values()):
            box.setEnabled(not busy)  # действуют со следующего подключения
        self.cmb_mode.setEnabled(not busy)
        p = self.active if busy else self._current()
        self.info["server"].setText(p.server if p else "—")
        kind = profiles.KINDS.get(p.kind, "—") if p else "—"
        if p and p.kind == "vless":
            kind += ", " + profiles.MODES.get(p.mode, p.mode).lower()
        self.info["kind"].setText(kind)
        engine = backend if busy else (self._engine(p) if p else None)
        self.info["engine"].setText(
            "—" if engine is None else getattr(engine, "exe", "") or
            ("встроенная имитация" if p and p.kind == "demo" else f"не найден: {engine.missing}"))
        if state == backends.CONNECTED:
            seconds = int(time.time() - backend.since)
            self.info["time"].setText(f"{seconds // 3600:02d}:{seconds // 60 % 60:02d}:"
                                      f"{seconds % 60:02d}")
            rx, tx = backend.counters()
            last_rx, last_tx, last_t = self._last
            dt = max(0.5, time.monotonic() - last_t)
            if last_rx or last_tx:
                self.info["speed"].setText(f"↓ {human_size(int((rx - last_rx) / dt))}/с   "
                                           f"↑ {human_size(int((tx - last_tx) / dt))}/с")
            self._last = (rx, tx, time.monotonic())
            self.info["traffic"].setText(f"{human_size(rx)} / {human_size(tx)}")
        else:
            for key in ("time", "traffic", "speed"):
                self.info[key].setText("—")

    def _engine(self, p: profiles.Profile):
        """Чем будет подключаться профиль (для строки «Клиент»), без повторного поиска."""
        key = (p.kind, p.mode)
        if getattr(self, "_engine_key", None) != key:
            self._engine_key = key
            self._engine_cache = backends.backend_for(p.kind, lambda t: None, p.mode)
        return self._engine_cache

    def _append_log(self, text: str) -> None:
        self.log_view.appendPlainText(f"{time.strftime('%H:%M:%S')}  {text}")

    def _check_ip(self) -> None:
        self.ip_label.setText("Проверяю...")

        def job():
            try:
                self.bridge.ip.emit(f"Внешний IP: {backends.public_ip()}")
            except Exception as e:
                self.bridge.ip.emit(f"Не удалось: {e}")

        threading.Thread(target=job, daemon=True).start()

    def closeEvent(self, event):
        # окно скрывается, подключение остаётся (как у обычных VPN-клиентов)
        if self.backend is not None and self.backend.state == backends.CONNECTED:
            self.bridge.log.emit("Окно закрыто, VPN остаётся подключённым")
        super().closeEvent(event)

    def _apps_text(self) -> None:
        from ui import settings as cfg
        apps = [a for a in str(cfg.get("vpn/direct_apps")).splitlines() if a.strip()]
        self.apps_btn.setText(f"Программы напрямую, мимо VPN ({len(apps)})...")

    def _edit_apps(self) -> None:
        from ui import settings as cfg
        apps = [a for a in str(cfg.get("vpn/direct_apps")).splitlines() if a.strip()]
        dialog = DirectAppsDialog(self, apps)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            cfg.set_("vpn/direct_apps", "\n".join(dialog.apps()))
            self._apps_text()

    def _release_block(self) -> None:
        from vpn import dnsguard, killswitch
        dns = dnsguard.restore()
        done = killswitch.disable()
        if self.backend is not None:
            self.backend.blocked = False
            if hasattr(self.backend, "dns_changed"):
                self.backend.dns_changed = False
        text = "Блокировка снята, интернет без VPN" if done else "Блокировки не было"
        if dns:
            text += "; DNS адаптеров возвращён"
        self._append_log(text)
        activity.record("vpn", text)
        self._tick()

    def shutdown(self) -> None:
        if self.backend is not None and self.backend.state != backends.DISCONNECTED:
            self.backend.disconnect()
