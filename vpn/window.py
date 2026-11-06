"""Окно VPN (прототип): профили, подключение, состояние, трафик, журнал."""
import threading
import time

from PySide6.QtCore import QObject, Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QFileDialog, QFrame, QGridLayout, QHBoxLayout,
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
        self.name = QLineEdit()
        self.name.setPlaceholderText("Название профиля")
        layout.addWidget(self.name)
        self.text = QPlainTextEdit()
        self.text.setPlaceholderText("Вставьте конфигурацию WireGuard ([Interface] ... [Peer]) "
                                     "или OpenVPN (client, remote ...)")
        layout.addWidget(self.text, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                   QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


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

        self.chk_auto = QCheckBox("Подключать этот профиль при запуске окна")
        self.chk_auto.toggled.connect(self._on_auto)
        right.addWidget(self.chk_auto)
        kill = QCheckBox("Блокировать интернет при обрыве VPN (kill switch)")
        kill.setEnabled(False)
        kill.setToolTip("В прототипе не реализовано: нужны правила брандмауэра на время "
                        "подключения (с откатом через журнал).")
        right.addWidget(kill)

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
        auto = next((p for p in self.profiles if p.auto_connect), None)
        if auto is not None:
            self.list.setCurrentRow(self.profiles.index(auto))
            QTimer.singleShot(300, self.toggle)

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
        self._tick()

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
        try:
            self._add(profiles.from_text(dialog.name.text().strip() or "Профиль",
                                         dialog.text.toPlainText()))
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
        backend = backends.backend_for(p.kind, self.bridge.log.emit)
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
        p = self.active if busy else self._current()
        self.info["server"].setText(p.server if p else "—")
        self.info["kind"].setText(profiles.KINDS.get(p.kind, "—") if p else "—")
        engine = backend if busy else (backends.backend_for(p.kind, lambda t: None) if p
                                       else None)
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

    def shutdown(self) -> None:
        if self.backend is not None and self.backend.state != backends.DISCONNECTED:
            self.backend.disconnect()
