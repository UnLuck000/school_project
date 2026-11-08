"""Вкладки страницы «Сеть»: DNS-запросы, TLS (SNI и JA3), маячки, блокировки брандмауэром."""
import ipaddress
import threading
import time

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QFileDialog, QHBoxLayout, QHeaderView, QInputDialog, QLabel,
    QLineEdit, QMenu, QMessageBox, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout,
    QWidget,
)

from networkmonitor import firewall
from ui.textutil import elide

MAX_ROWS = 3000
LEVEL_COLOR = {"critical": QColor("red"), "warning": QColor("darkorange"),
               "info": QColor("gray")}


class NetBridgeSignals(QObject):
    done = Signal(str, bool)      # сообщение, успех
    rules = Signal(object)


def _table(columns: list[tuple[str, int]]) -> QTableWidget:
    table = QTableWidget(0, len(columns))
    table.setHorizontalHeaderLabels([n for n, _ in columns])
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
    table.verticalHeader().setVisible(False)
    table.setWordWrap(False)
    header = table.horizontalHeader()
    header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    header.setStretchLastSection(True)
    for i, (_, width) in enumerate(columns):
        table.setColumnWidth(i, width)
    table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
    return table


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def run_block(parent: QWidget, bridge: NetBridgeSignals, ips: list[str], exes: list[str]) -> None:
    """Спрашивает подтверждение и блокирует адреса и программы в фоне."""
    ips = sorted({ip for ip in ips if _is_ip(ip)})
    exes = sorted({e for e in exes if e})
    if not ips and not exes:
        QMessageBox.information(parent, "Блокировка", "Нечего блокировать: адрес или путь "
                                                      "программы неизвестен")
        return
    lines = [f"адрес {ip}" for ip in ips] + [f"программа {elide(e, 120)}" for e in exes]
    answer = QMessageBox.question(
        parent, "Блокировка брандмауэром",
        "Заблокировать брандмауэром Windows?\n\n" + "\n".join(lines[:15])
        + "\n\nБлокировку можно снять на вкладке «Блокировки» или отменить в журнале действий.")
    if answer != QMessageBox.StandardButton.Yes:
        return

    def job():
        errors = []
        for ip in ips:
            try:
                firewall.block_ip(ip)
            except (OSError, ValueError) as e:
                errors.append(f"{ip}: {e}")
        for exe in exes:
            try:
                firewall.block_program(exe)
            except (OSError, ValueError) as e:
                errors.append(f"{exe}: {e}")
        if errors:
            bridge.done.emit("Не всё заблокировано:\n" + "\n".join(errors[:10]), False)
        else:
            bridge.done.emit(f"Заблокировано: {len(ips) + len(exes)}", True)

    threading.Thread(target=job, daemon=True).start()


class _RecordsPanel(QWidget):
    """Общая часть DNS и TLS: таблица с фильтром, меню блокировки."""
    COLUMNS: list[tuple[str, int]] = []
    blocked = Signal()

    def __init__(self, hint: str):
        super().__init__()
        self.records: list = []
        self.bridge = NetBridgeSignals()
        self.bridge.done.connect(self._on_done)
        layout = QVBoxLayout(self)
        row = QHBoxLayout()
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Фильтр: домен, процесс, адрес...")
        self.filter.textChanged.connect(self._apply_filter)
        self.only_flagged = QCheckBox("Только подозрительные")
        self.only_flagged.toggled.connect(self._apply_filter)
        clear = QPushButton("Очистить")
        clear.clicked.connect(self.clear)
        row.addWidget(self.filter, 1)
        row.addWidget(self.only_flagged)
        row.addWidget(clear)
        layout.addLayout(row)
        self.status = QLabel(hint)
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.table = _table(self.COLUMNS)
        self.table.customContextMenuRequested.connect(self._menu)
        layout.addWidget(self.table, 1)

    def values(self, r) -> list[str]:
        raise NotImplementedError

    def target(self, r) -> tuple[list[str], str]:
        """(адреса для блокировки, путь программы)."""
        raise NotImplementedError

    def add(self, records: list) -> None:
        bottom = self.table.verticalScrollBar().value() == self.table.verticalScrollBar().maximum()
        self.table.setUpdatesEnabled(False)
        for r in records:
            self.records.append(r)
            row = self.table.rowCount()
            self.table.insertRow(row)
            color = LEVEL_COLOR.get(r.level)
            for col, text in enumerate(self.values(r)):
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                if color is not None:
                    item.setForeground(QBrush(color))
                self.table.setItem(row, col, item)
            self.table.setRowHidden(row, not self._visible(r))
        extra = len(self.records) - MAX_ROWS
        if extra > 0:
            for _ in range(extra):
                self.table.removeRow(0)
            del self.records[:extra]
        self.table.setUpdatesEnabled(True)
        if bottom:
            self.table.scrollToBottom()

    def clear(self) -> None:
        self.records.clear()
        self.table.setRowCount(0)

    def _visible(self, r) -> bool:
        if self.only_flagged.isChecked() and not r.level:
            return False
        text = self.filter.text().strip().lower()
        return not text or any(text in v.lower() for v in self.values(r))

    def _apply_filter(self) -> None:
        for row, r in enumerate(self.records):
            self.table.setRowHidden(row, not self._visible(r))

    def _selected(self) -> list:
        rows = sorted({i.row() for i in self.table.selectedIndexes()})
        return [self.records[r] for r in rows if r < len(self.records)]

    def _menu(self, pos) -> None:
        selected = self._selected()
        if not selected:
            return
        ips, exes = [], []
        for r in selected:
            addresses, exe = self.target(r)
            ips += addresses
            exes.append(exe)
        menu = QMenu(self)
        a_ip = menu.addAction("Заблокировать адреса брандмауэром")
        a_ip.setEnabled(any(_is_ip(ip) for ip in ips))
        a_exe = menu.addAction("Запретить программе выход в сеть")
        a_exe.setEnabled(any(exes))
        a_copy = menu.addAction("Копировать")
        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        if chosen is a_ip:
            run_block(self, self.bridge, ips, [])
        elif chosen is a_exe:
            run_block(self, self.bridge, [], exes)
        elif chosen is a_copy:
            from PySide6.QtWidgets import QApplication
            QApplication.clipboard().setText(
                "\n".join("\t".join(self.values(r)) for r in selected))

    def _on_done(self, text: str, ok: bool) -> None:
        (QMessageBox.information if ok else QMessageBox.warning)(self, "Блокировка", text)
        if ok:
            self.blocked.emit()


class DnsPanel(_RecordsPanel):
    COLUMNS = [("Время", 70), ("Процесс", 150), ("PID", 60), ("Домен", 280),
               ("Ответ", 220), ("Оценка", 300)]

    def __init__(self, addresses_of=None):
        super().__init__("DNS-запросы программ. С правами администратора или без них они "
                         "видны через ETW вместе с процессом; если ETW недоступен, читается "
                         "кэш DNS Windows (без процессов).")
        self.addresses_of = addresses_of or (lambda domain: [])

    def values(self, r) -> list[str]:
        return [r.time, r.name, str(r.pid or ""), r.domain, r.addresses, r.verdict]

    def target(self, r) -> tuple[list[str], str]:
        ips = [a.strip() for a in r.addresses.split(",") if _is_ip(a.strip())]
        return ips or list(self.addresses_of(r.domain)), r.exe


class TlsPanel(_RecordsPanel):
    COLUMNS = [("Время", 70), ("Процесс", 150), ("PID", 60), ("Адрес", 150), ("Сайт (SNI)", 240),
               ("JA3", 250), ("ALPN", 60), ("Оценка", 260)]
    choose_dir = Signal(str)

    def __init__(self):
        super().__init__("Начала TLS-соединений (HTTPS): имя сайта и отпечаток программы JA3. "
                         "Нужны права администратора и WinDivert (используется в режиме "
                         "«только смотреть», трафик не меняется).")
        button = QPushButton("Указать папку WinDivert...")
        button.clicked.connect(self._choose)
        self.layout().itemAt(0).layout().addWidget(button)

    def _choose(self) -> None:
        folder = QFileDialog.getExistingDirectory(
            self, "Папка с WinDivert.dll и WinDivert64.sys")
        if folder:
            self.choose_dir.emit(folder)

    def values(self, r) -> list[str]:
        return [r.time, r.name, str(r.pid or ""), r.remote, r.sni, r.ja3, r.alpn, r.verdict]

    def target(self, r) -> tuple[list[str], str]:
        return [r.remote.rsplit(":", 1)[0]], r.exe


class BeaconPanel(QWidget):
    COLUMNS = [("Программа", 160), ("Куда", 260), ("Период, с", 80), ("Разброс", 70),
               ("Событий", 70), ("Последнее", 80), ("Источник", 70), ("Путь", 300)]

    def __init__(self):
        super().__init__()
        self.items: dict[tuple[str, str], object] = {}
        self.bridge = NetBridgeSignals()
        self.bridge.done.connect(lambda text, ok: (
            QMessageBox.information if ok else QMessageBox.warning)(self, "Блокировка", text))
        layout = QVBoxLayout(self)
        hint = QLabel("Маячки: программа обращается к одному адресу или домену через почти "
                      "равные промежутки (не меньше 6 раз, разброс до 15%). Так боты "
                      "спрашивают команды у управляющего сервера. Обновления и телеметрия "
                      "подписанных программ тоже бывают такими: оповещение получают только "
                      "программы без действительной подписи, здесь видны все.")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        self.table = _table(self.COLUMNS)
        self.table.setSortingEnabled(True)
        self.table.customContextMenuRequested.connect(self._menu)
        layout.addWidget(self.table, 1)

    def add(self, b) -> None:
        key = (b.exe.lower() or b.program.lower(), b.target.lower())
        self.items[key] = b
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for item in sorted(self.items.values(), key=lambda x: x.cv):
            row = self.table.rowCount()
            self.table.insertRow(row)
            values = [item.program, item.target, f"{item.period:.0f}", f"{item.cv:.0%}",
                      str(item.count), time.strftime("%H:%M:%S", time.localtime(item.last)),
                      item.source, item.exe]
            for col, text in enumerate(values):
                cell = QTableWidgetItem(text)
                cell.setToolTip(text)
                self.table.setItem(row, col, cell)
        self.table.setSortingEnabled(True)

    def _menu(self, pos) -> None:
        rows = sorted({i.row() for i in self.table.selectedIndexes()})
        if not rows:
            return
        targets = [self.table.item(r, 1).text() for r in rows]
        exes = [self.table.item(r, 7).text() for r in rows]
        menu = QMenu(self)
        a_ip = menu.addAction("Заблокировать адреса брандмауэром")
        a_ip.setEnabled(any(_is_ip(t) for t in targets))
        a_exe = menu.addAction("Запретить программе выход в сеть")
        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        if chosen is a_ip:
            run_block(self, self.bridge, targets, [])
        elif chosen is a_exe:
            run_block(self, self.bridge, [], exes)


class BlockPanel(QWidget):
    """Правила брандмауэра, созданные программой, и (галочка) все правила Windows и других
    программ — их только смотреть: снимать можно лишь свои блокировки."""
    COLUMNS = [("Правило", 330), ("Направление", 100), ("Цель", 320), ("Включено", 80)]
    SYSTEM_COLUMNS = [("Правило", 300), ("Направление", 100), ("Действие", 100),
                      ("Цель", 330), ("Включено", 80), ("Группа", 220)]

    def __init__(self):
        super().__init__()
        self.rules: list[firewall.Rule] = []
        self.bridge = NetBridgeSignals()
        self.bridge.rules.connect(self._show)
        self.bridge.done.connect(self._on_done)
        layout = QVBoxLayout(self)
        row = QHBoxLayout()
        for text, handler in (("Обновить", self.refresh),
                              ("Заблокировать адрес...", self._block_ip),
                              ("Снять блокировку", self._unblock)):
            button = QPushButton(text)
            button.clicked.connect(handler)
            row.addWidget(button)
        row.addStretch()
        layout.addLayout(row)
        self.status = QLabel("Правила брандмауэра Windows, созданные программой (группа "
                             "«myav»). Создание и снятие блокировок пишется в журнал действий "
                             "и отменяется оттуда. Нужны права администратора.")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.table = _table(self.COLUMNS)
        layout.addWidget(self.table, 1)

        # все правила брандмауэра: встроенные Windows и других программ
        from PySide6.QtWidgets import QCheckBox, QComboBox, QLineEdit
        system_row = QHBoxLayout()
        self.chk_system = QCheckBox("Показать правила Windows и других программ")
        self.chk_system.toggled.connect(self._toggle_system)
        self.system_filter = QComboBox()
        self.system_filter.addItems(["Блокирующие", "Все", "Только включённые"])
        self.system_filter.currentIndexChanged.connect(lambda _: self._fill_system())
        self.system_search = QLineEdit()
        self.system_search.setPlaceholderText("Поиск: имя, программа, адрес, группа")
        self.system_search.textChanged.connect(lambda _: self._fill_system())
        system_row.addWidget(self.chk_system)
        system_row.addWidget(self.system_filter)
        system_row.addWidget(self.system_search, 1)
        layout.addLayout(system_row)
        self.system_status = QLabel("")
        layout.addWidget(self.system_status)
        self.system_table = _table(self.SYSTEM_COLUMNS)
        layout.addWidget(self.system_table, 2)
        self.system_rules: list = []
        for w in (self.system_filter, self.system_search, self.system_status, self.system_table):
            w.setVisible(False)

    def _toggle_system(self, on: bool) -> None:
        for w in (self.system_filter, self.system_search, self.system_status, self.system_table):
            w.setVisible(on)
        if on:
            self.system_rules = firewall.list_system_rules()
            self._fill_system()

    def _fill_system(self) -> None:
        mode, query = self.system_filter.currentIndex(), self.system_search.text().lower()
        shown = []
        for r in self.system_rules:
            if mode == 0 and r.action != "Блокировать":
                continue
            if mode == 2 and not r.enabled:
                continue
            if query and query not in f"{r.title} {r.target} {r.group}".lower():
                continue
            shown.append(r)
        self.system_table.setSortingEnabled(False)
        self.system_table.setRowCount(len(shown))
        for row, r in enumerate(shown):
            group = r.group + (" (эта программа)" if r.own else "")
            for col, text in enumerate([r.title, r.direction, r.action, r.target,
                                        "да" if r.enabled else "нет", group]):
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                self.system_table.setItem(row, col, item)
        self.system_table.setSortingEnabled(True)
        blocked = sum(r.action == "Блокировать" for r in self.system_rules)
        self.system_status.setText(
            f"Правил брандмауэра всего: {len(self.system_rules)}, блокирующих: {blocked}, "
            f"показано: {len(shown)}. Правила Windows и других программ здесь только видны; "
            "менять их — в «Мониторе брандмауэра Защитника Windows» (wf.msc).")

    def refresh(self) -> None:
        self.status.setText("Читаю правила брандмауэра...")
        threading.Thread(target=lambda: self.bridge.rules.emit(firewall.list_rules()),
                         daemon=True).start()

    def _show(self, rules) -> None:
        self.rules = rules
        self.table.setRowCount(0)
        for r in rules:
            row = self.table.rowCount()
            self.table.insertRow(row)
            for col, text in enumerate([r.title, r.direction, r.target,
                                        "да" if r.enabled else "нет"]):
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                self.table.setItem(row, col, item)
        self.status.setText(f"Блокировок программы: {len(rules)}")
        if self.chk_system.isChecked():
            self.system_rules = firewall.list_system_rules()
            self._fill_system()

    def _block_ip(self) -> None:
        text, ok = QInputDialog.getText(self, "Блокировка", "Внешний IP-адрес:")
        if ok and text.strip():
            run_block(self, self.bridge, [text.strip()], [])

    def _unblock(self) -> None:
        rows = sorted({i.row() for i in self.table.selectedIndexes()})
        chosen = [self.rules[r] for r in rows if r < len(self.rules)]
        if not chosen:
            QMessageBox.information(self, "Блокировки", "Выберите правила в списке")
            return
        if QMessageBox.question(self, "Блокировки", f"Снять блокировок: {len(chosen)}?") \
                != QMessageBox.StandardButton.Yes:
            return

        def job():
            try:
                for target in sorted({r.target for r in chosen}):
                    firewall.unblock([r.name for r in chosen if r.target == target], target)
                self.bridge.done.emit("Блокировки сняты", True)
            except OSError as e:
                self.bridge.done.emit(f"Не удалось: {e}", False)

        threading.Thread(target=job, daemon=True).start()

    def _on_done(self, text: str, ok: bool) -> None:
        (QMessageBox.information if ok else QMessageBox.warning)(self, "Блокировки", text)
        self.refresh()
