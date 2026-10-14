import sys
import threading
import time
from pathlib import Path
import json

from PySide6.QtCore import QEvent, Qt, QThread, Signal, QObject, QSettings
from PySide6.QtGui import QFontMetrics, QBrush, QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QFileDialog, QHBoxLayout, QHeaderView,
    QLineEdit, QListWidget, QMainWindow, QMessageBox, QProgressBar,
    QPushButton, QStyledItemDelegate, QTableWidget, QTableWidgetItem,
    QTabWidget, QToolTip, QVBoxLayout, QWidget, QCheckBox, QLabel,
    QListWidgetItem
)

from scanner.whitelist import load_whitelist, remove_from_whitelist
from scanner.hashing import load_all_signatures
from scanner.engine import scan_tree
from scanner.yara_engine import load_rules
from quarantine import (
    QUARANTINE_DIR, STATUS_QUARANTINED, quarantine_file, list_quarantine, restore_file, delete_file,
)
from monitor import RealtimeMonitor
from networkmonitor.connections import LEVEL_TEXT, terminate_process
from networkmonitor.netmon import NetworkMonitor


SIGNATURES = Path("signatures/hashes.txt")
RULES_DIR = Path("signatures/rules")
NETFEEDS_DIR = Path("signatures/netfeeds")
ID_ROLE = Qt.ItemDataRole.UserRole
STATUS_ROLE = Qt.ItemDataRole.UserRole + 1
STATUS_TEXT = {
    "quarantined": "В карантине",
    "restored": "Восстановлено",
    "deleted": "Удалено",
}
DEFAULT_WATCH = [str(Path.home() / "Downloads")]


class NetBridge(QObject):
    event = Signal(str, object)


class MonitorBridge(QObject):
    """Передаёт события из потока монитора в главный поток."""
    event = Signal(str, str)


class ElidedTooltipDelegate(QStyledItemDelegate):
    """Показывает всплывающую подсказку с полным текстом ячейки,
    только если текст не помещается в столбец и обрезан многоточием."""

    def helpEvent(self, event, view, option, index):
        if event.type() == QEvent.Type.ToolTip:
            text = index.data(Qt.ItemDataRole.DisplayRole)
            if text:
                text_width = QFontMetrics(option.font).horizontalAdvance(str(text))
                # +10 пикселей на внутренние отступы ячейки
                if text_width + 10 > option.rect.width():
                    QToolTip.showText(event.globalPos(), str(text), view)
                    return True
            QToolTip.hideText()
            return True
        return super().helpEvent(event, view, option, index)


class ScanWorker(QThread):
    """Сканирует папку в отдельном потоке и сообщает о ходе работы сигналами."""
    file_checked = Signal(str)
    threat_found = Signal(str)
    error = Signal(str)
    scan_finished = Signal(int, bool)

    def __init__(self, root: str):
        super().__init__()
        self.root = root
        self.stop_event = threading.Event()

    def stop(self):
        self.stop_event.set()

    def run(self):
        try:
            sigs = load_all_signatures(SIGNATURES.parent)
        except OSError as e:
            self.error.emit(f"Не удалось загрузить базу сигнатур: {e}")
            return

        rules, rule_errors = load_rules(RULES_DIR)
        for err in rule_errors:
            self.threat_found.emit(f"[YARA] правило пропущено: {err}")

        last_emit = 0.0

        def on_file(path):
            nonlocal last_emit
            now = time.monotonic()
            if now - last_emit > 0.1:
                last_emit = now
                self.file_checked.emit(str(path))

        whitelist = set(load_whitelist())

        found = 0
        for infected, reason in scan_tree(
                Path(self.root), sigs, rules,
                exclude=[QUARANTINE_DIR, RULES_DIR.resolve()],
                on_file=on_file, stop=self.stop_event,
                whitelist=whitelist):
            found += 1
            try:
                quarantine_file(infected, reason=reason)
                self.threat_found.emit(f"[!] {infected} ({reason}) -> в карантине")
            except OSError as e:
                self.threat_found.emit(
                    f"[!] {infected} ({reason}) -> не удалось изолировать: {e}")

        self.scan_finished.emit(found, self.stop_event.is_set())


class MainWindow(QMainWindow):
    # заголовки и начальная ширина столбцов таблицы карантина
    QUAR_COLUMNS = [
        ("Дата", 140),
        ("Исходный путь", 300),
        ("Размер, КБ", 90),
        ("SHA-256", 220),
        ("Статус", 110),
        ("Причина", 160),
    ]

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Учебный антивирус")
        self.resize(1000, 560)
        self.worker: ScanWorker | None = None
        self.settings = QSettings("StudyAV", "myav")
        self.monitor: RealtimeMonitor | None = None
        self.bridge = MonitorBridge()
        self.bridge.event.connect(self.on_monitor_event)
        self.net_monitor: NetworkMonitor | None = None
        self.net_alerts: list = []  # порядок совпадает со строками таблицы
        self.net_bridge = NetBridge()
        self.net_bridge.event.connect(self.on_net_event)

        tabs = QTabWidget()
        tabs.addTab(self._build_scan_tab(), "Сканирование")
        tabs.addTab(self._build_protection_tab(), "Защита")
        tabs.addTab(self._build_network_tab(), "Сеть")
        tabs.addTab(self._build_quarantine_tab(), "Карантин")
        tabs.addTab(self._build_whitelist_tab(), "Белый список")
        self.setCentralWidget(tabs)

        self.statusBar().showMessage("Готов к работе")
        self.refresh_quarantine()
        self.refresh_whitelist()

    # ---------- вкладка «Сеть» ----------
    NET_COLUMNS = [("Время", 70), ("Уровень", 100), ("Процесс", 130), ("PID", 60),
                   ("Адрес", 160), ("Правило", 80), ("Подробности", 420)]

    def _build_network_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        row = QHBoxLayout()
        self.net_btn = QPushButton("Включить мониторинг сети")
        self.net_btn.clicked.connect(self.toggle_network)
        kill_btn = QPushButton("Завершить процесс")
        kill_btn.clicked.connect(self.kill_selected_process)
        clear_btn = QPushButton("Очистить")
        clear_btn.clicked.connect(self.clear_net_alerts)
        for w in (self.net_btn, kill_btn, clear_btn):
            row.addWidget(w)
        row.addStretch()
        layout.addLayout(row)

        self.net_status = QLabel("Мониторинг сети выключен")
        layout.addWidget(self.net_status)

        self.net_table = QTableWidget(0, len(self.NET_COLUMNS))
        self.net_table.setHorizontalHeaderLabels([n for n, _ in self.NET_COLUMNS])
        self.net_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.net_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.net_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.net_table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.net_table.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.net_table.verticalHeader().setVisible(False)
        header = self.net_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        header.setMinimumSectionSize(50)
        for i, (_, width) in enumerate(self.NET_COLUMNS):
            self.net_table.setColumnWidth(i, width)
        self.net_table.setItemDelegate(ElidedTooltipDelegate(self.net_table))
        layout.addWidget(self.net_table)
        return tab

    def toggle_network(self):
        if self.net_monitor is not None:
            self.net_btn.setEnabled(False)
            self.net_monitor.stop()
            self._net_stopped()
            return
        self.net_monitor = NetworkMonitor(
            sig_dir=SIGNATURES.parent, rules_dir=RULES_DIR, netfeeds_dir=NETFEEDS_DIR,
            on_event=lambda kind, payload: self.net_bridge.event.emit(kind, payload),
        )
        self.net_monitor.start()
        self.net_btn.setText("Выключить мониторинг сети")
        self.net_status.setText("Запускаю...")

    def _net_stopped(self):
        self.net_monitor = None
        self.net_btn.setEnabled(True)
        self.net_btn.setText("Включить мониторинг сети")
        self.net_status.setText("Мониторинг сети выключен")

    def on_net_event(self, kind: str, payload):
        if kind == "status":
            self.net_status.setText(payload)
        elif kind == "error":
            self.net_status.setText(f"Ошибка: {payload}")
        elif kind == "stopped":
            self._net_stopped()
        elif kind == "alert":
            self._add_net_alert(payload)

    def _add_net_alert(self, a):
        row = self.net_table.rowCount()
        self.net_table.insertRow(row)
        values = [a.time, LEVEL_TEXT.get(a.level, a.level), a.name, str(a.pid),
                  a.remote, a.rule, a.detail]
        color = QColor("red") if a.level == "critical" else QColor("darkorange")
        for col, text in enumerate(values):
            item = QTableWidgetItem(text)
            item.setForeground(QBrush(color))
            self.net_table.setItem(row, col, item)
        self.net_alerts.append(a)
        if len(self.net_alerts) > 500:  # таблица и список обрезаются синхронно
            self.net_table.removeRow(0)
            self.net_alerts.pop(0)
        self.net_table.scrollToBottom()
        self.statusBar().showMessage(f"[Сеть] {a.name}: {a.detail}")

    def kill_selected_process(self):
        row = self.net_table.currentRow()
        if row < 0 or row >= len(self.net_alerts):
            QMessageBox.information(self, "Сеть", "Сначала выберите строку в списке")
            return
        alert = self.net_alerts[row]
        answer = QMessageBox.question(
            self, "Завершить процесс",
            f"Завершить {alert.name} (PID {alert.pid})?\n\n{alert.exe or 'путь неизвестен'}\n\n"
            "Несохранённые данные программы будут потеряны.")
        if answer == QMessageBox.StandardButton.Yes:
            message = terminate_process(alert)
            self.statusBar().showMessage(message)
            QMessageBox.information(self, "Сеть", message)

    def clear_net_alerts(self):
        self.net_table.setRowCount(0)
        self.net_alerts.clear()

    # ---------- вкладка «Защита» (мониторинг) ----------
    def _build_protection_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        layout.addWidget(QLabel("Папки под наблюдением:"))
        self.watch_list = QListWidget()
        self.watch_list.setMaximumHeight(120)
        for folder in self._load_watch_folders():
            self.watch_list.addItem(folder)
        layout.addWidget(self.watch_list)

        row = QHBoxLayout()
        self.watch_add_btn = QPushButton("Добавить папку...")
        self.watch_add_btn.clicked.connect(self.add_watch_folder)
        self.watch_remove_btn = QPushButton("Убрать выбранную")
        self.watch_remove_btn.clicked.connect(self.remove_watch_folder)
        self.protect_btn = QPushButton("Включить защиту")
        self.protect_btn.clicked.connect(self.toggle_protection)
        row.addWidget(self.watch_add_btn)
        row.addWidget(self.watch_remove_btn)
        row.addStretch()
        row.addWidget(self.protect_btn)
        layout.addLayout(row)

        self.protect_status = QLabel("Защита выключена")
        layout.addWidget(self.protect_status)

        self.protect_log = QListWidget()
        layout.addWidget(self.protect_log)
        return tab

    def _load_watch_folders(self) -> list[str]:
        raw = self.settings.value("monitor/folders", None)
        if raw:
            try:
                folders = json.loads(raw)
                if isinstance(folders, list):
                    return [str(f) for f in folders]
            except (TypeError, ValueError):
                pass
        return list(DEFAULT_WATCH)

    def _save_watch_folders(self):
        folders = [self.watch_list.item(i).text() for i in range(self.watch_list.count())]
        self.settings.setValue("monitor/folders", json.dumps(folders, ensure_ascii=False))

    def add_watch_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Папка для наблюдения")
        if folder and not self.watch_list.findItems(folder, Qt.MatchFlag.MatchExactly):
            self.watch_list.addItem(folder)
            self._save_watch_folders()

    def remove_watch_folder(self):
        row = self.watch_list.currentRow()
        if row >= 0:
            self.watch_list.takeItem(row)
            self._save_watch_folders()

    def toggle_protection(self):
        if self.monitor is not None:
            self.protect_btn.setEnabled(False)
            self.monitor.stop()
            self._protection_stopped()
            return

        folders = [self.watch_list.item(i).text() for i in range(self.watch_list.count())]
        if not folders:
            QMessageBox.warning(self, "Защита", "Добавьте хотя бы одну папку")
            return

        self.monitor = RealtimeMonitor(
            folders,
            sig_dir=SIGNATURES.parent,
            rules_dir=RULES_DIR,
            exclude=[QUARANTINE_DIR, SIGNATURES.parent.resolve()],
            on_event=lambda kind, text: self.bridge.event.emit(kind, text),
        )
        self.monitor.start()
        self._set_protection_ui(True)

    def _set_protection_ui(self, running: bool):
        self.protect_btn.setEnabled(True)
        self.protect_btn.setText("Выключить защиту" if running else "Включить защиту")
        for w in (self.watch_list, self.watch_add_btn, self.watch_remove_btn):
            w.setEnabled(not running)
        self.protect_status.setText("Запускаю..." if running else "Защита выключена")

    def _protection_stopped(self):
        self.monitor = None
        self._set_protection_ui(False)

    def on_monitor_event(self, kind: str, text: str):
        if kind == "status":
            self.protect_status.setText(text)
            return
        if kind == "stopped":
            self._protection_stopped()
            return
        if kind == "threat":
            self.refresh_quarantine()
            self.statusBar().showMessage(text)

        item = QListWidgetItem(f"{time.strftime('%H:%M:%S')}  {text}")
        color = {"threat": "red", "error": "darkorange", "scanned": "gray"}.get(kind)
        if color:
            item.setForeground(QBrush(QColor(color)))
        self.protect_log.addItem(item)
        if self.protect_log.count() > 500:  # журнал не растёт бесконечно
            self.protect_log.takeItem(0)
        self.protect_log.scrollToBottom()

    # ---------- вкладка «Белый список» ----------
    def _build_whitelist_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.wl_table = QTableWidget(0, 3)
        self.wl_table.setHorizontalHeaderLabels(["Дата", "Путь при восстановлении", "SHA-256"])
        self.wl_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.wl_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.wl_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.wl_table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.wl_table.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.wl_table.verticalHeader().setVisible(False)

        header = self.wl_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        header.setMinimumSectionSize(50)
        for i, width in enumerate((140, 380, 300)):
            self.wl_table.setColumnWidth(i, width)

        self.wl_table.setItemDelegate(ElidedTooltipDelegate(self.wl_table))
        layout.addWidget(self.wl_table)

        row = QHBoxLayout()
        remove_btn = QPushButton("Убрать из белого списка")
        remove_btn.clicked.connect(self.remove_from_wl)
        row.addWidget(remove_btn)
        row.addStretch()
        layout.addLayout(row)
        return tab

    def refresh_whitelist(self):
        self.wl_table.setRowCount(0)
        entries = sorted(load_whitelist().items(), key=lambda kv: kv[1].get("added_at", ""))
        for sha, info in entries:
            row = self.wl_table.rowCount()
            self.wl_table.insertRow(row)
            self.wl_table.setItem(row, 0, QTableWidgetItem(info.get("added_at", "")))
            self.wl_table.setItem(row, 1, QTableWidgetItem(info.get("path", "")))
            self.wl_table.setItem(row, 2, QTableWidgetItem(sha))

    def remove_from_wl(self):
        row = self.wl_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Белый список", "Сначала выберите запись в списке")
            return
        sha = self.wl_table.item(row, 2).text()
        answer = QMessageBox.question(
            self, "Белый список",
            "Файл с этим хэшем снова будет проверяться сканером. Продолжить?")
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            remove_from_whitelist(sha)
            self.statusBar().showMessage("Хэш убран из белого списка")
        except OSError as e:
            QMessageBox.critical(self, "Ошибка", str(e))
        self.refresh_whitelist()

    # ---------- вкладка «Сканирование» ----------
    def _build_scan_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        row = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("Папка для сканирования")
        browse_btn = QPushButton("Обзор...")
        browse_btn.clicked.connect(self.choose_folder)
        row.addWidget(self.path_edit)
        row.addWidget(browse_btn)
        layout.addLayout(row)

        row = QHBoxLayout()
        self.scan_btn = QPushButton("Сканировать")
        self.scan_btn.clicked.connect(self.start_scan)
        self.stop_btn = QPushButton("Остановить")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_scan)
        row.addWidget(self.scan_btn)
        row.addWidget(self.stop_btn)
        row.addStretch()
        layout.addLayout(row)

        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setTextVisible(False)
        layout.addWidget(self.progress)

        self.log = QListWidget()
        layout.addWidget(self.log)
        return tab

    def choose_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Выберите папку")
        if folder:
            self.path_edit.setText(folder)

    def start_scan(self):
        root = self.path_edit.text().strip()
        if not root or not Path(root).is_dir():
            QMessageBox.warning(self, "Ошибка", "Выберите существующую папку")
            return

        self.log.clear()
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress.setRange(0, 0)

        self.worker = ScanWorker(root)
        self.worker.file_checked.connect(
            lambda f: self.statusBar().showMessage(f"Проверяю: {f}"))
        self.worker.threat_found.connect(self.log.addItem)
        self.worker.error.connect(self.on_error)
        self.worker.scan_finished.connect(self.on_finished)
        self.worker.start()

    def stop_scan(self):
        if self.worker:
            self.worker.stop()
            self.statusBar().showMessage("Останавливаю...")

    def on_error(self, text: str):
        self._reset_scan_ui()
        QMessageBox.critical(self, "Ошибка", text)

    def on_finished(self, found: int, stopped: bool):
        self._reset_scan_ui()
        self.statusBar().showMessage(
            f"{'Остановлено' if stopped else 'Готово'}. Найдено угроз: {found}")
        self.refresh_quarantine()

    def _reset_scan_ui(self):
        self.progress.setRange(0, 1)
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    # ---------- вкладка «Карантин» ----------
    def _build_quarantine_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.table = QTableWidget(0, len(self.QUAR_COLUMNS))
        self.table.setHorizontalHeaderLabels([name for name, _ in self.QUAR_COLUMNS])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.table.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.table.verticalHeader().setVisible(False)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        header.setMinimumSectionSize(50)
        for i, (_, width) in enumerate(self.QUAR_COLUMNS):
            self.table.setColumnWidth(i, width)

        self.table.setItemDelegate(ElidedTooltipDelegate(self.table))
        layout.addWidget(self.table)

        row = QHBoxLayout()
        for text, handler in (("Восстановить", self.restore_selected),
                              ("Удалить навсегда", self.delete_selected),
                              ("Обновить", self.refresh_quarantine)):
            btn = QPushButton(text)
            btn.clicked.connect(handler)
            row.addWidget(btn)

        self.history_cb = QCheckBox("Показывать историю")
        self.history_cb.setToolTip("Восстановленные и удалённые файлы")
        self.history_cb.toggled.connect(lambda _: self.refresh_quarantine())
        row.addWidget(self.history_cb)
        row.addStretch()
        layout.addLayout(row)
        return tab

    def refresh_quarantine(self):
        self.table.setRowCount(0)
        for m in list_quarantine(include_history=self.history_cb.isChecked()):
            row = self.table.rowCount()
            self.table.insertRow(row)

            size_bytes = int(m.get("size", 0))
            size_kb = f"{size_bytes / 1024:,.1f}".replace(",", " ")
            size_item = QTableWidgetItem(size_kb)
            size_item.setTextAlignment(
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

            status = m["status"]
            date_item = QTableWidgetItem(m["quarantined_at"])
            date_item.setData(ID_ROLE, m["id"])
            date_item.setData(STATUS_ROLE, status)

            items = [
                date_item,
                QTableWidgetItem(m["original_path"]),
                size_item,
                QTableWidgetItem(m.get("sha256", "")),
                QTableWidgetItem(STATUS_TEXT.get(status, status)),
                QTableWidgetItem(m["reason"]),
            ]
            for col, item in enumerate(items):
                if status != STATUS_QUARANTINED:  # записи истории выделяем серым
                    item.setForeground(QBrush(QColor("gray")))
                self.table.setItem(row, col, item)

    def _selected_id(self) -> str | None:
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Карантин", "Сначала выберите элемент в списке")
            return None
        cell = self.table.item(row, 0)
        if cell.data(STATUS_ROLE) != STATUS_QUARANTINED:
            QMessageBox.information(
                self, "Карантин", "Это запись из истории: файл уже восстановлен или удалён")
            return None
        return cell.data(ID_ROLE)

    def restore_selected(self):
        item_id = self._selected_id()
        if not item_id:
            return
        answer = QMessageBox.question(
            self, "Восстановление",
            "Вернуть файл на исходное место?\n\n"
            "Его SHA-256 будет добавлен в белый список, и сканер не будет "
            "считать этот файл угрозой, пока его содержимое не изменится.")
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            dest = restore_file(item_id)
            self.statusBar().showMessage(f"Восстановлен: {dest} (добавлен в белый список)")
        except (FileExistsError, ValueError, OSError) as e:
            QMessageBox.critical(self, "Ошибка восстановления", str(e))
        self.refresh_quarantine()
        self.refresh_whitelist()

    def delete_selected(self):
        item_id = self._selected_id()
        if not item_id:
            return
        answer = QMessageBox.question(
            self, "Удаление",
            "Файл будет удалён безвозвратно, а его SHA-256 добавлен в "
            "базу сигнатур (signatures/hashes.txt). Продолжить?")
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            added = delete_file(item_id)
            self.statusBar().showMessage(
                "Файл удалён, хэш добавлен в базу сигнатур" if added
                else "Файл удалён, хэш уже был в базе сигнатур")
        except (ValueError, OSError) as e:
            QMessageBox.critical(self, "Ошибка удаления", str(e))
        self.refresh_quarantine()

    # ---------- закрытие окна ----------
    def closeEvent(self, event):
        if self.net_monitor is not None:
            self.net_monitor.stop()
        if self.monitor is not None:
            self.monitor.stop()
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(5000)
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())