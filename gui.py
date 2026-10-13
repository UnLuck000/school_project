import sys
import threading
import time
from pathlib import Path

from PySide6.QtCore import QEvent, Qt, QThread, Signal
from PySide6.QtGui import QFontMetrics
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QFileDialog, QHBoxLayout, QHeaderView,
    QLineEdit, QListWidget, QMainWindow, QMessageBox, QProgressBar,
    QPushButton, QStyledItemDelegate, QTableWidget, QTableWidgetItem,
    QTabWidget, QToolTip, QVBoxLayout, QWidget,
)

from scanner.hashing import load_signatures
from scanner.engine import scan_tree
from scanner.yara_engine import load_rules
from quarantine import (
    QUARANTINE_DIR, quarantine_file, list_quarantine, restore_file, delete_file,
)

SIGNATURES = Path("signatures/hashes.txt")
RULES_DIR = Path("signatures/rules")


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
            sigs = load_signatures(SIGNATURES)
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

        found = 0
        for infected, reason in scan_tree(
                Path(self.root), sigs, rules,
                exclude=[QUARANTINE_DIR, RULES_DIR.resolve()],
                on_file=on_file, stop=self.stop_event):
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
        ("Причина", 160),
    ]

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Учебный антивирус")
        self.resize(1000, 560)
        self.worker: ScanWorker | None = None

        tabs = QTabWidget()
        tabs.addTab(self._build_scan_tab(), "Сканирование")
        tabs.addTab(self._build_quarantine_tab(), "Карантин")
        self.setCentralWidget(tabs)

        self.statusBar().showMessage("Готов к работе")
        self.refresh_quarantine()

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
        self.table.setTextElideMode(Qt.TextElideMode.ElideRight)  # длинный текст -> "..."
        self.table.verticalHeader().setVisible(False)

        # ширину каждого столбца можно менять перетаскиванием границы в заголовке
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        header.setMinimumSectionSize(50)
        for i, (_, width) in enumerate(self.QUAR_COLUMNS):
            self.table.setColumnWidth(i, width)

        # подсказка с полным текстом для обрезанных ячеек
        self.table.setItemDelegate(ElidedTooltipDelegate(self.table))

        layout.addWidget(self.table)

        row = QHBoxLayout()
        for text, handler in (("Восстановить", self.restore_selected),
                              ("Удалить навсегда", self.delete_selected),
                              ("Обновить", self.refresh_quarantine)):
            btn = QPushButton(text)
            btn.clicked.connect(handler)
            row.addWidget(btn)
        row.addStretch()
        layout.addLayout(row)
        return tab

    def refresh_quarantine(self):
        self.table.setRowCount(0)
        for m in list_quarantine():
            row = self.table.rowCount()
            self.table.insertRow(row)

            size_kb = f"{m.get('size', 0) / 1024:,.1f}".replace(",", " ")
            size_item = QTableWidgetItem(size_kb)
            size_item.setTextAlignment(
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

            date_item = QTableWidgetItem(m["quarantined_at"])
            # идентификатор элемента карантина прячем в данных ячейки
            date_item.setData(Qt.ItemDataRole.UserRole, m["id"])

            self.table.setItem(row, 0, date_item)
            self.table.setItem(row, 1, QTableWidgetItem(m["original_path"]))
            self.table.setItem(row, 2, size_item)
            self.table.setItem(row, 3, QTableWidgetItem(m.get("sha256", "")))
            self.table.setItem(row, 4, QTableWidgetItem(m["reason"]))

    def _selected_id(self) -> str | None:
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Карантин", "Сначала выберите элемент в списке")
            return None
        return self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)

    def restore_selected(self):
        item_id = self._selected_id()
        if not item_id:
            return
        answer = QMessageBox.question(self, "Восстановление",
                                      "Вернуть файл на исходное место?")
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            dest = restore_file(item_id)
            self.statusBar().showMessage(f"Восстановлен: {dest}")
        except (FileExistsError, ValueError, OSError) as e:
            QMessageBox.critical(self, "Ошибка восстановления", str(e))
        self.refresh_quarantine()

    def delete_selected(self):
        item_id = self._selected_id()
        if not item_id:
            return
        answer = QMessageBox.question(self, "Удаление", "Удалить файл безвозвратно?")
        if answer == QMessageBox.StandardButton.Yes:
            delete_file(item_id)
            self.refresh_quarantine()

    # ---------- закрытие окна ----------
    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(5000)
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())