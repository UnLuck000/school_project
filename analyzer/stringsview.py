import threading
from pathlib import Path

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QObject, Qt, QTimer, Signal
from PySide6.QtGui import QBrush, QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QFileDialog, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QMenu, QPushButton, QSpinBox, QTableView, QVBoxLayout,
    QWidget,
)

from analyzer import strings as strmod
from processmanager.colors import text_color

COLUMNS = ["Смещение", "Вид", "Категория", "Строка"]
MARK = (255, 255, 170)


class _Bridge(QObject):
    done = Signal(int, object, str)
    progress = Signal(int, str)


class StringsModel(QAbstractTableModel):
    """Таблица строк: показывает только отфильтрованные, без создания сотен тысяч виджетов."""
    def __init__(self):
        super().__init__()
        self.all: list[strmod.FoundString] = []
        self.rows: list[strmod.FoundString] = []
        self._mark = QBrush(QColor(*MARK))
        self._mark_text = QBrush(text_color(MARK))
        self._mono = QFont("Consolas")

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return COLUMNS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        s = self.rows[index.row()]
        col = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return f"{s.offset:08X}"
            if col == 1:
                return s.kind
            if col == 2:
                return strmod.CATEGORY_TITLES[s.category]
            return s.text if len(s.text) <= 300 else s.text[:300] + "…"
        if role == Qt.ItemDataRole.ToolTipRole and col == 3 and len(s.text) > 80:
            return s.text[:2000]
        if role == Qt.ItemDataRole.FontRole and col in (0, 3):
            return self._mono
        if s.category in strmod.INTERESTING_IDS:
            if role == Qt.ItemDataRole.BackgroundRole:
                return self._mark
            if role == Qt.ItemDataRole.ForegroundRole:
                return self._mark_text
        return None

    def set_rows(self, rows: list[strmod.FoundString]) -> None:
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()


class StringsTab(QWidget):
    """Строки файла: весь файл (до 256 МБ), категории, фильтры, экспорт."""
    offset_activated = Signal(int)  # двойной щелчок по строке: её смещение в файле
    def __init__(self):
        super().__init__()
        self._path: Path | None = None
        self._request = 0
        self._cancel = threading.Event()
        self._bridge = _Bridge()
        self._bridge.done.connect(self._on_done)
        self._bridge.progress.connect(
            lambda req, text: self.status.setText(text) if req == self._request else None)
        self._note = ""

        layout = QVBoxLayout(self)
        row = QHBoxLayout()
        self.filter = QLineEdit()
        self.filter.setAcceptDrops(False)
        self.filter.setPlaceholderText("Фильтр по тексту (можно несколько слов через пробел)...")
        self.category = QComboBox()
        self.category.addItem("Все категории", None)
        self.category.addItem("Только интересные", "interesting")
        for cid, title in strmod.CATEGORY_TITLES.items():
            self.category.addItem(title, cid)
        self.kind = QComboBox()
        self.kind.addItems(["ASCII и UTF-16", "ASCII", "UTF-16"])
        self.min_len = QSpinBox()
        self.min_len.setRange(4, 64)
        self.min_len.setValue(5)
        self.min_len.setPrefix("от ")
        self.min_len.setSuffix(" симв.")
        self.min_len.setToolTip("Минимальная длина строки. Изменение запускает поиск заново.")
        self.unique = QCheckBox("Без повторов")
        self.btn_export = QPushButton("Экспорт...")
        self.btn_export.clicked.connect(self.export)
        row.addWidget(self.filter, 1)
        for w in (self.category, self.kind, self.min_len, self.unique, self.btn_export):
            row.addWidget(w)
        layout.addLayout(row)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        self.model = StringsModel()
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(20)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        for i, width in enumerate((90, 65, 170)):
            self.table.setColumnWidth(i, width)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)
        self.table.doubleClicked.connect(
            lambda index: self.offset_activated.emit(self.model.rows[index.row()].offset))
        layout.addWidget(self.table, 1)

        self._timer = QTimer(self)  # фильтр применяется после паузы в наборе
        self._timer.setSingleShot(True)
        self._timer.setInterval(250)
        self._timer.timeout.connect(self.apply_filter)
        self.filter.textChanged.connect(lambda _: self._timer.start())
        for combo in (self.category, self.kind):
            combo.currentIndexChanged.connect(lambda _: self.apply_filter())
        self.unique.toggled.connect(lambda _: self.apply_filter())
        self.min_len.editingFinished.connect(self._restart)

    # ---------- загрузка ----------
    def set_file(self, path: Path | None) -> None:
        self._path = path
        self.model.all = []
        self.model.set_rows([])
        self._restart()

    def _restart(self) -> None:
        self._cancel.set()
        self._cancel = cancel = threading.Event()
        self._request += 1
        if self._path is None:
            self.status.setText("")
            return
        request, path, min_len = self._request, self._path, self.min_len.value()
        self.status.setText("Ищу строки во всём файле...")

        def work():
            try:
                found, note = strmod.extract(
                    path, min_len, cancel, lambda text: self._bridge.progress.emit(request, text))
            except (OSError, ValueError) as e:
                found, note = [], f"Не удалось прочитать файл: {e}"
            self._bridge.done.emit(request, found, note)

        threading.Thread(target=work, daemon=True).start()

    def _on_done(self, request: int, found, note: str) -> None:
        if request != self._request:
            return
        self.model.all = found
        self._note = note
        self.apply_filter()

    # ---------- фильтр ----------
    def _filtered(self) -> list[strmod.FoundString]:
        words = self.filter.text().lower().split()
        category = self.category.currentData()
        kind = {1: "ASCII", 2: "UTF-16"}.get(self.kind.currentIndex())
        result, seen = [], set()
        for s in self.model.all:
            if kind and s.kind != kind:
                continue
            if category == "interesting":
                if s.category not in strmod.INTERESTING_IDS:
                    continue
            elif category and s.category != category:
                continue
            if words:
                low = s.text.lower()
                if not all(w in low for w in words):
                    continue
            if self.unique.isChecked():
                if s.text in seen:
                    continue
                seen.add(s.text)
            result.append(s)
        return result

    def apply_filter(self) -> None:
        rows = self._filtered()
        self.model.set_rows(rows)
        counts: dict[str, int] = {}
        for s in self.model.all:
            counts[s.category] = counts.get(s.category, 0) + 1
        parts = [f"{strmod.CATEGORY_TITLES[c]}: {n}" for c, n in
                 sorted(counts.items(), key=lambda x: -x[1]) if c != "other"]
        self.status.setText(f"{self._note} Показано: {len(rows):,}. ".replace(",", " ")
                            + ("По категориям: " + ", ".join(parts) if parts else ""))

    # ---------- действия ----------
    def _menu(self, pos) -> None:
        rows = sorted({i.row() for i in self.table.selectionModel().selectedRows()})
        if not rows:
            return
        menu = QMenu(self)
        copy = menu.addAction("Копировать строку")
        copy_offset = menu.addAction("Копировать смещение")
        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        if chosen == copy:
            QApplication.clipboard().setText("\n".join(self.model.rows[r].text for r in rows))
        elif chosen == copy_offset:
            QApplication.clipboard().setText(
                "\n".join(f"0x{self.model.rows[r].offset:08X}" for r in rows))

    def export(self) -> None:
        if not self.model.rows:
            self.status.setText("Нечего экспортировать: список пуст")
            return
        name = (self._path.stem if self._path else "strings") + "_strings.csv"
        target, _ = QFileDialog.getSaveFileName(
            self, "Экспорт строк", name, "Таблица CSV (*.csv);;Текст (*.txt)")
        if not target:
            return
        try:
            strmod.export(self.model.rows, Path(target))
        except OSError as e:
            self.status.setText(f"Не удалось сохранить: {e}")
            return
        self.status.setText(f"Сохранено строк: {len(self.model.rows)} в {target}")
