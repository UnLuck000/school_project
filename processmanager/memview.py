"""Окна «Память процесса» (регионы и модули) и «Поиск внедрения кода» по всем процессам."""
import os
import threading
from concurrent.futures import ThreadPoolExecutor

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QComboBox, QDialog, QHBoxLayout, QHeaderView, QLabel,
    QMenu, QPlainTextEdit, QPushButton, QTabWidget, QTreeWidget, QTreeWidgetItem, QVBoxLayout,
    QWidget,
)

from analyzer.code import hexdump
from processmanager import memdeep
from processmanager.colors import text_color
from processmanager.system import open_in_explorer

LEVEL_COLORS = {"suspicious": (255, 160, 110), "check": (255, 235, 150)}
LEVEL_TEXT = {"suspicious": "Подозрительно", "check": "На проверку", "normal": ""}
NUM_ROLE = Qt.ItemDataRole.UserRole + 1
FILTERS = ["Подозрительные и на проверку", "Все исполняемые", "Все регионы"]


class _Item(QTreeWidgetItem):
    """Строка с числовой сортировкой по колонкам, где задано NUM_ROLE."""
    def __lt__(self, other):
        tree = self.treeWidget()
        col = tree.sortColumn() if tree else 0
        a, b = self.data(col, NUM_ROLE), other.data(col, NUM_ROLE)
        if a is not None and b is not None:
            return a < b
        return self.text(col).lower() < other.text(col).lower()


def _tree(columns: list[str], widths: list[int]) -> QTreeWidget:
    tree = QTreeWidget()
    tree.setHeaderLabels(columns)
    tree.setRootIsDecorated(False)
    tree.setUniformRowHeights(True)
    tree.setSortingEnabled(True)
    tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
    header = tree.header()
    header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    header.setStretchLastSection(True)
    for i, w in enumerate(widths):
        tree.setColumnWidth(i, w)
    tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
    tree.customContextMenuRequested.connect(lambda pos, t=tree: _copy_menu(t, pos))
    return tree


def _copy_menu(tree: QTreeWidget, pos) -> None:
    items = tree.selectedItems()
    if not items:
        return
    menu = QMenu(tree)
    action = menu.addAction("Копировать строки")
    if menu.exec(tree.viewport().mapToGlobal(pos)) == action:
        QApplication.clipboard().setText("\n".join(
            "\t".join(it.text(c) for c in range(tree.columnCount())) for it in items))


def _paint(item: QTreeWidgetItem, level: str, columns: int) -> None:
    rgb = LEVEL_COLORS.get(level)
    if rgb:
        for col in range(columns):
            item.setBackground(col, QBrush(QColor(*rgb)))
            item.setForeground(col, QBrush(text_color(rgb)))


def _text_dialog(parent, title: str, text: str, folder: str = "") -> None:
    dialog = QDialog(parent)
    dialog.setWindowTitle(title)
    dialog.resize(820, 560)
    box = QVBoxLayout(dialog)
    edit = QPlainTextEdit(text)
    edit.setReadOnly(True)
    edit.setFont(QFont("Consolas"))
    box.addWidget(edit, 1)
    row = QHBoxLayout()
    copy = QPushButton("Копировать")
    copy.clicked.connect(lambda: QApplication.clipboard().setText(text))
    row.addWidget(copy)
    if folder:
        show = QPushButton("Показать в папке")
        show.clicked.connect(lambda: open_in_explorer(folder))
        row.addWidget(show)
    row.addStretch()
    close = QPushButton("Закрыть")
    close.clicked.connect(dialog.accept)
    row.addWidget(close)
    box.addLayout(row)
    dialog.show()


def _size(n: int) -> str:
    return f"{n // 1024:,} КБ".replace(",", " ") if n >= 1024 else f"{n} Б"


class _Bridge(QObject):
    report = Signal(object)
    modules = Signal(object)
    progress = Signal(int, int, object)  # сделано, всего, отчёт
    finished = Signal()


class MemoryDialog(QDialog):
    """Карта памяти одного процесса и его модули."""
    def __init__(self, pid: int, name: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Память процесса: {name} (PID {pid})")
        self.resize(1250, 700)
        self.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint, True)
        self.pid, self.name = pid, name
        self.report: memdeep.MemoryReport | None = None
        self.bridge = _Bridge()
        self.bridge.report.connect(self._on_report)
        self.bridge.modules.connect(self._on_modules)

        layout = QVBoxLayout(self)
        hint = QLabel(
            "Признаки внедрения кода: приватная исполняемая память, участки RWX (чтение, запись "
            "и выполнение), заголовок PE в приватной памяти, образ вне списка модулей. У "
            "браузеров, .NET и Java исполняемая приватная память нормальна: так работает JIT.")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        self.summary = QLabel("Читаю память процесса...")
        self.summary.setWordWrap(True)
        layout.addWidget(self.summary)

        tabs = QTabWidget()
        regions = QWidget()
        box = QVBoxLayout(regions)
        row = QHBoxLayout()
        self.filter = QComboBox()
        self.filter.addItems(FILTERS)
        self.filter.currentIndexChanged.connect(lambda _: self._fill_regions())
        refresh = QPushButton("Обновить")
        refresh.clicked.connect(self.start)
        row.addWidget(QLabel("Показать:"))
        row.addWidget(self.filter)
        row.addStretch()
        row.addWidget(refresh)
        box.addLayout(row)
        self.regions_tree = _tree(
            ["Адрес", "Размер", "Права", "Тип", "Состояние", "Оценка", "Причина", "Файл"],
            [150, 90, 80, 140, 120, 120, 380, 300])
        self.regions_tree.itemDoubleClicked.connect(self._open_region)
        box.addWidget(self.regions_tree, 1)
        box.addWidget(QLabel("Двойной щелчок по региону: его содержимое (первые 4 КБ) в hex."))
        tabs.addTab(regions, "Регионы памяти")

        modules = QWidget()
        box = QVBoxLayout(modules)
        self.modules_tree = _tree(["Модуль", "Базовый адрес", "Размер", "Подпись", "Оценка",
                                   "Путь"], [220, 150, 90, 260, 260, 400])
        self.modules_tree.itemDoubleClicked.connect(self._open_module)
        box.addWidget(self.modules_tree, 1)
        box.addWidget(QLabel("Двойной щелчок по модулю: сведения о файле и переход к нему."))
        tabs.addTab(modules, "Модули")
        layout.addWidget(tabs, 1)
        self.start()

    def _open_region(self, item, _column) -> None:
        base, size = item.data(0, NUM_ROLE), item.data(1, NUM_ROLE)
        if base is None or self.report is None:
            return
        region = next((r for r in self.report.regions if r.base == base), None)
        data, error = memdeep.read_region(self.pid, base, min(size or 0, 4096))
        lines = [f"Адрес: {base:016X}", f"Размер: {_size(size)}",
                 f"Права: {item.text(2)}, тип: {item.text(3)}, состояние: {item.text(4)}"]
        if region is not None:
            lines.append(f"Права при выделении: {memdeep.protect_text(region.allocation_protect)}, "
                         f"начало выделения: {region.allocation_base:016X}")
        if item.text(6):
            lines.append(f"Причина: {item.text(6)}")
        if item.text(7):
            lines.append(f"Файл: {item.text(7)}")
        if data[:2] == b"MZ":
            lines.append("В начале региона заголовок PE (MZ): здесь лежит программа или библиотека")
        lines.append("")
        lines.append(hexdump(data, base) if data else error)
        _text_dialog(self, f"Регион {base:016X}", "\n".join(lines))

    def _open_module(self, item, _column) -> None:
        path = item.text(5)
        module = next((m for m in self.report.modules if m.path == path), None) if self.report else None
        if module is None:
            return
        lines = [f"Модуль: {os.path.basename(path)}", f"Путь: {path}",
                 f"Базовый адрес: {module.base:016X}", f"Размер в памяти: {_size(module.size)}",
                 f"Подпись: {module.sig or 'проверяется...'}",
                 f"Оценка: {'; '.join(module.reasons) or 'замечаний нет'}"]
        try:
            st = os.stat(path)
            lines.append(f"Размер файла: {_size(st.st_size)}")
        except OSError:
            lines.append("Файл на диске не найден")
        _text_dialog(self, os.path.basename(path), "\n".join(lines),
                     folder=path if os.path.exists(path) else "")

    def start(self) -> None:
        self.summary.setText("Читаю память процесса...")
        threading.Thread(target=self._job, daemon=True).start()

    def _job(self) -> None:
        report = memdeep.inspect_process(self.pid, self.name)
        self.bridge.report.emit(report)
        if report.modules:
            memdeep.assess_modules(report.modules)  # подписи модулей: долго
            self.bridge.modules.emit(report)

    def _on_report(self, report) -> None:
        self.report = report
        self.summary.setText(report.summary() + (" (32-разрядный процесс)" if report.wow64 else ""))
        self._fill_regions()
        self._fill_modules(checking=True)

    def _on_modules(self, report) -> None:
        if report is self.report:
            self._fill_modules(checking=False)

    def _fill_regions(self) -> None:
        tree = self.regions_tree
        tree.setSortingEnabled(False)
        tree.clear()
        if self.report is None:
            return
        mode = self.filter.currentIndex()
        items = []
        for r in self.report.regions:
            if mode == 0 and r.level == "normal":
                continue
            if mode == 1 and not r.executable:
                continue
            item = _Item([f"{r.base:016X}", _size(r.size), memdeep.protect_text(r.protect),
                          memdeep.TYPE_TEXT.get(r.type, hex(r.type)),
                          memdeep.STATE_TEXT.get(r.state, hex(r.state)), LEVEL_TEXT[r.level],
                          "; ".join(r.reasons), r.mapped_file])
            item.setData(0, NUM_ROLE, r.base)
            item.setData(1, NUM_ROLE, r.size)
            item.setToolTip(6, "; ".join(r.reasons))
            item.setToolTip(7, r.mapped_file)
            _paint(item, r.level, 8)
            items.append(item)
        tree.addTopLevelItems(items)
        tree.setSortingEnabled(True)
        if mode == 0 and not items:
            tree.addTopLevelItem(QTreeWidgetItem(["Подозрительных регионов не найдено"]))

    def _fill_modules(self, checking: bool) -> None:
        tree = self.modules_tree
        tree.setSortingEnabled(False)
        tree.clear()
        items = []
        for m in self.report.modules:
            item = _Item([os.path.basename(m.path), f"{m.base:016X}", _size(m.size),
                          "проверяю..." if checking else m.sig,
                          "; ".join(m.reasons), m.path])
            item.setData(1, NUM_ROLE, m.base)
            item.setData(2, NUM_ROLE, m.size)
            item.setToolTip(5, m.path)
            if not checking:
                _paint(item, m.level, 6)
            items.append(item)
        tree.addTopLevelItems(items)
        tree.setSortingEnabled(True)
        if not checking:
            tree.sortItems(4, Qt.SortOrder.DescendingOrder)  # проблемные модули сверху


class InjectionScanDialog(QDialog):
    """Проверка карты памяти всех процессов: где есть признаки внедрения кода."""
    def __init__(self, procs: list[tuple[int, str, str]], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Поиск внедрения кода в процессах")
        self.resize(1100, 640)
        self.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint, True)
        self.procs = procs
        self._cancel = threading.Event()
        self.bridge = _Bridge()
        self.bridge.progress.connect(self._on_progress)
        self.bridge.finished.connect(self._on_finished)

        layout = QVBoxLayout(self)
        self.status = QLabel("")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.tree = _tree(["Процесс", "PID", "Подозрительных", "На проверку", "Приватных X",
                           "RWX", "Главная причина", "Путь"],
                          [200, 70, 120, 100, 100, 70, 380, 300])
        self.tree.itemDoubleClicked.connect(self._open)
        layout.addWidget(self.tree, 1)
        row = QHBoxLayout()
        self.btn_stop = QPushButton("Остановить")
        self.btn_stop.clicked.connect(self._cancel.set)
        row.addWidget(QLabel("Двойной щелчок по строке: подробная карта памяти и модули."))
        row.addStretch()
        row.addWidget(self.btn_stop)
        layout.addLayout(row)
        self._done = 0
        self._found = 0
        threading.Thread(target=self._job, daemon=True).start()

    def _job(self) -> None:
        def work(proc):
            if self._cancel.is_set():
                return None
            pid, name, exe = proc
            report = memdeep.inspect_process(pid, name)
            report.exe = exe
            return report

        with ThreadPoolExecutor(max_workers=4) as pool:
            for i, report in enumerate(pool.map(work, self.procs), 1):
                self.bridge.progress.emit(i, len(self.procs), report)
        self.bridge.finished.emit()

    def _on_progress(self, done: int, total: int, report) -> None:
        self.status.setText(f"Проверено процессов: {done} из {total}. "
                            f"С признаками внедрения: {self._found}")
        if report is None or report.error:
            return
        suspicious = [r for r in report.regions if r.level == "suspicious"]
        check = [r for r in report.regions if r.level == "check"]
        if not suspicious and not check:
            return
        executable = [r for r in report.regions if r.executable]
        private_x = sum(1 for r in executable if r.type == memdeep.MEM_PRIVATE)
        rwx = sum(1 for r in executable if r.protect & memdeep.WRITE_EXEC)
        main = (suspicious or check)[0].reasons[0]
        item = _Item([report.name, str(report.pid), str(len(suspicious)), str(len(check)),
                      str(private_x), str(rwx), main, getattr(report, "exe", "")])
        for col, value in ((1, report.pid), (2, len(suspicious)), (3, len(check)),
                           (4, private_x), (5, rwx)):
            item.setData(col, NUM_ROLE, value)
        _paint(item, "suspicious" if suspicious else "check", 8)
        if suspicious:
            self._found += 1
        self.tree.addTopLevelItem(item)

    def _on_finished(self) -> None:
        self.btn_stop.setEnabled(False)
        self.tree.sortItems(2, Qt.SortOrder.DescendingOrder)
        prefix = "Остановлено" if self._cancel.is_set() else "Готово"
        self.status.setText(
            f"{prefix}. Процессов с подозрительными регионами: {self._found}, всего в списке: "
            f"{self.tree.topLevelItemCount()}. Жёлтые строки чаще всего нормальны (JIT, "
            "переходники); оранжевые стоит открыть и проверить.")

    def _open(self, item, _column) -> None:
        pid = item.data(1, NUM_ROLE)
        if pid is not None:
            MemoryDialog(pid, item.text(0), self).show()

    def closeEvent(self, event) -> None:
        self._cancel.set()
        super().closeEvent(event)
