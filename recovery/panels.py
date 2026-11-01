from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QHBoxLayout, QHeaderView, QLabel, QPushButton, QTabWidget,
    QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from processmanager.colors import text_color
from recovery import policies

LEVEL_COLORS = {"ok": (170, 230, 170), "info": (170, 204, 255),
                "warning": (255, 190, 110), "bad": (255, 128, 128)}
INDEX_ROLE = Qt.ItemDataRole.UserRole + 1


def _make_tree(columns: list[str], widths: list[int]) -> QTreeWidget:
    tree = QTreeWidget()
    tree.setHeaderLabels(columns)
    tree.setRootIsDecorated(False)
    tree.setUniformRowHeights(True)
    tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    header = tree.header()
    header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    header.setStretchLastSection(True)
    for i, width in enumerate(widths):
        tree.setColumnWidth(i, width)
    return tree


def _paint(item: QTreeWidgetItem, rgb, columns: int) -> None:
    for col in range(columns):
        item.setBackground(col, QBrush(QColor(*rgb)))
        item.setForeground(col, QBrush(text_color(rgb)))


def _hint(text: str) -> QLabel:
    label = QLabel(text)
    label.setWordWrap(True)
    return label


class FindingsPanel(QWidget):
    """Список находок одной проверки с кнопками исправления и добавления в исключения."""
    fix_requested = Signal(object)      # Finding
    exclude_requested = Signal(object)  # Finding

    def __init__(self, hint: str):
        super().__init__()
        self._findings: list = []
        layout = QVBoxLayout(self)
        layout.addWidget(_hint(hint))
        row = QHBoxLayout()
        self.summary = QLabel("Нажмите «Проверить всё»")
        self.btn_fix = QPushButton("Исправить выбранное")
        self.btn_fix.setEnabled(False)
        self.btn_fix.clicked.connect(self._on_fix)
        self.btn_trust = QPushButton("Доверять (в исключения)")
        self.btn_trust.setEnabled(False)
        self.btn_trust.clicked.connect(self._on_trust)
        row.addWidget(self.summary, 1)
        row.addWidget(self.btn_trust)
        row.addWidget(self.btn_fix)
        layout.addLayout(row)
        self.tree = _make_tree(["Проверка", "Состояние", "Подробности"], [380, 300, 520])
        self.tree.itemSelectionChanged.connect(self._update_buttons)
        layout.addWidget(self.tree, 1)

    def set_findings(self, findings: list) -> None:
        self._findings = findings
        self.tree.clear()
        for index, f in enumerate(findings):
            item = QTreeWidgetItem([f.title, f.status, f.detail])
            item.setData(0, INDEX_ROLE, index)
            _paint(item, LEVEL_COLORS[f.level], 3)
            for col in range(3):
                item.setToolTip(col, f.detail or f.status)
            self.tree.addTopLevelItem(item)
        problems = sum(1 for f in findings if f.level in ("warning", "bad"))
        self.summary.setText(f"Требуют внимания: {problems}" if problems else "Проблем не найдено")
        self._update_buttons()

    def _selected(self):
        items = self.tree.selectedItems()
        return self._findings[items[0].data(0, INDEX_ROLE)] if items else None

    def _update_buttons(self) -> None:
        f = self._selected()
        has_fix = f is not None and f.fix is not None
        self.btn_fix.setEnabled(has_fix)
        self.btn_fix.setText(f.fix_title if has_fix else "Исправить выбранное")
        self.btn_trust.setEnabled(f is not None and f.level != "ok")

    def _on_fix(self) -> None:
        f = self._selected()
        if f is not None and f.fix is not None:
            self.fix_requested.emit(f)

    def _on_trust(self) -> None:
        f = self._selected()
        if f is not None:
            self.exclude_requested.emit(f)


class PolicyPanel(QWidget):
    """Политики и блокировки в реестре: сканирование и ручная разблокировка."""
    scan_requested = Signal()
    unlock_hits_requested = Signal(object)   # список PolicyHit
    unlock_names_requested = Signal(object)  # список имён ограничений
    exclude_hits_requested = Signal(object)

    def __init__(self):
        super().__init__()
        self._hits: list = []
        layout = QVBoxLayout(self)
        layout.addWidget(_hint(
            "Ограничения, которые вредоносные программы и «твикеры» ставят через реестр: "
            "блокировка диспетчера задач, командной строки, реестра, запуска программ и т.п. "
            "Ищутся в HKLM, HKCU и в разделах других пользователей (нужны права администратора). "
            "Каждое снятие записывается в журнал и отменяется одним действием."))
        tabs = QTabWidget()
        tabs.addTab(self._build_scan_tab(), "Сканирование")
        tabs.addTab(self._build_manual_tab(), "Ручная разблокировка")
        layout.addWidget(tabs, 1)

    # ---------- вкладка «Сканирование» ----------
    def _build_scan_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        self.scan_tree = _make_tree(["№", "Ограничение", "Значение", "Путь"], [50, 520, 110, 560])
        layout.addWidget(self.scan_tree, 1)

        row = QHBoxLayout()
        self.auto_cb = QCheckBox("Предлагать разблокировку найденного сразу после сканирования")
        scan = QPushButton("Начать сканирование")
        scan.clicked.connect(lambda checked=False: self.scan_requested.emit())
        select = QPushButton("Выбрать все")
        select.clicked.connect(lambda checked=False: self._toggle_all(self.scan_tree))
        unlock = QPushButton("Разблокировать выбранные")
        unlock.clicked.connect(lambda checked=False: self._unlock_selected_hits())
        trust = QPushButton("Доверять выбранным")
        trust.clicked.connect(lambda checked=False: self._trust_selected())
        row.addWidget(self.auto_cb, 1)
        for button in (scan, select, trust, unlock):
            row.addWidget(button)
        layout.addLayout(row)
        return tab

    def _trust_selected(self) -> None:
        indices = self._checked_indices(self.scan_tree)
        if indices:
            self.exclude_hits_requested.emit([self._hits[i] for i in indices])

    def set_hits(self, hits: list) -> None:
        self._hits = hits
        self.scan_tree.clear()
        for number, hit in enumerate(hits, 1):
            item = QTreeWidgetItem([str(number), hit.title, str(hit.value),
                                    f"{hit.hive}\\{hit.path}\\{hit.name}"])
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(0, Qt.CheckState.Unchecked)
            item.setData(0, INDEX_ROLE, number - 1)
            _paint(item, LEVEL_COLORS["bad" if hit.restriction_name in policies.CRITICAL
                                      else "warning"], 4)
            item.setToolTip(1, "Перехват запуска может быть и законным (замена диспетчера задач "
                               "сторонней программой)" if hit.kind == "ifeo" else hit.title)
            self.scan_tree.addTopLevelItem(item)

        active = {h.restriction_name for h in hits if h.restriction_name}
        for name, item in self._manual_items.items():
            found = name in active
            item.setText(2, "Обнаружено" if found else "Не найдено")
            _paint(item, LEVEL_COLORS["warning" if found else "ok"], 3)
        if hits and self.auto_cb.isChecked():
            self.unlock_hits_requested.emit(list(hits))

    def _unlock_selected_hits(self) -> None:
        indices = self._checked_indices(self.scan_tree)
        if indices:
            self.unlock_hits_requested.emit([self._hits[i] for i in indices])

    # ---------- вкладка «Ручная разблокировка» ----------
    def _build_manual_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        self.manual_tree = _make_tree(["Ограничение", "Описание", "Состояние"], [260, 560, 160])
        self._manual_items: dict[str, QTreeWidgetItem] = {}
        for restriction in policies.CATALOG:
            item = QTreeWidgetItem([restriction.name, restriction.description,
                                    "Не проверялось"])
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(0, Qt.CheckState.Unchecked)
            self.manual_tree.addTopLevelItem(item)
            self._manual_items[restriction.name] = item
        layout.addWidget(self.manual_tree, 1)

        row = QHBoxLayout()
        select = QPushButton("Выбрать все")
        select.clicked.connect(lambda checked=False: self._toggle_all(self.manual_tree))
        unlock = QPushButton("Разблокировать выбранные ограничения")
        unlock.clicked.connect(lambda checked=False: self._unlock_selected_names())
        row.addWidget(select)
        row.addStretch()
        row.addWidget(unlock)
        layout.addLayout(row)
        return tab

    def _unlock_selected_names(self) -> None:
        names = [name for name, item in self._manual_items.items()
                 if item.checkState(0) == Qt.CheckState.Checked]
        if names:
            self.unlock_names_requested.emit(names)

    # ---------- общее ----------
    @staticmethod
    def _toggle_all(tree: QTreeWidget) -> None:
        items = [tree.topLevelItem(i) for i in range(tree.topLevelItemCount())]
        all_checked = all(it.checkState(0) == Qt.CheckState.Checked for it in items)
        target = Qt.CheckState.Unchecked if all_checked else Qt.CheckState.Checked
        for item in items:
            item.setCheckState(0, target)

    @staticmethod
    def _checked_indices(tree: QTreeWidget) -> list[int]:
        result = []
        for i in range(tree.topLevelItemCount()):
            item = tree.topLevelItem(i)
            if item.checkState(0) == Qt.CheckState.Checked:
                result.append(item.data(0, INDEX_ROLE))
        return result