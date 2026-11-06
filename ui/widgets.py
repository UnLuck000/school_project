"""Общие заготовки виджетов: дерево и таблица со стандартными настройками, строка дерева
с сортировкой по числу, подсказка с полным текстом обрезанной ячейки."""
from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtGui import QFontMetrics
from PySide6.QtWidgets import (
    QAbstractItemView, QAbstractScrollArea, QAbstractSpinBox, QApplication, QComboBox,
    QHeaderView, QStyledItemDelegate, QTableWidget, QToolTip, QTreeWidget, QTreeWidgetItem,
    QWidget,
)


def item_less(item: QTreeWidgetItem, other: QTreeWidgetItem, role: int) -> bool:
    """Сравнение строк дерева: по значению role, если оно задано у обеих, иначе по тексту."""
    tree = item.treeWidget()
    col = tree.sortColumn() if tree else 0
    a, b = item.data(col, role), other.data(col, role)
    if a is not None and b is not None:
        return a < b
    return item.text(col).lower() < other.text(col).lower()


class SortItem(QTreeWidgetItem):
    """Строка дерева с сортировкой по числу из SORT_ROLE (в наследнике — своя роль)."""
    SORT_ROLE = Qt.ItemDataRole.UserRole + 2

    def __lt__(self, other):
        return item_less(self, other, self.SORT_ROLE)


def make_tree(columns: list[str], widths: list[int], multi: bool = True,
              decorated: bool = False) -> QTreeWidget:
    """Дерево-таблица: заголовки и ширина столбцов, выделение с Ctrl и Shift (multi)."""
    tree = QTreeWidget()
    tree.setHeaderLabels(columns)
    tree.setRootIsDecorated(decorated)
    tree.setUniformRowHeights(True)
    tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection if multi
                          else QAbstractItemView.SelectionMode.SingleSelection)
    header = tree.header()
    header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    header.setStretchLastSection(True)
    for i, width in enumerate(widths):
        tree.setColumnWidth(i, width)
    return tree


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


def make_table(columns: list[tuple[str, int]]) -> QTableWidget:
    """Таблица только для чтения: выделение строк, обрезка длинного текста с подсказкой."""
    table = QTableWidget(0, len(columns))
    table.setHorizontalHeaderLabels([name for name, _ in columns])
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
    table.setTextElideMode(Qt.TextElideMode.ElideRight)
    table.verticalHeader().setVisible(False)
    header = table.horizontalHeader()
    header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    header.setStretchLastSection(True)
    header.setMinimumSectionSize(50)
    for i, (_, width) in enumerate(columns):
        table.setColumnWidth(i, width)
    table.setItemDelegate(ElidedTooltipDelegate(table))
    return table


class _WheelGuard(QObject):
    """Колесо над полем без фокуса прокручивает страницу, а не меняет значение."""

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Type.Wheel and not obj.hasFocus():
            parent = obj.parentWidget()
            while parent is not None and not isinstance(parent, QAbstractScrollArea):
                parent = parent.parentWidget()
            if parent is not None:
                QApplication.sendEvent(parent.verticalScrollBar(), event)
            return True
        return False


_wheel_guard: _WheelGuard | None = None


def guard_wheel(root: QWidget) -> None:
    """Поля со счётчиком, времени и выпадающие списки внутри root меняются колесом мыши
    только после щелчка по ним (фокус); иначе колесо прокручивает страницу — на длинной
    странице настроек случайный наезд курсора не меняет значения."""
    global _wheel_guard
    if _wheel_guard is None:
        _wheel_guard = _WheelGuard()
    for widget in root.findChildren(QAbstractSpinBox) + root.findChildren(QComboBox):
        widget.setFocusPolicy(Qt.FocusPolicy.StrongFocus)  # фокус — щелчком, не колесом
        widget.installEventFilter(_wheel_guard)
