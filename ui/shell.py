from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QListWidget, QListWidgetItem, QStackedWidget, QWidget,
)


class Shell(QWidget):
    """Боковая навигация слева, страницы справа."""
    page_changed = Signal(str)

    def __init__(self):
        super().__init__()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.nav = QListWidget()
        self.nav.setFixedWidth(220)
        self.nav.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.nav.setFrameShape(QFrame.Shape.NoFrame)
        self.nav.setSpacing(2)
        self.nav.setStyleSheet(
            "QListWidget { padding: 8px 6px; outline: none; show-decoration-selected: 1; }"
            "QListWidget::item { padding: 10px 12px; border-radius: 6px; border: none; }"
            "QListWidget::item:selected { background: palette(highlight);"
            " color: palette(highlighted-text); }")
        self.stack = QStackedWidget()
        layout.addWidget(self.nav)
        layout.addWidget(self.stack, 1)

        self._titles: list[str] = []
        self.nav.currentRowChanged.connect(self._on_row)

    def add_page(self, title: str, widget: QWidget, hidden: bool = False) -> None:
        self.stack.addWidget(widget)
        item = QListWidgetItem(title)
        self.nav.addItem(item)
        item.setHidden(hidden)  # только после addItem: у элемента вне списка флаг игнорируется
        self._titles.append(title)
        if self.nav.currentRow() < 0:
            self.nav.setCurrentRow(0)

    def set_page_visible(self, title: str, visible: bool) -> None:
        index = self._titles.index(title)
        self.nav.item(index).setHidden(not visible)
        if not visible and self.nav.currentRow() == index:
            self.nav.setCurrentRow(0)  # скрытая страница была открыта: возвращаемся на главную

    def show_page(self, title: str) -> None:
        self.nav.setCurrentRow(self._titles.index(title))

    def _on_row(self, row: int) -> None:
        if 0 <= row < len(self._titles):
            self.stack.setCurrentIndex(row)
            self.page_changed.emit(self._titles[row])