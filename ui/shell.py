from PySide6.QtCore import Signal
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
        self.nav.setFixedWidth(200)
        self.nav.setFrameShape(QFrame.Shape.NoFrame)
        self.nav.setSpacing(2)
        self.nav.setStyleSheet(
            "QListWidget { padding: 8px 6px; }"
            "QListWidget::item { padding: 10px 12px; border-radius: 6px; }"
            "QListWidget::item:selected { background: palette(highlight);"
            " color: palette(highlighted-text); }")
        self.stack = QStackedWidget()
        layout.addWidget(self.nav)
        layout.addWidget(self.stack, 1)

        self._titles: list[str] = []
        self.nav.currentRowChanged.connect(self._on_row)

    def add_page(self, title: str, widget: QWidget) -> None:
        self.stack.addWidget(widget)
        self.nav.addItem(QListWidgetItem(title))
        self._titles.append(title)
        if self.nav.currentRow() < 0:
            self.nav.setCurrentRow(0)

    def show_page(self, title: str) -> None:
        self.nav.setCurrentRow(self._titles.index(title))

    def _on_row(self, row: int) -> None:
        if 0 <= row < len(self._titles):
            self.stack.setCurrentIndex(row)
            self.page_changed.emit(self._titles[row])