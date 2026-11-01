from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QHBoxLayout, QHeaderView, QLabel, QMessageBox, QPushButton,
    QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from scanner import exclusions

CATEGORY_ROLE = Qt.ItemDataRole.UserRole + 1
KEY_ROLE = Qt.ItemDataRole.UserRole + 2


class ExclusionsPage(QWidget):
    def __init__(self, show_title: bool = True):
        super().__init__()
        layout = QVBoxLayout(self)
        margin = (16, 12, 16, 12) if show_title else (4, 4, 4, 4)
        layout.setContentsMargins(*margin)
        if show_title:  # на общей странице «Журнал действий» заголовок свой
            title = QLabel("Исключения")
            title.setStyleSheet("font-size: 20pt; font-weight: 600;")
            layout.addWidget(title)
        hint = QLabel(
            "Записи автозапуска и находки проверки системы, которым вы доверяете: они не "
            "показываются при проверках. Исключение перестаёт действовать, если запись или "
            "файл изменились. Убранное из исключений появится при следующей проверке.")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Раздел", "Что", "Подробности", "Добавлено"])
        self.tree.setRootIsDecorated(False)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)  # Ctrl, Shift
        header = self.tree.header()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        for i, width in enumerate((140, 380, 480, 160)):
            self.tree.setColumnWidth(i, width)
        layout.addWidget(self.tree, 1)

        row = QHBoxLayout()
        remove = QPushButton("Убрать из исключений")
        remove.clicked.connect(self.remove_selected)
        refresh = QPushButton("Обновить")
        refresh.clicked.connect(self.refresh)
        row.addWidget(remove)
        row.addWidget(refresh)
        row.addStretch()
        layout.addLayout(row)
        self.refresh()

    def refresh(self) -> None:
        self.tree.clear()
        for item in exclusions.items():
            row = QTreeWidgetItem([exclusions.CATEGORY_TEXT.get(item["category"], item["category"]),
                                   item["title"], item["detail"], item["added"].replace("T", " ")])
            row.setData(0, CATEGORY_ROLE, item["category"])
            row.setData(0, KEY_ROLE, item["key"])
            for col in range(4):
                row.setToolTip(col, item["detail"] or item["title"])
            self.tree.addTopLevelItem(row)

    def remove_selected(self) -> None:
        selected = self.tree.selectedItems()
        if not selected:
            QMessageBox.information(self, "Исключения", "Сначала выберите строку в списке")
            return
        lines = "\n".join(f"• {item.text(1)}" for item in selected[:10])
        if len(selected) > 10:
            lines += f"\n...и ещё {len(selected) - 10}"
        answer = QMessageBox.question(
            self, "Исключения", f"Убрать из исключений ({len(selected)})?\n\n{lines}\n\n"
            "При следующей проверке записи снова будут показаны.")
        if answer == QMessageBox.StandardButton.Yes:
            for item in selected:
                exclusions.remove(item.data(0, CATEGORY_ROLE), item.data(0, KEY_ROLE))
            self.refresh()