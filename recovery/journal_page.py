from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QHBoxLayout, QHeaderView, QLabel, QMessageBox, QPushButton,
    QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

import autoruns.actions  # noqa: F401  (регистрирует откат действий автозапуска)
import recovery.actions  # noqa: F401  (регистрирует откат исправлений системы)
from recovery import journal

ID_ROLE = Qt.ItemDataRole.UserRole + 1


class JournalPage(QWidget):
    undone = Signal(object)  # запись журнала, действие которой отменено

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        title = QLabel("Журнал действий")
        title.setStyleSheet("font-size: 20pt; font-weight: 600;")
        layout.addWidget(title)
        hint = QLabel(
            "Исправления, которые сделала программа: автозапуск, проверка системы, карантин. "
            "Выберите действие и нажмите «Отменить действие», чтобы вернуть прежнее состояние.")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Время", "Действие", "Статус"])
        self.tree.setRootIsDecorated(False)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        header = self.tree.header()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        for i, width in enumerate((160, 800, 160)):
            self.tree.setColumnWidth(i, width)
        layout.addWidget(self.tree, 1)

        row = QHBoxLayout()
        undo = QPushButton("Отменить действие")
        undo.clicked.connect(self.undo_selected)
        refresh = QPushButton("Обновить")
        refresh.clicked.connect(self.refresh)
        row.addWidget(undo)
        row.addWidget(refresh)
        row.addStretch()
        layout.addLayout(row)
        self.refresh()

    def refresh(self) -> None:
        self.tree.clear()
        for record in reversed(journal.read_all()):
            status = f"Отменено {record['undone_at']}" if record["undone"] else "Выполнено"
            item = QTreeWidgetItem([record["time"].replace("T", " "), record["title"], status])
            item.setData(0, ID_ROLE, record["id"])
            if record["undone"]:
                for col in range(3):
                    item.setForeground(col, QBrush(QColor("gray")))
            self.tree.addTopLevelItem(item)

    def undo_selected(self) -> None:
        item = self.tree.currentItem()
        if item is None:
            QMessageBox.information(self, "Журнал", "Сначала выберите действие в списке")
            return
        record_id = item.data(0, ID_ROLE)
        record = next((r for r in journal.read_all() if r["id"] == record_id), None)
        answer = QMessageBox.question(
            self, "Отмена действия", f"Отменить действие?\n\n{item.text(1)}")
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            message = journal.undo(record_id)
        except (ValueError, OSError) as exc:
            QMessageBox.critical(self, "Отмена действия", f"Не удалось отменить: {exc}")
            return
        QMessageBox.information(self, "Отмена действия", message)
        self.refresh()
        if record is not None:
            self.undone.emit(record)