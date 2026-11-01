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

    def __init__(self, show_title: bool = True):
        super().__init__()
        layout = QVBoxLayout(self)
        margin = (16, 12, 16, 12) if show_title else (4, 4, 4, 4)
        layout.setContentsMargins(*margin)
        if show_title:  # на общей странице «Журнал действий» заголовок свой
            title = QLabel("Журнал действий")
            title.setStyleSheet("font-size: 20pt; font-weight: 600;")
            layout.addWidget(title)
        hint = QLabel(
            "Исправления, которые сделала программа: автозапуск, проверка системы, карантин. "
            "Выберите действия (несколько: с Ctrl или Shift) и нажмите «Отменить действие», "
            "чтобы вернуть прежнее состояние.")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Время", "Действие", "Статус"])
        self.tree.setRootIsDecorated(False)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)  # Ctrl, Shift
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
        records = {r["id"]: r for r in journal.read_all()}
        # порядок списка: сверху новые, поэтому действия отменяются от последнего к первому
        items = [self.tree.topLevelItem(i) for i in range(self.tree.topLevelItemCount())]
        items = [it for it in items if it.isSelected()
                 and not records.get(it.data(0, ID_ROLE), {}).get("undone", True)]
        if not items:
            QMessageBox.information(self, "Журнал",
                                    "Выберите в списке действия, которые ещё не отменены")
            return
        lines = "\n".join(f"• {it.text(1)}" for it in items[:10])
        if len(items) > 10:
            lines += f"\n...и ещё {len(items) - 10}"
        answer = QMessageBox.question(
            self, "Отмена действия",
            f"Отменить действия ({len(items)})?\n\n{lines}" if len(items) > 1
            else f"Отменить действие?\n\n{items[0].text(1)}")
        if answer != QMessageBox.StandardButton.Yes:
            return
        messages, errors = [], []
        for it in items:
            record_id = it.data(0, ID_ROLE)
            try:
                messages.append(journal.undo(record_id))
            except (ValueError, OSError) as exc:
                errors.append(f"{it.text(1)}: {exc}")
                continue
            self.undone.emit(records[record_id])
        self.refresh()
        if errors:
            QMessageBox.warning(
                self, "Отмена действия", f"Отменено: {len(messages)}. Не удалось: {len(errors)}"
                "\n\n" + "\n".join(errors[:10]))
        elif len(messages) == 1:
            QMessageBox.information(self, "Отмена действия", messages[0])
        else:
            QMessageBox.information(self, "Отмена действия", f"Отменено действий: {len(messages)}")