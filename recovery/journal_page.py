from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QHBoxLayout, QHeaderView, QLabel, QMenu, QMessageBox, QPushButton,
    QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

import autoruns.actions  # noqa: F401  (регистрирует откат действий автозапуска)
import scanner.overrides  # noqa: F401  (откат исключений хэшей и правил)
import networkmonitor.firewall  # noqa: F401  (регистрирует откат блокировок)
import recovery.actions  # noqa: F401  (регистрирует откат исправлений системы)
import usbguard.repair  # noqa: F401  (откат восстановления флешки)
import toolbox.decoys  # noqa: F401  (откат создания и удаления ловушек)
import toolbox.stealerguard  # noqa: F401  (откат разрешений защиты от стилеров)
import vpn.dnsguard  # noqa: F401  (откат DNS на время VPN)
import vpn.killswitch  # noqa: F401  (откат kill switch)
import vpn.xray  # noqa: F401  (откат системного прокси)
from recovery import journal

ID_ROLE = Qt.ItemDataRole.UserRole + 1


# где сделано действие: «Перейти к месту действия» (обработку делает главное окно)
PLACES = {
    "firewall_remove": "net_block", "firewall_restore": "net_block",
    "quarantine_restore": "protect_journal", "whitelist_remove": "protect_journal",
    "reg_set": "autoruns", "move_back": "autoruns", "service_start": "autoruns",
    "task_enable": "autoruns",
    "reg_restore": "system_checks", "reg_restore_many": "system_checks",
    "hosts_restore": "system_checks", "service_mode": "system_checks",
    "task_enabled": "system_checks", "firewall_state": "system_checks",
    "bcd_set": "system_checks", "assoc_restore": "assoc",
    "fp_hash_restore": "false_positives", "fp_rule_enable": "false_positives",
    "vpn_killswitch_off": "vpn_settings", "vpn_dns_restore": "vpn_settings",
    "vpn_proxy_restore": "vpn_connect", "vpn_disconnect": "vpn_connect",
    "driver_enable": "drivers", "ext_restore": "extensions", "notify_allow": "extensions",
    "usb_attrs": "usb", "usb_moves": "usb", "usb_unvaccinate": "usb",
    "decoys_remove": "protection", "decoys_create": "protection",
    "stealer_untrust": "protection", "file_rename": "file",
}
TEST_ONLY_PLACES = {"false_positives"}   # окна есть только в тестовой версии (diag/edition)


def place_of(op: str) -> str | None:
    """Куда ведёт «Перейти к месту действия»; None — некуда (в том числе окно, которого нет
    в релизной версии: «Ложные срабатывания»)."""
    place = PLACES.get(op)
    if place in TEST_ONLY_PLACES:
        from diag import edition
        if not edition.is_test():
            return None
    return place


class JournalPage(QWidget):
    undone = Signal(object)  # запись журнала, действие которой отменено
    goto = Signal(str, object)  # место из PLACES, запись журнала

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
            "Исправления, которые сделала программа: автозапуск, проверка системы, карантин, "
            "сеть, VPN. Выберите действия (несколько: с Ctrl или Shift) и нажмите «Отменить "
            "действие»; правый клик — отменить или перейти к месту действия. Действия, которые "
            "уже сняты другим путём, и повторы одного и того же из журнала убираются сами.")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Время", "Действие", "Статус"])
        self.tree.setRootIsDecorated(False)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)  # Ctrl, Shift
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._menu)
        self.tree.itemDoubleClicked.connect(lambda item, col: self._goto(item))
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

    def _record(self, item) -> dict | None:
        record_id = item.data(0, ID_ROLE) if item is not None else None
        return next((r for r in journal.read_all() if r["id"] == record_id), None)

    def _menu(self, pos) -> None:
        item = self.tree.itemAt(pos)
        record = self._record(item)
        if record is None:
            return
        menu = QMenu(self)
        undo = menu.addAction("Отменить действие", self.undo_selected)
        undo.setEnabled(not record["undone"])
        place = menu.addAction("Перейти к месту действия", lambda: self._goto(item))
        place.setEnabled(place_of(record["op"]) is not None)
        menu.exec(self.tree.viewport().mapToGlobal(pos))

    def _goto(self, item) -> None:
        record = self._record(item)
        place = place_of(record["op"]) if record is not None else None
        if place is not None:
            self.goto.emit(place, record)

    def refresh(self) -> None:
        journal.cleanup()  # снятые другим путём и повторы — убрать
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