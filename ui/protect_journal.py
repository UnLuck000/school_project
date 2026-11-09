"""Вкладка «Журнал защиты» страницы «Журнал»: найденное и его состояние (recovery/threatlog).

Автокарантин временно выключен, поэтому находка остаётся на месте со статусом «Найдено», и
решение за пользователем: в карантин, удалить, разобрать или убрать из списка. Файлы в
карантине (в том числе положенные туда из автозапуска и сканера) — здесь же: восстановить
(хэш уходит в белый список; отмена в «Действиях» убирает его оттуда) или удалить навсегда.
Белого списка как вкладки больше нет: он пополняется только отсюда.
"""
import os

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QCheckBox, QHBoxLayout, QLabel, QMenu, QMessageBox, QPushButton, QTreeWidgetItem,
    QVBoxLayout, QWidget,
)

from recovery import threatlog
from ui.widgets import make_tree

ID_ROLE = Qt.ItemDataRole.UserRole + 1
COLORS = {"threat": "#d9534f", "suspicious": "#d68910"}


class ProtectJournalPage(QWidget):
    changed = Signal()            # карантин, белый список или журнал действий изменились
    analyze = Signal(str)         # открыть файл в сканере
    false_positive = Signal(str)  # разобрать срабатывание (режим отладки)

    def __init__(self):
        super().__init__()
        self.debug_mode = False
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        hint = QLabel(
            "Всё, что нашла защита и проверки дисков. Найденное само в карантин не "
            "помещается: выберите строки (несколько — с Ctrl или Shift) и решите, что с ними "
            "делать. Восстановленный из карантина файл попадает в белый список; отменить это "
            "можно во вкладке «Действия». Двойной щелчок — описание.")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        self.tree = make_tree(["Время", "Файл", "Что найдено", "Источник", "Состояние"],
                              [140, 260, 380, 130, 160])
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._menu)
        self.tree.itemDoubleClicked.connect(lambda item, col: self.describe(item))
        layout.addWidget(self.tree, 1)

        row = QHBoxLayout()
        for text, handler in (("В карантин", self.quarantine_selected),
                              ("Удалить", self.delete_selected),
                              ("Восстановить из карантина", self.restore_selected),
                              ("Убрать из списка", self.dismiss_selected),
                              ("Обновить", self.refresh)):
            button = QPushButton(text)
            button.clicked.connect(lambda checked=False, h=handler: h())
            row.addWidget(button)
        self.history_cb = QCheckBox("Показывать завершённые")
        self.history_cb.setToolTip("Удалённые, восстановленные и убранные из списка")
        self.history_cb.toggled.connect(lambda _: self.refresh())
        row.addWidget(self.history_cb)
        row.addStretch()
        layout.addLayout(row)
        self.refresh()

    # ---------- список ----------
    def refresh(self) -> None:
        self.tree.clear()
        for r in threatlog.merged(self.history_cb.isChecked()):
            path = r.get("path") or ""
            name = os.path.basename(path) if path else "—"
            count = f" (×{r['count']})" if r.get("count", 1) > 1 else ""
            item = QTreeWidgetItem([r["time"].replace("T", " "), name, r["text"] + count,
                                    r.get("source", ""),
                                    threatlog.STATUS_TEXT.get(r["status"], r["status"])])
            item.setData(0, ID_ROLE, r["id"])
            item.setToolTip(1, path)
            item.setToolTip(2, r["text"])
            if r["status"] in threatlog.OPEN:
                item.setForeground(2, QBrush(QColor(COLORS.get(r["level"], "#d68910"))))
            else:
                for col in range(5):
                    item.setForeground(col, QBrush(QColor("gray")))
            self.tree.addTopLevelItem(item)

    def _selected(self) -> list[dict]:
        ids = [it.data(0, ID_ROLE) for it in self.tree.selectedItems()]
        records = {r["id"]: r for r in threatlog.merged(True)}
        return [records[i] for i in ids if i in records]

    def _menu(self, pos) -> None:
        records = self._selected()
        if not records:
            return
        first = records[0]
        path = first.get("path") or ""
        found = [r for r in records if r["status"] == threatlog.FOUND and threatlog.exists(r["path"])]
        quarantined = [r for r in records if r["status"] == threatlog.QUARANTINED]
        menu = QMenu(self)
        menu.addAction("Описание", lambda: self.describe(self.tree.currentItem()))
        menu.addSeparator()
        n = lambda items: f" ({len(items)})" if len(items) > 1 else ""  # noqa: E731
        menu.addAction("В карантин" + n(found), self.quarantine_selected).setEnabled(bool(found))
        menu.addAction("Удалить" + n(found + quarantined),
                       self.delete_selected).setEnabled(bool(found or quarantined))
        menu.addAction("Восстановить из карантина" + n(quarantined),
                       self.restore_selected).setEnabled(bool(quarantined))
        menu.addAction("Убрать из списка", self.dismiss_selected)
        menu.addSeparator()
        on_disk = threatlog.exists(path)
        menu.addAction("Открыть в сканере", lambda: self.analyze.emit(path)).setEnabled(on_disk)
        from analyzer import fileops
        menu.addAction("Показать в проводнике",
                       lambda: fileops.show_in_explorer(path)).setEnabled(on_disk)
        from diag import edition
        if self.debug_mode and edition.is_test():  # разбор ложных — только в тестовой версии
            menu.addAction("Разобрать срабатывание (ложное?)",
                           lambda: self.false_positive.emit(path)).setEnabled(on_disk)
        menu.exec(self.tree.viewport().mapToGlobal(pos))

    def describe(self, item) -> None:
        if item is None:
            return
        r = threatlog.get(item.data(0, ID_ROLE))
        if r is None:
            return
        from ui.details import show_details
        path = r.get("path") or ""
        rows = [("Файл", path), ("Что найдено", r["text"]),
                ("Уровень", "угроза" if r["level"] == "threat" else "подозрительно"),
                ("Источник", r.get("source", "")),
                ("Состояние", threatlog.STATUS_TEXT.get(r["status"], r["status"])),
                ("Найдено впервые", (r.get("first") or r["time"]).replace("T", " ")),
                ("Последний раз", r["time"].replace("T", " ")),
                ("Сколько раз", str(r.get("count", 1))),
                ("Файл на месте", "да" if threatlog.exists(path) else "нет"),
                ("SHA-256", r.get("sha256", "")), ("Подпись", r.get("signature", "")),
                ("ID в карантине", r.get("qid", ""))]
        actions = []
        if r["status"] == threatlog.FOUND and threatlog.exists(path):
            actions.append(("В карантин", lambda d: (self._quarantine([r]), d.accept())))
        if r["status"] == threatlog.QUARANTINED:
            actions.append(("Восстановить", lambda d: (self._restore([r]), d.accept())))
        if r["status"] in threatlog.OPEN:
            actions.append(("Удалить", lambda d: (self._delete([r]), d.accept())))
        if threatlog.exists(path):
            actions.append(("Открыть в сканере", lambda d: self.analyze.emit(path)))
        show_details(self, "Журнал защиты: описание", rows, actions)

    # ---------- действия ----------
    def _done(self, title: str, ok: int, failed: list[str]) -> None:
        self.refresh()
        self.changed.emit()
        if failed:
            QMessageBox.warning(self, title, f"Готово: {ok}. Не удалось: {len(failed)}\n\n"
                                + "\n".join(failed[:10]))

    def quarantine_selected(self) -> None:
        records = [r for r in self._selected()
                   if r["status"] == threatlog.FOUND and threatlog.exists(r["path"])]
        if records:
            self._quarantine(records)

    def _quarantine(self, records: list[dict]) -> None:
        from analyzer import fileops
        ok, failed = 0, []
        for r in records:
            try:
                qid = fileops.quarantine(r["path"], f"Журнал защиты: {r['text']}")
                threatlog.set_status(r["id"], threatlog.QUARANTINED, qid)
                ok += 1
            except OSError as e:
                failed.append(f"{os.path.basename(r['path'])}: {e}")
        self._done("Карантин", ok, failed)

    def restore_selected(self) -> None:
        records = [r for r in self._selected() if r["status"] == threatlog.QUARANTINED]
        if not records:
            QMessageBox.information(self, "Восстановление", "Выберите файлы в карантине")
            return
        answer = QMessageBox.question(
            self, "Восстановление",
            f"Вернуть файлы на прежнее место ({len(records)})?\n\nИх SHA-256 будет добавлен в "
            "белый список: сканер не будет считать файл угрозой, пока его содержимое не "
            "изменится. Убрать из белого списка — отменой действия во вкладке «Действия».")
        if answer == QMessageBox.StandardButton.Yes:
            self._restore(records)

    def _restore(self, records: list[dict]) -> None:
        from quarantine import restore_file
        from recovery import journal
        import analyzer.fileops  # noqa: F401  (откат «whitelist_remove»)
        ok, failed = 0, []
        for r in records:
            try:
                dest = restore_file(r["qid"])
            except (FileExistsError, ValueError, OSError) as e:
                failed.append(f"{os.path.basename(r.get('path') or '')}: {e}")
                continue
            import hashlib
            sha = r.get("sha256") or hashlib.sha256(dest.read_bytes()).hexdigest()
            journal.log_action(f"Файл «{dest.name}» восстановлен из карантина и добавлен в "
                               "белый список", "whitelist_remove",
                               {"sha256": sha, "path": str(dest)})
            if not r["id"].startswith("q:"):
                threatlog.set_status(r["id"], threatlog.RESTORED)
            ok += 1
        self._done("Восстановление", ok, failed)

    def delete_selected(self) -> None:
        records = [r for r in self._selected() if r["status"] in threatlog.OPEN]
        if records:
            self._delete(records)

    def _delete(self, records: list[dict]) -> None:
        answer = QMessageBox.question(
            self, "Удаление",
            f"Удалить файлы безвозвратно ({len(records)})?\n\nИх SHA-256 будет добавлен в "
            "свою базу сигнатур (signatures/hashes.txt): такой файл будет найден снова.")
        if answer != QMessageBox.StandardButton.Yes:
            return
        from quarantine import delete_file, quarantine_file
        from pathlib import Path
        ok, failed = 0, []
        for r in records:
            try:
                qid = r.get("qid") if r["status"] == threatlog.QUARANTINED else ""
                if not qid:  # файл на месте: через карантин (хэш в базу и запись удаления)
                    if not threatlog.exists(r["path"]):
                        raise OSError("файла уже нет")
                    qid = quarantine_file(Path(r["path"]), f"Удалён из журнала защиты: {r['text']}")
                delete_file(qid)
                if not r["id"].startswith("q:"):
                    threatlog.set_status(r["id"], threatlog.DELETED, qid)
                ok += 1
            except (ValueError, OSError) as e:
                failed.append(f"{os.path.basename(r.get('path') or '')}: {e}")
        self._done("Удаление", ok, failed)

    def dismiss_selected(self) -> None:
        records = self._selected()
        skipped = 0
        for r in records:
            if r["status"] == threatlog.QUARANTINED:
                skipped += 1  # файл в карантине: восстановить или удалить
                continue
            threatlog.dismiss(r["id"])
        self.refresh()
        if skipped:
            QMessageBox.information(self, "Журнал защиты",
                                    f"Файлы в карантине ({skipped}) из списка не убираются: "
                                    "восстановите или удалите их.")
