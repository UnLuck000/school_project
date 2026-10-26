import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QHBoxLayout, QHeaderView, QLabel, QMainWindow, QMenu,
    QMessageBox, QPushButton, QTabWidget, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from autoruns import actions
from autoruns.model import KIND_TITLES, LEVEL_TEXT, LEVELS, Entry
from autoruns.scanner import Context, assess, collect_all
from processmanager.colors import text_color
from processmanager.memscan import get_rules
from processmanager.system import is_admin, open_in_explorer
from recovery import journal
from scanner.hashing import load_all_signatures
from scanner.whitelist import load_whitelist

from pathlib import Path

SIG_DIR = Path(__file__).resolve().parent.parent / "signatures"
COLUMNS = ["Риск", "Тип", "Имя", "Команда", "Подпись", "Место", "Замечания"]
KEY_ROLE = Qt.ItemDataRole.UserRole + 1
RANK_ROLE = Qt.ItemDataRole.UserRole + 2
LEVEL_COLORS = {"threat": (255, 128, 128), "suspicious": (255, 190, 110),
                "check": (255, 255, 170)}
ASSESS_WORKERS = 4

FLAG_DONE = "обработано программой"
FLAG_QUARANTINED = "файл в карантине"
REMOVE_ROW_KINDS = {"run", "startup", "service"}


class Bridge(QObject):
    entries = Signal(object)
    updated = Signal(str)
    progress = Signal(str)
    done = Signal(object)


class RankItem(QTreeWidgetItem):
    """Строка с сортировкой по числовому рангу (риск)."""
    def __lt__(self, other):
        tree = self.treeWidget()
        col = tree.sortColumn() if tree else 0
        a, b = self.data(col, RANK_ROLE), other.data(col, RANK_ROLE)
        if a is not None and b is not None:
            return a < b
        return self.text(col).lower() < other.text(col).lower()


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


class AutorunsWindow(QMainWindow):
    quarantine_changed = Signal()
    analyze_requested = Signal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Сканер автозапуска")
        self.resize(1350, 680)

        self.bridge = Bridge()
        self.bridge.entries.connect(self.on_entries)
        self.bridge.updated.connect(self.on_updated)
        self.bridge.progress.connect(lambda t: self.statusBar().showMessage(t))
        self.bridge.done.connect(self.on_done)

        self.entries: dict[str, Entry] = {}
        self.items: dict[str, RankItem] = {}
        self.removed: dict[str, Entry] = {}  # удалённые из списка записи (для отката)
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_entries_tab(), "Автозапуск")
        self.tabs.addTab(self._build_journal_tab(), "Журнал действий")
        self.setCentralWidget(self.tabs)

        if is_admin():
            self.statusBar().showMessage("Нажмите «Сканировать»")
        else:
            self.statusBar().showMessage(
                "Без прав администратора часть задач и записей недоступна для чтения и изменения")
        self.refresh_journal()

    # ---------- вкладка «Автозапуск» ----------
    def _build_entries_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        row = QHBoxLayout()
        self.btn_scan = QPushButton("Сканировать")
        self.btn_scan.clicked.connect(self.scan)
        self.btn_fix = QPushButton("Отключить / удалить")
        self.btn_fix.clicked.connect(self.fix_selected)
        self.btn_quarantine = QPushButton("Карантин файла")
        self.btn_quarantine.clicked.connect(self.quarantine_selected)
        self.btn_folder = QPushButton("Папка файла")
        self.btn_folder.clicked.connect(self.open_folder)
        self.btn_analyze = QPushButton("Открыть в анализаторе")
        self.btn_analyze.clicked.connect(self.analyze_selected)
        self.hide_normal = QCheckBox("Скрывать проверенные (норма)")
        self.hide_normal.setChecked(True)
        self.hide_normal.toggled.connect(lambda _: self._apply_hide())
        for w in (self.btn_scan, self.btn_fix, self.btn_quarantine, self.btn_folder, self.btn_analyze):
            row.addWidget(w)
        row.addWidget(self.hide_normal)
        row.addStretch()
        layout.addLayout(row)

        self.tree = _make_tree(COLUMNS, [110, 150, 230, 380, 220, 220, 300])
        self.tree.setSortingEnabled(True)
        self.tree.sortByColumn(0, Qt.SortOrder.DescendingOrder)  # сначала самые опасные
        self.tree.itemSelectionChanged.connect(self._update_buttons)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._show_menu)
        layout.addWidget(self.tree)
        self._update_buttons()
        return tab

    def selected_entry(self) -> Entry | None:
        selected = self.tree.selectedItems()
        return self.entries.get(selected[0].data(0, KEY_ROLE)) if selected else None

    def _update_buttons(self):
        e = self.selected_entry()
        if e is None:
            allowed, reason, q_allowed, q_reason = False, "Выберите запись", False, ""
            self.btn_fix.setText("Отключить / удалить")
        else:
            allowed, reason = actions.can_remediate(e)
            q_allowed, q_reason = actions.can_quarantine(e)
            self.btn_fix.setText(actions.REMEDIATION.get(e.kind, ("Исправить", ""))[0])
        self.btn_fix.setEnabled(allowed)
        self.btn_fix.setToolTip(reason)
        self.btn_quarantine.setEnabled(q_allowed)
        self.btn_quarantine.setToolTip(q_reason)
        self.btn_analyze.setEnabled(e is not None and bool(e.exe) and os.path.isfile(e.exe))
        self.btn_folder.setEnabled(e is not None and bool(e.exe) and os.path.exists(e.exe))

    def _show_menu(self, pos):
        menu = QMenu(self)
        for button in (self.btn_fix, self.btn_quarantine, self.btn_folder, self.btn_analyze):
            action = menu.addAction(button.text())
            action.setEnabled(button.isEnabled())
            action.triggered.connect(lambda checked=False, b=button: b.click())
        menu.exec(self.tree.viewport().mapToGlobal(pos))

    # ---------- сканирование ----------
    def scan(self):
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self.btn_scan.setEnabled(False)
        self.statusBar().showMessage("Собираю записи автозапуска...")
        self._thread = threading.Thread(target=self._scan_job, daemon=True)
        self._thread.start()

    def analyze_selected(self):
        e = self.selected_entry()
        if e is not None and e.exe and os.path.isfile(e.exe):
            self.analyze_requested.emit(e.exe)

    def _scan_job(self):
        entries, notes = collect_all()
        self.bridge.entries.emit(entries)
        self.bridge.progress.emit(f"Найдено записей: {len(entries)}. Проверяю файлы и подписи...")
        ctx = Context(load_all_signatures(SIG_DIR), get_rules("all"), set(load_whitelist()))

        def work(e: Entry):
            if self._stop.is_set():
                return
            try:
                assess(e, ctx)
            except Exception as exc:  # одна проблемная запись не должна остановить проверку
                e.level = "check"
                e.assessed = True
                e.flags.append(f"ошибка проверки: {exc}")

        with ThreadPoolExecutor(max_workers=ASSESS_WORKERS) as pool:
            futures = {pool.submit(work, e): e for e in entries}
            for done, future in enumerate(as_completed(futures), 1):
                future.result()
                self.bridge.updated.emit(futures[future].key)
                if done % 20 == 0:
                    self.bridge.progress.emit(f"Проверено записей: {done}/{len(entries)}")
        self.bridge.done.emit(notes)

    def on_entries(self, entries: list[Entry]):
        self.tree.setSortingEnabled(False)
        self.tree.clear()
        self.entries, self.items = {}, {}
        for e in entries:
            item = RankItem()
            item.setData(0, KEY_ROLE, e.key)
            self.entries[e.key] = e
            self.removed = {}
            self.items[e.key] = item
            self.tree.addTopLevelItem(item)
            self._fill(item, e)
        self.tree.setSortingEnabled(True)
        self._apply_hide()

    def on_updated(self, key: str):
        e, item = self.entries.get(key), self.items.get(key)
        if e and item:
            self._fill(item, e)
            item.setHidden(self.hide_normal.isChecked() and e.level == "normal")
            if item.isSelected():
                self._update_buttons()

    def _add_row(self, e: Entry):
        item = RankItem()
        item.setData(0, KEY_ROLE, e.key)
        self._fill(item, e)  # сначала заполняем, потом вставляем: сортировка видит итоговые данные
        self.entries[e.key] = e
        self.items[e.key] = item
        self.tree.addTopLevelItem(item)
        item.setHidden(self.hide_normal.isChecked() and e.level == "normal")

    def _remove_row(self, key: str):
        item = self.items.pop(key, None)
        entry = self.entries.pop(key, None)
        if item is not None:
            index = self.tree.indexOfTopLevelItem(item)
            if index >= 0:
                self.tree.takeTopLevelItem(index)
        if entry is not None:
            self.removed[key] = entry
        self._update_buttons()

    def _after_undo(self, record: dict) -> bool:
        """Обновляет список после отката. False, если запись в списке не найдена."""
        key = record["data"].get("entry_key")
        if not key:
            return True
        quarantine = record["op"] == "quarantine_restore"
        if key in self.removed:  # запись вернулась в автозапуск
            e = self.removed.pop(key)
            e.enabled = True
            if FLAG_DONE in e.flags:
                e.flags.remove(FLAG_DONE)
            self._add_row(e)
            return True
        if key in self.entries:
            e = self.entries[key]
            flag = FLAG_QUARANTINED if quarantine else FLAG_DONE
            if flag in e.flags:
                e.flags.remove(flag)
            if not quarantine:
                e.enabled = True
            self._fill(self.items[key], e)
            return True
        return False

    def on_done(self, notes: list[str]):
        self.btn_scan.setEnabled(True)
        counts = {level: sum(1 for e in self.entries.values() if e.level == level)
                  for level in LEVELS}
        message = (f"Готово. Записей: {len(self.entries)}; угроз: {counts['threat']}, "
                   f"подозрительных: {counts['suspicious']}, на проверку: {counts['check']}")
        if notes:
            message += ". " + "; ".join(notes)
        self.statusBar().showMessage(message)

    def _fill(self, item: RankItem, e: Entry):
        state = "" if e.enabled else " (отключена)"
        values = [LEVEL_TEXT[e.level], KIND_TITLES[e.kind], e.name + state, e.command,
                  e.sig or ("" if e.assessed else "…"), e.location, "; ".join(e.flags)]
        for col, text in enumerate(values):
            if item.text(col) != text:
                item.setText(col, text)
            item.setToolTip(col, text)
        item.setData(0, RANK_ROLE, LEVELS.index(e.level))
        color = LEVEL_COLORS.get(e.level)
        for col in range(len(COLUMNS)):
            if color:
                item.setBackground(col, QBrush(QColor(*color)))
                item.setForeground(col, QBrush(text_color(color)))
            else:
                item.setData(col, Qt.ItemDataRole.BackgroundRole, None)
                item.setData(col, Qt.ItemDataRole.ForegroundRole, None)

    def _apply_hide(self):
        hide = self.hide_normal.isChecked()
        for key, item in self.items.items():
            item.setHidden(hide and self.entries[key].level == "normal")

    # ---------- исправление ----------
    def fix_selected(self):
        e = self.selected_entry()
        if e is None:
            return
        allowed, reason = actions.can_remediate(e)
        if not allowed:
            QMessageBox.information(self, "Автозапуск", reason)
            return
        title, text = actions.REMEDIATION[e.kind]
        answer = QMessageBox.question(
            self, title, f"{e.name}\n{e.command}\n\n{text}\n\nВыполнить?")
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            message = actions.remediate(e)
        except OSError as exc:  # включает PermissionError и ошибки реестра
            QMessageBox.critical(
                self, title, f"Не удалось выполнить: {exc}\n\n"
                "Возможно, нужны права администратора.")
            return
        e.flags.append(FLAG_DONE)
        if e.kind in REMOVE_ROW_KINDS:
            self._remove_row(e.key)  # запись исчезает из списка сразу
        else:
            e.enabled = False        # задача остаётся в списке как отключённая
            self._fill(self.items[e.key], e)
        self.statusBar().showMessage(message, 10000)
        self.refresh_journal()
        self._update_buttons()

    def quarantine_selected(self):
        e = self.selected_entry()
        if e is None:
            return
        allowed, reason = actions.can_quarantine(e)
        if not allowed:
            QMessageBox.information(self, "Карантин файла", reason)
            return
        answer = QMessageBox.question(
            self, "Карантин файла",
            f"Переместить в карантин файл:\n{e.exe}\n\n"
            "Запись автозапуска останется, поэтому обычно сначала отключают её. "
            "Вернуть файл можно на вкладке «Журнал действий».")
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            message = actions.quarantine_target(e)
        except PermissionError:
            QMessageBox.critical(
                self, "Карантин файла",
                "Файл занят: вероятно, программа запущена. Завершите процесс "
                "(диспетчер процессов) и повторите.")
            return
        except OSError as exc:
            QMessageBox.critical(self, "Карантин файла", f"Не удалось выполнить: {exc}")
            return
        if FLAG_QUARANTINED not in e.flags:
            e.flags.append(FLAG_QUARANTINED)
        self._fill(self.items[e.key], e)
        self.statusBar().showMessage(message, 10000)
        self.refresh_journal()
        self.quarantine_changed.emit()

    def open_folder(self):
        e = self.selected_entry()
        if e is not None and e.exe and os.path.exists(e.exe):
            open_in_explorer(e.exe)

    # ---------- вкладка «Журнал действий» ----------
    def _build_journal_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(QLabel(
            "Все исправления программы. Выберите действие и нажмите «Отменить действие», "
            "чтобы вернуть прежнее состояние."))
        self.journal_tree = _make_tree(["Время", "Действие", "Статус"], [160, 800, 140])
        layout.addWidget(self.journal_tree)

        row = QHBoxLayout()
        undo_btn = QPushButton("Отменить действие")
        undo_btn.clicked.connect(self.undo_selected)
        refresh_btn = QPushButton("Обновить")
        refresh_btn.clicked.connect(self.refresh_journal)
        row.addWidget(undo_btn)
        row.addWidget(refresh_btn)
        row.addStretch()
        layout.addLayout(row)
        return tab

    def refresh_journal(self):
        self.journal_tree.clear()
        for record in reversed(journal.read_all()):
            status = f"Отменено {record['undone_at']}" if record["undone"] else "Выполнено"
            item = QTreeWidgetItem([record["time"].replace("T", " "), record["title"], status])
            item.setData(0, KEY_ROLE, record["id"])
            if record["undone"]:
                for col in range(3):
                    item.setForeground(col, QBrush(QColor("gray")))
            self.journal_tree.addTopLevelItem(item)

    def show_journal(self):
        self.tabs.setCurrentIndex(1)
        self.refresh_journal()

    def undo_selected(self):
        item = self.journal_tree.currentItem()
        if item is None:
            QMessageBox.information(self, "Журнал", "Сначала выберите действие в списке")
            return
        record_id = item.data(0, KEY_ROLE)
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
        if record is not None and not self._after_undo(record):
            message += " Нажмите «Сканировать», чтобы обновить список записей."
        self.statusBar().showMessage(message, 10000)
        self.refresh_journal()
        self.quarantine_changed.emit()

    def shutdown(self):
        """Вызывается при закрытии главного окна."""
        self._stop.set()

    def closeEvent(self, event):
        self._stop.set()
        event.accept()