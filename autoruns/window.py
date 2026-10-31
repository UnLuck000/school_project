import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

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

SIG_DIR = Path(__file__).resolve().parent.parent / "signatures"
COLUMNS = ["Риск", "Тип", "Имя", "Команда", "Подпись", "Место", "Замечания"]
KEY_ROLE = Qt.ItemDataRole.UserRole + 1
RANK_ROLE = Qt.ItemDataRole.UserRole + 2
LEVEL_COLORS = {"threat": (255, 128, 128), "suspicious": (255, 190, 110),
                "check": (255, 255, 170)}
ASSESS_WORKERS = 4
FLAG_DONE = "обработано программой"
FLAG_QUARANTINED = "файл в карантине"
REMOVE_ROW_KINDS = {"run", "startup", "service"}  # после исправления записи нет в списке

TAB_ALL, TAB_REGISTRY, TAB_STARTUP, TAB_TASKS, TAB_JOURNAL = range(5)
# какие записи показывает каждая вкладка
VIEWS = [
    ("all", lambda e: True),
    ("run", lambda e: e.kind == "run" and not e.location.endswith("RunOnce")),
    ("runonce", lambda e: e.kind == "run" and e.location.endswith("RunOnce")),
    ("winlogon", lambda e: e.kind == "winlogon"),
    ("startup", lambda e: e.kind == "startup"),
    ("tasks", lambda e: e.kind == "task"),
]


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


def fill_item(item: RankItem, e: Entry) -> None:
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


class EntryView(QWidget):
    """Одна вкладка со списком: показывает записи, подходящие под условие accepts."""
    selection_changed = Signal()
    context_requested = Signal(object, object)  # вкладка, позиция

    def __init__(self, accepts, hide_normal: bool = False):
        super().__init__()
        self.accepts = accepts
        self.hide_normal = hide_normal
        self.items: dict[str, RankItem] = {}
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.tree = _make_tree(COLUMNS, [110, 150, 230, 380, 220, 220, 300])
        self.tree.setSortingEnabled(True)
        self.tree.sortByColumn(0, Qt.SortOrder.DescendingOrder)  # сначала самые опасные
        self.tree.itemSelectionChanged.connect(self.selection_changed.emit)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(
            lambda pos: self.context_requested.emit(self, pos))
        layout.addWidget(self.tree)

    def begin_bulk(self) -> None:
        self.tree.setSortingEnabled(False)

    def end_bulk(self) -> None:
        self.tree.setSortingEnabled(True)

    def clear(self) -> None:
        self.tree.clear()
        self.items = {}

    def add(self, e: Entry) -> None:
        if not self.accepts(e):
            return
        item = RankItem()
        item.setData(0, KEY_ROLE, e.key)
        fill_item(item, e)  # сначала заполняем, потом вставляем: сортировка видит итоговые данные
        self.items[e.key] = item
        self.tree.addTopLevelItem(item)
        item.setHidden(self.hide_normal and e.level == "normal")

    def refresh(self, e: Entry) -> None:
        item = self.items.get(e.key)
        if item is not None:
            fill_item(item, e)
            item.setHidden(self.hide_normal and e.level == "normal")

    def remove(self, key: str) -> None:
        item = self.items.pop(key, None)
        if item is not None:
            index = self.tree.indexOfTopLevelItem(item)
            if index >= 0:
                self.tree.takeTopLevelItem(index)

    def apply_hide(self, entries: dict, hide: bool) -> None:
        self.hide_normal = hide
        for key, item in self.items.items():
            item.setHidden(hide and entries[key].level == "normal")

    def selected_key(self):
        items = self.tree.selectedItems()
        return items[0].data(0, KEY_ROLE) if items else None


class AutorunsWindow(QMainWindow):
    quarantine_changed = Signal()
    analyze_requested = Signal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Сканер автозапуска")
        self.resize(1350, 700)

        self.bridge = Bridge()
        self.bridge.entries.connect(self.on_entries)
        self.bridge.updated.connect(self.on_updated)
        self.bridge.progress.connect(lambda t: self.statusBar().showMessage(t))
        self.bridge.done.connect(self.on_done)

        self.entries: dict[str, Entry] = {}
        self.removed: dict[str, Entry] = {}  # удалённые из списка записи (для отката)
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

        self.views = {key: EntryView(accepts, hide_normal=(key == "all"))
                      for key, accepts in VIEWS}
        for view in self.views.values():
            view.selection_changed.connect(self._update_buttons)
            view.context_requested.connect(self._show_menu)

        root = QWidget()
        layout = QVBoxLayout(root)
        layout.addLayout(self._build_toolbar())

        self.main_tabs = QTabWidget()
        self.reg_tabs = QTabWidget()
        self.main_tabs.addTab(self.views["all"], "Всё")
        self.reg_tabs.addTab(self.views["run"], "Run")
        self.reg_tabs.addTab(self.views["runonce"], "RunOnce")
        self.reg_tabs.addTab(self.views["winlogon"], "Winlogon")
        self.main_tabs.addTab(self.reg_tabs, "Реестр")
        self.main_tabs.addTab(self.views["startup"], "Папка автозагрузки")
        self.main_tabs.addTab(self.views["tasks"], "Планировщик заданий")
        self.main_tabs.addTab(self._build_journal_tab(), "Журнал действий")
        layout.addWidget(self.main_tabs, 1)
        self.main_tabs.currentChanged.connect(lambda _: self._update_buttons())
        self.reg_tabs.currentChanged.connect(lambda _: self._update_buttons())
        self.setCentralWidget(root)

        if is_admin():
            self.statusBar().showMessage("Нажмите «Сканировать всё»")
        else:
            self.statusBar().showMessage(
                "Без прав администратора часть задач и записей недоступна для чтения и изменения")
        self.refresh_journal()
        self._update_buttons()

    # ---------- панель кнопок (видна на любой вкладке) ----------
    def _build_toolbar(self) -> QHBoxLayout:
        row = QHBoxLayout()
        self.btn_scan = QPushButton("Сканировать всё")
        self.btn_scan.setToolTip("Общее сканирование всей автозагрузки Windows: "
                                 "результаты появятся на всех вкладках")
        self.btn_scan.clicked.connect(self.scan)
        self.btn_fix = QPushButton("Отключить / удалить")
        self.btn_fix.clicked.connect(self.fix_selected)
        self.btn_quarantine = QPushButton("Карантин файла")
        self.btn_quarantine.clicked.connect(self.quarantine_selected)
        self.btn_folder = QPushButton("Папка файла")
        self.btn_folder.clicked.connect(self.open_folder)
        self.btn_analyze = QPushButton("Открыть в анализаторе")
        self.btn_analyze.clicked.connect(self.analyze_selected)
        self.hide_normal = QCheckBox("Скрывать проверенные (вкладка «Всё»)")
        self.hide_normal.setChecked(True)
        self.hide_normal.toggled.connect(
            lambda on: self.views["all"].apply_hide(self.entries, on))
        for w in (self.btn_scan, self.btn_fix, self.btn_quarantine,
                  self.btn_folder, self.btn_analyze, self.hide_normal):
            row.addWidget(w)
        row.addStretch()
        return row

    def _current_view(self) -> EntryView | None:
        index = self.main_tabs.currentIndex()
        if index == TAB_ALL:
            return self.views["all"]
        if index == TAB_REGISTRY:
            return self.views[("run", "runonce", "winlogon")[self.reg_tabs.currentIndex()]]
        if index == TAB_STARTUP:
            return self.views["startup"]
        if index == TAB_TASKS:
            return self.views["tasks"]
        return None  # вкладка журнала

    def selected_entry(self) -> Entry | None:
        view = self._current_view()
        key = view.selected_key() if view else None
        return self.entries.get(key) if key else None

    def _update_buttons(self) -> None:
        e = self.selected_entry()
        if e is None:
            allowed, reason, q_allowed, q_reason = False, "Выберите запись в списке", False, ""
            self.btn_fix.setText("Отключить / удалить")
        else:
            allowed, reason = actions.can_remediate(e)
            q_allowed, q_reason = actions.can_quarantine(e)
            self.btn_fix.setText(actions.REMEDIATION.get(e.kind, ("Исправить", ""))[0])
        has_file = e is not None and bool(e.exe) and os.path.isfile(e.exe)
        self.btn_fix.setEnabled(allowed)
        self.btn_fix.setToolTip(reason)
        self.btn_quarantine.setEnabled(q_allowed)
        self.btn_quarantine.setToolTip(q_reason)
        self.btn_folder.setEnabled(has_file)
        self.btn_analyze.setEnabled(has_file)

    def _show_menu(self, view: EntryView, pos) -> None:
        menu = QMenu(self)
        for button in (self.btn_fix, self.btn_quarantine, self.btn_folder, self.btn_analyze):
            action = menu.addAction(button.text())
            action.setEnabled(button.isEnabled())
            action.triggered.connect(lambda checked=False, b=button: b.click())
        menu.exec(view.tree.viewport().mapToGlobal(pos))

    def _update_titles(self) -> None:
        n = {key: len(view.items) for key, view in self.views.items()}
        self.main_tabs.setTabText(TAB_ALL, f"Всё ({n['all']})")
        self.main_tabs.setTabText(
            TAB_REGISTRY, f"Реестр ({n['run'] + n['runonce'] + n['winlogon']})")
        self.reg_tabs.setTabText(0, f"Run ({n['run']})")
        self.reg_tabs.setTabText(1, f"RunOnce ({n['runonce']})")
        self.reg_tabs.setTabText(2, f"Winlogon ({n['winlogon']})")
        self.main_tabs.setTabText(TAB_STARTUP, f"Папка автозагрузки ({n['startup']})")
        self.main_tabs.setTabText(TAB_TASKS, f"Планировщик заданий ({n['tasks']})")

    # ---------- сканирование (всегда общее) ----------
    def scan(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self.btn_scan.setEnabled(False)
        self.statusBar().showMessage("Собираю записи автозапуска...")
        self._thread = threading.Thread(target=self._scan_job, daemon=True)
        self._thread.start()

    def _scan_job(self) -> None:
        entries, notes = collect_all()
        self.bridge.entries.emit(entries)
        self.bridge.progress.emit(f"Найдено записей: {len(entries)}. Проверяю файлы и подписи...")
        ctx = Context(load_all_signatures(SIG_DIR), get_rules("all"), set(load_whitelist()))

        def work(e: Entry) -> None:
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

    def on_entries(self, entries: list[Entry]) -> None:
        self.entries = {e.key: e for e in entries}
        self.removed = {}
        for view in self.views.values():
            view.begin_bulk()
            view.clear()
            for e in entries:
                view.add(e)
            view.end_bulk()
        self._update_titles()
        self._update_buttons()

    def on_updated(self, key: str) -> None:
        e = self.entries.get(key)
        if e is None:
            return
        self._refresh_entry(e)
        current = self.selected_entry()
        if current is not None and current.key == key:
            self._update_buttons()

    def on_done(self, notes: list[str]) -> None:
        self.btn_scan.setEnabled(True)
        counts = {level: sum(1 for e in self.entries.values() if e.level == level)
                  for level in LEVELS}
        message = (f"Готово. Записей: {len(self.entries)}; угроз: {counts['threat']}, "
                   f"подозрительных: {counts['suspicious']}, на проверку: {counts['check']}")
        if notes:
            message += ". " + "; ".join(notes)
        self.statusBar().showMessage(message)

    def _refresh_entry(self, e: Entry) -> None:
        for view in self.views.values():
            view.refresh(e)

    def _add_row(self, e: Entry) -> None:
        self.entries[e.key] = e
        for view in self.views.values():
            view.add(e)
        self._update_titles()

    def _remove_row(self, key: str) -> None:
        for view in self.views.values():
            view.remove(key)
        entry = self.entries.pop(key, None)
        if entry is not None:
            self.removed[key] = entry
        self._update_titles()
        self._update_buttons()

    def _after_undo(self, record: dict) -> bool:
        """Обновляет списки после отката. False, если запись в них не найдена."""
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
            self._refresh_entry(e)
            return True
        return False

    # ---------- исправление ----------
    def fix_selected(self) -> None:
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
            self._remove_row(e.key)  # запись исчезает из всех списков сразу
        else:
            e.enabled = False        # задача остаётся в списке как отключённая
            self._refresh_entry(e)
        self.statusBar().showMessage(message, 10000)
        self.refresh_journal()
        self._update_buttons()

    def quarantine_selected(self) -> None:
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
        self._refresh_entry(e)
        self.statusBar().showMessage(message, 10000)
        self.refresh_journal()
        self.quarantine_changed.emit()

    def open_folder(self) -> None:
        e = self.selected_entry()
        if e is not None and e.exe and os.path.exists(e.exe):
            open_in_explorer(e.exe)

    def analyze_selected(self) -> None:
        e = self.selected_entry()
        if e is not None and e.exe and os.path.isfile(e.exe):
            self.analyze_requested.emit(e.exe)

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

    def refresh_journal(self) -> None:
        self.journal_tree.clear()
        for record in reversed(journal.read_all()):
            status = f"Отменено {record['undone_at']}" if record["undone"] else "Выполнено"
            item = QTreeWidgetItem([record["time"].replace("T", " "), record["title"], status])
            item.setData(0, KEY_ROLE, record["id"])
            if record["undone"]:
                for col in range(3):
                    item.setForeground(col, QBrush(QColor("gray")))
            self.journal_tree.addTopLevelItem(item)

    def show_journal(self) -> None:
        self.main_tabs.setCurrentIndex(TAB_JOURNAL)
        self.refresh_journal()

    def undo_selected(self) -> None:
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
            message += " Нажмите «Сканировать всё», чтобы обновить списки."
        self.statusBar().showMessage(message, 10000)
        self.refresh_journal()
        self.quarantine_changed.emit()

    def shutdown(self) -> None:
        """Вызывается при закрытии главного окна."""
        self._stop.set()

    def closeEvent(self, event) -> None:
        self._stop.set()
        event.accept()