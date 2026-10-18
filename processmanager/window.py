import os
import threading
from pathlib import Path

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QDialog, QHeaderView, QLabel,
    QLineEdit, QMainWindow, QMenu, QMessageBox, QPushButton, QTextEdit,
    QTreeWidget, QTreeWidgetItem, QVBoxLayout,
)

from processmanager.memscan import MemResult, get_rules, scan_process
from processmanager.system import (
    ProcInfo, enable_debug_privilege, is_admin, open_in_explorer,
    process_details, relaunch_as_admin, run_action, take_snapshot,
)
from scanner.engine import check_file
from scanner.hashing import load_all_signatures
from scanner.signature import describe, inspect_signature
from scanner.whitelist import load_whitelist

SIG_DIR = Path(__file__).resolve().parent.parent / "signatures"
COLUMNS = ["Процесс", "PID", "CPU, %", "Память, МБ", "Пользователь",
           "Подпись", "Память (YARA)", "Путь"]
KEY_ROLE = Qt.ItemDataRole.UserRole + 1
SORT_ROLE = Qt.ItemDataRole.UserRole + 2


class Bridge(QObject):
    """Передаёт события из фоновых потоков в главный поток."""
    snapshot = Signal(object)
    mem_result = Signal(str, object)
    mem_progress = Signal(str)
    mem_done = Signal(bool)
    task_done = Signal(str, str)


class ProcItem(QTreeWidgetItem):
    """Строка дерева с числовой сортировкой."""
    def __lt__(self, other):
        tree = self.treeWidget()
        col = tree.sortColumn() if tree else 0
        a, b = self.data(col, SORT_ROLE), other.data(col, SORT_ROLE)
        if a is not None and b is not None:
            return a < b
        return self.text(col).lower() < other.text(col).lower()


class TextDialog(QDialog):
    def __init__(self, title: str, text: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(780, 540)
        layout = QVBoxLayout(self)
        edit = QTextEdit()
        edit.setReadOnly(True)
        edit.setFontFamily("Consolas")
        edit.setPlainText(text)
        layout.addWidget(edit)


class ProcessWindow(QMainWindow):
    def __init__(self):
        super().__init__()  # без родителя: отдельное окно
        self.setWindowTitle("Диспетчер процессов")
        self.resize(1280, 680)

        self.bridge = Bridge()
        self.bridge.snapshot.connect(self.on_snapshot)
        self.bridge.mem_result.connect(self.on_mem_result)
        self.bridge.mem_progress.connect(lambda t: self.statusBar().showMessage(t))
        self.bridge.mem_done.connect(self.on_mem_done)
        self.bridge.task_done.connect(self.on_task_done)

        self.items: dict[str, ProcItem] = {}
        self.procs: dict[str, ProcInfo] = {}
        self.mem_results: dict[str, MemResult] = {}
        self._scan_matches: list[str] = []
        self._sig_cache: dict[str, str] = {}
        self._stop_snapshots = threading.Event()
        self._snap_thread: threading.Thread | None = None
        self._scan_cancel = threading.Event()
        self._scan_thread: threading.Thread | None = None

        self.admin = is_admin()
        self.debug_priv = enable_debug_privilege() if self.admin else False

        self._build_ui()

    # ---------- интерфейс ----------
    def _build_ui(self):
        toolbar = self.addToolBar("Действия")
        toolbar.setMovable(False)
        self.menu_actions: list[QAction | None] = []
        definitions = [
            ("Завершить", lambda: self.do_action("terminate")),
            ("Приостановить", lambda: self.do_action("suspend")),
            ("Возобновить", lambda: self.do_action("resume")),
            ("Папка файла", self.open_folder),
            ("Свойства", self.show_properties),
            None,
            ("Проверить файл", self.check_selected_file),
            ("Сканировать память", self.scan_selected_memory),
            ("Сканировать все процессы", self.scan_all_memory),
            ("Остановить скан", self.cancel_scan),
        ]
        for d in definitions:
            if d is None:
                toolbar.addSeparator()
                self.menu_actions.append(None)
                continue
            text, handler = d
            action = QAction(text, self)
            action.triggered.connect(lambda checked=False, h=handler: h())
            toolbar.addAction(action)
            self.menu_actions.append(action)

        self.community_cb = QCheckBox("Все правила (медленнее)")
        self.community_cb.setToolTip("Кроме правил для памяти использовать и правила для файлов")
        toolbar.addWidget(self.community_cb)

        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Фильтр: имя, PID, путь...")
        self.filter_edit.setMaximumWidth(240)
        self.filter_edit.textChanged.connect(lambda _: self._apply_filter())
        toolbar.addWidget(self.filter_edit)

        if not self.admin:
            btn = QPushButton("Запустить от администратора")
            btn.clicked.connect(self.relaunch)
            toolbar.addWidget(btn)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(COLUMNS)
        self.tree.setUniformRowHeights(True)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        header = self.tree.header()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        for i, width in enumerate((260, 70, 70, 100, 170, 260, 200, 400)):
            self.tree.setColumnWidth(i, width)
        self.tree.setSortingEnabled(True)
        self.tree.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._show_menu)
        self.setCentralWidget(self.tree)

        if self.admin:
            state = "включена" if self.debug_priv else "не удалось включить"
            text = f"Администратор, SeDebugPrivilege: {state}"
        else:
            text = "Без прав администратора: часть процессов недоступна"
        self.statusBar().addPermanentWidget(QLabel(text))

    def _show_menu(self, pos):
        menu = QMenu(self)
        for action in self.menu_actions:
            menu.addSeparator() if action is None else menu.addAction(action)
        menu.exec(self.tree.viewport().mapToGlobal(pos))

    # ---------- поток обновления списка ----------
    def _snapshot_loop(self):
        while not self._stop_snapshots.is_set():
            try:
                procs = take_snapshot()
                budget = 6  # подписи считаем постепенно, не больше 6 новых за цикл
                for p in procs:
                    if not p.exe:
                        continue
                    if p.exe not in self._sig_cache and budget > 0:
                        budget -= 1
                        try:
                            self._sig_cache[p.exe] = describe(inspect_signature(Path(p.exe))) or "—"
                        except Exception:
                            self._sig_cache[p.exe] = "—"
                    p.sig = self._sig_cache.get(p.exe, "")
                self.bridge.snapshot.emit(procs)
            except Exception:
                pass
            self._stop_snapshots.wait(2.0)

    def _start_snapshots(self):
        self._stop_snapshots.clear()
        if self._snap_thread is None or not self._snap_thread.is_alive():
            self._snap_thread = threading.Thread(target=self._snapshot_loop, daemon=True)
            self._snap_thread.start()

    def showEvent(self, event):
        super().showEvent(event)
        self._start_snapshots()

    def closeEvent(self, event):
        self._stop_snapshots.set()
        self._scan_cancel.set()
        event.accept()

    def shutdown(self):
        """Вызывается при закрытии главного окна."""
        self._stop_snapshots.set()
        self._scan_cancel.set()

    # ---------- обновление дерева ----------
    def on_snapshot(self, procs: list[ProcInfo]):
        self.tree.setSortingEnabled(False)  # без перестановок во время обновления
        try:
            current = {p.key: p for p in procs}
            self.procs = current

            for key in [k for k in self.items if k not in current]:
                self._remove_item(key)

            by_pid = {p.pid: p.key for p in procs}
            new_keys = [k for k in current if k not in self.items]
            for key in new_keys:
                item = ProcItem()
                item.setData(0, KEY_ROLE, key)
                self.items[key] = item
            for key in new_keys:
                p, item = current[key], self.items[key]
                parent_key = by_pid.get(p.ppid)
                parent = None
                # родитель должен быть старше потомка: исключает циклы и повторное использование PID
                if parent_key and parent_key != key and current[parent_key].created < p.created:
                    parent = self.items.get(parent_key)
                if parent is not None:
                    parent.addChild(item)
                else:
                    self.tree.addTopLevelItem(item)
            for key in new_keys:
                item = self.items[key]
                if item.childCount():
                    item.setExpanded(True)

            for key, p in current.items():
                self._fill(self.items[key], p)
            self._apply_filter()
        finally:
            self.tree.setSortingEnabled(True)

    def _remove_item(self, key: str):
        item = self.items.pop(key)
        self.mem_results.pop(key, None)
        for i in reversed(range(item.childCount())):
            self.tree.addTopLevelItem(item.takeChild(i))  # потомки поднимаются на верхний уровень
        parent = item.parent()
        if parent is not None:
            parent.removeChild(item)
        else:
            index = self.tree.indexOfTopLevelItem(item)
            if index >= 0:
                self.tree.takeTopLevelItem(index)

    def _fill(self, item: ProcItem, p: ProcInfo):
        res = self.mem_results.get(p.key)
        values = [p.name, str(p.pid), f"{p.cpu:.1f}", f"{p.rss / 1048576:.1f}",
                  p.user, p.sig, res.text() if res else "", p.exe]
        for col, text in enumerate(values):
            if item.text(col) != text:
                item.setText(col, text)
        item.setData(1, SORT_ROLE, p.pid)
        item.setData(2, SORT_ROLE, p.cpu)
        item.setData(3, SORT_ROLE, p.rss)
        for col in (4, 5, 6, 7):
            item.setToolTip(col, values[col])

        color = None
        if res and res.status == "match":
            color = Qt.GlobalColor.red
        elif "Недействительна" in p.sig:
            color = Qt.GlobalColor.darkYellow
        for col in range(len(COLUMNS)):
            item.setData(col, Qt.ItemDataRole.ForegroundRole, color)

    def _apply_filter(self):
        text = self.filter_edit.text().strip().lower()
        if not text:
            for item in self.items.values():
                item.setHidden(False)
            return
        visible = set()
        for item in self.items.values():
            haystack = " ".join(item.text(c) for c in range(len(COLUMNS))).lower()
            if text in haystack:
                node = item
                while node is not None:  # родители совпавших строк остаются видимыми
                    visible.add(node.data(0, KEY_ROLE))
                    node = node.parent()
        for key, item in self.items.items():
            item.setHidden(key not in visible)

    # ---------- действия над процессом ----------
    def _selected(self) -> ProcInfo | None:
        selected = self.tree.selectedItems()
        if not selected:
            QMessageBox.information(self, "Диспетчер процессов", "Сначала выберите процесс")
            return None
        return self.procs.get(selected[0].data(0, KEY_ROLE))

    def do_action(self, action: str):
        p = self._selected()
        if not p:
            return
        if action == "terminate":
            answer = QMessageBox.question(
                self, "Завершить процесс",
                f"Завершить {p.name} (PID {p.pid})?\n\n{p.exe or 'путь неизвестен'}\n\n"
                "Несохранённые данные программы будут потеряны.")
            if answer != QMessageBox.StandardButton.Yes:
                return
        self.statusBar().showMessage(run_action(action, p.pid, p.created), 8000)

    def open_folder(self):
        p = self._selected()
        if not p:
            return
        if p.exe and Path(p.exe).exists():
            open_in_explorer(p.exe)
        else:
            self.statusBar().showMessage("Путь к файлу недоступен", 5000)

    def show_properties(self):
        p = self._selected()
        if not p:
            return
        self.statusBar().showMessage("Собираю сведения...")
        title = f"Свойства: {p.name} ({p.pid})"
        threading.Thread(
            target=lambda: self.bridge.task_done.emit(title, process_details(p.pid, p.created)),
            daemon=True).start()

    def check_selected_file(self):
        p = self._selected()
        if not p:
            return
        if not p.exe:
            QMessageBox.information(self, "Проверка файла", "Путь к файлу процесса недоступен")
            return
        self.statusBar().showMessage("Проверяю файл (при первом запуске компилируются правила)...")

        def job():
            try:
                reason = check_file(Path(p.exe), load_all_signatures(SIG_DIR),
                                    get_rules("all"), set(load_whitelist()))
                text = f"Файл: {p.exe}\n\nРезультат: {reason or 'угроз не найдено'}"
            except OSError as e:
                text = f"Не удалось прочитать файл: {e}"
            self.bridge.task_done.emit(f"Проверка файла: {p.name}", text)

        threading.Thread(target=job, daemon=True).start()

    def on_task_done(self, title: str, text: str):
        self.statusBar().clearMessage()
        TextDialog(title, text, self).exec()

    def relaunch(self):
        if relaunch_as_admin():
            QApplication.quit()
        else:
            QMessageBox.warning(self, "Права администратора",
                                "Не удалось перезапустить (запрос UAC отклонён?)")

    # ---------- сканирование памяти ----------
    def scan_selected_memory(self):
        p = self._selected()
        if p:
            self._start_mem_scan([p])

    def scan_all_memory(self):
        procs = [p for p in self.procs.values() if p.pid not in (0, 4, os.getpid())]
        answer = QMessageBox.question(
            self, "Сканирование памяти",
            f"Проверить память {len(procs)} процессов? Это может занять несколько минут. "
            "Остановить можно кнопкой «Остановить скан».")
        if answer == QMessageBox.StandardButton.Yes:
            self._start_mem_scan(procs)

    def cancel_scan(self):
        self._scan_cancel.set()
        self.statusBar().showMessage("Останавливаю после текущего процесса...")

    def _start_mem_scan(self, procs: list[ProcInfo]):
        if self._scan_thread is not None and self._scan_thread.is_alive():
            QMessageBox.information(self, "Сканирование памяти", "Сканирование уже идёт")
            return
        self._scan_cancel.clear()
        self._scan_matches = []
        kind = "all" if self.community_cb.isChecked() else "memory"
        self._scan_thread = threading.Thread(
            target=self._mem_scan_loop, args=(list(procs), kind), daemon=True)
        self._scan_thread.start()

    def _mem_scan_loop(self, procs: list[ProcInfo], kind: str):
        self.bridge.mem_progress.emit("Загружаю правила...")
        try:
            rules = get_rules(kind)
        except Exception as e:
            self.bridge.task_done.emit("Сканирование памяти", f"Не удалось загрузить правила: {e}")
            self.bridge.mem_done.emit(True)
            return
        if rules is None:
            self.bridge.task_done.emit(
                "Сканирование памяти",
                "Нет ни одного рабочего правила. Проверьте signatures/rules/memory/")
            self.bridge.mem_done.emit(True)
            return
        cancelled = False
        for i, p in enumerate(procs, 1):
            if self._scan_cancel.is_set():
                cancelled = True
                break
            self.bridge.mem_progress.emit(f"Память: {i}/{len(procs)}  {p.name} (PID {p.pid})")
            self.bridge.mem_result.emit(p.key, scan_process(rules, p.pid))
        self.bridge.mem_done.emit(cancelled)

    def on_mem_result(self, key: str, res: MemResult):
        self.mem_results[key] = res
        p, item = self.procs.get(key), self.items.get(key)
        if p and item:
            self._fill(item, p)
            if res.status == "match":
                self._scan_matches.append(f"{p.name} (PID {p.pid}): {', '.join(res.matches)}")

    def on_mem_done(self, cancelled: bool):
        prefix = "Остановлено. " if cancelled else "Готово. "
        self.statusBar().showMessage(f"{prefix}Совпадений в памяти: {len(self._scan_matches)}")
        if self._scan_matches:
            QMessageBox.warning(
                self, "Сканирование памяти",
                "Найдены совпадения:\n\n" + "\n".join(self._scan_matches[:15]))