import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QAction, QBrush, QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog, QDockWidget,
    QHeaderView, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMenu,
    QMessageBox, QPushButton, QTextEdit, QTreeWidget, QTreeWidgetItem, QVBoxLayout,
)

from processmanager.colors import BY_ID, CATEGORIES, classify, text_color
from processmanager.memscan import MemResult, get_rules, scan_process
from processmanager.origin import FILTERS, HELP, ORIGINS
from processmanager.system import (
    ProcInfo, enable_debug_privilege, is_admin, open_in_explorer,
    process_details, relaunch_as_admin, run_action, take_snapshot,
)
from scanner.engine import check_file
from scanner.hashing import load_all_signatures
from scanner.heuristics import analyze_pe
from scanner.signature import describe, inspect_signature
from scanner.whitelist import load_whitelist
from ui import settings as cfg

SIG_DIR = Path(__file__).resolve().parent.parent / "signatures"
COLUMNS = ["Процесс", "PID", "CPU, %", "Память, МБ", "Пользователь", "Запуск",
           "Подпись", "Память (YARA)", "Путь"]
DESC_FIRST = {2, 3}  # числовые колонки при первом клике сортируются по убыванию
KEY_ROLE = Qt.ItemDataRole.UserRole + 1
SORT_ROLE = Qt.ItemDataRole.UserRole + 2
LOCKED_TIP = "Системный процесс: изменение запрещено"
ASC = Qt.SortOrder.AscendingOrder
DESC = Qt.SortOrder.DescendingOrder


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
        self._scan_workers = 4
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
        self.resize(1500, 700)
        self.bridge = Bridge()
        self.bridge.snapshot.connect(self.on_snapshot)
        self.bridge.mem_result.connect(self.on_mem_result)
        self.bridge.mem_progress.connect(lambda t: self.statusBar().showMessage(t))
        self.bridge.mem_done.connect(self.on_mem_done)
        self.bridge.task_done.connect(self.on_task_done)

        self.items: dict[str, ProcItem] = {}
        self.procs: dict[str, ProcInfo] = {}
        self.mem_results: dict[str, MemResult] = {}
        self._flat = False                  # плоский список (сортировка или фильтр запуска)
        self._sort: tuple[int, Qt.SortOrder] | None = None  # None = дерево
        self._scan_matches: list[str] = []
        self._scan_started = 0.0
        self._sig_cache: dict[str, tuple[str, str]] = {}
        self._pe_cache: dict[str, tuple[bool, bool]] = {}
        self._stop_snapshots = threading.Event()
        self._snap_thread: threading.Thread | None = None
        self._scan_cancel = threading.Event()
        self._scan_thread: threading.Thread | None = None
        self._scan_workers = 4

        self.admin = is_admin()
        self.debug_priv = enable_debug_privilege() if self.admin else False

        self._build_ui()

    # ---------- интерфейс ----------
    def _build_ui(self):
        toolbar = self.addToolBar("Действия")
        toolbar.setMovable(False)
        self.menu_actions: list[QAction | None] = []
        self.actions: dict[str, QAction] = {}
        definitions = [
            ("terminate", "Завершить", lambda: self.do_action("terminate")),
            ("suspend", "Приостановить", lambda: self.do_action("suspend")),
            ("resume", "Возобновить", lambda: self.do_action("resume")),
            ("folder", "Папка файла", self.open_folder),
            ("props", "Свойства", self.show_properties),
            None,
            ("check", "Проверить файл", self.check_selected_file),
            ("scan", "Сканировать память", self.scan_selected_memory),
            ("scan_all", "Сканировать все процессы", self.scan_all_memory),
            ("cancel", "Остановить скан", self.cancel_scan),
        ]
        for d in definitions:
            if d is None:
                toolbar.addSeparator()
                self.menu_actions.append(None)
                continue
            action_id, text, handler = d
            action = QAction(text, self)
            action.triggered.connect(lambda checked=False, h=handler: h())
            toolbar.addAction(action)
            self.menu_actions.append(action)
            self.actions[action_id] = action

        self.community_cb = QCheckBox("Все правила (медленнее)")
        self.community_cb.setToolTip("Кроме правил для памяти использовать и правила для файлов")
        toolbar.addWidget(self.community_cb)

        self.origin_combo = QComboBox()
        for title, _ in FILTERS:
            self.origin_combo.addItem(title)
        self.origin_combo.setToolTip(
            "Показать процессы по способу запуска (список становится плоским)")
        self.origin_combo.currentIndexChanged.connect(lambda _: self._on_origin_filter())
        toolbar.addWidget(self.origin_combo)

        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Фильтр: имя, PID, путь...")
        self.filter_edit.setMaximumWidth(200)
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
        self.tree.setSortingEnabled(False)  # сортировкой управляем сами (дерево / плоский список)
        header = self.tree.header()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        header.setSectionsClickable(True)
        header.setSortIndicatorShown(False)
        header.sectionClicked.connect(self._on_header_clicked)
        for i, width in enumerate((260, 70, 70, 100, 170, 210, 260, 200, 400)):
            self.tree.setColumnWidth(i, width)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._show_menu)
        self.tree.itemSelectionChanged.connect(lambda: self._update_actions(announce=True))
        self.setCentralWidget(self.tree)

        self._build_legend(toolbar)
        self._update_actions()

        if self.admin:
            state = "включена" if self.debug_priv else "не удалось включить"
            text = f"Администратор, SeDebugPrivilege: {state}"
        else:
            text = "Без прав администратора: часть процессов недоступна"
        self.statusBar().addPermanentWidget(QLabel(text))

    def _build_legend(self, toolbar):
        """Панель справа: цвета, способы запуска, защита."""
        dock = QDockWidget("Легенда цветов", self)
        dock.setMinimumWidth(340)
        legend = QListWidget()
        legend.setWordWrap(True)
        legend.setSpacing(2)
        legend.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        legend.addItem(QListWidgetItem(
            "ЦВЕТА. Цвет получает первое совпадение сверху вниз."))
        for category in CATEGORIES:
            item = QListWidgetItem(f"{category.title}\n{category.description}")
            item.setBackground(QBrush(QColor(*category.rgb)))
            item.setForeground(QBrush(text_color(category.rgb)))
            legend.addItem(item)
        legend.addItem(QListWidgetItem(
            "ЗАПУСК (колонка «Запуск»). Windows не хранит, как запущен процесс, поэтому "
            "способ определяется по признакам; «вероятно» означает догадку."))
        for origin_id, description in HELP:
            legend.addItem(QListWidgetItem(f"{ORIGINS[origin_id]}\n{description}"))
        legend.addItem(QListWidgetItem(
            "ЗАЩИТА. Для защищённых процессов (System, System Idle Process, их потомки, "
            "ядро и ключевые процессы Windows, компоненты Windows от системных учётных "
            "записей, критические процессы) кнопки «Завершить», «Приостановить» и "
            "«Возобновить» отключены. Причина указана в подсказке над именем процесса."))
        dock.setWidget(legend)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, dock)
        toolbar.addSeparator()
        toolbar.addAction(dock.toggleViewAction())  # кнопка показа и скрытия легенды

    def _show_menu(self, pos):
        menu = QMenu(self)
        for action in self.menu_actions:
            menu.addSeparator() if action is None else menu.addAction(action)
        menu.exec(self.tree.viewport().mapToGlobal(pos))

    def _current(self) -> ProcInfo | None:
        selected = self.tree.selectedItems()
        return self.procs.get(selected[0].data(0, KEY_ROLE)) if selected else None

    def _update_actions(self, announce: bool = False):
        """Кнопки, меняющие процесс, неактивны для защищённых процессов."""
        p = self._current()
        locked = p is not None and p.protected
        reason = (p.protect_reason or "критический процесс Windows") if locked else ""
        for action_id, normal_tip in (("terminate", "Завершить процесс"),
                                      ("suspend", "Приостановить процесс"),
                                      ("resume", "Возобновить процесс")):
            action = self.actions[action_id]
            action.setEnabled(p is not None and not locked)
            action.setToolTip(f"{LOCKED_TIP} ({reason})" if locked else normal_tip)
        if locked and announce:
            self.statusBar().showMessage(
                f"{p.name}: защищён ({reason}). Завершение, приостановка и "
                "возобновление отключены", 8000)

    # ---------- сортировка и режим списка ----------
    def _on_header_clicked(self, col: int):
        """Первый клик: сортировка, второй: обратный порядок, третий: снова дерево."""
        first = DESC if col in DESC_FIRST else ASC
        second = ASC if first == DESC else DESC
        if self._sort is None or self._sort[0] != col:
            self._sort = (col, first)
        elif self._sort[1] == first:
            self._sort = (col, second)
        else:
            self._sort = None
        self._update_layout()
        if self._sort is None:
            self.statusBar().showMessage("Сортировка выключена: показано дерево процессов", 5000)
        else:
            self.statusBar().showMessage(
                "Плоский список. Повторный клик меняет направление, третий возвращает дерево",
                7000)

    def _on_origin_filter(self):
        self._update_layout()
        self._apply_filter()

    def _origin_ids(self):
        return FILTERS[self.origin_combo.currentIndex()][1]

    def _update_layout(self):
        want_flat = self._sort is not None or self._origin_ids() is not None
        self._set_flat(want_flat)
        self._resort()
        self._apply_filter()

    def _resort(self):
        col, order = self._sort if self._sort else (0, ASC)  # дерево: по имени среди соседей
        self.tree.sortItems(col, order)
        self.tree.header().setSortIndicatorShown(self._sort is not None)

    def _set_flat(self, flat: bool):
        """Переключает между деревом и плоским списком, сохраняя выделение."""
        if flat == self._flat:
            return
        selected = self._current()
        self._flat = flat
        self.tree.setUpdatesEnabled(False)
        try:
            for item in self.items.values():  # отсоединяем все строки
                parent = item.parent()
                if parent is not None:
                    parent.removeChild(item)
                else:
                    index = self.tree.indexOfTopLevelItem(item)
                    if index >= 0:
                        self.tree.takeTopLevelItem(index)
            self.tree.setRootIsDecorated(not flat)
            self._attach(list(self.items))
            if not flat:
                self.tree.expandAll()
        finally:
            self.tree.setUpdatesEnabled(True)
        if selected is not None and selected.key in self.items:
            item = self.items[selected.key]
            item.setSelected(True)
            self.tree.scrollToItem(item)

    # ---------- поток обновления списка ----------
    def _snapshot_loop(self):
        while not self._stop_snapshots.is_set():
            try:
                procs = take_snapshot()
                sig_budget, pe_budget = 6, 3  # тяжёлые проверки распределяем по циклам
                for p in procs:
                    if not p.has_file:  # у Registry, Memory Compression и т.п. файла нет
                        p.sig = "Без файла (ядро Windows)" if p.core else ""
                        continue
                    if p.exe not in self._sig_cache and sig_budget > 0:
                        sig_budget -= 1
                        try:
                            info = inspect_signature(Path(p.exe))
                            self._sig_cache[p.exe] = (describe(info) or "—", info.status)
                        except Exception:
                            self._sig_cache[p.exe] = ("—", "")
                    if p.exe not in self._pe_cache and pe_budget > 0:
                        pe_budget -= 1
                        try:
                            report = analyze_pe(Path(p.exe))
                            packed = sum(f.points for f in report.findings
                                         if f.category == "pack") >= 4
                            self._pe_cache[p.exe] = (packed, report.dotnet)
                        except Exception:
                            self._pe_cache[p.exe] = (False, False)
                    p.sig, p.sig_status = self._sig_cache.get(p.exe, ("", ""))
                    p.packed, p.dotnet = self._pe_cache.get(p.exe, (False, False))
                self.bridge.snapshot.emit(procs)
            except Exception:
                pass
            self._stop_snapshots.wait(float(cfg.get("process/interval")))

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

    # ---------- обновление списка ----------
    def on_snapshot(self, procs: list[ProcInfo]):
        current = {p.key: p for p in procs}
        self.procs = current

        for key in [k for k in self.items if k not in current]:
            self._remove_item(key)

        new_keys = [k for k in current if k not in self.items]
        for key in new_keys:
            item = ProcItem()
            item.setData(0, KEY_ROLE, key)
            self.items[key] = item
        self._attach(new_keys)

        for key, p in current.items():
            self._fill(self.items[key], p)
        self._resort()
        self._apply_filter()
        self._update_actions()

    def _parent_item(self, p: ProcInfo, by_pid: dict[int, str]) -> ProcItem | None:
        parent_key = by_pid.get(p.ppid)
        if not parent_key or parent_key == p.key:
            return None
        parent = self.procs[parent_key]
        # у System и Idle время создания условное, остальные родители должны быть старше
        if parent.pid not in (0, 4) and parent.created >= p.created:
            return None
        return self.items.get(parent_key)

    def _attach(self, keys: list[str]):
        """Добавляет строки в дерево (или в плоский список, если включён такой режим)."""
        by_pid = {p.pid: p.key for p in self.procs.values()}
        for key in keys:
            item = self.items[key]
            parent = None if self._flat else self._parent_item(self.procs[key], by_pid)
            if parent is not None:
                parent.addChild(item)
            else:
                self.tree.addTopLevelItem(item)
        if not self._flat:
            for key in keys:
                if self.items[key].childCount():
                    self.items[key].setExpanded(True)

    def _remove_item(self, key: str):
        item = self.items.pop(key)
        self.mem_results.pop(key, None)
        for i in reversed(range(item.childCount())):
            self.tree.addTopLevelItem(item.takeChild(i))  # потомки поднимаются наверх
        parent = item.parent()
        if parent is not None:
            parent.removeChild(item)
        else:
            index = self.tree.indexOfTopLevelItem(item)
            if index >= 0:
                self.tree.takeTopLevelItem(index)

    def _fill(self, item: ProcItem, p: ProcInfo):
        res = self.mem_results.get(p.key)
        values = [p.name, str(p.pid), f"{p.cpu:.1f}", f"{p.rss / 1048576:.1f}", p.user,
                  ORIGINS.get(p.origin, ""), p.sig, res.text() if res else "", p.exe]
        for col, text in enumerate(values):
            if item.text(col) != text:
                item.setText(col, text)
        item.setData(1, SORT_ROLE, p.pid)
        item.setData(2, SORT_ROLE, p.cpu)
        item.setData(3, SORT_ROLE, p.rss)
        for col in range(4, len(COLUMNS)):
            item.setToolTip(col, values[col])

        category = BY_ID.get(classify(p, bool(res and res.status == "match")))
        tip = category.title if category else ""
        if p.protected:
            tip += ("\n" if tip else "") + f"Защищён: {p.protect_reason or 'критический процесс Windows'}"
        elif p.sys_account:
            tip += ("\n" if tip else "") + (
                "Системная учётная запись, но процесс не в списке защищённых "
                f"(файл: {p.exe or 'путь недоступен'})")
        item.setToolTip(0, tip)

        for col in range(len(COLUMNS)):
            if category:
                item.setBackground(col, QBrush(QColor(*category.rgb)))
                item.setForeground(col, QBrush(text_color(category.rgb)))
            else:
                item.setData(col, Qt.ItemDataRole.BackgroundRole, None)
                item.setData(col, Qt.ItemDataRole.ForegroundRole, None)

    def _apply_filter(self):
        text = self.filter_edit.text().strip().lower()
        origin_ids = self._origin_ids()

        def text_ok(item: ProcItem) -> bool:
            if not text:
                return True
            return text in " ".join(item.text(c) for c in range(len(COLUMNS))).lower()

        if self._flat:
            for key, item in self.items.items():
                p = self.procs.get(key)
                origin_ok = origin_ids is None or (p is not None and p.origin in origin_ids)
                item.setHidden(not (origin_ok and text_ok(item)))
            return

        if not text:
            for item in self.items.values():
                item.setHidden(False)
            return
        visible = set()
        for item in self.items.values():
            if text_ok(item):
                node = item
                while node is not None:  # родители совпавших строк остаются видимыми
                    visible.add(node.data(0, KEY_ROLE))
                    node = node.parent()
        for key, item in self.items.items():
            item.setHidden(key not in visible)

    # ---------- действия над процессом ----------
    def _selected(self) -> ProcInfo | None:
        p = self._current()
        if p is None:
            QMessageBox.information(self, "Диспетчер процессов", "Сначала выберите процесс")
        return p

    def do_action(self, action: str):
        p = self._selected()
        if not p:
            return
        if p.protected:  # кнопки уже отключены, это вторая линия защиты
            self.statusBar().showMessage(
                f"{LOCKED_TIP} ({p.protect_reason or 'критический процесс Windows'})", 6000)
            return
        if action == "terminate":
            answer = QMessageBox.question(
                self, "Завершить процесс",
                f"Завершить {p.name} (PID {p.pid})?\n\n{p.exe or 'путь неизвестен'}\n\n"
                "Несохранённые данные программы будут потеряны.")
            if answer != QMessageBox.StandardButton.Yes:
                return
        self.statusBar().showMessage(run_action(action, p), 8000)

    def open_folder(self):
        p = self._selected()
        if not p:
            return
        if p.has_file and Path(p.exe).exists():
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
        if not p.has_file:
            QMessageBox.information(self, "Проверка файла", "У процесса нет доступного файла")
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
        self.statusBar().showMessage("Останавливаю после текущих процессов...")

    def _start_mem_scan(self, procs: list[ProcInfo]):
        if self._scan_thread is not None and self._scan_thread.is_alive():
            QMessageBox.information(self, "Сканирование памяти", "Сканирование уже идёт")
            return
        self._scan_cancel.clear()
        self._scan_matches = []
        self._scan_started = time.monotonic()
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

        def work(p: ProcInfo):
            if self._scan_cancel.is_set():
                return p, None
            return p, scan_process(rules, p.pid)

        done = 0
        workers = int(cfg.get("scan/workers"))
        self._scan_workers = workers
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(work, p) for p in procs]
            for future in as_completed(futures):
                p, res = future.result()
                if res is None:
                    continue
                done += 1
                self.bridge.mem_progress.emit(f"Память: {done}/{len(procs)}  {p.name} (PID {p.pid})")
                self.bridge.mem_result.emit(p.key, res)
        self.bridge.mem_done.emit(self._scan_cancel.is_set())

    def on_mem_result(self, key: str, res: MemResult):
        self.mem_results[key] = res
        p, item = self.procs.get(key), self.items.get(key)
        if p and item:
            self._fill(item, p)
            if res.status == "match":
                self._scan_matches.append(f"{p.name} (PID {p.pid}): {', '.join(res.matches)}")

    def on_mem_done(self, cancelled: bool):
        elapsed = time.monotonic() - self._scan_started
        prefix = "Остановлено. " if cancelled else "Готово. "
        self.statusBar().showMessage(
            f"{prefix}Совпадений в памяти: {len(self._scan_matches)}. "
            f"Время: {elapsed:.1f} с (потоков: {self._scan_workers})")
        if self._scan_matches:
            QMessageBox.warning(
                self, "Сканирование памяти",
                "Найдены совпадения:\n\n" + "\n".join(self._scan_matches[:15]))