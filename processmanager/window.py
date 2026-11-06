import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from PySide6.QtCore import QObject, Qt, Signal, QEvent
from PySide6.QtGui import QAction, QBrush, QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDialog, QDockWidget, QHeaderView, QLabel,
    QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMenu, QMessageBox, QPushButton,
    QTextEdit, QTreeWidget, QVBoxLayout,
)

from processmanager.colors import BY_ID, CATEGORIES, classify, text_color
from scanner import cpucores
from scanner.signature import VALID, inspect_signature
from processmanager import memcache
from processmanager.memscan import MemResult, get_rules, kernel_process, scan_process
from scanner.yara_engine import rules_version
from processmanager.memview import InjectionScanDialog, MemoryDialog
from processmanager.origin import FILTERS, HELP, ORIGINS
from processmanager.system import (
    ProcInfo, enable_debug_privilege, is_admin, open_in_explorer,
    process_details, run_action, take_snapshot,
)
from processmanager.enrich import Enricher

from ui import settings as cfg
from ui.widgets import SortItem

SIG_DIR = Path(__file__).resolve().parent.parent / "signatures"
COLUMNS = ["Процесс", "PID", "CPU, %", "Память, МБ", "Пользователь", "Запуск",
           "Подпись", "Память (YARA)", "Путь"]


def apply_enriched(p, result) -> None:
    if result:
        p.sig, p.sig_status, p.packed, p.dotnet = result


DESC_FIRST = {2, 3}  # числовые колонки при первом клике сортируются по убыванию
KEY_ROLE = Qt.ItemDataRole.UserRole + 1
SORT_ROLE = Qt.ItemDataRole.UserRole + 2
LOCKED_TIP = "Системный процесс: изменение запрещено"
ASC = Qt.SortOrder.AscendingOrder
DESC = Qt.SortOrder.DescendingOrder
DYNAMIC_COLUMNS = {2, 3}  # CPU и память меняются постоянно


class Bridge(QObject):
    """Передаёт события из фоновых потоков в главный поток."""
    snapshot = Signal(object)
    mem_result = Signal(str, object)
    mem_progress = Signal(str)
    mem_done = Signal(bool)
    task_done = Signal(str, str)


class ProcItem(SortItem):
    """Строка дерева с числовой сортировкой (роль SORT_ROLE модуля — та же, что у SortItem)."""


assert ProcItem.SORT_ROLE == SORT_ROLE


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
    analyze_requested = Signal(str)
    restart_requested = Signal()

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
        self._row_state: dict[str, tuple] = {}  # что сейчас показано в строке
        self._pending_snapshot = None           # снимок, полученный, пока окно было скрыто
        self._last_resort = 0.0
        self._brushes: dict = {}
        self.enricher = Enricher()
        self.enricher.changed.connect(self._on_enriched)
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
            ("memdeep", "Память: регионы и модули", self.show_memory_map),
            ("inject", "Найти внедрение кода", self.find_injections),
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
        self.community_cb.setToolTip(
            "Кроме правил для памяти (свои и Elastic) использовать и правила для файлов")
        toolbar.addWidget(self.community_cb)
        self.full_memory_cb = QCheckBox("Вся память (медленно)")
        self.full_memory_cb.setToolTip(
            "Проверять и модули, и отображённые файлы. По умолчанию проверяется только "
            "приватная память (кучи, стеки, внедрённый код) и модули с правами RWX: "
            "содержимое DLL лежит на диске и проверяется сканером файлов")
        toolbar.addWidget(self.full_memory_cb)

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

        legend = self._build_legend(toolbar)
        self.tree.itemDoubleClicked.connect(lambda *_: self.show_properties())

        # меню «Вид»: панель действий и легенду можно вернуть, даже если обе закрыты
        view_menu = self.menuBar().addMenu("Вид")
        toolbar_action = toolbar.toggleViewAction()
        toolbar_action.setText("Панель действий")
        legend_action = legend.toggleViewAction()
        legend_action.setText("Легенда цветов")
        view_menu.addAction(toolbar_action)
        view_menu.addAction(legend_action)
        process_menu = self.menuBar().addMenu("Процесс")
        for action in self.menu_actions:
            process_menu.addSeparator() if action is None else process_menu.addAction(action)
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
        return dock

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
                for p in procs:
                    if p.has_file:
                        apply_enriched(p, self.enricher.lookup(p.exe))  # None: проверка уже в очереди
                    else:
                        p.sig = "Без файла (ядро Windows)" if p.core else ""
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
        if self._pending_snapshot is not None:
            self.on_snapshot(self._pending_snapshot)

    def changeEvent(self, event):
        super().changeEvent(event)
        if (event.type() == QEvent.Type.WindowStateChange and not self.isMinimized()
                and self._pending_snapshot is not None):
            self.on_snapshot(self._pending_snapshot)

    def closeEvent(self, event):
        self._stop_snapshots.set()
        self._scan_cancel.set()
        self.enricher.save()
        event.accept()

    def shutdown(self):
        """Вызывается при закрытии главного окна."""
        self._stop_snapshots.set()
        self._scan_cancel.set()
        self.enricher.shutdown()

    # ---------- обновление списка ----------
    def on_snapshot(self, procs: list[ProcInfo]):
        if self.isMinimized() or not self.isVisible():
            self._pending_snapshot = procs  # окно скрыто: применим, когда его покажут
            return
        self._pending_snapshot = None
        current = {p.key: p for p in procs}
        self.procs = current
        self.tree.setUpdatesEnabled(False)  # одна перерисовка вместо сотен
        try:
            removed = [k for k in self.items if k not in current]
            for key in removed:
                self._remove_item(key)
            new_keys = [k for k in current if k not in self.items]
            for key in new_keys:
                item = ProcItem()
                item.setData(0, KEY_ROLE, key)
                self.items[key] = item
            self._attach(new_keys)
            for key, p in current.items():
                self._fill(self.items[key], p)

            structure_changed = bool(removed or new_keys)
            now = time.monotonic()
            dynamic_sort = self._sort is not None and self._sort[0] in DYNAMIC_COLUMNS
            if structure_changed or (dynamic_sort and now - self._last_resort > 4.0):
                self._resort()
                self._last_resort = now
            if (structure_changed or self.filter_edit.text().strip()
                    or self._origin_ids() is not None):
                self._apply_filter()
        finally:
            self.tree.setUpdatesEnabled(True)
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
        self._row_state.pop(key, None)
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
        """Обновляет только то, что изменилось с прошлого раза."""
        res = self.mem_results.get(p.key)
        values = (p.name, str(p.pid), f"{p.cpu:.1f}", f"{p.rss / 1048576:.1f}", p.user,
                  ORIGINS.get(p.origin, ""), p.sig, res.text() if res else "", p.exe)
        category_id = classify(p, bool(res and res.status == "match"))
        category = BY_ID.get(category_id)
        tip = category.title if category else ""
        if p.protected:
            tip += ("\n" if tip else "") + f"Защищён: {p.protect_reason or 'критический процесс Windows'}"
        elif p.sys_account:
            tip += ("\n" if tip else "") + (
                "Системная учётная запись, но процесс не в списке защищённых "
                f"(файл: {p.exe or 'путь недоступен'})")

        state = self._row_state.get(p.key)
        old = state[0] if state else None
        for col, text in enumerate(values):
            if old is None or old[col] != text:
                item.setText(col, text)
        if old is None or old[1] != values[1]:
            item.setData(1, SORT_ROLE, p.pid)
        if old is None or old[2] != values[2]:
            item.setData(2, SORT_ROLE, p.cpu)
        if old is None or old[3] != values[3]:
            item.setData(3, SORT_ROLE, p.rss)
        for col in range(4, len(COLUMNS)):
            if old is None or old[col] != values[col]:
                item.setToolTip(col, values[col])
        if state is None or state[2] != tip:
            item.setToolTip(0, tip)
        if state is None or state[1] != category_id:
            self._apply_colors(item, category_id)
        self._row_state[p.key] = (values, category_id, tip)

    def _apply_colors(self, item: ProcItem, category_id):
        category = BY_ID.get(category_id)
        if category is None:
            for col in range(len(COLUMNS)):
                item.setData(col, Qt.ItemDataRole.BackgroundRole, None)
                item.setData(col, Qt.ItemDataRole.ForegroundRole, None)
            return
        if category_id not in self._brushes:  # кисти создаются один раз на категорию
            self._brushes[category_id] = (QBrush(QColor(*category.rgb)),
                                          QBrush(text_color(category.rgb)))
        background, foreground = self._brushes[category_id]
        for col in range(len(COLUMNS)):
            item.setBackground(col, background)
            item.setForeground(col, foreground)

    def _on_enriched(self):
        """Появились результаты проверки подписей: обновляем строки, не дожидаясь снимка."""
        if not self.isVisible() or self.isMinimized():
            return
        self.tree.setUpdatesEnabled(False)
        try:
            for key, p in self.procs.items():
                if p.has_file:
                    result = self.enricher.peek(p.exe)
                    item = self.items.get(key)
                    if result and item is not None:
                        apply_enriched(p, result)
                        self._fill(item, p)
        finally:
            self.tree.setUpdatesEnabled(True)

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
        self.analyze_requested.emit(p.exe)

    def on_task_done(self, title: str, text: str):
        self.statusBar().clearMessage()
        TextDialog(title, text, self).exec()

    def relaunch(self):
        self.restart_requested.emit()

    # ---------- карта памяти (VirtualQueryEx) и модули ----------
    def show_memory_map(self):
        p = self._selected()
        if p:
            MemoryDialog(p.pid, p.name, self).show()

    def set_memory_allowed(self, on: bool) -> None:
        """Карта памяти и поиск внедрения кода (запрет «Память» в ui/access.py)."""
        for action_id in ("memdeep", "inject"):
            self.actions[action_id].setVisible(on)

    def find_injections(self):
        procs = [(p.pid, p.name, p.exe) for p in self.procs.values()
                 if p.pid not in (0, 4, os.getpid())]
        InjectionScanDialog(procs, self).show()

    # ---------- сканирование памяти ----------
    def scan_selected_memory(self):
        p = self._selected()
        if p:
            self._start_mem_scan([p], force=True)  # выбран вручную: проверить в любом случае

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

    def _start_mem_scan(self, procs: list[ProcInfo], force: bool = False):
        if self._scan_thread is not None and self._scan_thread.is_alive():
            QMessageBox.information(self, "Сканирование памяти", "Сканирование уже идёт")
            return
        self._scan_cancel.clear()
        self._scan_matches = []
        self._scan_signed = []
        self._scan_cached = 0  # системных процессов без изменений: не сканировались
        self._scan_started = time.monotonic()
        kind = "memory_all" if self.community_cb.isChecked() else "memory"
        full = self.full_memory_cb.isChecked()
        self._scan_thread = threading.Thread(
            target=self._mem_scan_loop, args=(list(procs), kind, full, force), daemon=True)
        self._scan_thread.start()

    def _mem_scan_loop(self, procs: list[ProcInfo], kind: str, full: bool = False,
                       force: bool = False):
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

        rules_key = f"{kind}|{full}|{rules_version(rules) or id(rules)}"

        def work(p: ProcInfo):
            if self._scan_cancel.is_set():
                return p, None
            if kernel_process(p.pid, p.ppid, p.exe):
                return p, MemResult("kernel")
            # системный процесс без изменений с прошлой проверки — не сканируется (memcache)
            cached, fp = (None, None) if force else memcache.lookup(p, rules_key)
            if cached is not None:
                return p, cached
            res = scan_process(rules, p.pid, full=full)
            memcache.store(p, rules_key, fp, res)
            if res.status == "match" and p.exe:
                # в памяти подписанных программ (IDE, браузеры, мессенджеры) бывают любые
                # строки, вплоть до текста правил: такое совпадение — повод проверить, а не угроза
                try:
                    if inspect_signature(Path(p.exe)).status == VALID:
                        res.status = "signed"
                except OSError:
                    pass
            return p, res

        done = 0
        workers = int(cfg.get("scan/workers"))
        self._scan_workers = workers
        # производительные ядра заняты (игра и т. п.) — потоки проверки идут на энергоэффективные
        chooser = cpucores.choose_now()
        self._scan_cores = chooser.text()
        with ThreadPoolExecutor(max_workers=workers, initializer=cpucores.pin_current_thread,
                                initargs=(chooser.cpus(),)) as pool:
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
        self._scan_cached += res.cached
        p, item = self.procs.get(key), self.items.get(key)
        if p and item:
            self._fill(item, p)
            if res.status == "match":
                self._scan_matches.append(f"{p.name} (PID {p.pid}): {', '.join(res.matches)}")
            elif res.status == "signed":
                self._scan_signed.append(f"{p.name} (PID {p.pid}): {', '.join(res.matches)}")

    def on_mem_done(self, cancelled: bool):
        elapsed = time.monotonic() - self._scan_started
        prefix = "Остановлено. " if cancelled else "Готово. "
        self.statusBar().showMessage(
            f"{prefix}Совпадений в памяти: {len(self._scan_matches)}"
            f" (у подписанных программ: {len(self._scan_signed)}). "
            + (f"Системных процессов без изменений, не сканировались: {self._scan_cached}. "
               if self._scan_cached else "") +
            f"Время: {elapsed:.1f} с (потоков: {self._scan_workers}; "
            f"{getattr(self, '_scan_cores', 'все ядра')})")
        if self._scan_matches:
            text = "Найдены совпадения:\n\n" + "\n".join(self._scan_matches[:15])
            if self._scan_signed:
                text += ("\n\nЕщё совпадения у подписанных программ (скорее ложные, "
                         "подробности в столбце памяти): " + str(len(self._scan_signed)))
            QMessageBox.warning(self, "Сканирование памяти", text)