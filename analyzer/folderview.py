"""Сканирование папки: файлы и папки этого уровня, проверка каждого файла движком, действия
по правой кнопке и свойства папки. Вложенная папка до 128 МБ проверяется целиком (со всеми
файлами внутри), крупнее — только считается её размер."""
import os
import queue
import threading
import time
from pathlib import Path

from PySide6.QtCore import QMimeData, QObject, Qt, QUrl, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QDialog, QHeaderView, QInputDialog, QLabel, QMenu,
    QMessageBox, QPushButton, QTabWidget, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from analyzer import fileops
from processmanager.colors import text_color
from processmanager.memscan import get_rules
from scanner import pool as scan_pool
from scanner.hashing import load_all_signatures
from scanner.whitelist import load_whitelist, trusted_hashes
from ui.widgets import item_less

SIG_DIR = Path(__file__).resolve().parent.parent / "signatures"
PATH_ROLE = Qt.ItemDataRole.UserRole + 1
SORT_ROLE = Qt.ItemDataRole.UserRole + 2
IS_DIR_ROLE = Qt.ItemDataRole.UserRole + 3
COLORS = {"threat": (255, 128, 128), "suspicious": (255, 190, 110), "error": (255, 255, 170)}
COLUMNS = ["Имя", "Тип", "Размер", "Изменён", "Проверка"]
DIR_LIMIT = 128 * 1024 ** 2  # вложенная папка тяжелее — не проверяется


class _Bridge(QObject):
    checked = Signal(int, object)           # номер запроса, [(путь, уровень, текст)]
    dir_size = Signal(int, str, object, int, bool)  # запрос, папка, размер, файлов, открылась
    dir_state = Signal(int, str, str, str, str)     # запрос, папка, уровень, текст, подсказка
    finished = Signal(int, int, int)        # номер запроса, угроз, подозрительных
    props = Signal(int, object)             # номер запроса, свойства папки
    item_props = Signal(str, object)        # заголовок окна, свойства файла или папки


class _Item(QTreeWidgetItem):
    """Папки выше файлов, размер сортируется как число (по размеру — вперемешку с файлами)."""
    def __lt__(self, other):
        tree = self.treeWidget()
        if tree is not None and tree.sortColumn() == 2:
            return item_less(self, other, SORT_ROLE)
        a_dir, b_dir = self.data(0, IS_DIR_ROLE), other.data(0, IS_DIR_ROLE)
        if a_dir != b_dir:
            ascending = tree is None or tree.header().sortIndicatorOrder() == Qt.SortOrder.AscendingOrder
            return a_dir if ascending else b_dir
        return item_less(self, other, SORT_ROLE)


def rules_and_bases():
    """Базы загружаются один раз за запуск (правила кэширует memscan)."""
    global _bases
    if _bases is None:
        _bases = (load_all_signatures(SIG_DIR), get_rules("all"))
    return _bases[0], _bases[1], trusted_hashes()


_bases = None
SCAN_WORKERS = max(2, min(8, (os.cpu_count() or 4)))  # потоков для разбора срабатываний
BATCH_SECONDS = 0.15  # результаты уходят в интерфейс пачками: таблица не дёргается на каждом файле


def reset_bases() -> None:
    """Базы обновились: при следующей проверке загрузить их заново."""
    global _bases
    _bases = None


def classify(reason: str | None) -> tuple[str, str]:
    """(уровень, текст) по ответу движка."""
    if not reason:
        return "clean", "Чисто"
    if reason.startswith("Heuristic"):
        return "suspicious", "Подозрительно: " + reason.removeprefix("Heuristic: ")
    if reason.startswith("hash match"):
        return "threat", "Угроза: хэш в базе сигнатур" + reason.removeprefix("hash match")
    return "threat", "Угроза: " + reason


def _props_dialog(parent, title: str, rows: list[tuple[str, str]]) -> None:
    dialog = QDialog(parent)
    dialog.setWindowTitle(title)
    dialog.resize(720, 360)
    box = QVBoxLayout(dialog)
    tree = QTreeWidget()
    tree.setHeaderLabels(["Свойство", "Значение"])
    tree.setRootIsDecorated(False)
    tree.setColumnWidth(0, 170)
    for key, value in rows:
        item = QTreeWidgetItem([key, value])
        item.setToolTip(1, value)
        tree.addTopLevelItem(item)
    box.addWidget(tree, 1)
    copy = QPushButton("Копировать")
    copy.clicked.connect(lambda: QApplication.clipboard().setText(
        "\n".join(f"{k}: {v}" for k, v in rows)))
    box.addWidget(copy, 0, Qt.AlignmentFlag.AlignLeft)
    dialog.show()


class FolderView(QWidget):
    scan_file = Signal(str)        # «Сканировать» файл: подробный анализ
    scan_folder = Signal(str)      # «Сканировать» вложенную папку
    status = Signal(str, int)
    quarantine_changed = Signal()
    journal_changed = Signal()
    scan_done = Signal()

    def __init__(self):
        super().__init__()
        self.folder: str | None = None
        self._request = 0
        self._cancel = threading.Event()
        self._items: dict[str, _Item] = {}
        self.bridge = _Bridge()
        self.bridge.checked.connect(self._on_checked)
        self.bridge.dir_size.connect(self._on_dir_size)
        self.bridge.dir_state.connect(self._on_dir_state)
        self.bridge.finished.connect(self._on_finished)
        self.bridge.props.connect(self._on_props)
        self.bridge.item_props.connect(lambda title, rows: _props_dialog(self, title, rows))

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.summary = QLabel("")
        self.summary.setWordWrap(True)
        self.summary.setStyleSheet("padding: 8px; border-radius: 6px; font-size: 11pt;")
        layout.addWidget(self.summary)

        self.tabs = QTabWidget()
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(COLUMNS)
        self.tree.setRootIsDecorated(False)
        self.tree.setUniformRowHeights(True)
        self.tree.setSortingEnabled(True)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        header = self.tree.header()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        for i, width in enumerate((300, 200, 100, 150)):
            self.tree.setColumnWidth(i, width)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._menu)
        self.tree.itemDoubleClicked.connect(self._double_clicked)
        self.tabs.addTab(self.tree, "Файлы и папки")

        self.props_tree = QTreeWidget()
        self.props_tree.setHeaderLabels(["Свойство", "Значение"])
        self.props_tree.setRootIsDecorated(False)
        self.props_tree.setColumnWidth(0, 200)
        self.tabs.addTab(self.props_tree, "Свойства")
        layout.addWidget(self.tabs, 1)
        layout.addWidget(QLabel("Двойной щелчок: папка открывается здесь, файл анализируется "
                                "подробно. Правая кнопка мыши: действия с файлом или папкой."))

    # ---------- загрузка папки ----------
    def set_folder(self, folder: str) -> None:
        self._cancel.set()
        self._cancel = cancel = threading.Event()
        self._request += 1
        request = self._request
        self._found: list[str] = []  # угрозы и подозрительные — для отчёта о работе
        self._found_extra: list[str] = []  # то же во вложенных папках (пишет поток проверки)
        self._big = 0  # вложенных папок тяжелее DIR_LIMIT
        self.folder = os.path.abspath(folder)
        self.tree.setSortingEnabled(False)
        self.tree.clear()
        self._items = {}
        files, dirs = [], []
        try:
            entries = sorted(os.scandir(self.folder), key=lambda e: e.name.lower())
        except OSError as e:
            self.summary.setText(f"Не удалось открыть папку: {e}")
            return
        for entry in entries:
            try:
                is_dir = entry.is_dir()
                st = entry.stat()
            except OSError:
                continue
            item = _Item([entry.name, "Папка" if is_dir else fileops.file_type(entry.path),
                          "считаю..." if is_dir else fileops.human_size(st.st_size),
                          fileops.fmt_time(st.st_mtime)[:16],
                          "Считаю размер..." if is_dir else "Ожидает проверки"])
            item.setData(0, PATH_ROLE, entry.path)
            item.setData(0, IS_DIR_ROLE, is_dir)
            item.setData(2, SORT_ROLE, -1 if is_dir else st.st_size)
            item.setData(3, SORT_ROLE, st.st_mtime)
            item.setToolTip(0, entry.path)
            self.tree.addTopLevelItem(item)
            self._items[entry.path] = item
            if is_dir:
                if not entry.is_junction() and not entry.is_symlink():
                    dirs.append(entry.path)
                else:
                    item.setText(2, "")
                    item.setText(4, "Ссылка на другую папку, не проверяется")
            else:
                files.append(entry.path)
        self.tree.setSortingEnabled(True)
        self.tree.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        folders = len(entries) - len(files)
        self.summary.setStyleSheet("padding: 8px; border-radius: 6px; font-size: 11pt;")
        self.summary.setText(f"Папка {self.folder}: файлов {len(files)}, папок {folders}. "
                             "Проверяю файлы и вложенные папки до 128 МБ...")
        self.props_tree.clear()
        self.props_tree.addTopLevelItem(QTreeWidgetItem(["Считаю...", ""]))
        sized: queue.Queue = queue.Queue()  # папки с посчитанным размером → проверка
        threading.Thread(target=self._sizes_job, args=(request, dirs, sized, cancel),
                         daemon=True).start()
        threading.Thread(target=self._scan_job, args=(request, files, sized, cancel),
                         daemon=True).start()
        threading.Thread(target=self._props_job, args=(request, self.folder, cancel),
                         daemon=True).start()

    def _sizes_job(self, request: int, dirs: list[str], sized: queue.Queue,
                   cancel: threading.Event) -> None:
        """Размер каждой вложенной папки; папка до DIR_LIMIT уходит на проверку со списком
        файлов. В конце — None: папок больше не будет."""
        for folder in dirs:
            if cancel.is_set():
                break
            files, size, count, opened = fileops.folder_files(folder, DIR_LIMIT, cancel)
            if cancel.is_set():
                break
            self.bridge.dir_size.emit(request, folder, size, count, opened)
            if opened and files:
                sized.put((folder, files))
        sized.put(None)

    def _scan_job(self, request: int, files: list[str], sized: queue.Queue,
                  cancel: threading.Event) -> None:
        threats = suspicious = 0
        try:
            signatures, rules, whitelist = rules_and_bases()
        except OSError as e:
            self.bridge.checked.emit(request, [(path, "error", f"Базы не загружены: {e}")
                                               for path in files])
            self.bridge.finished.emit(request, 0, 0)
            return

        # проверка идёт в рабочих процессах (scanner.pool): интерфейс не делит с ней GIL;
        # повторная проверка неизменённых файлов берёт ответ из кэша вердиктов
        batch, sent = [], time.monotonic()
        for path, reason, error in scan_pool.check_files(files, signatures, rules, whitelist,
                                                         cancel=cancel):
            if error is not None:
                level, text = "error", f"Не прочитан: {error.strerror or error}"
            else:
                level, text = classify(reason)
            threats += level == "threat"
            suspicious += level == "suspicious"
            batch.append((path, level, text))
            if time.monotonic() - sent >= BATCH_SECONDS:
                self.bridge.checked.emit(request, batch)
                batch, sent = [], time.monotonic()
        if batch:
            self.bridge.checked.emit(request, batch)
        while not cancel.is_set():
            entry = sized.get()
            if entry is None:
                break
            folder, folder_files = entry
            found = self._scan_dir(request, folder, folder_files, signatures, rules,
                                   whitelist, cancel)
            threats += found[0]
            suspicious += found[1]
        if not cancel.is_set():
            self.bridge.finished.emit(request, threats, suspicious)

    def _scan_dir(self, request, folder, files, signatures, rules, whitelist,
                  cancel) -> tuple[int, int]:
        """Проверка вложенной папки целиком; в строке папки — ход и итог."""
        threats = suspicious = done = 0
        found: list[str] = []
        sent = 0.0
        total = len(files)
        for path, reason, error in scan_pool.check_files(files, signatures, rules, whitelist,
                                                         cancel=cancel):
            done += 1
            if error is None:
                level, text = classify(reason)
                if level in ("threat", "suspicious"):
                    threats += level == "threat"
                    suspicious += level == "suspicious"
                    found.append(f"{path}: {text}")
            if time.monotonic() - sent >= 0.5:
                sent = time.monotonic()
                self.bridge.dir_state.emit(request, folder, "", f"Проверяю: {done} из {total}",
                                           "")
        if cancel.is_set():
            return threats, suspicious
        tip = "\n".join(found[:30]) + (f"\n...и ещё {len(found) - 30}" if len(found) > 30
                                        else "")
        if threats:
            state = ("threat", f"Угроз: {threats}, подозрительных: {suspicious}"
                     f" (из {total} файлов)")
        elif suspicious:
            state = ("suspicious", f"Подозрительных: {suspicious} (из {total} файлов)")
        else:
            state = ("clean", f"Чисто (файлов: {total})")
        self.bridge.dir_state.emit(request, folder, state[0], state[1], tip)
        if request == self._request:
            self._found_extra.extend(found)
        return threats, suspicious

    def _props_job(self, request: int, folder: str, cancel: threading.Event) -> None:
        try:
            rows = fileops.folder_properties(folder, cancel)
        except OSError as e:
            rows = [("Ошибка", str(e))]
        if not cancel.is_set():
            self.bridge.props.emit(request, rows)

    def _paint(self, item, level: str) -> None:
        rgb = COLORS.get(level)
        if rgb:
            for col in range(len(COLUMNS)):
                item.setBackground(col, QBrush(QColor(*rgb)))
                item.setForeground(col, QBrush(text_color(rgb)))

    def _on_dir_size(self, request: int, folder: str, size: int, count: int,
                     opened: bool) -> None:
        item = self._items.get(folder)
        if request != self._request or item is None:
            return
        if not opened:
            item.setText(2, "")
            item.setText(4, "Нет доступа")
            return
        item.setText(2, fileops.human_size(size))
        item.setToolTip(2, f"{fileops.exact_size(size)}, файлов: {count}")
        item.setData(2, SORT_ROLE, size)
        if size > DIR_LIMIT:
            self._big += 1
            text = "Вес > 128 МБ, не проверена"
        elif count == 0:
            text = "Пустая"
        else:
            text = "Ожидает проверки"
        item.setText(4, text)
        item.setToolTip(4, text)

    def _on_dir_state(self, request: int, folder: str, level: str, text: str,
                      tip: str) -> None:
        item = self._items.get(folder)
        if request != self._request or item is None:
            return
        item.setText(4, text)
        item.setToolTip(4, tip or text)
        self._paint(item, level)

    def _on_checked(self, request: int, batch) -> None:
        if request != self._request:
            return
        for path, level, text in batch:
            item = self._items.get(path)
            if item is None:
                continue
            item.setText(4, text)
            item.setToolTip(4, text)
            if level in ("threat", "suspicious"):
                self._found.append(f"{path}: {text}")
            self._paint(item, level)

    def _on_finished(self, request: int, threats: int, suspicious: int) -> None:
        if request != self._request:
            return
        if threats:
            rgb, text = COLORS["threat"], f"Найдено угроз: {threats}, подозрительных: {suspicious}"
        elif suspicious:
            rgb, text = COLORS["suspicious"], f"Подозрительных файлов: {suspicious}"
        else:
            rgb, text = (170, 230, 170), "Угроз не найдено"
        self.summary.setStyleSheet(
            f"padding: 8px; border-radius: 6px; font-size: 11pt; font-weight: 600; "
            f"background: rgb{rgb}; color: {text_color(rgb).name()};")
        skipped = (f" Не проверены вложенные папки тяжелее 128 МБ: {self._big}." if self._big
                   else "")
        self.summary.setText(f"{self.folder}: {text}.{skipped}")
        from recovery import activity
        activity.record("scan_folder", f"{self.folder}: {text}",
                        found=self._found + self._found_extra)
        self.summary.setToolTip("Ядра для проверки: " + scan_pool.get_pool().cores_text())
        self.status.emit(f"Проверка папки завершена. {text}", 10000)
        self.scan_done.emit()

    def _on_props(self, request: int, rows) -> None:
        if request != self._request:
            return
        self.props_tree.clear()
        for key, value in rows:
            item = QTreeWidgetItem([key, value])
            item.setToolTip(1, value)
            self.props_tree.addTopLevelItem(item)

    # ---------- действия ----------
    def _selected(self) -> list[tuple[str, bool]]:
        return [(it.data(0, PATH_ROLE), bool(it.data(0, IS_DIR_ROLE)))
                for it in self.tree.selectedItems()]

    def _double_clicked(self, item, _column) -> None:
        path = item.data(0, PATH_ROLE)
        if item.data(0, IS_DIR_ROLE):
            self.scan_folder.emit(path)
        else:
            self.scan_file.emit(path)

    def _menu(self, pos) -> None:
        selected = self._selected()
        if not selected:
            return
        paths = [p for p, _ in selected]
        first, first_is_dir = selected[0]
        files = [p for p, is_dir in selected if not is_dir]
        menu = QMenu(self)

        def add(text, handler, enabled=True):
            action = menu.addAction(text)
            action.setEnabled(enabled)
            action.triggered.connect(lambda checked=False: handler())

        single = len(selected) == 1
        if all(not is_dir for _, is_dir in selected):
            add("Открыть", lambda: self._safe(fileops.open_file, first), single)
            add("Открыть от имени администратора", lambda: self._open_admin(first), single)
            add("Открыть в проводнике", lambda: fileops.show_in_explorer(first), single)
            menu.addSeparator()
            add("Сканировать", lambda: self.scan_file.emit(first), single)
            add("Поместить в карантин", lambda: self._quarantine(files))
            add("Поместить в белый список", lambda: self._whitelist(files))
            menu.addSeparator()
            add("Копировать", lambda: self._copy(paths))
            add("Удалить", lambda: self._delete(paths))
            add("Переименовать", lambda: self._rename(first), single)
            menu.addSeparator()
            add("Свойства", lambda: self._properties(first, False), single)
        elif all(is_dir for _, is_dir in selected):
            add("Открыть в проводнике", lambda: fileops.open_folder(first), single)
            add("Сканировать", lambda: self.scan_folder.emit(first), single)
            menu.addSeparator()
            add("Удалить", lambda: self._delete(paths))
            add("Переименовать", lambda: self._rename(first), single)
            menu.addSeparator()
            add("Свойства", lambda: self._properties(first, True), single)
        else:  # выделены и файлы, и папки
            add("Копировать", lambda: self._copy(paths))
            add("Удалить", lambda: self._delete(paths))
        menu.exec(self.tree.viewport().mapToGlobal(pos))

    def _safe(self, fn, *args) -> None:
        try:
            fn(*args)
        except OSError as e:
            QMessageBox.warning(self, "Открыть", f"Не удалось открыть: {e}")

    def _open_admin(self, path: str) -> None:
        if not fileops.open_as_admin(path):
            self.status.emit("Запуск от имени администратора отменён или не удался", 6000)

    def _copy(self, paths: list[str]) -> None:
        data = QMimeData()
        data.setUrls([QUrl.fromLocalFile(p) for p in paths])  # вставляется в Проводнике
        data.setText("\n".join(paths))
        QApplication.clipboard().setMimeData(data)
        self.status.emit(f"Скопировано в буфер обмена: {len(paths)}. Вставьте в Проводнике "
                         "(Ctrl+V)", 6000)

    def _names(self, paths: list[str]) -> str:
        text = "\n".join(f"• {os.path.basename(p)}" for p in paths[:10])
        return text + (f"\n...и ещё {len(paths) - 10}" if len(paths) > 10 else "")

    def _delete(self, paths: list[str]) -> None:
        answer = QMessageBox.question(
            self, "Удалить", f"Переместить в Корзину ({len(paths)})?\n\n{self._names(paths)}\n\n"
            "Вернуть можно из Корзины Windows.")
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            fileops.to_recycle_bin(paths)
        except OSError as e:
            QMessageBox.warning(self, "Удалить", str(e))
        self.set_folder(self.folder)

    def _rename(self, path: str) -> None:
        old = os.path.basename(path)
        new, ok = QInputDialog.getText(self, "Переименовать", "Новое имя:", text=old)
        if not ok or not new.strip() or new.strip() == old:
            return
        try:
            fileops.rename(path, new.strip())
        except (OSError, ValueError) as e:
            QMessageBox.warning(self, "Переименовать", f"Не удалось: {e}")
            return
        self.journal_changed.emit()
        self.status.emit("Переименовано. Отменить можно в журнале действий.", 6000)
        self.set_folder(self.folder)

    def _quarantine(self, files: list[str]) -> None:
        answer = QMessageBox.question(
            self, "Карантин", f"Переместить в карантин ({len(files)})?\n\n{self._names(files)}\n\n"
            "Вернуть можно в «Журнале действий», вкладка «Карантин».")
        if answer != QMessageBox.StandardButton.Yes:
            return
        errors = []
        for path in files:
            try:
                fileops.quarantine(path, "Сканирование папки: перемещено пользователем")
            except PermissionError:
                errors.append(f"{os.path.basename(path)}: файл занят (программа запущена)")
            except OSError as e:
                errors.append(f"{os.path.basename(path)}: {e}")
        if errors:
            QMessageBox.warning(self, "Карантин", "Не удалось:\n" + "\n".join(errors[:10]))
        self.quarantine_changed.emit()
        self.journal_changed.emit()
        self.set_folder(self.folder)

    def _whitelist(self, files: list[str]) -> None:
        answer = QMessageBox.question(
            self, "Белый список",
            f"Доверять файлам ({len(files)})?\n\n{self._names(files)}\n\nОни перестанут "
            "проверяться, пока их содержимое не изменится. Отменить можно в журнале действий.")
        if answer != QMessageBox.StandardButton.Yes:
            return
        added = 0
        for path in files:
            try:
                added += fileops.whitelist_file(path)
            except OSError as e:
                QMessageBox.warning(self, "Белый список", f"{os.path.basename(path)}: {e}")
        self.status.emit(f"Добавлено в белый список: {added}", 6000)
        self.quarantine_changed.emit()  # страница «Белый список» обновится вместе с карантином
        self.journal_changed.emit()
        self.set_folder(self.folder)

    def _properties(self, path: str, is_dir: bool) -> None:
        self.status.emit("Собираю свойства...", 3000)

        def job():
            try:
                rows = (fileops.folder_properties(path) if is_dir
                        else fileops.file_properties(path))
            except OSError as e:
                rows = [("Ошибка", str(e))]
            self.bridge.item_props.emit(f"Свойства: {os.path.basename(path)}", rows)

        threading.Thread(target=job, daemon=True).start()

    def stop(self) -> None:
        self._cancel.set()
