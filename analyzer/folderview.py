"""Сканирование папки: файлы и папки только этого уровня (вложенные не затрагиваются),
проверка каждого файла движком, действия по правой кнопке и свойства папки."""
import os
import threading
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
from scanner.engine import check_file
from scanner.hashing import load_all_signatures
from scanner.whitelist import load_whitelist

SIG_DIR = Path(__file__).resolve().parent.parent / "signatures"
PATH_ROLE = Qt.ItemDataRole.UserRole + 1
SORT_ROLE = Qt.ItemDataRole.UserRole + 2
IS_DIR_ROLE = Qt.ItemDataRole.UserRole + 3
COLORS = {"threat": (255, 128, 128), "suspicious": (255, 190, 110), "error": (255, 255, 170)}
COLUMNS = ["Имя", "Тип", "Размер", "Изменён", "Проверка"]


class _Bridge(QObject):
    checked = Signal(int, str, str, str)    # номер запроса, путь, уровень, текст
    finished = Signal(int, int, int)        # номер запроса, угроз, подозрительных
    props = Signal(int, object)             # номер запроса, свойства папки
    item_props = Signal(str, object)        # заголовок окна, свойства файла или папки


class _Item(QTreeWidgetItem):
    """Папки всегда выше файлов, размер сортируется как число."""
    def __lt__(self, other):
        tree = self.treeWidget()
        col = tree.sortColumn() if tree else 0
        a_dir, b_dir = self.data(0, IS_DIR_ROLE), other.data(0, IS_DIR_ROLE)
        if a_dir != b_dir:
            ascending = tree is None or tree.header().sortIndicatorOrder() == Qt.SortOrder.AscendingOrder
            return a_dir if ascending else b_dir
        a, b = self.data(col, SORT_ROLE), other.data(col, SORT_ROLE)
        if a is not None and b is not None:
            return a < b
        return self.text(col).lower() < other.text(col).lower()


def _rules_and_bases():
    """Базы загружаются один раз за запуск (правила кэширует memscan)."""
    global _bases
    if _bases is None:
        _bases = (load_all_signatures(SIG_DIR), get_rules("all"))
    return _bases[0], _bases[1], set(load_whitelist())


_bases = None


def classify(reason: str | None) -> tuple[str, str]:
    """(уровень, текст) по ответу движка."""
    if not reason:
        return "clean", "Чисто"
    if reason.startswith("Heuristic"):
        return "suspicious", "Подозрительно: " + reason.removeprefix("Heuristic: ")
    if reason == "hash match":
        return "threat", "Угроза: хэш в базе сигнатур"
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
        self.folder = os.path.abspath(folder)
        self.tree.setSortingEnabled(False)
        self.tree.clear()
        self._items = {}
        files = []
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
                          "" if is_dir else fileops.human_size(st.st_size),
                          fileops.fmt_time(st.st_mtime)[:16],
                          "—" if is_dir else "Ожидает проверки"])
            item.setData(0, PATH_ROLE, entry.path)
            item.setData(0, IS_DIR_ROLE, is_dir)
            item.setData(2, SORT_ROLE, -1 if is_dir else st.st_size)
            item.setData(3, SORT_ROLE, st.st_mtime)
            item.setToolTip(0, entry.path)
            self.tree.addTopLevelItem(item)
            self._items[entry.path] = item
            if not is_dir:
                files.append(entry.path)
        self.tree.setSortingEnabled(True)
        self.tree.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        folders = len(entries) - len(files)
        self.summary.setStyleSheet("padding: 8px; border-radius: 6px; font-size: 11pt;")
        self.summary.setText(f"Папка {self.folder}: файлов {len(files)}, папок {folders}. "
                             "Проверяю файлы (вложенные папки не сканируются)...")
        self.props_tree.clear()
        self.props_tree.addTopLevelItem(QTreeWidgetItem(["Считаю...", ""]))
        threading.Thread(target=self._scan_job, args=(request, files, cancel), daemon=True).start()
        threading.Thread(target=self._props_job, args=(request, self.folder, cancel),
                         daemon=True).start()

    def _scan_job(self, request: int, files: list[str], cancel: threading.Event) -> None:
        threats = suspicious = 0
        try:
            signatures, rules, whitelist = _rules_and_bases()
        except OSError as e:
            for path in files:
                self.bridge.checked.emit(request, path, "error", f"Базы не загружены: {e}")
            self.bridge.finished.emit(request, 0, 0)
            return
        for path in files:
            if cancel.is_set():
                return
            try:
                level, text = classify(check_file(Path(path), signatures, rules, whitelist))
            except OSError as e:
                level, text = "error", f"Не прочитан: {e.strerror or e}"
            threats += level == "threat"
            suspicious += level == "suspicious"
            self.bridge.checked.emit(request, path, level, text)
        self.bridge.finished.emit(request, threats, suspicious)

    def _props_job(self, request: int, folder: str, cancel: threading.Event) -> None:
        try:
            rows = fileops.folder_properties(folder, cancel)
        except OSError as e:
            rows = [("Ошибка", str(e))]
        if not cancel.is_set():
            self.bridge.props.emit(request, rows)

    def _on_checked(self, request: int, path: str, level: str, text: str) -> None:
        item = self._items.get(path)
        if request != self._request or item is None:
            return
        item.setText(4, text)
        item.setToolTip(4, text)
        rgb = COLORS.get(level)
        if rgb:
            for col in range(len(COLUMNS)):
                item.setBackground(col, QBrush(QColor(*rgb)))
                item.setForeground(col, QBrush(text_color(rgb)))

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
        self.summary.setText(f"{self.folder}: {text}. Вложенные папки не проверялись.")
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
