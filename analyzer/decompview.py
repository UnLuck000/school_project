"""Вкладка «Декомпилятор» анализатора: дерево частей файла (analyzer.unpack) с проверкой
каждой извлечённой части и код выбранной части (analyzer.decompile).

Разбор начинается, когда вкладку впервые открывают для файла (или кнопкой «Разобрать
заново»): у больших установщиков он не бесплатный, а большинству проверок файла не нужен.
"""
from __future__ import annotations

import shutil
import threading
from pathlib import Path

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont
from PySide6.QtWidgets import (
    QFileDialog, QHBoxLayout, QLabel, QMenu, QPushButton, QSplitter, QTreeWidgetItem,
    QVBoxLayout, QWidget,
)

from analyzer import decompile, unpack
from analyzer.codeview import CodeEdit, Highlighter
from analyzer.report import human_size
from processmanager.colors import text_color
from ui.widgets import make_tree

NODE_ROLE = Qt.ItemDataRole.UserRole + 1
LEVEL_COLORS = {"threat": (255, 128, 128), "suspicious": (255, 190, 110),
                "error": (220, 220, 220)}


class _Bridge(QObject):
    progress = Signal(int, str)
    unpacked = Signal(int, object, object)      # номер разбора, корень, итоги проверки
    failed = Signal(int, str)
    code = Signal(int, str, str, str)           # номер запроса, текст, язык, пояснение
    functions = Signal(object, object, str)     # узел программы, узлы функций, итог


class DecompileTab(QWidget):
    def __init__(self):
        super().__init__()
        self._path: Path | None = None
        self._root: unpack.Node | None = None
        self._run = 0                # номер разбора: ответ старого разбора не нужен
        self._request = 0            # номер запроса кода
        self._cancel = threading.Event()
        self._started = False
        self._highlighter = None
        self.bridge = _Bridge()
        self.bridge.progress.connect(self._on_progress)
        self.bridge.unpacked.connect(self._on_unpacked)
        self.bridge.failed.connect(self._on_failed)
        self.bridge.code.connect(self._on_code)
        self.bridge.functions.connect(self._on_functions)
        self._items: dict[int, QTreeWidgetItem] = {}   # id(узла) → строка дерева
        self._analyzed: set[int] = set()               # программы, для которых есть функции
        self._build()

    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        top = QHBoxLayout()
        self.status = QLabel("Откройте файл: здесь появится его устройство — что упаковано "
                             "внутри, и код каждой части.")
        self.status.setWordWrap(True)
        self.btn_run = QPushButton("Разобрать заново")
        self.btn_run.clicked.connect(lambda: self.start(force=True))
        self.btn_stop = QPushButton("Остановить")
        self.btn_stop.clicked.connect(lambda: self._cancel.set())  # текущий разбор
        self.btn_stop.hide()
        top.addWidget(self.status, 1)
        top.addWidget(self.btn_stop)
        top.addWidget(self.btn_run)
        layout.addLayout(top)

        split = QSplitter(Qt.Orientation.Horizontal)
        self.tree = make_tree(["Часть файла", "Что это", "Размер", "Проверка"],
                              [300, 150, 90, 260], multi=False, decorated=True)
        self.tree.currentItemChanged.connect(self._selected)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._menu)
        self.tree.itemDoubleClicked.connect(lambda item, _c: self._details(item))
        right = QWidget()
        rbox = QVBoxLayout(right)
        rbox.setContentsMargins(0, 0, 0, 0)
        self.note = QLabel()
        self.note.setWordWrap(True)
        self.note.hide()
        self.btn_bytecode = QPushButton("Байт-код")
        self.btn_bytecode.setCheckable(True)
        self.btn_bytecode.setToolTip("Python 3.11+ pycdc восстанавливает не целиком: байт-код "
                                     "(pycdas) показывает всю логику")
        self.btn_bytecode.toggled.connect(self._toggle_bytecode)
        self.btn_bytecode.hide()
        self.code = CodeEdit()
        bar = QHBoxLayout()
        bar.addWidget(self.note, 1)
        bar.addWidget(self.btn_bytecode, 0, Qt.AlignmentFlag.AlignTop)
        rbox.addLayout(bar)
        rbox.addWidget(self.code, 1)
        split.addWidget(self.tree)
        split.addWidget(right)
        split.setSizes([620, 760])
        layout.addWidget(split, 1)
        self.btn_run.setEnabled(False)

    # ---------- файл и разбор
    def set_file(self, path: Path | None) -> None:
        """Новый файл в анализаторе: прежний разбор больше не нужен."""
        self._cancel.set()
        from analyzer import rizin
        threading.Thread(target=rizin.close_all, daemon=True).start()
        self._items.clear()
        self._analyzed.clear()
        self._path = path
        self._root = None
        self._started = False
        self._run += 1
        self.tree.clear()
        self.code.setPlainText("")
        self.note.hide()
        self.btn_run.setEnabled(path is not None)
        self.status.setText("Разбор начнётся, когда откроете вкладку." if path else "")
        if self.isVisible():
            self.start()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if not self._started:
            self.start()

    def start(self, force: bool = False) -> None:
        if self._path is None or (self._started and not force):
            return
        self._cancel.set()
        self._cancel = threading.Event()
        self._started = True
        self._run += 1
        self.tree.clear()
        self.code.setPlainText("")
        self.status.setText(f"Разбираю {self._path.name}...")
        self.btn_stop.show()
        self.btn_run.setEnabled(False)
        from diag import features
        features.begin("analyzer.decompile")
        features.step("analyzer.decompile", f"разбор {self._path.suffix or 'файла'}")
        threading.Thread(target=self._job, args=(self._run, self._path, self._cancel),
                         daemon=True, name="decompile").start()

    def _job(self, run: int, path: Path, cancel: threading.Event) -> None:
        def progress(text):
            self.bridge.progress.emit(run, text)
        try:
            root = unpack.unpack(path, cancel, progress)
            progress(f"Проверяю извлечённое: {len(root.files())} файлов...")
            counts = unpack.check_tree(root, cancel, progress)
        except Exception as e:
            self.bridge.failed.emit(run, f"{type(e).__name__}: {e}")
            return
        self.bridge.unpacked.emit(run, root, counts)

    def _on_progress(self, run: int, text: str) -> None:
        if run == self._run:
            self.status.setText(text)

    def _on_failed(self, run: int, text: str) -> None:
        if run != self._run:
            return
        from diag import features
        features.end_if_active("analyzer.decompile", False, error=text)
        self.btn_stop.hide()
        self.btn_run.setEnabled(True)
        self.status.setText(f"Разобрать не удалось: {text}")

    def _on_unpacked(self, run: int, root: unpack.Node, counts: dict) -> None:
        if run != self._run:
            return
        from diag import features
        self._root = root
        self.btn_stop.hide()
        self.btn_run.setEnabled(True)
        item = self._add(None, root)
        item.setExpanded(True)
        for i in range(item.childCount()):
            item.child(i).setExpanded(item.childCount() <= 4)
        self.tree.setCurrentItem(item)
        files = counts.get("files", 0)
        parts = [f"Частей: {sum(1 for _ in root.walk()) - 1}", f"извлечено файлов: {files}"]
        if counts.get("threat"):
            parts.append(f"угроз: {counts['threat']}")
        if counts.get("suspicious"):
            parts.append(f"подозрительных: {counts['suspicious']}")
        if files and not counts.get("threat") and not counts.get("suspicious"):
            parts.append("все чистые")
        if self._cancel.is_set():
            parts.append("разбор остановлен")
        self.status.setText(", ".join(parts))
        features.end_if_active("analyzer.decompile", True, files=files,
                               threats=counts.get("threat", 0))

    def _add(self, parent: QTreeWidgetItem | None, node: unpack.Node) -> QTreeWidgetItem:
        item = QTreeWidgetItem([node.name, unpack.KIND_TEXT.get(node.kind, node.kind),
                                human_size(node.size) if node.size else "",
                                node.verdict if node.level not in ("", "clean") else
                                ("Чисто" if node.level == "clean" else "")])
        item.setData(0, NODE_ROLE, node)
        self._items[id(node)] = item
        if node.note:
            item.setToolTip(0, node.note)
        if node.kind in ("pyinstaller", "dotnet", "upx") or "Main" in node.name or \
                node.note.startswith("Скрипт"):        # точки входа PyInstaller
            font = QFont(item.font(0))
            font.setBold(True)
            item.setFont(0, font)
        rgb = LEVEL_COLORS.get(node.level)
        if rgb:
            for col in range(4):
                item.setBackground(col, QBrush(QColor(*rgb)))
                item.setForeground(col, QBrush(text_color(rgb)))
        if parent is None:
            self.tree.addTopLevelItem(item)
        else:
            parent.addChild(item)
        for child in node.children:
            self._add(item, child)
        return item

    # ---------- код выбранной части
    def _node(self, item) -> unpack.Node | None:
        return item.data(0, NODE_ROLE) if item is not None else None

    def _selected(self, item, _previous=None) -> None:
        node = self._node(item)
        if node is None:
            return
        is_python = node.lang == "python" and bool(node.path)
        self.btn_bytecode.blockSignals(True)
        self.btn_bytecode.setChecked(False)
        self.btn_bytecode.blockSignals(False)
        self.btn_bytecode.setVisible(is_python)
        self._load_code(node)

    def _toggle_bytecode(self, on: bool) -> None:
        node = self._node(self.tree.currentItem())
        if node is not None:
            self._bytecode(node) if on else self._load_code(node)

    def _load_code(self, node: unpack.Node) -> None:
        self._request += 1
        if node.lang == "native" and node.path and id(node) not in self._analyzed:
            self._analyzed.add(id(node))
            self._show(decompile.describe(node) + "\n\nИщу функции (rizin, анализ один раз на "
                       "файл; у больших программ — до нескольких минут)...", "", "")
            threading.Thread(target=self._functions_job, args=(node,), daemon=True,
                             name="decompile-functions").start()
            return
        if (node.lang in ("python", "java", "csharp") and (node.path or node.owner)) or \
                node.kind == "function":
            self._show("Восстанавливаю код...", "", "")
            threading.Thread(target=self._code_job, args=(self._request, node), daemon=True,
                             name="decompile-code").start()
        else:
            self._show(*decompile.decompile(node))

    def _code_job(self, request: int, node: unpack.Node, bytecode: bool = False) -> None:
        try:
            if bytecode:
                text, lang, note = decompile.python_bytecode(Path(node.path))
            else:
                text, lang, note = decompile.decompile(node)
        except Exception as e:
            text, lang, note = f"Ошибка: {type(e).__name__}: {e}", "", ""
        self.bridge.code.emit(request, text, lang, note)

    def _functions_job(self, node: unpack.Node) -> None:
        try:
            nodes, summary = decompile.native_functions(node)
        except Exception as e:
            nodes, summary = [], f"Анализ функций не удался: {type(e).__name__}: {e}"
        self.bridge.functions.emit(node, nodes, summary)

    def _on_functions(self, node: unpack.Node, nodes: list, summary: str) -> None:
        item = self._items.get(id(node))
        if item is None:                   # файл в анализаторе уже другой
            return
        if nodes:
            group = unpack.Node(f"Функции ({len(nodes)})", "folder",
                                note="Код каждой функции на C — декомпилятор Ghidra")
            group.children = nodes
            node.children.insert(0, group)
            group_item = self._add(None, group)
            self.tree.takeTopLevelItem(self.tree.indexOfTopLevelItem(group_item))
            item.insertChild(0, group_item)
            group_item.setExpanded(True)
            item.setExpanded(True)
        if self._node(self.tree.currentItem()) is node:
            self._show(decompile.describe(node) + "\n\n" + summary +
                       ("\nВыберите функцию в дереве: первыми — точка входа и main."
                        if nodes else ""), "", "")

    def _on_code(self, request: int, text: str, lang: str, note: str) -> None:
        if request == self._request:
            self._show(text, lang, note)

    def _show(self, text: str, lang: str, note: str) -> None:
        if self._highlighter is not None:
            self._highlighter.setDocument(None)
            self._highlighter = None
        self.code.setPlainText(text)
        if lang:
            self._highlighter = Highlighter(self.code.document(), lang)
        self.note.setText(note)
        self.note.setVisible(bool(note))

    # ---------- меню
    def _menu(self, pos) -> None:
        item = self.tree.itemAt(pos)
        node = self._node(item)
        if node is None:
            return
        menu = QMenu(self)
        menu.addAction("Описание", lambda: self._details(item))
        if node.path and node.kind != "root":
            menu.addAction("Открыть в анализаторе", lambda: self._open(node))
            menu.addAction("Сохранить файл как...", lambda: self._save(node))
            menu.addAction("Показать в проводнике", lambda: self._reveal(node))
        menu.exec(self.tree.viewport().mapToGlobal(pos))

    def _details(self, item) -> None:
        node = self._node(item)
        if node is None:
            return
        from ui.details import show_details
        rows = [("Часть файла", node.name), ("Что это", unpack.KIND_TEXT.get(node.kind, node.kind)),
                ("Размер", f"{node.size:,} байт".replace(",", " ") if node.size else ""),
                ("Проверка", node.verdict or ("Чисто" if node.level == "clean" else "")),
                ("Пояснение", node.note), ("Тип .NET", node.ref), ("Извлечён в", node.path)]
        actions = []
        if node.path and node.kind != "root":
            actions = [("Открыть в анализаторе", lambda: self._open(node)),
                       ("Показать в проводнике", lambda: self._reveal(node))]
        show_details(self, "Описание", [(k, v) for k, v in rows if v], actions)

    def _open(self, node: unpack.Node) -> None:
        from ui.details import main_window
        window = main_window()
        if window is not None:
            window.open_analyzer(node.path)

    def _save(self, node: unpack.Node) -> None:
        target, _ = QFileDialog.getSaveFileName(self, "Сохранить извлечённый файл",
                                                Path(node.path).name)
        if target:
            shutil.copyfile(node.path, target)

    def _reveal(self, node: unpack.Node) -> None:
        from processmanager.system import open_in_explorer
        open_in_explorer(node.path)

    def _bytecode(self, node: unpack.Node) -> None:
        self._request += 1
        self._show("Читаю байт-код...", "", "")
        threading.Thread(target=self._code_job, args=(self._request, node, True),
                         daemon=True).start()
