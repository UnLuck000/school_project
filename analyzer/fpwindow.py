"""Окно «Ложные срабатывания»: разбор срабатываний по файлу или папке и ручная правка баз
(убрать хэш, отключить правило YARA, исключить программу из хэшей или YARA). Файлы можно не
искать вручную: «Найти по журналам» берёт всё, что находили защита, проверки дисков, контроль
запуска и мониторинг сети за 30 дней. Оценка, подпись и путь — в описании (двойной щелчок
или правая кнопка). Открывается с вкладки «Отладка»."""
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QMainWindow,
    QMenu, QMessageBox, QPushButton, QTabWidget, QTreeWidget, QTreeWidgetItem, QVBoxLayout,
    QWidget,
)

from analyzer import fileops
from analyzer.folderview import SCAN_WORKERS, rules_and_bases
from scanner import overrides
from scanner.fpcheck import LAYER_TEXT, Hit, explain_file, iter_files
from ui.textutil import elide

COLUMNS = [("Файл", 260), ("Слой", 80), ("Что сработало", 300), ("Источник", 200),
           ("Угроза сейчас", 110)]
LOG_DAYS = 30  # «Найти по журналам»: за сколько дней
HIT_ROLE = Qt.ItemDataRole.UserRole
COLORS = {"active": (231, 76, 60), "suppressed": (127, 140, 141)}


class _Bridge(QObject):
    hits = Signal(int, list)
    progress = Signal(int, int, int)  # запрос, проверено, срабатываний
    done = Signal(int, bool)


class FalsePositiveWindow(QMainWindow):
    journal_changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Ложные срабатывания")
        self.resize(1300, 700)
        self.bridge = _Bridge()
        self.bridge.hits.connect(self._on_hits)
        self.bridge.progress.connect(self._on_progress)
        self.bridge.done.connect(self._on_done)
        self._request = 0
        self._cancel = threading.Event()
        self._found = 0

        central = QWidget()
        layout = QVBoxLayout(central)
        hint = QLabel(
            "Проверяет файл или папку всеми слоями и показывает каждое срабатывание, даже "
            "подавленное подписью или исключением. Хэш, ошибочно попавший в базу, можно убрать: "
            "он перестанет срабатывать и после обновления баз. Правило YARA с ложными "
            "срабатываниями можно отключить. Всё пишется в журнал действий и отменяется оттуда.")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        row = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("Файл или папка")
        self.path_edit.returnPressed.connect(self.start)
        row.addWidget(self.path_edit, 1)
        for text, handler in (("Файл…", self._pick_file), ("Папка…", self._pick_folder)):
            button = QPushButton(text)
            button.clicked.connect(handler)
            row.addWidget(button)
        self.recursive_cb = QCheckBox("С подпапками")
        row.addWidget(self.recursive_cb)
        self.start_btn = QPushButton("Проверить")
        self.start_btn.clicked.connect(self.start)
        row.addWidget(self.start_btn)
        self.stop_btn = QPushButton("Стоп")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(lambda: self._cancel.set())  # всегда текущий запуск
        row.addWidget(self.stop_btn)
        layout.addLayout(row)

        presets = QHBoxLayout()
        presets.addWidget(QLabel("Заведомо чистые папки:"))
        windows = os.environ.get("SystemRoot", r"C:\Windows")
        for title, path, recursive in (
                ("System32", os.path.join(windows, "System32"), False),
                ("Windows", windows, False),
                ("Program Files", os.environ.get("ProgramFiles", r"C:\Program Files"), True)):
            button = QPushButton(title)
            button.clicked.connect(lambda checked=False, p=path, r=recursive: self.start(p, r))
            presets.addWidget(button)
        from_logs = QPushButton("Найти по журналам")
        from_logs.setToolTip(f"Файлы, которые за {LOG_DAYS} дней находили защита, проверки "
                             "дисков, контроль запуска и мониторинг сети")
        from_logs.clicked.connect(self.start_from_logs)
        presets.addWidget(from_logs)
        self.only_active_cb = QCheckBox("Только то, что сейчас считается угрозой")
        self.only_active_cb.toggled.connect(self._apply_filter)
        presets.addStretch()
        presets.addWidget(self.only_active_cb)
        layout.addLayout(presets)

        self.status = QLabel("Выберите файл или папку")
        layout.addWidget(self.status)

        self.tabs = QTabWidget()
        hits_tab = QWidget()
        hits_layout = QVBoxLayout(hits_tab)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels([name for name, _ in COLUMNS])
        for i, (_, width) in enumerate(COLUMNS):
            self.tree.setColumnWidth(i, width)
        self.tree.setRootIsDecorated(False)
        self.tree.setSortingEnabled(True)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.tree.itemDoubleClicked.connect(lambda *_: self.describe())
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._menu)
        hits_layout.addWidget(self.tree)
        actions = QHBoxLayout()
        for text, handler in (("Описание", self.describe),
                              ("Убрать хэш из базы", self.ignore_hashes),
                              ("Отключить правило", self.disable_rules),
                              ("Исключить программу", lambda: self.exclude_programs(None)),
                              ("Открыть в сканере", self._open_selected),
                              ("Показать в проводнике", self._show_selected)):
            button = QPushButton(text)
            button.clicked.connect(handler)
            actions.addWidget(button)
        actions.addStretch()
        hits_layout.addLayout(actions)
        self.tabs.addTab(hits_tab, "Срабатывания")

        excluded_tab = QWidget()
        excluded_layout = QVBoxLayout(excluded_tab)
        self.excluded = QTreeWidget()
        self.excluded.setHeaderLabels(["Что", "Значение", "Источник / слои", "Файл", "Когда"])
        for i, width in enumerate((110, 420, 170, 380, 150)):
            self.excluded.setColumnWidth(i, width)
        self.excluded.setRootIsDecorated(False)
        self.excluded.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        excluded_layout.addWidget(self.excluded)
        restore = QPushButton("Вернуть выбранное")
        restore.clicked.connect(self.restore_selected)
        row2 = QHBoxLayout()
        row2.addWidget(restore)
        row2.addStretch()
        excluded_layout.addLayout(row2)
        self.tabs.addTab(excluded_tab, "Убрано из баз")
        layout.addWidget(self.tabs, 1)
        self.setCentralWidget(central)
        self.refresh_excluded()

    # ---------- выбор и запуск ----------
    def _pick_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Файл")
        if path:
            self.path_edit.setText(os.path.normpath(path))

    def _pick_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Папка")
        if path:
            self.path_edit.setText(os.path.normpath(path))

    def start(self, path: str | None = None, recursive: bool | None = None):
        if isinstance(path, str):
            self.path_edit.setText(path)
        if recursive is not None:
            self.recursive_cb.setChecked(recursive)
        if not isinstance(path, str) and self.path_edit.text().startswith("Из журналов:"):
            self.start_from_logs()  # «Проверить» после «Найти по журналам» — то же самое
            return
        self._from_logs = False
        target = Path(self.path_edit.text().strip().strip('"'))
        if not target.exists():
            QMessageBox.warning(self, "Ложные срабатывания", "Файл или папка не найдены")
            return
        self._cancel.set()
        self._cancel = threading.Event()
        self._request += 1
        self._found = 0
        self.tree.clear()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status.setText("Загружаю базы и проверяю...")
        threading.Thread(target=self._job, daemon=True,
                         args=(self._request, target, self.recursive_cb.isChecked(),
                               self._cancel)).start()

    def start_from_logs(self):
        """Проверить всё, что находили защита и сеть: журнал защиты и события за LOG_DAYS дней."""
        self._from_logs = True
        paths = found_in_logs()
        if not paths:
            QMessageBox.information(self, "Ложные срабатывания",
                                    f"За {LOG_DAYS} дней в журналах нет файлов, которые ещё на месте")
            return
        self._cancel.set()
        self._cancel = threading.Event()
        self._request += 1
        self.tree.clear()
        self.path_edit.setText(f"Из журналов: {len(paths)} файлов")
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status.setText(f"Проверяю файлы из журналов: {len(paths)}...")
        threading.Thread(target=self._job, daemon=True,
                         args=(self._request, None, False, self._cancel, paths)).start()

    def _job(self, request: int, target: Path | None, recursive: bool, cancel: threading.Event,
             paths: list[Path] | None = None):
        try:
            signatures, rules, _ = rules_and_bases()
        except OSError:
            self.bridge.hits.emit(request, [])
            self.bridge.done.emit(request, True)
            return

        def one(path: Path) -> list[Hit]:
            if cancel.is_set():
                return []
            try:
                return explain_file(path, signatures, rules)
            except OSError:
                return []

        checked = found = 0
        batch: list[Hit] = []
        files = paths if paths is not None else iter_files(target, recursive)
        with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as pool:
            for hits in pool.map(one, files):
                if cancel.is_set():
                    break
                checked += 1
                found += len(hits)
                batch.extend(hits)
                if checked % 50 == 0:
                    self.bridge.hits.emit(request, batch)
                    batch = []
                    self.bridge.progress.emit(request, checked, found)
        self.bridge.hits.emit(request, batch)
        self.bridge.progress.emit(request, checked, found)
        self.bridge.done.emit(request, cancel.is_set())

    # ---------- результаты ----------
    def _on_hits(self, request: int, hits: list):
        if request != self._request:
            return
        self.tree.setSortingEnabled(False)
        for hit in hits:
            item = QTreeWidgetItem([
                os.path.basename(hit.path), LAYER_TEXT.get(hit.layer, hit.layer),
                elide(hit.value, 80), hit.source, "да" if hit.active else "нет"])
            item.setData(0, HIT_ROLE, hit)
            item.setToolTip(0, hit.path)
            item.setToolTip(2, f"{hit.value}\n{hit.detail}".strip())
            color = QColor(*COLORS["active" if hit.active else "suppressed"])
            for col in range(len(COLUMNS)):
                item.setForeground(col, QBrush(color))
            self.tree.addTopLevelItem(item)
            item.setHidden(self.only_active_cb.isChecked() and not hit.active)
        self.tree.setSortingEnabled(True)

    def _on_progress(self, request: int, checked: int, found: int):
        if request == self._request:
            self.status.setText(f"Проверено файлов: {checked}, срабатываний: {found}")

    def _on_done(self, request: int, cancelled: bool):
        if request != self._request:
            return
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        active = sum(1 for i in range(self.tree.topLevelItemCount())
                     if self.tree.topLevelItem(i).data(0, HIT_ROLE).active)
        self.status.setText(self.status.text() + (" — остановлено" if cancelled else " — готово")
                            + f". Считаются угрозой сейчас: {active}")

    def _apply_filter(self):
        only = self.only_active_cb.isChecked()
        for i in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(i)
            item.setHidden(only and not item.data(0, HIT_ROLE).active)

    def _selected_hits(self) -> list[Hit]:
        return [item.data(0, HIT_ROLE) for item in self.tree.selectedItems()]

    # ---------- описание и меню ----------
    def _menu(self, pos):
        hits = self._selected_hits()
        if not hits:
            return
        menu = QMenu(self)
        menu.addAction("Описание", self.describe)
        menu.addSeparator()
        menu.addAction("Убрать хэш из базы", self.ignore_hashes).setEnabled(
            any(h.layer == "hash" and not h.excluded for h in hits))
        menu.addAction("Отключить правило YARA", self.disable_rules).setEnabled(
            any(h.layer == "yara" and not h.excluded for h in hits))
        sub = menu.addMenu("Исключить программу")
        sub.addAction("Из правил YARA", lambda: self.exclude_programs(["yara"]))
        sub.addAction("Из базы хэшей", lambda: self.exclude_programs(["hash"]))
        sub.addAction("Из YARA и хэшей", lambda: self.exclude_programs(["yara", "hash"]))
        menu.addSeparator()
        menu.addAction("Открыть в сканере", self._open_selected)
        menu.addAction("Показать в проводнике", self._show_selected)
        menu.exec(self.tree.viewport().mapToGlobal(pos))

    def describe(self):
        hits = self._selected_hits()
        if not hits:
            return
        hit = hits[0]
        from ui.details import show_details
        rows = [("Файл", hit.path), ("SHA-256", hit.sha256),
                ("Слой", LAYER_TEXT.get(hit.layer, hit.layer)), ("Что сработало", hit.value),
                ("Источник (база или правила)", hit.source), ("Подробности", hit.detail),
                ("Подпись", hit.signature),
                ("Связь с подписанной программой", hit.partner),
                ("Слабое срабатывание", "да (PUA, HackTool, эвристика...)" if hit.weak else "нет"),
                ("Исключено вручную", "да" if hit.excluded else "нет"),
                ("Считается угрозой сейчас", "да" if hit.active else "нет"),
                ("Оценка", hit.verdict)]
        actions = []
        if hit.layer == "hash" and not hit.excluded:
            actions.append(("Убрать хэш из базы", lambda d: self._ignore([hit])))
        if hit.layer == "yara" and not hit.excluded:
            actions.append(("Отключить правило", lambda d: self._disable({hit.value: hit.source})))
        if hit.layer in ("hash", "yara") and not hit.excluded:
            actions.append(("Исключить программу из этого слоя",
                            lambda d: self.exclude_programs([hit.layer], [hit])))
        actions += [("Открыть в сканере", lambda d: self._open_path(hit.path)),
                    ("Показать в проводнике", lambda d: fileops.show_in_explorer(hit.path))]
        show_details(self, f"Срабатывание: {os.path.basename(hit.path)}", rows, actions,
                     width=880)

    # ---------- действия ----------
    def exclude_programs(self, layers: list[str] | None, hits: list[Hit] | None = None):
        """Исключить файл (по SHA-256) из слоя хэшей и/или YARA: остальные слои действуют."""
        hits = hits or self._selected_hits()
        files = {h.sha256: h.path for h in hits if h.sha256}
        if not files:
            QMessageBox.information(self, "Исключить программу", "Выберите срабатывания")
            return
        if layers is None:
            layers = sorted({h.layer for h in hits if h.layer in ("hash", "yara")}) or ["yara"]
        what = " и ".join(overrides.FILE_LAYERS[x] for x in layers)
        names = "\n".join(f"• {os.path.basename(p)}" for p in list(files.values())[:10])
        answer = QMessageBox.question(
            self, "Исключить программу",
            f"Не проверять эти файлы по: {what}?\n\n{names}\n\nИсключение действует, пока "
            "файл не изменится (по SHA-256); эвристика и другие слои продолжают работать. "
            "Отменить можно в журнале действий или на вкладке «Убрано из баз».")
        if answer != QMessageBox.StandardButton.Yes:
            return
        for digest, path in files.items():
            overrides.exclude_file(digest, path, layers)
        self._after_change()

    def _ignore(self, hits):
        for h in hits:
            overrides.ignore_hash(h.value, h.path, h.source)
        self._after_change()

    def _disable(self, rules: dict):
        for name, source in rules.items():
            overrides.disable_rule(name, source)
        self._after_change()

    def ignore_hashes(self):
        hits = [h for h in self._selected_hits() if h.layer == "hash" and not h.excluded]
        if not hits:
            QMessageBox.information(self, "Убрать хэш", "Выберите строки со слоем «Хэш»")
            return
        names = "\n".join(f"• {os.path.basename(h.path)} ({h.source})" for h in hits[:10])
        answer = QMessageBox.question(
            self, "Убрать хэш из базы",
            f"Убрать из базы хэшей ({len(hits)})?\n\n{names}\n\nФайлы с этими хэшами больше "
            "не будут считаться угрозой, в том числе после обновления баз. Отменить можно "
            "в журнале действий или на вкладке «Убрано из баз».")
        if answer != QMessageBox.StandardButton.Yes:
            return
        for h in hits:
            overrides.ignore_hash(h.value, h.path, h.source)
        self._after_change()

    def disable_rules(self):
        rules = {}
        for h in self._selected_hits():
            if h.layer == "yara" and not h.excluded:
                rules.setdefault(h.value, h.source)
        if not rules:
            QMessageBox.information(self, "Отключить правило", "Выберите строки со слоем «YARA»")
            return
        answer = QMessageBox.question(
            self, "Отключить правило",
            "Отключить правила YARA?\n\n" + "\n".join(f"• {n} ({s})" for n, s in rules.items())
            + "\n\nПравило перестанет срабатывать на всех файлах и в памяти процессов.")
        if answer != QMessageBox.StandardButton.Yes:
            return
        for name, source in rules.items():
            overrides.disable_rule(name, source)
        self._after_change()

    def _after_change(self):
        self.refresh_excluded()
        self.journal_changed.emit()
        # оценки в таблице пересчитываются повторной проверкой того же, что проверялось
        # (после «Найти по журналам» в поле пути — подпись, а не путь)
        if getattr(self, "_from_logs", False):
            self.start_from_logs()
        elif self.path_edit.text().strip():
            self.start()

    def refresh_excluded(self):
        self.excluded.clear()
        data = overrides.load()
        for digest, info in data["hashes"].items():
            item = QTreeWidgetItem(["Хэш", digest, info.get("source", ""), info.get("path", ""),
                                    info.get("added_at", "").replace("T", " ")])
            item.setData(0, HIT_ROLE, ("hash", digest))
            self.excluded.addTopLevelItem(item)
        for name, info in data["rules"].items():
            item = QTreeWidgetItem(["Правило YARA", name, info.get("source", ""), "",
                                    info.get("added_at", "").replace("T", " ")])
            item.setData(0, HIT_ROLE, ("rule", name))
            self.excluded.addTopLevelItem(item)
        for digest, info in data.get("files", {}).items():
            layers = ", ".join(overrides.FILE_LAYERS.get(x, x) for x in info.get("layers", []))
            item = QTreeWidgetItem(["Программа", digest, layers, info.get("path", ""),
                                    info.get("added_at", "").replace("T", " ")])
            item.setData(0, HIT_ROLE, ("file", digest))
            self.excluded.addTopLevelItem(item)

    def restore_selected(self):
        chosen = [item.data(0, HIT_ROLE) for item in self.excluded.selectedItems()]
        if not chosen:
            return
        for kind, value in chosen:
            if kind == "hash":
                overrides.restore_hash(value)
            elif kind == "file":
                overrides.include_file(value)
            else:
                overrides.enable_rule(value)
        self.refresh_excluded()
        self.journal_changed.emit()

    def _open_selected(self):
        hits = self._selected_hits()
        if hits:
            self._open_path(hits[0].path)

    @staticmethod
    def _open_path(path: str):
        from ui.details import main_window
        main = main_window()
        if main is not None:
            main.open_analyzer(path)
            main.show_main()

    def _show_selected(self):
        hits = self._selected_hits()
        if hits:
            fileops.show_in_explorer(hits[0].path)

    def closeEvent(self, event):
        self._cancel.set()
        super().closeEvent(event)


def found_in_logs(days: int = LOG_DAYS) -> list[Path]:
    """Файлы, которые находили защита (журнал защиты), проверки дисков, контроль запуска и
    мониторинг сети (события recovery/activity) за days дней — только те, что ещё на месте."""
    import time
    from recovery import activity, threatlog
    seen, result = set(), []

    def add(path: str):
        path = (path or "").strip().strip('"')
        key = os.path.normcase(path)
        if path and key not in seen and os.path.isfile(path):
            seen.add(key)
            result.append(Path(path))

    for r in threatlog.merged(include_done=True):
        if r["status"] != threatlog.DELETED:
            add(r.get("path", ""))
    for e in activity.read_events(since=time.time() - days * 86400):
        details = e.get("details") or {}
        if details.get("exe"):
            add(details["exe"])
        if e.get("kind") in ("threat", "launch"):
            add(e.get("text", "").split(": ")[0])
        for line in details.get("found") or []:
            add(str(line).split(": ")[0])
    return result
