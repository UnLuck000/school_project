import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QCheckBox, QHBoxLayout, QMainWindow, QMenu, QMessageBox, QPushButton, QTabWidget,
    QVBoxLayout, QWidget,
)

from autoruns import actions
from autoruns.model import KIND_TITLES, LEVEL_TEXT, LEVELS, Entry
from autoruns.scanner import Context, assess, collect_all
from processmanager.colors import text_color
from processmanager.memscan import get_rules
from processmanager.system import is_admin, open_in_explorer
from scanner import exclusions, pool as scan_pool
from scanner.hashing import load_all_signatures
from scanner.whitelist import trusted_hashes
from ui.textutil import elide
from ui.widgets import SortItem, make_tree

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

TAB_ALL, TAB_REGISTRY, TAB_STARTUP, TAB_TASKS, TAB_SERVICES = range(5)
# какие записи показывает каждая вкладка
VIEWS = [
    ("all", lambda e: True),
    ("run", lambda e: e.kind == "run" and not e.location.endswith("RunOnce")),
    ("runonce", lambda e: e.kind == "run" and e.location.endswith("RunOnce")),
    ("winlogon", lambda e: e.kind == "winlogon"),
    ("startup", lambda e: e.kind == "startup"),
    ("tasks", lambda e: e.kind == "task"),
    ("services", lambda e: e.kind == "service"),
]
# что скрывает галочка «Скрывать проверенное»
HIDE_RULES = {
    "all": lambda e: e.level == "normal",
    "services": lambda e: e.level == "normal",
    "tasks": lambda e: e.level == "normal" and e.name.lower().startswith("\\microsoft\\"),
}


class Bridge(QObject):
    entries = Signal(object)
    updated = Signal(str)
    progress = Signal(str)
    done = Signal(object)


class RankItem(SortItem):
    """Строка с сортировкой по числовому рангу (риск)."""
    SORT_ROLE = RANK_ROLE



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

    def __init__(self, accepts, hide_rule=None):
        super().__init__()
        self.accepts = accepts
        self.hide_rule = hide_rule
        self.hide_enabled = hide_rule is not None  # по умолчанию проверенное скрыто
        self.items: dict[str, RankItem] = {}
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.tree = make_tree(COLUMNS, [110, 150, 230, 380, 220, 220, 300])
        self.tree.setSortingEnabled(True)
        self.tree.sortByColumn(0, Qt.SortOrder.DescendingOrder)  # сначала самые опасные
        self.tree.itemSelectionChanged.connect(self.selection_changed.emit)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(
            lambda pos: self.context_requested.emit(self, pos))
        layout.addWidget(self.tree)

    def _is_hidden(self, e: Entry) -> bool:
        return self.hide_enabled and self.hide_rule is not None and self.hide_rule(e)

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
        item.setHidden(self._is_hidden(e))

    def refresh(self, e: Entry) -> None:
        item = self.items.get(e.key)
        if item is not None:
            fill_item(item, e)
            item.setHidden(self._is_hidden(e))

    def remove(self, key: str) -> None:
        item = self.items.pop(key, None)
        if item is not None:
            index = self.tree.indexOfTopLevelItem(item)
            if index >= 0:
                self.tree.takeTopLevelItem(index)

    def set_hide(self, enabled: bool, entries: dict) -> None:
        self.hide_enabled = enabled
        for key, item in self.items.items():
            item.setHidden(self._is_hidden(entries[key]))

    def selected_keys(self) -> list[str]:
        """Ключи выделенных строк (текущая строка первой)."""
        items = self.tree.selectedItems()
        current = self.tree.currentItem()
        if current in items:
            items.remove(current)
            items.insert(0, current)
        return [item.data(0, KEY_ROLE) for item in items]


class AutorunsWindow(QMainWindow):
    quarantine_changed = Signal()
    analyze_requested = Signal(str)
    journal_changed = Signal()
    exclusions_changed = Signal()

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

        self.views = {key: EntryView(accepts, HIDE_RULES.get(key)) for key, accepts in VIEWS}
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
        self.main_tabs.addTab(self.views["services"], "Службы")
        layout.addWidget(self.main_tabs, 1)
        self.main_tabs.currentChanged.connect(lambda _: self._update_buttons())
        self.reg_tabs.currentChanged.connect(lambda _: self._update_buttons())
        self.setCentralWidget(root)

        if is_admin():
            self.statusBar().showMessage("Нажмите «Сканировать всё»")
        else:
            self.statusBar().showMessage(
                "Без прав администратора часть задач и записей недоступна для чтения и изменения")
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
        self.btn_trust = QPushButton("Доверять (в исключения)")
        self.btn_trust.clicked.connect(self.trust_selected)
        self.btn_folder = QPushButton("Папка файла")
        self.btn_folder.clicked.connect(self.open_folder)
        self.btn_analyze = QPushButton("Открыть в анализаторе")
        self.btn_analyze.clicked.connect(self.analyze_selected)
        self.hide_cb = QCheckBox("Скрывать проверенное")
        self.hide_cb.setToolTip("Вкладки «Всё» и «Службы»: записи с нормальной оценкой. "
                                "«Планировщик заданий»: проверенные задачи Microsoft.")
        self.hide_cb.setChecked(True)
        self.hide_cb.toggled.connect(self._toggle_hide)
        for w in (self.btn_scan, self.btn_fix, self.btn_quarantine, self.btn_trust,
                  self.btn_folder, self.btn_analyze, self.hide_cb):
            row.addWidget(w)
        row.addStretch()
        return row

    def _toggle_hide(self, enabled: bool) -> None:
        for view in self.views.values():
            if view.hide_rule is not None:
                view.set_hide(enabled, self.entries)

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
        if index == TAB_SERVICES:
            return self.views["services"]
        return None

    def selected_entries(self) -> list[Entry]:
        view = self._current_view()
        keys = view.selected_keys() if view else []
        return [self.entries[k] for k in keys if k in self.entries]

    def selected_entry(self) -> Entry | None:
        entries = self.selected_entries()
        return entries[0] if entries else None

    def _update_buttons(self) -> None:
        selected = self.selected_entries()
        e = selected[0] if selected else None
        if e is None:
            allowed, reason, q_allowed, q_reason = False, "Выберите запись в списке", False, ""
            self.btn_fix.setText("Отключить / удалить")
        elif len(selected) == 1:
            allowed, reason = actions.can_remediate(e)
            q_allowed, q_reason = actions.can_quarantine(e)
            self.btn_fix.setText(actions.REMEDIATION.get(e.kind, ("Исправить", ""))[0])
        else:  # несколько записей: кнопка доступна, если подходит хотя бы одна
            fixable = sum(1 for x in selected if actions.can_remediate(x)[0])
            files = sum(1 for x in selected if actions.can_quarantine(x)[0])
            allowed, q_allowed = fixable > 0, files > 0
            reason = f"Подходит записей: {fixable} из {len(selected)}"
            q_reason = f"Подходит файлов: {files} из {len(selected)}"
            self.btn_fix.setText(f"Отключить / удалить ({fixable})")
        has_file = len(selected) == 1 and bool(e.exe) and os.path.isfile(e.exe)
        self.btn_fix.setEnabled(allowed)
        self.btn_fix.setToolTip(reason)
        self.btn_quarantine.setEnabled(q_allowed)
        self.btn_quarantine.setToolTip(q_reason)
        self.btn_trust.setEnabled(any(x.assessed for x in selected))
        self.btn_folder.setEnabled(has_file)
        self.btn_analyze.setEnabled(has_file)

    def _show_menu(self, view: EntryView, pos) -> None:
        menu = QMenu(self)
        for button in (self.btn_fix, self.btn_quarantine, self.btn_trust,
                       self.btn_folder, self.btn_analyze):
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
        self.main_tabs.setTabText(TAB_SERVICES, f"Службы ({n['services']})")

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
        entries, notes = collect_all(self.bridge.progress.emit)

        data = exclusions.load()  # записи из исключений не показываем и не проверяем
        kept = [e for e in entries
                if not exclusions.matches(data, "autoruns", exclusions.entry_key(e),
                                          exclusions.fingerprint(e.exe))]
        if len(kept) != len(entries):
            notes.append(f"Скрыто исключений: {len(entries) - len(kept)}")
        entries = kept

        self.bridge.entries.emit(entries)
        self.bridge.progress.emit(f"Найдено записей: {len(entries)}. Проверяю файлы и подписи...")
        ctx = Context(load_all_signatures(SIG_DIR), get_rules("all"), trusted_hashes())
        # файлы проверяются в рабочих процессах (интерфейс не тормозит), подписи — здесь
        exes = sorted({e.exe for e in entries if e.exe and os.path.isfile(e.exe)})
        for path, reason, error in scan_pool.check_files(exes, ctx.signatures, ctx.rules,
                                                         ctx.whitelist, cancel=self._stop):
            ctx.verdicts[path] = "" if error is not None else reason or ""

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

    def _drop_entry(self, key: str) -> Entry | None:
        for view in self.views.values():
            view.remove(key)
        entry = self.entries.pop(key, None)
        self._update_titles()
        self._update_buttons()
        return entry

    def _remove_row(self, key: str) -> None:
        entry = self._drop_entry(key)
        if entry is not None:
            self.removed[key] = entry  # запоминаем: откат из журнала вернёт запись в список

    def handle_undo(self, record: dict) -> None:
        """Вызывается главным окном, когда в журнале отменено действие."""
        self._after_undo(record)

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

    # ---------- действия ----------
    @staticmethod
    def _names(entries: list[Entry], limit: int = 10) -> str:
        lines = "\n".join(f"• {elide(e.name)}" for e in entries[:limit])
        if len(entries) > limit:
            lines += f"\n...и ещё {len(entries) - limit}"
        return lines

    def _report(self, title: str, done: int, errors: list[str]) -> None:
        if errors:
            QMessageBox.warning(
                self, title, f"Выполнено: {done}. Не удалось: {len(errors)}\n\n"
                + "\n".join(errors[:10]) + "\n\nВозможно, нужны права администратора.")

    def fix_selected(self) -> None:
        selected = self.selected_entries()
        entries = [e for e in selected if actions.can_remediate(e)[0]]
        if not entries:
            if selected:
                QMessageBox.information(self, "Автозапуск", actions.can_remediate(selected[0])[1])
            return
        if len(entries) == 1:
            e = entries[0]
            title, text = actions.REMEDIATION[e.kind]
            question = f"{e.name}\n{e.command}\n\n{text}\n\nВыполнить?"
        else:
            title = "Отключить / удалить"
            question = (f"Отключить или удалить записей: {len(entries)}?\n\n{self._names(entries)}"
                        "\n\nКаждое действие попадёт в журнал и отменяется отдельно.")
        if QMessageBox.question(self, title, question) != QMessageBox.StandardButton.Yes:
            return
        errors, message = [], ""
        for e in entries:
            try:
                message = actions.remediate(e)
            except OSError as exc:  # включает PermissionError и ошибки реестра
                errors.append(f"{e.name}: {exc}")
                continue
            e.flags.append(FLAG_DONE)
            if e.kind in REMOVE_ROW_KINDS:
                self._remove_row(e.key)  # запись исчезает из всех списков сразу
            else:
                e.enabled = False        # задача остаётся в списке как отключённая
                self._refresh_entry(e)
        done = len(entries) - len(errors)
        if len(entries) > 1:
            message = f"Отключено или удалено записей: {done}"
        if done:
            self.statusBar().showMessage(message, 10000)
            self.journal_changed.emit()
        self._report(title, done, errors)
        self._update_buttons()

    def quarantine_selected(self) -> None:
        selected = self.selected_entries()
        entries, seen = [], set()
        for e in selected:  # один файл может запускаться несколькими записями
            if actions.can_quarantine(e)[0] and os.path.normcase(e.exe) not in seen:
                seen.add(os.path.normcase(e.exe))
                entries.append(e)
        if not entries:
            if selected:
                QMessageBox.information(self, "Карантин файла",
                                        actions.can_quarantine(selected[0])[1])
            return
        files = "\n".join(e.exe for e in entries[:10])
        if len(entries) > 10:
            files += f"\n...и ещё {len(entries) - 10}"
        answer = QMessageBox.question(
            self, "Карантин файла",
            f"Переместить в карантин файлы ({len(entries)}):\n{files}\n\n"
            "Записи автозапуска останутся, поэтому обычно сначала отключают их. "
            "Вернуть файлы можно на странице «Журнал».")
        if answer != QMessageBox.StandardButton.Yes:
            return
        errors, message = [], ""
        for e in entries:
            try:
                message = actions.quarantine_target(e)
            except PermissionError:
                errors.append(f"{e.exe}: файл занят (программа запущена, завершите процесс)")
                continue
            except OSError as exc:
                errors.append(f"{e.exe}: {exc}")
                continue
            for other in selected:  # отметка у всех выделенных записей с этим файлом
                if os.path.normcase(other.exe) == os.path.normcase(e.exe):
                    if FLAG_QUARANTINED not in other.flags:
                        other.flags.append(FLAG_QUARANTINED)
                    self._refresh_entry(other)
        done = len(entries) - len(errors)
        if done:
            self.statusBar().showMessage(
                message if len(entries) == 1 else f"В карантин перемещено файлов: {done}", 10000)
            self.journal_changed.emit()
            self.quarantine_changed.emit()
        self._report("Карантин файла", done, errors)

    def trust_selected(self) -> None:
        entries = [e for e in self.selected_entries() if e.assessed]
        if not entries:
            return
        what = (f"{elide(entries[0].name)}\n{elide(entries[0].command)}" if len(entries) == 1
                else f"Записей: {len(entries)}\n{self._names(entries)}")
        answer = QMessageBox.question(
            self, "Доверять записи",
            f"{what}\n\nДобавить в исключения? Записи не будут показываться при "
            "сканировании, пока не изменится их команда или файл. Управлять исключениями "
            "можно на странице «Исключения» главного окна.")
        if answer != QMessageBox.StandardButton.Yes:
            return
        for e in entries:
            exclusions.add("autoruns", exclusions.entry_key(e),
                           f"{KIND_TITLES[e.kind]}: {e.name}", e.command,
                           exclusions.fingerprint(e.exe))
            self._drop_entry(e.key)
        self.statusBar().showMessage(f"Добавлено в исключения: {len(entries)}", 8000)
        self.exclusions_changed.emit()

    def open_folder(self) -> None:
        e = self.selected_entry()
        if e is not None and e.exe and os.path.exists(e.exe):
            open_in_explorer(e.exe)

    def analyze_selected(self) -> None:
        e = self.selected_entry()
        if e is not None and e.exe and os.path.isfile(e.exe):
            self.analyze_requested.emit(e.exe)

    def shutdown(self) -> None:
        """Вызывается при закрытии главного окна."""
        self._stop.set()

    def closeEvent(self, event) -> None:
        self._stop.set()
        event.accept()
