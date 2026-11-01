from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox, QHBoxLayout, QLabel, QPushButton, QSplitter, QTreeWidgetItem, QVBoxLayout,
    QWidget,
)

from recovery.panels import LEVEL_COLORS, _hint, _make_tree, _paint

INDEX_ROLE = Qt.ItemDataRole.UserRole + 1
LEVEL_TEXT = {"ok": "В порядке", "warning": "Внимание", "bad": "Перехват"}


class AssocPanel(QWidget):
    """Файловые ассоциации: проверка критичных расширений, снимки и восстановление."""
    check_requested = Signal()
    fix_requested = Signal(object)        # список AssocIssue
    exclude_requested = Signal(object)    # AssocIssue
    snapshot_requested = Signal()
    compare_requested = Signal(object)    # путь к снимку
    restore_requested = Signal(object)    # список AssocDiff

    def __init__(self):
        super().__init__()
        self._issues: list = []
        self._diffs: list = []
        self.checked_once = False
        layout = QVBoxLayout(self)
        layout.addWidget(_hint(
            "Ассоциация определяет, какая программа открывает файл. Вредоносные программы "
            "перехватывают запуск .exe, .bat, .lnk и других файлов через HKCU (права "
            "администратора для этого не нужны). Снимок сохраняет текущие ассоциации, чтобы "
            "позже сравнить и вернуть их. Все изменения пишутся в журнал и отменяются."))

        splitter = QSplitter(Qt.Orientation.Vertical)

        top = QWidget()
        top_layout = QVBoxLayout(top)
        top_layout.setContentsMargins(0, 0, 0, 0)
        row = QHBoxLayout()
        self.btn_check = QPushButton("Проверить критичные расширения")
        self.btn_check.clicked.connect(self.check_requested.emit)
        self.issue_summary = QLabel("")
        self.btn_trust = QPushButton("Доверять (в исключения)")
        self.btn_trust.clicked.connect(self._on_trust)
        self.btn_fix = QPushButton("Исправить выбранное")
        self.btn_fix.clicked.connect(self._on_fix)
        self.btn_fix_all = QPushButton("Исправить все перехваты")
        self.btn_fix_all.clicked.connect(self._on_fix_all)
        row.addWidget(self.btn_check)
        row.addWidget(self.issue_summary, 1)
        for b in (self.btn_trust, self.btn_fix, self.btn_fix_all):
            row.addWidget(b)
        top_layout.addLayout(row)
        self.issues_tree = _make_tree(["Расширение", "Состояние", "Проверка", "Подробности"],
                                      [100, 110, 330, 600])
        self.issues_tree.itemSelectionChanged.connect(self._update_buttons)
        top_layout.addWidget(self.issues_tree, 1)
        splitter.addWidget(top)

        bottom = QWidget()
        bottom_layout = QVBoxLayout(bottom)
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        row = QHBoxLayout()
        row.addWidget(QLabel("Снимок:"))
        self.snapshots = QComboBox()
        self.snapshots.setMinimumWidth(300)
        self.btn_snapshot = QPushButton("Сделать снимок")
        self.btn_snapshot.clicked.connect(self.snapshot_requested.emit)
        self.btn_compare = QPushButton("Сравнить с текущим")
        self.btn_compare.clicked.connect(self._on_compare)
        self.btn_restore = QPushButton("Восстановить отмеченное")
        self.btn_restore.clicked.connect(self._on_restore)
        row.addWidget(self.snapshots, 1)
        for b in (self.btn_snapshot, self.btn_compare, self.btn_restore):
            row.addWidget(b)
        bottom_layout.addLayout(row)
        self.diff_summary = QLabel("Выберите снимок и нажмите «Сравнить с текущим»")
        self.diff_summary.setWordWrap(True)
        bottom_layout.addWidget(self.diff_summary)
        self.diff_tree = _make_tree(["Расширение", "Что изменилось", "В снимке", "Сейчас"],
                                    [110, 330, 330, 330])
        bottom_layout.addWidget(self.diff_tree, 1)
        splitter.addWidget(bottom)
        splitter.setSizes([300, 300])
        layout.addWidget(splitter, 1)
        self.busy_buttons = [self.btn_check, self.btn_fix_all, self.btn_snapshot,
                             self.btn_compare, self.btn_restore]
        self._update_buttons()

    # ---------- проверка ----------
    def set_issues(self, issues: list) -> None:
        self.checked_once = True
        self._issues = issues
        self.issues_tree.clear()
        order = {"bad": 0, "warning": 1, "ok": 2}
        for index, issue in sorted(enumerate(issues), key=lambda x: order[x[1].level]):
            item = QTreeWidgetItem([issue.ext, LEVEL_TEXT[issue.level], issue.title,
                                    issue.detail])
            item.setData(0, INDEX_ROLE, index)
            item.setToolTip(3, issue.detail)
            _paint(item, LEVEL_COLORS[issue.level], 4)
            self.issues_tree.addTopLevelItem(item)
        problems = [i for i in issues if i.level != "ok"]
        self.issue_summary.setText(f"Найдено проблем: {len(problems)}" if problems
                                   else "Перехватов не найдено")
        self._update_buttons()

    def _selected_issue(self):
        items = self.issues_tree.selectedItems()
        return self._issues[items[0].data(0, INDEX_ROLE)] if items else None

    def _update_buttons(self) -> None:
        issue = self._selected_issue()
        self.btn_fix.setEnabled(issue is not None and bool(issue.ops))
        self.btn_trust.setEnabled(issue is not None and issue.level != "ok")
        self.btn_fix_all.setEnabled(any(i.ops for i in self._issues))

    def _on_fix(self) -> None:
        issue = self._selected_issue()
        if issue is not None and issue.ops:
            self.fix_requested.emit([issue])

    def _on_fix_all(self) -> None:
        issues = [i for i in self._issues if i.ops]
        if issues:
            self.fix_requested.emit(issues)

    def _on_trust(self) -> None:
        issue = self._selected_issue()
        if issue is not None:
            self.exclude_requested.emit(issue)

    # ---------- снимки ----------
    def set_snapshots(self, snapshots: list) -> None:
        current = self.snapshots.currentData()
        self.snapshots.clear()
        for path, time, comment, count in snapshots:
            text = time.replace("T", " ") + (f" ({comment})" if comment else "")
            self.snapshots.addItem(f"{text}, расширений: {count}", path)
        index = self.snapshots.findData(current)
        if index >= 0:
            self.snapshots.setCurrentIndex(index)
        self.btn_compare.setEnabled(bool(snapshots))

    def _on_compare(self) -> None:
        path = self.snapshots.currentData()
        if path is not None:
            self.compare_requested.emit(path)

    def set_diffs(self, diffs: list) -> None:
        self._diffs = diffs
        self.diff_tree.clear()
        for index, d in enumerate(diffs):
            item = QTreeWidgetItem([d.ext, d.field, d.before, d.now])
            item.setData(0, INDEX_ROLE, index)
            for col, text in enumerate((d.ext, d.field, d.before, d.now)):
                item.setToolTip(col, d.note or text)
            if d.restorable:
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                item.setCheckState(0, Qt.CheckState.Checked)
                _paint(item, LEVEL_COLORS["warning"], 4)
            else:
                _paint(item, LEVEL_COLORS["info"], 4)
            self.diff_tree.addTopLevelItem(item)
        restorable = sum(1 for d in diffs if d.restorable)
        if not diffs:
            self.diff_summary.setText("Отличий от снимка нет")
        else:
            self.diff_summary.setText(
                f"Отличий: {len(diffs)}, можно восстановить: {restorable}. Отмеченные строки "
                "вернутся к состоянию снимка. Синие строки восстанавливаются вручную "
                "(подсказка при наведении).")
        self.btn_restore.setEnabled(restorable > 0)

    def _on_restore(self) -> None:
        chosen = []
        for i in range(self.diff_tree.topLevelItemCount()):
            item = self.diff_tree.topLevelItem(i)
            d = self._diffs[item.data(0, INDEX_ROLE)]
            if d.restorable and item.checkState(0) == Qt.CheckState.Checked:
                chosen.append(d)
        if chosen:
            self.restore_requested.emit(chosen)
