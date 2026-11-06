"""Окно «USB-накопители»: проверка флешки и её восстановление после вируса-ярлыка."""
import threading

from PySide6.QtCore import QObject, QUrl, Signal
from PySide6.QtGui import QBrush, QColor, QDesktopServices
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QHBoxLayout, QLabel, QMainWindow, QMessageBox, QPushButton,
    QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from processmanager.colors import text_color
from recovery import activity
from usbguard import repair
from usbguard.scan import DriveReport, add_program_verdicts, removable_drives, scan_drive, \
    sort_findings

LEVELS = {"threat": ("Угроза", (255, 128, 128)), "suspicious": ("Проверить", (255, 190, 110)),
          "info": ("Сведения", None)}
FIXES = {"quarantine": "в карантин", "unhide": "показать (снять «скрытый»)",
         "restore_folder": "вернуть файлы в корень", "": "—"}


def check_drive(root: str, label: str = "", cancel: threading.Event | None = None) -> DriveReport:
    """Полная проверка: структура флешки и программы на ней — сканером (scanner.pool)."""
    from analyzer.folderview import rules_and_bases
    from scanner import pool as scan_pool
    report = scan_drive(root, label)
    if report.programs:
        try:
            signatures, rules, whitelist = rules_and_bases()
            results = list(scan_pool.check_files(report.programs[:500], signatures, rules,
                                                 whitelist, cancel=cancel))
            add_program_verdicts(report, results)
        except OSError as e:
            report.error = f"Программы не проверены: {e}"
    sort_findings(report)
    return report


def auto_fixes(report: DriveReport) -> list:
    """Что защита исправляет сама: только при явном вирусе-ярлыке (есть угрозы) —
    угрозы в карантин и файлы из папки без имени обратно. Подозрительное — на усмотрение
    пользователя в инструменте «USB-накопители»."""
    if not report.infected:
        return []
    return [f for f in report.findings
            if (f.level == "threat" and f.fix) or f.fix == "restore_folder"]


def summary(report: DriveReport) -> str:
    threats = sum(f.level == "threat" for f in report.findings)
    suspicious = sum(f.level == "suspicious" for f in report.findings)
    name = f"{report.root[:2]} {report.label}".strip()
    if threats:
        return f"{name}: найдено угроз — {threats}, подозрительного — {suspicious}"
    if suspicious:
        return f"{name}: подозрительного — {suspicious}"
    return f"{name}: угроз не найдено"


class _Bridge(QObject):
    done = Signal(object)


class UsbWindow(QMainWindow):
    journal_changed = Signal()
    quarantine_changed = Signal()

    def __init__(self):
        super().__init__()
        self.setWindowTitle("USB-накопители")
        self.resize(1000, 560)
        self.report: DriveReport | None = None
        self._busy = False
        self.bridge = _Bridge()
        self.bridge.done.connect(self._on_done)

        root = QWidget()
        layout = QVBoxLayout(root)
        hint = QLabel(
            "Вирус-ярлык прячет файлы флешки в скрытую папку, а вместо них оставляет ярлык, "
            "который запускает вирус и открывает спрятанные файлы. Здесь можно найти такой "
            "ярлык, скрипты вируса и autorun.inf, убрать их в карантин и вернуть файлы на "
            "место. Все действия записываются в журнал и отменяются.")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        row = QHBoxLayout()
        self.drives = QComboBox()
        self.drives.setMinimumWidth(220)
        refresh = QPushButton("Обновить список")
        refresh.clicked.connect(self.refresh_drives)
        self.btn_check = QPushButton("Проверить")
        self.btn_check.clicked.connect(self.check)
        self.btn_open = QPushButton("Открыть флешку")
        self.btn_open.clicked.connect(self._open_drive)
        for w in (QLabel("Накопитель:"), self.drives, refresh, self.btn_check, self.btn_open):
            row.addWidget(w)
        row.addStretch()
        layout.addLayout(row)

        self.status = QLabel("Выберите накопитель и нажмите «Проверить»")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Уровень", "Что найдено", "Путь", "Подробности", "Действие"])
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.tree.setRootIsDecorated(False)
        for col, width in enumerate((90, 330, 260, 260)):
            self.tree.setColumnWidth(col, width)
        layout.addWidget(self.tree, 1)

        actions = QHBoxLayout()
        self.btn_cure = QPushButton("Вылечить флешку")
        self.btn_cure.setToolTip("Угрозы — в карантин, файлы из скрытой папки — обратно в "
                                 "корень, скрытые файлы и папки — показать.")
        self.btn_cure.clicked.connect(self.cure)
        self.btn_selected = QPushButton("Исправить выбранное")
        self.btn_selected.clicked.connect(self.fix_selected)
        self.btn_vaccine = QPushButton("Защитить от autorun")
        self.btn_vaccine.setToolTip("Создать на флешке скрытую папку autorun.inf: вирус не "
                                    "сможет записать одноимённый файл автозапуска.")
        self.btn_vaccine.clicked.connect(self.vaccinate)
        for w in (self.btn_cure, self.btn_selected, self.btn_vaccine):
            actions.addWidget(w)
        actions.addStretch()
        layout.addLayout(actions)
        self.setCentralWidget(root)
        self.refresh_drives()

    # ---------- список и проверка ----------
    def refresh_drives(self) -> None:
        current = self.drives.currentData()
        self.drives.clear()
        for root, label in removable_drives():
            self.drives.addItem(f"{root[:2]}  {label or 'без метки'}", (root, label))
        if current:
            index = self.drives.findData(current)
            if index >= 0:
                self.drives.setCurrentIndex(index)
        if not self.drives.count():
            self.status.setText("Съёмных накопителей не найдено. Подключите флешку и нажмите "
                                "«Обновить список».")
        self._update_buttons()

    def show_drive(self, root: str, report: DriveReport | None = None) -> None:
        self.refresh_drives()
        for i in range(self.drives.count()):
            if self.drives.itemData(i)[0] == root:
                self.drives.setCurrentIndex(i)
        if report is not None:
            self._on_done(report)
        else:
            self.check()

    def check(self) -> None:
        data = self.drives.currentData()
        if not data or self._busy:
            return
        self._busy = True
        self._update_buttons()
        self.status.setText(f"Проверяю {data[0][:2]}...")
        self.tree.clear()
        threading.Thread(target=lambda: self.bridge.done.emit(check_drive(*data)),
                         daemon=True).start()

    def _on_done(self, report: DriveReport) -> None:
        self._busy = False
        self.report = report
        self.tree.clear()
        for f in report.findings:
            level, rgb = LEVELS.get(f.level, (f.level, None))
            item = QTreeWidgetItem([level, f.title, f.path, f.detail, FIXES.get(f.fix, f.fix)])
            for col in range(5):
                item.setToolTip(col, item.text(col))
                if rgb:
                    item.setBackground(col, QBrush(QColor(*rgb)))
                    item.setForeground(col, QBrush(text_color(rgb)))
            item.setData(0, 256, f)
            self.tree.addTopLevelItem(item)
        text = summary(report) + (f". {report.error}" if report.error else "")
        if report.programs:
            text += f". Программ проверено сканером: {min(len(report.programs), 500)}"
        self.status.setText(text)
        self._update_buttons()

    def _update_buttons(self) -> None:
        has_drive = self.drives.count() > 0 and not self._busy
        fixable = bool(self.report and any(f.fix for f in self.report.findings))
        self.btn_check.setEnabled(has_drive)
        self.btn_open.setEnabled(has_drive)
        self.btn_vaccine.setEnabled(has_drive)
        self.btn_cure.setEnabled(has_drive and fixable)
        self.btn_selected.setEnabled(has_drive and fixable)

    # ---------- исправление ----------
    def _fix(self, findings: list, question: str) -> None:
        findings = [f for f in findings if f.fix]
        if not findings:
            QMessageBox.information(self, "USB", "Исправлять нечего")
            return
        if QMessageBox.question(self, "USB", question) != QMessageBox.StandardButton.Yes:
            return
        done, errors = repair.apply(findings)
        activity.record("usb", f"{self.report.root[:2]}: исправлено {done}",
                        fixed=[f"{f.path}: {f.title}" for f in findings], errors=errors)
        self.journal_changed.emit()
        self.quarantine_changed.emit()
        text = f"Исправлено: {done}. Всё можно отменить в «Журнале действий»."
        if errors:
            text += "\n\nНе удалось:\n" + "\n".join(errors[:10])
        QMessageBox.information(self, "USB", text)
        self.check()

    def cure(self) -> None:
        if self.report is None:
            return
        self._fix(self.report.findings,
                  "Убрать в карантин ярлыки, скрипты и autorun.inf вируса, вернуть файлы из "
                  "скрытой папки в корень флешки и показать скрытые файлы?")

    def fix_selected(self) -> None:
        findings = [item.data(0, 256) for item in self.tree.selectedItems()]
        self._fix(findings, f"Исправить выбранное ({len(findings)})?")

    def vaccinate(self) -> None:
        data = self.drives.currentData()
        if not data:
            return
        try:
            created = repair.vaccinate(data[0])
        except OSError as e:
            QMessageBox.warning(self, "USB", f"Не удалось: {e}")
            return
        if created:
            activity.record("usb", f"{data[0][:2]}: защитная папка autorun.inf")
            self.journal_changed.emit()
        QMessageBox.information(self, "USB", "Защитная папка создана" if created else
                                "autorun.inf на флешке уже есть: сначала проверьте флешку")

    def _open_drive(self) -> None:
        data = self.drives.currentData()
        if data:
            QDesktopServices.openUrl(QUrl.fromLocalFile(data[0]))
