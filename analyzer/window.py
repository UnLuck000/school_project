import threading
from pathlib import Path

from PySide6.QtCore import QObject, QUrl, Signal
from PySide6.QtGui import QBrush, QColor, QDesktopServices, QFont
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QFileDialog, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMainWindow, QMessageBox, QPushButton, QTabWidget, QTreeWidget,
    QTreeWidgetItem, QVBoxLayout, QWidget,
)

import autoruns.actions  # noqa: F401  (регистрирует откат карантина в журнале)
from analyzer.report import (
    INTERESTING, FileReport, build_report, human_size, is_suspicious_api, is_windows_path,
)
from processmanager.colors import text_color
from processmanager.memscan import get_rules
from processmanager.system import allow_drops_from_lower_integrity, is_admin, open_in_explorer
from quarantine import quarantine_file
from recovery import journal
from scanner.hashing import load_all_signatures
from scanner.whitelist import load_whitelist

from analyzer.codeview import CodeTab

SIG_DIR = Path(__file__).resolve().parent.parent / "signatures"
LEVEL_COLORS = {"threat": (255, 128, 128), "suspicious": (255, 190, 110),
                "clean": (170, 230, 170), "info": (170, 204, 255)}
WARN = (255, 190, 110)
OK = (170, 230, 170)
BAD = (255, 128, 128)
MARK = (255, 255, 170)
STATUS_TEXT = {"valid": "Действительна", "unsigned": "Нет подписи",
               "invalid": "Недействительна", "unavailable": "Проверка недоступна"}
SOURCE_TEXT = {"embedded": "встроена в файл", "catalog": "каталог Windows"}
MAX_SHOWN_STRINGS = 5000


class Bridge(QObject):
    done = Signal(object)
    failed = Signal(str)


def _make_tree(columns: list[str], widths: list[int]) -> QTreeWidget:
    tree = QTreeWidget()
    tree.setHeaderLabels(columns)
    tree.setUniformRowHeights(True)
    tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    header = tree.header()
    header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    header.setStretchLastSection(True)
    for i, width in enumerate(widths):
        tree.setColumnWidth(i, width)
    return tree


def _paint(item: QTreeWidgetItem, rgb: tuple[int, int, int], columns: int) -> None:
    for col in range(columns):
        item.setBackground(col, QBrush(QColor(*rgb)))
        item.setForeground(col, QBrush(text_color(rgb)))


def _group(tree: QTreeWidget, title: str) -> QTreeWidgetItem:
    item = QTreeWidgetItem([title])
    font = QFont(item.font(0))
    font.setBold(True)
    item.setFont(0, font)
    tree.addTopLevelItem(item)
    return item


class AnalyzerWindow(QMainWindow):
    quarantine_changed = Signal()

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Анализатор файла")
        self.resize(1150, 780)
        self.setAcceptDrops(True)

        self.bridge = Bridge()
        self.bridge.done.connect(self.on_done)
        self.bridge.failed.connect(self.on_failed)
        self.report: FileReport | None = None
        self._banner_before = None
        self._busy = False
        self._strings: list[tuple[int, str, str]] = []
        self._build_ui()

    # ---------- интерфейс ----------
    def _build_ui(self):
        root = QWidget()
        layout = QVBoxLayout(root)

        row = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setAcceptDrops(False)  # иначе поле само перехватывает перетаскивание
        self.path_edit.setPlaceholderText("Путь к файлу или перетащите файл в это окно")
        self.path_edit.returnPressed.connect(self.analyze_clicked)
        browse = QPushButton("Обзор...")
        browse.clicked.connect(self.browse)
        self.btn_analyze = QPushButton("Анализировать")
        self.btn_analyze.clicked.connect(self.analyze_clicked)
        row.addWidget(self.path_edit, 1)
        row.addWidget(browse)
        row.addWidget(self.btn_analyze)
        layout.addLayout(row)

        self.banner = QLabel("Выберите файл для анализа. Файл не запускается: анализ статический.")
        self.banner.setWordWrap(True)
        self.banner.setStyleSheet("padding: 10px; border-radius: 6px; font-size: 12pt;")
        layout.addWidget(self.banner)

        self.tabs = QTabWidget()
        self.general_tree = _make_tree(["Параметр", "Значение"], [220, 800])
        self.sig_tree = _make_tree(["Параметр", "Значение"], [220, 800])
        self.checks_tree = _make_tree(["Слой проверки", "Результат", "Подробности"], [260, 260, 600])
        self.pe_tree = _make_tree(["Элемент", "Значение", "Размер на диске", "Энтропия", "Права"],
                                  [320, 260, 130, 90, 80])
        self.code_tab = CodeTab()
        self.tabs.addTab(self.general_tree, "Общие")
        self.tabs.addTab(self.sig_tree, "Подпись")
        self.tabs.addTab(self.checks_tree, "Проверка")
        self.tabs.addTab(self.pe_tree, "PE")
        self.tabs.addTab(self.code_tab, "Код")
        self.tabs.addTab(self._build_strings_tab(), "Строки")
        layout.addWidget(self.tabs, 1)

        buttons = QHBoxLayout()
        self.btn_quarantine = QPushButton("Карантин")
        self.btn_quarantine.clicked.connect(self.quarantine)
        self.btn_copy = QPushButton("Копировать хэши")
        self.btn_copy.clicked.connect(self.copy_hashes)
        self.btn_vt = QPushButton("Искать хэш на VirusTotal")
        self.btn_vt.setToolTip("Открывает страницу в браузере. Сам файл никуда не отправляется.")
        self.btn_vt.clicked.connect(self.open_virustotal)
        self.btn_folder = QPushButton("Папка файла")
        self.btn_folder.clicked.connect(self.open_folder)
        for button in (self.btn_quarantine, self.btn_copy, self.btn_vt, self.btn_folder):
            buttons.addWidget(button)
        buttons.addStretch()
        layout.addLayout(buttons)

        self.setCentralWidget(root)
        self._set_actions(False)

    def _build_strings_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        row = QHBoxLayout()
        self.str_filter = QLineEdit()
        self.str_filter.setAcceptDrops(False)
        self.str_filter.setPlaceholderText("Фильтр по тексту строки...")
        self.str_filter.textChanged.connect(lambda _: self._refill_strings())
        self.str_interesting = QCheckBox("Только интересные (адреса, ключи реестра, API и т.п.)")
        self.str_interesting.toggled.connect(lambda _: self._refill_strings())
        self.str_count = QLabel("")
        row.addWidget(self.str_filter, 1)
        row.addWidget(self.str_interesting)
        row.addWidget(self.str_count)
        layout.addLayout(row)
        self.str_tree = _make_tree(["Смещение", "Вид", "Строка"], [100, 70, 900])
        self.str_tree.setRootIsDecorated(False)
        layout.addWidget(self.str_tree)
        return tab

    def _set_actions(self, enabled: bool):
        for button in (self.btn_quarantine, self.btn_copy, self.btn_vt, self.btn_folder):
            button.setEnabled(enabled)

    # ---------- загрузка файла ----------
    @staticmethod
    def _first_local_file(event) -> str | None:
        for url in event.mimeData().urls():
            if url.isLocalFile():
                return url.toLocalFile()
        return None

    def dragEnterEvent(self, event):
        if self._first_local_file(event):
            if self._banner_before is None:
                self._banner_before = self.banner.text()
            self.banner.setText("Отпустите кнопку мыши, чтобы проанализировать файл")
            event.acceptProposedAction()

    def dragLeaveEvent(self, event):
        self._restore_banner()

    def dropEvent(self, event):
        path = self._first_local_file(event)
        self._restore_banner()
        if path:
            event.acceptProposedAction()
            self.load_file(path)

    def _restore_banner(self):
        if self._banner_before is not None:
            self.banner.setText(self._banner_before)
            self._banner_before = None

    def showEvent(self, event):
        super().showEvent(event)
        if is_admin():  # окно с повышенными правами по умолчанию не принимает файлы из обычного Проводника
            allow_drops_from_lower_integrity(int(self.winId()))

    def browse(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выберите файл для анализа")
        if path:
            self.load_file(path)

    def analyze_clicked(self):
        path = self.path_edit.text().strip().strip('"')
        if path:
            self.load_file(path)

    def load_file(self, path: str):
        file = Path(path)
        if not file.is_file():
            QMessageBox.warning(self, "Анализатор", f"Файл не найден или это папка:\n{path}")
            return
        if self._busy:
            return
        self._busy = True
        self.btn_analyze.setEnabled(False)
        self._set_actions(False)
        self.path_edit.setText(str(file))
        self.banner.setStyleSheet("padding: 10px; border-radius: 6px; font-size: 12pt;")
        self.banner.setText("Анализирую...")
        self.statusBar().showMessage(
            "Загружаю базы и правила (при первом запуске это занимает несколько секунд)...")
        threading.Thread(target=self._job, args=(file,), daemon=True).start()

    def _job(self, path: Path):
        try:
            report = build_report(path, load_all_signatures(SIG_DIR),
                                  get_rules("all"), set(load_whitelist()))
        except OSError as e:
            self.bridge.failed.emit(f"Не удалось прочитать файл: {e}")
            return
        except Exception as e:  # ошибка анализа не должна ронять программу
            self.bridge.failed.emit(f"Ошибка анализа: {e}")
            return
        self.bridge.done.emit(report)

    def on_failed(self, text: str):
        self._busy = False
        self.btn_analyze.setEnabled(True)
        self.banner.setText(text)
        self.statusBar().clearMessage()

    def on_done(self, report: FileReport):
        self._busy = False
        self.report = report
        self.btn_analyze.setEnabled(True)
        self._set_actions(True)

        rgb = LEVEL_COLORS[report.level]
        self.banner.setStyleSheet(
            f"padding: 10px; border-radius: 6px; font-size: 12pt; font-weight: 600; "
            f"background: rgb{rgb}; color: {text_color(rgb).name()};")
        self.banner.setText(report.verdict)
        self._fill_general(report)
        self._fill_signature(report)
        self._fill_checks(report)
        self._fill_pe(report)
        self.code_tab.set_view(report.code)
        self._strings = report.strings
        self._refill_strings()
        self.statusBar().showMessage(f"Готово: {report.name}", 8000)

    # ---------- заполнение вкладок ----------
    def _fill_general(self, r: FileReport):
        tree = self.general_tree
        tree.clear()
        size_text = f"{r.size:,} байт ({human_size(r.size)})".replace(",", " ")
        if r.entropy > 7.2:
            entropy_text = f"{r.entropy:.3f} из 8: данные похожи на сжатые или зашифрованные"
        else:
            entropy_text = f"{r.entropy:.3f} из 8"
        rows = [("Имя", r.name), ("Путь", r.path), ("Размер", size_text),
                ("Тип по содержимому", r.file_type), ("Расширение", r.ext or "нет"),
                ("Создан", r.created), ("Изменён", r.modified), ("Открыт", r.accessed),
                ("MD5", r.md5), ("SHA-1", r.sha1), ("SHA-256", r.sha256),
                ("Энтропия файла", entropy_text)]
        for key, value in rows:
            tree.addTopLevelItem(QTreeWidgetItem([key, value]))
        for note in r.notes:
            item = QTreeWidgetItem(["Замечание", note])
            _paint(item, WARN, 2)
            tree.addTopLevelItem(item)

    def _fill_signature(self, r: FileReport):
        tree = self.sig_tree
        tree.clear()
        sig = r.signature
        explain = {
            "valid": "Подпись проверена Windows и считается доверенной. Это не гарантия "
                     "безопасности: иногда подписывают и вредоносные программы.",
            "unsigned": "Подписи нет. Для программ из интернета это бывает нормально, "
                        "для системных файлов нет.",
            "invalid": "Подпись есть, но недействительна: файл изменён после подписи "
                       "или издатель не доверенный.",
        }.get(sig.status, "Проверка подписи недоступна в этой системе.")
        rows = [("Статус", STATUS_TEXT.get(sig.status, sig.status)),
                ("Издатель", sig.publisher or "не определён"),
                ("Источник подписи", SOURCE_TEXT.get(sig.source, "—")),
                ("Пояснение", explain)]
        for key, value in rows:
            item = QTreeWidgetItem([key, value])
            if key == "Статус":
                _paint(item, {"valid": OK, "invalid": BAD}.get(sig.status, MARK), 2)
            tree.addTopLevelItem(item)

    def _fill_checks(self, r: FileReport):
        tree = self.checks_tree
        tree.clear()

        def add(layer: str, result: str, details: str, rgb) -> QTreeWidgetItem:
            item = QTreeWidgetItem([layer, result, details])
            if rgb:
                _paint(item, rgb, 3)
            tree.addTopLevelItem(item)
            return item

        add("Белый список", "Да" if r.whitelisted else "Нет",
            "Файл восстановлен пользователем" if r.whitelisted else "", MARK if r.whitelisted else None)
        add("База хэшей", "Совпадение" if r.hash_match else "Нет совпадений",
            f"Хэшей в базе: {r.hash_db_size:,}".replace(",", " "), BAD if r.hash_match else OK)

        if r.yara_skipped:
            add("Правила YARA", "Пропущено", "Файл слишком большой для проверки", MARK)
        elif not r.rules_ok:
            add("Правила YARA", "Правила не загружены", "Проверьте signatures/rules/", MARK)
        else:
            item = add("Правила YARA", f"Сработало: {len(r.yara)}" if r.yara else "Нет совпадений",
                       "", BAD if r.yara else OK)
            for rule in r.yara:
                item.addChild(QTreeWidgetItem([rule]))
            item.setExpanded(True)

        heur = r.heuristics
        if not heur.is_pe:
            add("Эвристика PE", "Не PE-файл", "Эвристика применяется только к EXE, DLL, SYS", None)
        else:
            triggered = heur.score >= r.threshold
            item = add("Эвристика PE", f"{heur.score} баллов (порог {r.threshold})",
                       "Порог достигнут" if triggered else "Ниже порога",
                       WARN if triggered else OK)
            for finding in heur.findings:
                kind = "упаковка" if finding.category == "pack" else "API"
                item.addChild(QTreeWidgetItem([finding.text, f"+{finding.points}", kind]))
            item.setExpanded(True)

        sig = r.signature
        add("Цифровая подпись", STATUS_TEXT.get(sig.status, sig.status), sig.publisher or "",
            {"valid": OK, "invalid": BAD}.get(sig.status))

    def _fill_pe(self, r: FileReport):
        tree = self.pe_tree
        tree.clear()
        if r.pe is None:
            tree.addTopLevelItem(QTreeWidgetItem(["Файл не является PE-файлом (EXE, DLL, SYS)"]))
            return
        pe = r.pe
        header = _group(tree, "Заголовок")
        for key, value in pe.header:
            item = QTreeWidgetItem([key, value])
            if key == "Замечание":
                _paint(item, WARN, 5)
            header.addChild(item)
        header.setExpanded(True)

        sections = _group(tree, f"Секции ({len(pe.sections)})")
        for s in pe.sections:
            item = QTreeWidgetItem([s["name"], f"виртуальный размер {s['virtual']:,}".replace(",", " "),
                                    f"{s['raw']:,}".replace(",", " "), f"{s['entropy']:.2f}",
                                    s["flags"]])
            writable_exec = "W" in s["flags"] and "X" in s["flags"]
            packed_code = "X" in s["flags"] and s["entropy"] > 7.0
            if writable_exec or packed_code:
                _paint(item, WARN, 5)
                item.setToolTip(0, "Исполняемая и записываемая секция или сжатый код")
            sections.addChild(item)
        sections.setExpanded(True)

        imports = _group(tree, f"Импорты ({len(pe.imports)} библиотек)")
        for dll, functions in pe.imports.items():
            dll_item = QTreeWidgetItem([dll, f"{len(functions)} функций"])
            for name in functions:
                child = QTreeWidgetItem([name])
                if is_suspicious_api(name):
                    _paint(child, WARN, 5)
                    child.setToolTip(0, "Функция из набора признаков эвристики")
                dll_item.addChild(child)
            imports.addChild(dll_item)

        if pe.exports:
            exports = _group(tree, f"Экспорты ({len(pe.exports)})")
            for name in pe.exports:
                exports.addChild(QTreeWidgetItem([name]))

    def _refill_strings(self):
        text = self.str_filter.text().strip().lower()
        only = self.str_interesting.isChecked()
        tree = self.str_tree
        tree.setUpdatesEnabled(False)
        tree.clear()
        shown = 0
        for offset, kind, value in self._strings:
            interesting = bool(INTERESTING.search(value))
            if only and not interesting:
                continue
            if text and text not in value.lower():
                continue
            item = QTreeWidgetItem([f"{offset:08X}", kind, value])
            if interesting:
                _paint(item, MARK, 3)
            tree.addTopLevelItem(item)
            shown += 1
            if shown >= MAX_SHOWN_STRINGS:
                break
        tree.setUpdatesEnabled(True)
        self.str_count.setText(f"Показано {shown} из {len(self._strings)}")

    # ---------- действия ----------
    def copy_hashes(self):
        r = self.report
        if r is not None:
            QApplication.clipboard().setText(
                f"MD5: {r.md5}\nSHA-1: {r.sha1}\nSHA-256: {r.sha256}")
            self.statusBar().showMessage("Хэши скопированы в буфер обмена", 5000)

    def open_virustotal(self):
        r = self.report
        if r is not None:
            QDesktopServices.openUrl(QUrl(f"https://www.virustotal.com/gui/file/{r.sha256}"))

    def open_folder(self):
        r = self.report
        if r is not None and Path(r.path).exists():
            open_in_explorer(r.path)

    def quarantine(self):
        r = self.report
        if r is None:
            return
        path = Path(r.path)
        if not path.is_file():
            QMessageBox.information(self, "Карантин", "Файл уже не найден на диске")
            return
        if r.signature.status == "valid" and is_windows_path(path):
            QMessageBox.information(
                self, "Карантин",
                "Это компонент Windows с действительной подписью: карантин запрещён.")
            return
        answer = QMessageBox.question(
            self, "Карантин",
            f"Переместить файл в карантин?\n\n{r.path}\n\nВернуть его можно на странице "
            "«Карантин» или в «Журнале действий».")
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            item_id = quarantine_file(path, reason="Анализатор файла: " + r.verdict[:80])
        except PermissionError:
            QMessageBox.critical(self, "Карантин",
                                 "Файл занят: вероятно, программа запущена. "
                                 "Завершите процесс и повторите.")
            return
        except OSError as e:
            QMessageBox.critical(self, "Карантин", f"Не удалось выполнить: {e}")
            return
        journal.log_action(f"Файл «{path.name}» перемещён в карантин (анализатор)",
                           "quarantine_restore", {"id": item_id})
        self.btn_quarantine.setEnabled(False)
        self.statusBar().showMessage("Файл перемещён в карантин", 8000)
        self.quarantine_changed.emit()