import threading
from pathlib import Path

from PySide6.QtCore import QObject, Qt, QUrl, Signal
from PySide6.QtGui import QBrush, QColor, QDesktopServices, QFont
from PySide6.QtWidgets import (
    QApplication, QGroupBox, QHBoxLayout, QLabel, QMessageBox, QPushButton, QSplitter,
    QTabWidget, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from analyzer.report import (
    FileReport, build_report, human_size, is_suspicious_api, is_windows_path,
)
from processmanager.colors import text_color
from processmanager.memscan import get_rules
from processmanager.system import open_in_explorer
from scanner.hashing import load_all_signatures
from scanner.whitelist import load_whitelist

from analyzer import fileops
from ui.widgets import make_tree
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


class Bridge(QObject):
    done = Signal(object)
    failed = Signal(str)



def _file_tree(columns: list[str], widths: list[int]) -> QTreeWidget:
    """Деревья вкладок файла: одна выбранная строка, с ветками."""
    return make_tree(columns, widths, multi=False, decorated=True)


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


def _section(title: str, widget: QWidget) -> QGroupBox:
    """Раздел вкладки с заголовком (например, «Общие сведения» и «Цифровая подпись»)."""
    box = QGroupBox(title)
    layout = QVBoxLayout(box)
    layout.setContentsMargins(6, 6, 6, 6)
    layout.addWidget(widget)
    return box


def _split(*sections: QWidget, sizes=None) -> QSplitter:
    splitter = QSplitter(Qt.Orientation.Vertical)
    for s in sections:
        splitter.addWidget(s)
    if sizes:
        splitter.setSizes(sizes)
    return splitter


class FileView(QWidget):
    """Результат проверки одного файла: «Общие», «Проверка», «Код»."""
    quarantine_changed = Signal()
    status = Signal(str, int)        # текст для строки состояния, время показа (мс)
    busy_changed = Signal(bool)

    def __init__(self):
        super().__init__()
        self.bridge = Bridge()
        self.bridge.done.connect(self.on_done)
        self.bridge.failed.connect(self.on_failed)
        self.report: FileReport | None = None
        self._busy = False
        self._build_ui()

    # ---------- интерфейс ----------
    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.banner = QLabel("Файл не запускается: анализ статический.")
        self.banner.setWordWrap(True)
        self.banner.setStyleSheet("padding: 10px; border-radius: 6px; font-size: 12pt;")
        layout.addWidget(self.banner)

        self.tabs = QTabWidget()
        self.general_tree = _file_tree(["Параметр", "Значение"], [220, 800])
        self.sig_tree = _file_tree(["Параметр", "Значение"], [220, 800])
        self.checks_tree = _file_tree(["Слой проверки", "Результат", "Подробности"], [260, 260, 600])
        self.pe_tree = _file_tree(["Элемент", "Значение", "Размер на диске", "Энтропия", "Права"],
                                  [320, 260, 130, 90, 80])
        self.code_tab = CodeTab()
        self.tabs.addTab(_split(_section("Общие сведения", self.general_tree),
                                _section("Цифровая подпись", self.sig_tree), sizes=[420, 170]),
                         "Общие")
        self.tabs.addTab(_split(_section("Слои проверки", self.checks_tree),
                                _section("Структура PE", self.pe_tree), sizes=[230, 360]),
                         "Проверка")
        self.tabs.addTab(self.code_tab, "Код")
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
        self._set_actions(False)

    def _set_actions(self, enabled: bool):
        for button in (self.btn_quarantine, self.btn_copy, self.btn_vt, self.btn_folder):
            button.setEnabled(enabled)

    # ---------- загрузка файла ----------
    def load_file(self, path: str) -> bool:
        file = Path(path)
        if not file.is_file():
            QMessageBox.warning(self, "Сканирование", f"Файл не найден:\n{path}")
            return False
        if self._busy:
            return False
        self._busy = True
        self.busy_changed.emit(True)
        self._set_actions(False)
        self.banner.setStyleSheet("padding: 10px; border-radius: 6px; font-size: 12pt;")
        self.banner.setText(f"Анализирую {file.name}...")
        self.status.emit(
            "Загружаю базы и правила (при первом запуске это занимает несколько секунд)...", 0)
        threading.Thread(target=self._job, args=(file,), daemon=True).start()
        return True

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
        self.busy_changed.emit(False)
        self.banner.setText(text)
        self.status.emit("", 0)

    def on_done(self, report: FileReport):
        self._busy = False
        self.busy_changed.emit(False)
        self.report = report
        self._set_actions(True)

        rgb = LEVEL_COLORS[report.level]
        self.banner.setStyleSheet(
            f"padding: 10px; border-radius: 6px; font-size: 12pt; font-weight: 600; "
            f"background: rgb{rgb}; color: {text_color(rgb).name()};")
        self.banner.setText(report.verdict)
        from recovery import activity
        activity.record("scan_file", f"{report.path}: {report.verdict}", level=report.level)
        self._fill_general(report)
        self._fill_signature(report)
        self._fill_checks(report)
        self._fill_pe(report)
        self.code_tab.set_view(report.code)
        self.code_tab.set_file(Path(report.path), report.pe is not None)
        self.status.emit(f"Готово: {report.name}", 8000)

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

    # ---------- действия ----------
    def copy_hashes(self):
        r = self.report
        if r is not None:
            QApplication.clipboard().setText(
                f"MD5: {r.md5}\nSHA-1: {r.sha1}\nSHA-256: {r.sha256}")
            self.status.emit("Хэши скопированы в буфер обмена", 5000)

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
            "«Журнал действий», вкладка «Карантин».")
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            fileops.quarantine(str(path), "Сканирование файла: " + r.verdict[:80])
        except PermissionError:
            QMessageBox.critical(self, "Карантин",
                                 "Файл занят: вероятно, программа запущена. "
                                 "Завершите процесс и повторите.")
            return
        except OSError as e:
            QMessageBox.critical(self, "Карантин", f"Не удалось выполнить: {e}")
            return
        self.btn_quarantine.setEnabled(False)
        self.status.emit("Файл перемещён в карантин", 8000)
        self.quarantine_changed.emit()