import re
import threading
from pathlib import Path

from PySide6.QtCore import QObject, QRect, QSize, Qt, Signal
from PySide6.QtGui import (
    QBrush, QColor, QFont, QPainter, QPalette, QSyntaxHighlighter, QTextCharFormat, QTextCursor,
)
from PySide6.QtWidgets import (
    QComboBox, QDialog, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QPlainTextEdit,
    QPushButton, QSplitter, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from analyzer import disasm
from analyzer.stringsview import StringsTab
from processmanager.colors import text_color

CATEGORY_COLORS = {"decoded": (170, 204, 255), "suspicious": (255, 190, 110),
                   "ioc": (255, 255, 170), "info": None}
CATEGORY_TEXT = {"decoded": "Расшифровано", "suspicious": "Подозрительно",
                 "ioc": "Адрес", "info": "Сведения"}
INDEX_ROLE = Qt.ItemDataRole.UserRole + 1


def _fmt(rgb, bold=False, italic=False, underline=False) -> QTextCharFormat:
    f = QTextCharFormat()
    f.setForeground(QColor(*rgb))
    if bold:
        f.setFontWeight(QFont.Weight.Bold)
    f.setFontItalic(italic)
    f.setFontUnderline(underline)
    return f


KEYWORDS = {
    "bat": r"echo|set|if|else|for|goto|call|exit|start|copy|move|del|rd|md|mkdir|reg|net|attrib|"
           r"taskkill|shutdown|powershell|cmd|certutil|schtasks|sc|bitsadmin|wmic|vssadmin|bcdedit",
    "ps1": r"function|param|if|else|elseif|foreach|while|return|try|catch|finally|switch|"
           r"Invoke-Expression|iex|New-Object|Start-Process|Set-ItemProperty|Invoke-WebRequest|"
           r"Add-Type|Get-\w+|Set-\w+",
    "vbs": r"Dim|Set|If|Then|Else|ElseIf|End|For|Next|Sub|Function|Call|CreateObject|Const|"
           r"Wscript|Do|Loop|While|Wend|Select|Case",
    "js": r"var|let|const|function|if|else|for|while|return|new|eval|try|catch|ActiveXObject|WScript",
    "py": r"def|class|import|from|if|else|elif|for|while|return|try|except|with|lambda|exec|eval",
    "sh": r"if|then|else|fi|for|do|done|while|case|esac|echo|curl|wget|chmod|rm",
    "asm": r"mov|push|pop|call|jmp|je|jne|jz|jnz|ret|lea|xor|add|sub|cmp|test|nop|int3",
    # вкладка «Декомпилятор»
    "cs": r"using|namespace|class|struct|interface|enum|public|private|protected|internal|"
          r"static|readonly|const|void|var|new|return|if|else|for|foreach|while|do|switch|case|"
          r"break|continue|try|catch|finally|throw|async|await|this|base|null|true|false|"
          r"string|int|long|bool|byte|object|override|virtual|abstract|sealed|get|set|out|ref",
    "java": r"package|import|class|interface|enum|extends|implements|public|private|"
            r"protected|static|final|void|new|return|if|else|for|while|do|switch|case|break|"
            r"continue|try|catch|finally|throw|throws|this|super|null|true|false|int|long|"
            r"boolean|byte|char|String|Object|synchronized|abstract",
    "c": r"if|else|for|while|do|switch|case|break|continue|return|goto|void|int|char|long|"
         r"short|unsigned|signed|struct|union|typedef|static|const|sizeof|uint8_t|uint16_t|"
         r"uint32_t|uint64_t|int32_t|int64_t|bool|NULL",
}
COMMENTS = {"bat": r"^\s*(?:@?rem\b|::).*", "ps1": r"#.*", "vbs": r"'.*", "js": r"//.*",
            "py": r"#.*", "sh": r"#.*", "reg": r";.*", "ini": r";.*", "cs": r"//.*",
            "java": r"//.*", "c": r"//.*"}
STRING = r"\"[^\"\r\n]*\"|'[^'\r\n]*'"
URL = r"(?:https?|ftp)://[^\s'\"<>)]+"


def _rules(language: str):
    rules = []
    if language in KEYWORDS:
        rules.append((re.compile(rf"\b(?:{KEYWORDS[language]})\b", re.IGNORECASE),
                      _fmt((86, 156, 214), bold=True)))
    if language in ("reg", "ini"):
        rules.append((re.compile(r"^\[.*\]", re.MULTILINE), _fmt((86, 156, 214), bold=True)))
    if language != "asm":
        rules.append((re.compile(STRING), _fmt((206, 145, 120))))
        rules.append((re.compile(URL, re.IGNORECASE), _fmt((78, 160, 255), underline=True)))
    if language in COMMENTS:
        rules.append((re.compile(COMMENTS[language], re.IGNORECASE | re.MULTILINE),
                      _fmt((106, 153, 85), italic=True)))
    return rules


class Highlighter(QSyntaxHighlighter):
    def __init__(self, document, language: str):
        super().__init__(document)
        self._rules = _rules(language)

    def highlightBlock(self, text: str) -> None:
        for pattern, fmt in self._rules:
            for m in pattern.finditer(text):
                self.setFormat(m.start(), m.end() - m.start(), fmt)


class _Gutter(QWidget):
    def __init__(self, editor):
        super().__init__(editor)
        self._editor = editor

    def sizeHint(self) -> QSize:
        return QSize(self._editor.gutter_width(), 0)

    def paintEvent(self, event) -> None:
        self._editor.paint_gutter(event)


class CodeEdit(QPlainTextEdit):
    """Поле кода с номерами строк."""
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setAcceptDrops(False)  # перетаскивание файла должно доходить до окна
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        font = QFont("Consolas")
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.setFont(font)
        self._gutter = _Gutter(self)
        self.blockCountChanged.connect(self._update_margin)
        self.updateRequest.connect(self._update_gutter)
        self._update_margin()

    def gutter_width(self) -> int:
        digits = len(str(max(1, self.blockCount())))
        return 14 + self.fontMetrics().horizontalAdvance("9") * digits

    def _update_margin(self, *_) -> None:
        self.setViewportMargins(self.gutter_width(), 0, 0, 0)

    def _update_gutter(self, rect, dy) -> None:
        if dy:
            self._gutter.scroll(0, dy)
        else:
            self._gutter.update(0, rect.y(), self._gutter.width(), rect.height())
        if rect.contains(self.viewport().rect()):
            self._update_margin()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        area = self.contentsRect()
        self._gutter.setGeometry(QRect(area.left(), area.top(), self.gutter_width(), area.height()))

    def paint_gutter(self, event) -> None:
        painter = QPainter(self._gutter)
        painter.fillRect(event.rect(), self.palette().alternateBase())
        painter.setPen(self.palette().color(QPalette.ColorRole.PlaceholderText))
        block = self.firstVisibleBlock()
        number = block.blockNumber()
        top = round(self.blockBoundingGeometry(block).translated(self.contentOffset()).top())
        bottom = top + round(self.blockBoundingRect(block).height())
        height = self.fontMetrics().height()
        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                painter.drawText(0, top, self._gutter.width() - 6, height,
                                 Qt.AlignmentFlag.AlignRight, str(number + 1))
            block = block.next()
            top = bottom
            bottom = top + round(self.blockBoundingRect(block).height())
            number += 1

    def goto_line(self, line: int) -> None:
        block = self.document().findBlockByNumber(max(0, line - 1))
        self.setTextCursor(QTextCursor(block))
        self.centerCursor()


class _Bridge(QObject):
    done = Signal(int, str, str, str)  # номер запроса, текст, язык, пояснение


MODE_OVERVIEW, MODE_DISASM, MODE_HEX = range(3)


class CodeTab(QWidget):
    """Вкладка «Код»: обзор (исходный текст, разбор скрипта), дизассемблер разделов PE
    и постраничный hex-просмотр всего файла."""
    def __init__(self):
        super().__init__()
        self._view = None
        self._highlighter = None
        self._path: Path | None = None
        self._pe_map = None
        self._page = 0
        self._strings_loaded = False
        self._request = 0
        self._bridge = _Bridge()
        self._bridge.done.connect(self._on_done)
        layout = QVBoxLayout(self)

        controls = QHBoxLayout()
        self.mode = QComboBox()
        self.mode.addItems(["Обзор", "Дизассемблер", "Hex и строки (весь файл)"])
        self.mode.setToolTip("Обзор: исходный текст скрипта или код точки входа.\n"
                             "Дизассемблер: выбранный раздел программы.\n"
                             "Hex и строки: байты всего файла по страницам 64 КБ и все "
                             "строки файла (двойной щелчок по строке: переход к ней).")
        self.mode.currentIndexChanged.connect(lambda _: self._mode_changed())
        controls.addWidget(QLabel("Вид:"))
        controls.addWidget(self.mode)

        self.region = QComboBox()
        self.region.setMinimumWidth(240)
        self.size = QComboBox()
        for n in disasm.DISASM_SIZES:
            self.size.addItem(f"{n // 1024} КБ" if n < 1048576 else f"{n // 1048576} МБ", n)
        self.size.setCurrentIndex(1)
        self.btn_disasm = QPushButton("Разобрать")
        self.btn_disasm.clicked.connect(self._run_disasm)
        self.disasm_controls = [QLabel("Раздел:"), self.region, QLabel("Объём:"), self.size,
                                self.btn_disasm]

        self.btn_prev = QPushButton("◀")
        self.btn_prev.setFixedWidth(36)
        self.btn_prev.clicked.connect(lambda: self._show_page(self._page - 1))
        self.page_label = QLabel("")
        self.btn_next = QPushButton("▶")
        self.btn_next.setFixedWidth(36)
        self.btn_next.clicked.connect(lambda: self._show_page(self._page + 1))
        self.goto_edit = QLineEdit()
        self.goto_edit.setAcceptDrops(False)
        self.goto_edit.setPlaceholderText("Перейти к смещению (hex)")
        self.goto_edit.setMaximumWidth(190)
        self.goto_edit.returnPressed.connect(self._goto_offset)
        self.hex_controls = [self.btn_prev, self.page_label, self.btn_next, self.goto_edit]

        for w in self.disasm_controls + self.hex_controls:
            controls.addWidget(w)
        controls.addStretch()
        layout.addLayout(controls)

        self.note = QLabel("")
        self.note.setWordWrap(True)
        self.note.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.note)

        splitter = QSplitter(Qt.Orientation.Vertical)
        self.edit = CodeEdit()
        splitter.addWidget(self.edit)
        self.findings = QTreeWidget()
        self.findings.setHeaderLabels(["Вид", "Что найдено", "Значение", "Строка"])
        self.findings.setRootIsDecorated(False)
        header = self.findings.header()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(False)
        for i, width in enumerate((130, 330, 560, 70)):
            self.findings.setColumnWidth(i, width)
        splitter.addWidget(self.findings)
        self.strings = StringsTab()  # видна в режиме «Hex и строки»
        self.strings.offset_activated.connect(self.goto_offset)
        splitter.addWidget(self.strings)
        splitter.setSizes([430, 190, 260])
        layout.addWidget(splitter, 1)
        self.findings.itemClicked.connect(self._goto)
        self.findings.itemDoubleClicked.connect(self._show_full)
        self._mode_changed()

    # ---------- файл и режимы ----------
    def set_file(self, path: Path | None, is_pe: bool) -> None:
        """Файл для дизассемблера и hex-просмотра (вызывается после set_view)."""
        self._path = path
        self._page = 0
        self._strings_loaded = False  # строки ищутся при первом переходе в режим «Hex и строки»
        self.strings.set_file(None)
        self._pe_map = disasm.load_pe_map(path) if (path and is_pe) else None
        self.region.clear()
        if self._pe_map is not None:
            for r in self._pe_map.regions:
                if r.size:
                    self.region.addItem(f"{r.title} ({max(1, r.size // 1024)} КБ)", r)
        self.mode.model().item(MODE_DISASM).setEnabled(self._pe_map is not None)
        if self.mode.currentIndex() != MODE_OVERVIEW:
            self.mode.setCurrentIndex(MODE_OVERVIEW)
        else:
            self._mode_changed()

    def _mode_changed(self) -> None:
        mode = self.mode.currentIndex()
        for w in self.disasm_controls:
            w.setVisible(mode == MODE_DISASM)
        for w in self.hex_controls:
            w.setVisible(mode == MODE_HEX)
        self.findings.setVisible(mode == MODE_OVERVIEW)
        self.strings.setVisible(mode == MODE_HEX)
        if mode == MODE_HEX and not self._strings_loaded and self._path is not None:
            self._strings_loaded = True
            self.strings.set_file(self._path)
        if mode == MODE_OVERVIEW:
            self._show_overview()
        elif mode == MODE_DISASM:
            self._run_disasm()
        else:
            self._show_page(self._page)

    def _set_text(self, text: str, language: str) -> None:
        if self._highlighter is not None:
            self._highlighter.setDocument(None)  # иначе подсветки накладываются друг на друга
        self.edit.setPlainText(text)
        self._highlighter = Highlighter(self.edit.document(), language)

    def _show_overview(self) -> None:
        view = self._view
        self.note.setText(f"<b>{view.title}.</b> {view.note}" if view else "")
        self._set_text(view.text if view else "", view.language if view else "text")

    def _run_disasm(self) -> None:
        region = self.region.currentData()
        if self._path is None or self._pe_map is None or region is None:
            return
        self._request += 1
        request, path, pe_map, size = self._request, self._path, self._pe_map, self.size.currentData()
        self.note.setText("Дизассемблирую...")
        self.btn_disasm.setEnabled(False)

        def work():
            try:
                text, note = disasm.disassemble(path, pe_map, region, size)
                language = "text" if note.startswith("Не удалось") else "asm"
            except Exception as e:  # просмотр не должен ломать окно
                text, note, language = "", f"Не удалось дизассемблировать: {e}", "text"
            self._bridge.done.emit(request, text, language, note)

        threading.Thread(target=work, daemon=True).start()

    def _on_done(self, request: int, text: str, language: str, note: str) -> None:
        self.btn_disasm.setEnabled(True)
        if request != self._request or self.mode.currentIndex() != MODE_DISASM:
            return  # устаревший результат
        self.note.setText(note)
        self._set_text(text, language)

    def _show_page(self, page: int) -> None:
        if self._path is None:
            return
        try:
            text, self._page, pages = disasm.hex_page(self._path, page)
        except OSError as e:
            self.note.setText(f"Не удалось прочитать файл: {e}")
            return
        start = self._page * disasm.HEX_PAGE
        self.page_label.setText(f"Страница {self._page + 1} из {pages}")
        self.btn_prev.setEnabled(self._page > 0)
        self.btn_next.setEnabled(self._page < pages - 1)
        self.note.setText(f"Байты с 0x{start:08X} по 0x{start + disasm.HEX_PAGE - 1:08X}. "
                          "Слева смещение в файле, справа печатные символы.")
        self._set_text(text, "text")

    def _goto_offset(self) -> None:
        text = self.goto_edit.text().strip().lower().removeprefix("0x")
        try:
            offset = int(text, 16)
        except ValueError:
            self.note.setText("Смещение указывается в шестнадцатеричном виде, например 1F400")
            return
        self.goto_offset(offset)

    def goto_offset(self, offset: int) -> None:
        """Показывает страницу hex с нужным смещением и выделяет его строку."""
        if self.mode.currentIndex() != MODE_HEX:
            self.mode.setCurrentIndex(MODE_HEX)
        self._show_page(offset // disasm.HEX_PAGE)
        self.edit.goto_line((offset % disasm.HEX_PAGE) // 16 + 1)
        cursor = self.edit.textCursor()
        cursor.select(QTextCursor.SelectionType.LineUnderCursor)
        self.edit.setTextCursor(cursor)

    # ---------- обзор ----------
    def set_view(self, view) -> None:
        self._view = view
        self.findings.clear()
        if view is None:
            self._path, self._pe_map = None, None
        if self.mode.currentIndex() == MODE_OVERVIEW:
            self._show_overview()
        if view is None:
            return
        for index, f in enumerate(view.findings):
            shown = f.value.replace("\n", " ")
            item = QTreeWidgetItem([CATEGORY_TEXT.get(f.category, f.category), f.title,
                                    shown[:300], str(f.line) if f.line else ""])
            item.setData(0, INDEX_ROLE, index)
            item.setToolTip(2, "Двойной щелчок: показать полностью")
            rgb = CATEGORY_COLORS.get(f.category)
            if rgb:
                for col in range(4):
                    item.setBackground(col, QBrush(QColor(*rgb)))
                    item.setForeground(col, QBrush(text_color(rgb)))
            self.findings.addTopLevelItem(item)

    def _finding(self, item):
        return self._view.findings[item.data(0, INDEX_ROLE)] if self._view else None

    def _goto(self, item, _column) -> None:
        f = self._finding(item)
        if f is not None and f.line and self.mode.currentIndex() == MODE_OVERVIEW:
            self.edit.goto_line(f.line)

    def _show_full(self, item, _column) -> None:
        f = self._finding(item)
        if f is None:
            return
        dialog = QDialog(self)
        dialog.setWindowTitle(f.title)
        dialog.resize(720, 460)
        box = QVBoxLayout(dialog)
        view = QPlainTextEdit(f.value)
        view.setReadOnly(True)
        view.setAcceptDrops(False)
        box.addWidget(view)
        dialog.exec()
