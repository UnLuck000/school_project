import re

from PySide6.QtCore import QRect, QSize, Qt
from PySide6.QtGui import (
    QBrush, QColor, QFont, QPainter, QPalette, QSyntaxHighlighter, QTextCharFormat, QTextCursor,
)
from PySide6.QtWidgets import (
    QDialog, QHeaderView, QLabel, QPlainTextEdit, QSplitter, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget,
)

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
}
COMMENTS = {"bat": r"^\s*(?:@?rem\b|::).*", "ps1": r"#.*", "vbs": r"'.*", "js": r"//.*",
            "py": r"#.*", "sh": r"#.*", "reg": r";.*", "ini": r";.*"}
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


class CodeTab(QWidget):
    """Вкладка «Код»: исходный текст (или дизассемблер) и результаты разбора."""
    def __init__(self):
        super().__init__()
        self._view = None
        self._highlighter = None
        layout = QVBoxLayout(self)
        self.note = QLabel("")
        self.note.setWordWrap(True)
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
        splitter.setSizes([430, 190])
        layout.addWidget(splitter, 1)
        self.findings.itemClicked.connect(self._goto)
        self.findings.itemDoubleClicked.connect(self._show_full)

    def set_view(self, view) -> None:
        self._view = view
        self.findings.clear()
        if view is None:
            self.note.setText("")
            self.edit.setPlainText("")
            return
        self.note.setText(f"<b>{view.title}.</b> {view.note}")
        if self._highlighter is not None:
            self._highlighter.setDocument(None)  # иначе подсветки накладываются друг на друга
        self.edit.setPlainText(view.text)
        self._highlighter = Highlighter(self.edit.document(), view.language)
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
        if f is not None and f.line:
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