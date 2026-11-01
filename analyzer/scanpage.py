"""Страница «Сканирование папки/файла»: файл анализируется подробно, папка — списком
своих файлов и папок (без вложенных)."""
import os

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFileDialog, QHBoxLayout, QLabel, QLineEdit, QPushButton, QStackedWidget, QVBoxLayout,
    QWidget,
)

from analyzer.folderview import FolderView
from analyzer.window import FileView


class ScanPage(QWidget):
    status = Signal(str, int)
    quarantine_changed = Signal()
    journal_changed = Signal()
    folder_scanned = Signal()

    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        title = QLabel("Сканирование папки/файла")
        title.setStyleSheet("font-size: 20pt; font-weight: 600;")
        layout.addWidget(title)

        row = QHBoxLayout()
        self.btn_up = QPushButton("↑")
        self.btn_up.setFixedWidth(36)
        self.btn_up.setToolTip("На уровень выше (к папке, где лежит файл или папка)")
        self.btn_up.clicked.connect(self.go_up)
        self.path_edit = QLineEdit()
        self.path_edit.setAcceptDrops(False)  # перетаскивание принимает вся страница
        self.path_edit.setPlaceholderText("Путь к файлу или папке, или перетащите их сюда")
        self.path_edit.returnPressed.connect(self.scan_clicked)
        btn_file = QPushButton("Файл...")
        btn_file.clicked.connect(self.choose_file)
        btn_folder = QPushButton("Папка...")
        btn_folder.clicked.connect(self.choose_folder)
        self.btn_scan = QPushButton("Сканировать")
        self.btn_scan.clicked.connect(self.scan_clicked)
        for w in (self.btn_up, self.path_edit, btn_file, btn_folder, self.btn_scan):
            row.addWidget(w, 1 if w is self.path_edit else 0)
        layout.addLayout(row)

        self.stack = QStackedWidget()
        hint = QLabel("Выберите файл или папку.\n\nФайл: подробный статический анализ "
                      "(файл не запускается).\nПапка: проверка всех файлов в ней, вложенные "
                      "папки не затрагиваются.")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint.setWordWrap(True)
        self.file_view = FileView()
        self.folder_view = FolderView()
        for w in (hint, self.file_view, self.folder_view):
            self.stack.addWidget(w)
        layout.addWidget(self.stack, 1)

        for view in (self.file_view, self.folder_view):
            view.status.connect(self.status.emit)
            view.quarantine_changed.connect(self.quarantine_changed.emit)
        self.folder_view.journal_changed.connect(self.journal_changed.emit)
        self.folder_view.scan_file.connect(self.scan)
        self.folder_view.scan_folder.connect(self.scan)
        self.folder_view.scan_done.connect(self.folder_scanned.emit)
        self.file_view.busy_changed.connect(lambda busy: self.btn_scan.setEnabled(not busy))
        self._current: str | None = None
        self.btn_up.setEnabled(False)

    # ---------- выбор ----------
    def choose_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Файл для проверки", self._start_dir())
        if path:
            self.scan(path)

    def choose_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Папка для проверки", self._start_dir())
        if path:
            self.scan(path)

    def _start_dir(self) -> str:
        if self._current:
            return self._current if os.path.isdir(self._current) else os.path.dirname(self._current)
        return ""

    def scan_clicked(self) -> None:
        path = self.path_edit.text().strip().strip('"')
        if path:
            self.scan(path)

    def go_up(self) -> None:
        if self._current:
            parent = os.path.dirname(os.path.normpath(self._current))
            if parent and parent != self._current:
                self.scan(parent)

    def scan(self, path: str) -> None:
        """Файл: подробный анализ; папка: список и проверка её файлов."""
        path = os.path.normpath(os.path.expandvars(path))
        if os.path.isdir(path):
            self._current = path
            self.path_edit.setText(path)
            self.stack.setCurrentWidget(self.folder_view)
            self.folder_view.set_folder(path)
        elif os.path.isfile(path):
            if self.file_view.load_file(path):
                self._current = path
                self.path_edit.setText(path)
                self.stack.setCurrentWidget(self.file_view)
        else:
            self.status.emit(f"Не найдено: {path}", 6000)
            return
        parent = os.path.dirname(path)
        self.btn_up.setEnabled(bool(parent) and parent != path)

    # ---------- перетаскивание ----------
    def dragEnterEvent(self, event):
        if any(u.isLocalFile() for u in event.mimeData().urls()):
            event.acceptProposedAction()

    def dropEvent(self, event):
        for url in event.mimeData().urls():
            if url.isLocalFile():
                event.acceptProposedAction()
                self.scan(url.toLocalFile())
                break

    def shutdown(self) -> None:
        self.folder_view.stop()
