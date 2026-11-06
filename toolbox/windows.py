"""Окна инструментов: проверка ссылки, проверка пароля по утечкам, ловушки."""
import os
import threading
from pathlib import Path

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QProgressBar,
    QPushButton, QVBoxLayout,
)

from recovery import activity

COLORS = {"danger": "#c0392b", "warning": "#d68910", "clean": "#2e9e4f", "": ""}


def _banner(label: QLabel, level: str, text: str) -> None:
    color = COLORS.get(level, "")
    label.setStyleSheet(f"padding: 8px; border-radius: 6px; font-weight: 600; "
                        f"border: 1px solid {color or 'palette(mid)'}; color: {color};"
                        if color else "padding: 8px;")
    label.setText(text)


def fit_height(window: QDialog, width: int) -> None:
    """Ширина окна постоянная, высота — ровно по содержимому (переносы строк учтены)."""
    window.setFixedWidth(width)
    layout = window.layout()
    layout.activate()
    window.setFixedHeight(layout.totalHeightForWidth(width))


def info_dialog(parent, title: str, text: str, width: int = 640) -> None:
    """Длинный текст абзацами: QMessageBox режет строки и переносит их неровно."""
    dialog = QDialog(parent)
    dialog.setWindowTitle(title)
    layout = QVBoxLayout(dialog)
    label = QLabel(text)
    label.setWordWrap(True)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    layout.addWidget(label)
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
    buttons.accepted.connect(dialog.accept)
    layout.addWidget(buttons)
    fit_height(dialog, width)
    dialog.exec()


class _Bridge(QObject):
    progress = Signal(int, int)
    done = Signal(object, str)      # результат, ошибка
    scanned = Signal(str, str)      # уровень, текст вердикта


# ---------- проверка ссылки ----------
class LinkCheckWindow(QDialog):
    open_file = Signal(str)          # путь скачанного файла: открыть в сканере
    quarantine_changed = Signal()
    WIDTH = 1060

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Проверка ссылки и файла")
        self.setWindowFlag(Qt.WindowType.Window)
        self.path: Path | None = None
        self._cancel = threading.Event()
        self.bridge = _Bridge()
        self.bridge.progress.connect(self._on_progress)
        self.bridge.done.connect(self._on_downloaded)
        self.bridge.scanned.connect(self._on_scanned)

        layout = QVBoxLayout(self)
        hint = QLabel("Вставьте ссылку из письма, сообщения или с сайта. Программа проверит "
                      "адрес по базам вредоносных сайтов, а по желанию скачает файл в "
                      "отдельную папку и проверит его, не запуская.")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        self.edit = QLineEdit()
        self.edit.setPlaceholderText("https://...")
        self.edit.returnPressed.connect(self.check)
        layout.addWidget(self.edit)
        row = QHBoxLayout()
        self.btn_check = QPushButton("Проверить ссылку")
        self.btn_check.clicked.connect(self.check)
        self.btn_download = QPushButton("Скачать и проверить файл")
        self.btn_download.clicked.connect(self.download)
        self.btn_stop = QPushButton("Остановить")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._cancel.set)
        for w in (self.btn_check, self.btn_download, self.btn_stop):
            row.addWidget(w)
        row.addStretch()
        layout.addLayout(row)
        self.result = QLabel("")
        self.result.setWordWrap(True)
        self.result.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.result)
        self.bar = QProgressBar()
        self.bar.setVisible(False)
        layout.addWidget(self.bar)
        self.file_label = QLabel("")
        self.file_label.setWordWrap(True)
        layout.addWidget(self.file_label)
        files = QHBoxLayout()
        self.btn_scan = QPushButton("Подробно в сканере")
        self.btn_scan.clicked.connect(self._open_in_scanner)
        self.btn_folder = QPushButton("Показать в папке")
        self.btn_folder.clicked.connect(self._show_folder)
        self.btn_delete = QPushButton("Удалить скачанный файл")
        self.btn_delete.clicked.connect(self._delete)
        for w in (self.btn_scan, self.btn_folder, self.btn_delete):
            w.setVisible(False)
            files.addWidget(w)
        files.addStretch()
        layout.addLayout(files)
        self.result.setVisible(False)
        self.file_label.setVisible(False)
        self._fit()

    def _fit(self):
        for label in (self.result, self.file_label):
            label.setVisible(bool(label.text()))
        fit_height(self, self.WIDTH)

    def check(self):
        from toolbox.linkcheck import check_url
        url = self.edit.text().strip()
        if not url:
            return None
        verdict = check_url(url)
        title = {"danger": "Опасная ссылка", "warning": "Ссылка подозрительная",
                 "clean": "Угроз не найдено"}[verdict.level]
        _banner(self.result, verdict.level,
                f"{title}: {verdict.host}\n• " + "\n• ".join(verdict.notes))
        activity.record("link", f"{verdict.url}: {title}", notes=verdict.notes)
        self._fit()
        return verdict

    def download(self):
        verdict = self.check()
        if verdict is None:
            return
        if verdict.level == "danger" and QMessageBox.question(
                self, "Ссылка", "Ссылка в списке вредоносных. Всё равно скачать файл для "
                "проверки? Он не будет запущен.") != QMessageBox.StandardButton.Yes:
            return
        self._cancel.clear()
        self._busy(True)
        url = verdict.url

        def job():
            from toolbox.linkcheck import download
            try:
                path = download(url, lambda got, total: self.bridge.progress.emit(got, total),
                                self._cancel)
            except Exception as e:
                self.bridge.done.emit(None, str(e))
                return
            self.bridge.done.emit(path, "")

        threading.Thread(target=job, daemon=True).start()

    def _busy(self, on: bool):
        self.btn_check.setEnabled(not on)
        self.btn_download.setEnabled(not on)
        self.btn_stop.setEnabled(on)
        self.bar.setVisible(on)
        self.bar.setRange(0, 0)
        self._fit()

    def _on_progress(self, got: int, total: int):
        if total:
            self.bar.setRange(0, total)
            self.bar.setValue(got)
        self.file_label.setText(f"Скачано {got / 2**20:.1f} МБ"
                                + (f" из {total / 2**20:.1f}" if total else ""))

    def _on_downloaded(self, path, error: str):
        self._busy(False)
        if error:
            self.file_label.setText(f"Не скачано: {error}")
            self._fit()
            return
        self.path = path
        self.file_label.setText(f"Скачан: {path.name}. Проверяю...")
        self._fit()
        threading.Thread(target=self._scan, args=(path,), daemon=True).start()

    def _scan(self, path: Path):
        from analyzer.folderview import rules_and_bases, classify
        from scanner import pool as scan_pool
        try:
            signatures, rules, whitelist = rules_and_bases()
            results = list(scan_pool.check_files([str(path)], signatures, rules, whitelist))
            _, reason, error = results[0]
            level, text = ("error", f"Не проверен: {error}") if error else classify(reason)
        except OSError as e:
            level, text = "error", f"Не проверен: {e}"
        self.bridge.scanned.emit(level, text)

    def _on_scanned(self, level: str, text: str):
        colors = {"threat": "danger", "suspicious": "warning", "error": "warning"}
        color = colors.get(level, "clean")
        _banner(self.file_label, color, f"Файл {self.path.name}: {text}\n"
                f"Сохранён в папке программы и помечен как скачанный из интернета.")
        activity.record("link", f"Скачан и проверен {self.path.name}: {text}",
                        url=self.edit.text().strip())
        for w in (self.btn_scan, self.btn_folder, self.btn_delete):
            w.setVisible(True)
        self._fit()

    def _open_in_scanner(self):
        if self.path:
            self.open_file.emit(str(self.path))

    def _show_folder(self):
        if self.path:
            from analyzer import fileops
            fileops.show_in_explorer(str(self.path))

    def _delete(self):
        if self.path and QMessageBox.question(
                self, "Файл", f"Удалить {self.path.name}?") == QMessageBox.StandardButton.Yes:
            try:
                self.path.unlink(missing_ok=True)
            except OSError as e:
                QMessageBox.warning(self, "Файл", str(e))
                return
            self.file_label.setText("Файл удалён")
            for w in (self.btn_scan, self.btn_folder, self.btn_delete):
                w.setVisible(False)
            self.path = None
            self._fit()


# ---------- пароль по утечкам ----------
class PasswordLeakWindow(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Проверка пароля по утечкам")
        self.bridge = _Bridge()
        self.bridge.done.connect(self._on_done)
        layout = QVBoxLayout(self)
        hint = QLabel(
            "Проверка по базе Have I Been Pwned: в ней пароли из сотен утёкших баз сайтов. "
            "Сам пароль никуда не отправляется: на сервер уходят только первые 5 символов "
            "его хэша SHA-1, а сервер возвращает сотни похожих хэшей — совпадение ищется "
            "здесь, на компьютере. Программа не сохраняет пароль.")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        row = QHBoxLayout()
        self.edit = QLineEdit()
        self.edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.edit.setPlaceholderText("Пароль")
        self.edit.returnPressed.connect(self.check)
        show = QPushButton("Показать")
        show.setCheckable(True)
        show.toggled.connect(lambda on: self.edit.setEchoMode(
            QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password))
        self.btn = QPushButton("Проверить")
        self.btn.clicked.connect(self.check)
        row.addWidget(self.edit, 1)
        row.addWidget(show)
        row.addWidget(self.btn)
        layout.addLayout(row)
        self.result = QLabel("")
        self.result.setWordWrap(True)
        layout.addWidget(self.result)
        self._fit()

    def _fit(self):
        self.result.setVisible(bool(self.result.text()))
        fit_height(self, 860)

    def check(self):
        password = self.edit.text()
        if not password:
            return
        self.edit.clear()  # пароль в окне не остаётся
        self.btn.setEnabled(False)
        self.result.setText("Проверяю...")
        self._fit()

        def job():
            from toolbox.pwned import times_pwned
            try:
                self.bridge.done.emit(times_pwned(password), "")
            except Exception as e:
                self.bridge.done.emit(None, str(e))

        threading.Thread(target=job, daemon=True).start()

    def _on_done(self, count, error: str):
        self.btn.setEnabled(True)
        if error:
            _banner(self.result, "warning", f"Нет связи с сервером: {error}")
            self._fit()
            return
        activity.record("password", f"Пароль проверен: найден в утечках {count} раз")
        if count:
            _banner(self.result, "danger",
                    f"Пароль встречается в утечках {count:,} раз.".replace(",", " ")
                    + " Его знают злоумышленники и перебирают первым — смените его везде, "
                    "где он используется, и не используйте один пароль на разных сайтах.")
        else:
            _banner(self.result, "clean", "В известных утечках пароль не найден. Это не "
                                          "значит, что он надёжный: пароль должен быть "
                                          "длинным и своим для каждого сайта.")
        self._fit()


# ---------- ловушки ----------
def decoy_alarm(parent, changed: list[str], culprit: dict | None, watcher=None) -> None:
    """Окно срабатывания ловушки: завершить процесс и убрать файл в карантин или отпустить."""
    from toolbox import decoys
    files = "\n".join(os.path.basename(p) for p in changed[:5])
    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Icon.Critical)
    box.setWindowTitle("Похоже на шифровальщик")
    if culprit:
        state = "приостановлен" if culprit.get("suspended") else "НЕ удалось приостановить"
        box.setText(f"Процесс {culprit['name']} (PID {culprit['pid']}) изменил файлы-ловушки "
                    f"и {state}.\n\n{culprit['exe'] or 'путь неизвестен'}\n\n"
                    f"Изменены:\n{files}")
        kill = box.addButton("Завершить и в карантин", QMessageBox.ButtonRole.DestructiveRole)
        box.addButton("Это не вирус — продолжить", QMessageBox.ButtonRole.RejectRole)
    else:
        box.setText(f"Изменены файлы-ловушки, но программу, которая это сделала, определить "
                    f"не удалось.\n\nИзменены:\n{files}\n\nЕсли файлы на компьютере начали "
                    "менять расширения или не открываются — выключите компьютер.")
        kill = None
        box.addButton(QMessageBox.StandardButton.Ok)
    activity.record("decoy", "Ловушка сработала: " + (
        f"{culprit['name']} ({culprit['exe']})" if culprit else "виновник не найден"),
        changed=changed)
    box.exec()
    if culprit and box.clickedButton() is kill:
        message = _kill_and_quarantine(culprit)
        activity.record("decoy", message)
        QMessageBox.information(parent, "Ловушки", message)
    elif culprit and culprit.get("suspended"):
        decoys.resume(culprit["pid"])
        activity.record("decoy", f"{culprit['name']}: пользователь разрешил продолжить")
    if watcher is not None:
        watcher.mute(5)  # пересоздание приманок — не повод для новой тревоги
    try:
        decoys.repair()  # приманки снова целы
    except OSError:
        pass


def _kill_and_quarantine(culprit: dict) -> str:
    import psutil
    try:
        psutil.Process(culprit["pid"]).kill()
    except Exception as e:
        return f"Не удалось завершить {culprit['name']}: {e}"
    if not culprit.get("exe"):
        return f"{culprit['name']} завершён"
    from analyzer import fileops
    try:
        import time
        time.sleep(0.5)  # файл освобождается после завершения процесса
        fileops.quarantine(culprit["exe"], "Ловушка для шифровальщиков")
        return f"{culprit['name']} завершён, файл перемещён в карантин"
    except OSError as e:
        return f"{culprit['name']} завершён, но файл не перемещён в карантин: {e}"
