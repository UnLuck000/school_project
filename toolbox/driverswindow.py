"""Окно «Уязвимые драйверы»: драйверы системы по базе LOLDrivers (scanner/drivers.py)."""
import threading

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QHBoxLayout, QLabel, QMenu, QMessageBox, QPushButton, QVBoxLayout,
)

from recovery import activity
from scanner import drivers
from ui.widgets import SortItem, make_tree

COLORS = {"danger": "#c0392b", "warning": "#d68910"}
PATH_ROLE = Qt.ItemDataRole.UserRole


class _Bridge(QObject):
    done = Signal(object, object)   # список Driver, ошибка
    progress = Signal(int, int)


class DriversWindow(QDialog):
    journal_changed = Signal()
    exclusions_changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Уязвимые драйверы")
        self.setWindowFlag(Qt.WindowType.Window)
        self.resize(1180, 680)
        self.items: list[drivers.Driver] = []
        self._busy = False
        self.bridge = _Bridge()
        self.bridge.done.connect(self._on_done)
        self.bridge.progress.connect(self._on_progress)

        layout = QVBoxLayout(self)
        hint = QLabel(
            "Вредонос с правами администратора может поставить старый подписанный драйвер с "
            "известной уязвимостью и через него выключить антивирус (атака BYOVD). Подпись у "
            "такого драйвера настоящая, поэтому драйверы сверяются с базой LOLDrivers: по хэшу "
            "файла и Authenticode-хэшу.")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        self.windows_state = QLabel()
        self.windows_state.setWordWrap(True)
        layout.addWidget(self.windows_state)

        row = QHBoxLayout()
        self.btn_scan = QPushButton("Проверить драйверы")
        self.btn_scan.setMinimumHeight(32)
        self.btn_scan.clicked.connect(self.scan)
        self.chk_all = QCheckBox("Показывать все драйверы (и исключения)")
        self.chk_all.toggled.connect(self._fill)
        self.status = QLabel("")
        row.addWidget(self.btn_scan)
        row.addWidget(self.chk_all)
        row.addWidget(self.status, 1)
        layout.addLayout(row)

        self.tree = make_tree(["Драйвер", "Служба", "Состояние", "Запуск", "Вердикт", "Описание",
                               "Путь"], [170, 140, 110, 110, 330, 300, 300], multi=False)
        self.tree.setSortingEnabled(True)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._menu)
        layout.addWidget(self.tree, 1)
        self._show_windows_state()

    def _show_windows_state(self) -> None:
        state = drivers.blocklist_status()
        text = {True: "включён", False: "ВЫКЛЮЧЕН", None: "неизвестно"}
        self.windows_state.setText(
            f"Защита Windows: список блокировки уязвимых драйверов Microsoft — "
            f"{text[state['blocklist']]}, целостность памяти (HVCI) — {text[state['hvci']]}. "
            "Они не дают загрузить часть известных драйверов, но список Microsoft обновляется "
            "редко и не полон.")

    def showEvent(self, event):
        super().showEvent(event)
        if not self.items and not self._busy:
            self.scan()

    def scan(self) -> None:
        if self._busy:
            return
        self._busy = True
        self.btn_scan.setEnabled(False)
        self.status.setText("Читаю список драйверов...")

        def job():
            try:
                db = drivers.load_db()
                if not len(db):
                    self.bridge.done.emit([], "База уязвимых драйверов не скачана: она "
                                              "обновляется вместе с остальными базами "
                                              "(python updater.py drivers).")
                    return
                found = drivers.list_drivers()
                excluded = drivers.excluded_hashes()
                for i, d in enumerate(found):
                    drivers.check(d, db, excluded)
                    if i % 20 == 0:
                        self.bridge.progress.emit(i, len(found))
                self.bridge.done.emit(found, None)
            except Exception as e:
                self.bridge.done.emit([], f"{type(e).__name__}: {e}")

        threading.Thread(target=job, daemon=True).start()

    def _on_progress(self, done: int, total: int) -> None:
        self.status.setText(f"Проверяю: {done} из {total}")

    def _on_done(self, found, error) -> None:
        self._busy = False
        self.btn_scan.setEnabled(True)
        if error:
            self.status.setText(error)
            return
        self.items = found
        bad = [d for d in found if d.level == "danger"]
        weak = [d for d in found if d.level == "warning"]
        self.status.setText(f"Драйверов: {len(found)}. Уязвимых и вредоносных: {len(bad)}, "
                            f"совпадений только по имени: {len(weak)}.")
        activity.record("drivers", f"Проверка драйверов: {len(found)}, найдено {len(bad)}",
                        found=[f"{d.path}: {d.verdict()}" for d in bad + weak])
        self._fill()

    def _fill(self) -> None:
        self.tree.setSortingEnabled(False)
        self.tree.clear()
        for d in self.items:
            if d.level == "clean" and not self.chk_all.isChecked():
                continue  # в том числе исключения: видны с «Показывать все»
            state = "загружен" if d.running or d.loaded else (
                "не загружен" if d.service else "без службы")
            start = drivers.START_TEXT.get(d.start, "") if d.start is not None else ""
            desc = d.entry.description if d.entry else d.error
            item = SortItem([d.name, d.service, state, start, d.verdict(), desc, d.path])
            item.setData(0, PATH_ROLE, d.path)
            for col, text in ((5, desc), (6, d.path), (4, d.verdict())):
                item.setToolTip(col, text)
            color = COLORS.get(d.level)
            if color:
                for col in range(7):
                    item.setForeground(col, QBrush(QColor(color)))
            self.tree.addTopLevelItem(item)
        self.tree.setSortingEnabled(True)
        self.tree.sortByColumn(4, Qt.SortOrder.AscendingOrder)
        if not self.tree.topLevelItemCount():
            self.status.setText(self.status.text() + " Ничего подозрительного.")

    def _selected(self) -> drivers.Driver | None:
        item = self.tree.currentItem()
        if item is None:
            return None
        path = item.data(0, PATH_ROLE)
        return next((d for d in self.items if d.path == path), None)

    def _menu(self, pos) -> None:
        d = self._selected()
        if d is None:
            return
        menu = QMenu(self)
        from analyzer import fileops
        menu.addAction("Показать в проводнике", lambda: fileops.show_in_explorer(d.path))
        if d.service:
            act = menu.addAction("Отключить службу драйвера", lambda: self._disable(d))
            act.setEnabled(d.start != 4)
        if d.sha256 and d.entry is not None:
            if d.excluded:
                menu.addAction("Убрать из исключений", lambda: self._exclude(d, False))
            else:
                menu.addAction("Добавить в исключения (доверяю)",
                               lambda: self._exclude(d, True))
        menu.addAction("Копировать SHA-256", lambda: self._copy(d.sha256))
        menu.exec(self.tree.viewport().mapToGlobal(pos))

    def _exclude(self, d: drivers.Driver, on: bool) -> None:
        if on:
            answer = QMessageBox.question(
                self, "Исключения",
                f"{d.name}: {d.verdict()}.\n\nДоверять этому драйверу (по хэшу файла)? Он "
                "перестанет показываться как уязвимый; исключение попадёт в релиз программы. "
                "Убрать: правый клик здесь или «Журнал действий» → «Исключения».")
            if answer != QMessageBox.StandardButton.Yes:
                return
            drivers.exclude(d)
        else:
            drivers.include(d)
        activity.record("drivers", f"{d.name}: {'в исключениях' if on else 'убран из исключений'}")
        self.exclusions_changed.emit()
        self._fill()

    @staticmethod
    def _copy(text: str) -> None:
        from PySide6.QtWidgets import QApplication
        QApplication.clipboard().setText(text)

    def _disable(self, d: drivers.Driver) -> None:
        answer = QMessageBox.question(
            self, "Отключить драйвер",
            f"Служба {d.service} ({d.name}) больше не будет запускаться. Если это драйвер "
            "нужного устройства или программы (например, утилиты производителя ноутбука), "
            "они перестанут работать; отменить можно в журнале действий.\n\nОтключить?")
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            message = drivers.disable_service(d.service)
        except PermissionError:
            message = "Нужны права администратора: перезапустите программу от администратора."
        except OSError as e:
            message = f"Не удалось: {e}"
        else:
            d.start = 4
            activity.record("drivers", message)
            self.journal_changed.emit()
            self._fill()
        QMessageBox.information(self, "Драйвер", message)
