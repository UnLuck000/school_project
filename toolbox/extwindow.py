"""Окно «Расширения браузеров»: расширения с правами и папками, уведомления сайтов."""
import threading

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QDialog, QHBoxLayout, QLabel, QMenu, QMessageBox, QPushButton,
    QTabWidget, QVBoxLayout, QWidget,
)

from recovery import activity
from toolbox import extensions as ext_mod
from ui.widgets import SortItem, make_tree

COLORS = {"danger": "#c0392b", "warning": "#d68910", "removed": "#8a8a8a"}
RISK_TEXT = {"danger": "Опасно", "warning": "Проверить", "ok": "Обычное",
             "removed": "Удалено"}
RISK_ORDER = {"danger": 0, "warning": 1, "ok": 2, "removed": 3}
INDEX_ROLE = Qt.ItemDataRole.UserRole


class _Bridge(QObject):
    done = Signal(object, object)  # расширения, уведомления


class ExtensionsWindow(QDialog):
    journal_changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Расширения браузеров")
        self.setWindowFlag(Qt.WindowType.Window)
        self.resize(1220, 700)
        self.window_ref = parent
        self.items: list[ext_mod.Extension] = []
        self.sites: list[ext_mod.NotificationSite] = []
        self.bridge = _Bridge()
        self.bridge.done.connect(self._on_done)

        layout = QVBoxLayout(self)
        hint = QLabel(
            "Реклама и всплывающие окна «на весь компьютер» обычно приходят двумя путями: "
            "сайт получил разрешение на уведомления («Разрешите, чтобы продолжить») или "
            "расширение установлено политикой или через реестр — тогда из браузера его не "
            "удалить, а после удаления оно ставится снова. Здесь видно, откуда установлено "
            "каждое расширение и где оно лежит на диске; удаление убирает и записи реестра, и "
            "папку (с откатом в журнале). Браузер перед изменениями нужно закрыть.")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        row = QHBoxLayout()
        self.btn_refresh = QPushButton("Обновить")
        self.btn_refresh.clicked.connect(self.refresh)
        self.chk_all = QCheckBox("Показывать обычные расширения из магазина")
        self.chk_all.setChecked(True)
        self.chk_all.toggled.connect(self._fill)
        self.chk_removed = QCheckBox("Показывать удалённые")
        self.chk_removed.setToolTip("Расширение удалено (папки нет), но браузер хранит запись "
                                    "«удалено пользователем», чтобы не установить его снова")
        self.chk_removed.toggled.connect(self._fill)
        self.status = QLabel("")
        row.addWidget(self.btn_refresh)
        row.addWidget(self.chk_all)
        row.addWidget(self.chk_removed)
        row.addWidget(self.status, 1)
        layout.addLayout(row)

        self.tabs = QTabWidget()
        # причины, папка и ID — в описании (двойной щелчок или правая кнопка → «Описание»)
        self.tree = make_tree(["Риск", "Браузер", "Профиль", "Расширение", "Версия", "Вкл.",
                               "Откуда"], [90, 130, 160, 280, 90, 50, 260], multi=False)
        self.tree.setSortingEnabled(True)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._ext_menu)
        self.tree.itemDoubleClicked.connect(lambda item, col: self.describe())
        self.tabs.addTab(self.tree, "Расширения")
        sites_page = QWidget()
        sites_layout = QVBoxLayout(sites_page)
        sites_layout.setContentsMargins(0, 6, 0, 0)
        sites_hint = QLabel("Сайты, которым браузер разрешил присылать уведомления. Незнакомый "
                            "сайт с разрешением — частая причина рекламы в углу экрана. "
                            "Правый клик: запретить.")
        sites_hint.setWordWrap(True)
        sites_layout.addWidget(sites_hint)
        self.sites_tree = make_tree(["Браузер", "Профиль", "Сайт", "Уведомления"],
                                    [140, 180, 420, 140], multi=False)
        self.sites_tree.setSortingEnabled(True)
        self.sites_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.sites_tree.customContextMenuRequested.connect(self._site_menu)
        sites_layout.addWidget(self.sites_tree, 1)
        self.tabs.addTab(sites_page, "Уведомления сайтов")
        layout.addWidget(self.tabs, 1)

    def showEvent(self, event):
        super().showEvent(event)
        if not self.items and not self.sites:
            self.refresh()

    def refresh(self) -> None:
        self.btn_refresh.setEnabled(False)
        self.status.setText("Читаю профили браузеров...")

        def job():
            try:
                self.bridge.done.emit(ext_mod.all_extensions(), ext_mod.notification_sites())
            except Exception as e:
                self.bridge.done.emit(f"{type(e).__name__}: {e}", [])

        threading.Thread(target=job, daemon=True).start()

    def _on_done(self, items, sites) -> None:
        self.btn_refresh.setEnabled(True)
        if isinstance(items, str):
            self.status.setText(f"Не удалось прочитать: {items}")
            return
        self.items, self.sites = items, sites
        danger = sum(e.risk[0] == "danger" for e in items)
        removed = sum(e.removed for e in items)
        allowed = sum(s.allowed for s in sites)
        self.status.setText(f"Расширений: {len(items) - removed}, опасных: {danger}"
                            + (f", удалённых: {removed}" if removed else "")
                            + f". Сайтов с разрешёнными уведомлениями: {allowed}.")
        activity.record("extensions", self.status.text(),
                        found=[f"{e.browser}: {e.name} ({e.ext_id}) — {e.path}"
                               for e in items if e.risk[0] == "danger"])
        self._fill()

    def _fill(self) -> None:
        self.tree.setSortingEnabled(False)
        self.tree.clear()
        for i, e in enumerate(self.items):
            level, reasons = e.risk
            if level == "ok" and not self.chk_all.isChecked():
                continue
            if level == "removed" and not self.chk_removed.isChecked():
                continue
            item = SortItem([RISK_TEXT[level], e.browser, e.profile, e.name, e.version,
                             "да" if e.enabled else "нет", e.source])
            item.setData(0, SortItem.SORT_ROLE, RISK_ORDER[level])
            item.setData(0, INDEX_ROLE, i)
            item.setToolTip(0, "; ".join(reasons))
            item.setToolTip(6, e.source)
            color = COLORS.get(level)
            if level == "removed":
                for col in range(7):
                    item.setForeground(col, QBrush(QColor(color)))
            elif color:
                item.setForeground(0, QBrush(QColor(color)))
                item.setForeground(3, QBrush(QColor(color)))
            self.tree.addTopLevelItem(item)
        self.tree.setSortingEnabled(True)
        self.tree.sortByColumn(0, Qt.SortOrder.AscendingOrder)

        self.sites_tree.setSortingEnabled(False)
        self.sites_tree.clear()
        for i, s in enumerate(self.sites):
            item = SortItem([s.browser, s.profile, s.site,
                             "разрешены" if s.allowed else "запрещены"])
            item.setData(0, INDEX_ROLE, i)
            if s.allowed:
                item.setForeground(3, QBrush(QColor(COLORS["warning"])))
            self.sites_tree.addTopLevelItem(item)
        self.sites_tree.setSortingEnabled(True)

    # ----- действия -----
    def _current(self, tree, items):
        item = tree.currentItem()
        return None if item is None else items[item.data(0, INDEX_ROLE)]

    def _ext_menu(self, pos) -> None:
        e = self._current(self.tree, self.items)
        if e is None:
            return
        from analyzer import fileops
        import os
        menu = QMenu(self)
        exists = bool(e.path) and os.path.exists(e.path)
        menu.addAction("Описание", self.describe)
        menu.addSeparator()
        folder = menu.addAction("Показать папку в проводнике",
                                lambda: fileops.show_in_explorer(e.path))
        folder.setEnabled(exists)
        if self.window_ref is not None:
            scan = menu.addAction("Проверить папку сканером",
                                  lambda: self.window_ref.open_analyzer(e.path))
            scan.setEnabled(exists)
        remove = menu.addAction("Удалить расширение полностью", lambda: self._remove(e))
        # у удалённого запись в настройках не трогаем: без неё браузер поставит его снова
        remove.setEnabled(not e.removed or bool(e.registry))
        menu.addAction("Копировать ID", lambda: QApplication.clipboard().setText(e.ext_id))
        menu.exec(self.tree.viewport().mapToGlobal(pos))

    def describe(self) -> None:
        """Всё о расширении: причины риска, папка, ID, права, браузер и профиль; действия."""
        e = self._current(self.tree, self.items)
        if e is None:
            return
        import os
        from analyzer import fileops
        from ui.details import show_details
        level, reasons = e.risk
        rows = [("Расширение", e.name), ("Версия", e.version), ("ID", e.ext_id),
                ("Риск", RISK_TEXT[level]), ("Причины", "; ".join(reasons)),
                ("Браузер", e.browser), ("Профиль", e.profile),
                ("Включено", "да" if e.enabled else "нет"), ("Откуда установлено", e.source),
                ("Из магазина", "да" if e.from_store else "нет"),
                ("Установлено принудительно", "да (политика или реестр)" if e.forced else "нет"),
                ("Доступ ко всем сайтам", "да" if e.all_sites else "нет"),
                ("Права", ", ".join(e.permissions) or "нет"),
                ("Папка на диске", e.path), ("Папка профиля", e.prefs),
                ("Программа браузера", e.exe),
                ("Записи реестра", "; ".join("\\".join(r[:2]) + (f" ({r[2]})" if r[2] else "")
                                             for r in e.registry))]
        exists = bool(e.path) and os.path.exists(e.path)
        actions = []
        if exists:
            actions.append(("Показать папку", lambda d: fileops.show_in_explorer(e.path)))
            if self.window_ref is not None:
                actions.append(("Проверить папку сканером",
                                lambda d: self.window_ref.open_analyzer(e.path)))
        if not e.removed or e.registry:
            actions.append(("Удалить полностью", lambda d: (d.accept(), self._remove(e))))
        actions.append(("Копировать ID", lambda d: QApplication.clipboard().setText(e.ext_id)))
        show_details(self, f"Расширение {e.name or e.ext_id}", rows, actions, width=860)

    def _remove(self, e: ext_mod.Extension) -> None:
        parts = []
        if e.registry:
            parts.append(f"записи реестра и политик: {len(e.registry)}")
        if e.prefs:
            parts.append("запись в настройках профиля")
        if e.path:
            parts.append(f"файлы: {e.path}")
        answer = QMessageBox.question(
            self, "Удалить расширение",
            f"{e.name} ({e.browser})\n\nБудет удалено: " + "; ".join(parts) +
            ".\n\nКопии сохранятся, отменить можно в журнале действий. Браузер должен быть "
            "закрыт. Удалить?")
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            message = ext_mod.remove_extension(e)
        except PermissionError:
            message = ("Нет доступа: записи в HKLM (политики для всех пользователей) удаляет "
                       "только администратор.")
        except OSError as err:
            message = str(err)
        else:
            activity.record("extensions", f"{e.name} ({e.ext_id}): {message}")
            self.journal_changed.emit()
            self.refresh()
        QMessageBox.information(self, "Расширение", message)

    def _site_menu(self, pos) -> None:
        s = self._current(self.sites_tree, self.sites)
        if s is None:
            return
        menu = QMenu(self)
        act = menu.addAction("Запретить уведомления", lambda: self._block(s))
        act.setEnabled(s.allowed)
        menu.exec(self.sites_tree.viewport().mapToGlobal(pos))

    def _block(self, s: ext_mod.NotificationSite) -> None:
        try:
            message = ext_mod.block_notifications(s)
        except Exception as err:  # OSError или sqlite3.Error (Firefox)
            message = str(err)
        else:
            activity.record("extensions", message)
            self.journal_changed.emit()
            self.refresh()
        QMessageBox.information(self, "Уведомления", message)
