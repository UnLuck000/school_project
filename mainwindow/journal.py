"""Журнал: журнал защиты, действия, белый список и карантин, проверка списков доверия. Часть
главного окна: методы MainWindow (gui.py)."""
import os

from PySide6.QtWidgets import (
    QHBoxLayout,
    QMessageBox,
    QPushButton,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from recovery import activity
from scanner.whitelist import load_whitelist, remove_from_whitelist
from ui import access
from ui.widgets import make_table
import appinfo
import userdata
from mainwindow.common import LOG_PAGE, _dlog


class JournalMixin:
    """Атрибуты и сигналы — у MainWindow (gui.py)."""

    def _refresh_log_tab(self):
        widget = self.log_tabs.currentWidget()
        if widget is self.protect_journal:
            self.protect_journal.refresh()
        elif widget is self.journal_page:
            self.journal_page.refresh()
        elif widget is self.exclusions_page:
            self.exclusions_page.refresh()

    def show_log(self, tab: str = "Действия"):
        """Открывает страницу «Журнал» на нужной вкладке."""
        if tab == "Действия" and not access.allowed("btnUndoJournal"):
            tab = "Журнал защиты"  # журнал действий запрещён: остальные вкладки доступны
        self.show_main(LOG_PAGE)
        for i in range(self.log_tabs.count()):
            if self.log_tabs.tabText(i) == tab:
                self.log_tabs.setCurrentIndex(i)
        self._refresh_log_tab()

    def _on_protect_journal_changed(self):
        self.journal_page.refresh()
        self.refresh_whitelist()
        self.refresh_dashboard()

    def goto_action_place(self, place: str, record: dict):
        """«Перейти к месту действия» из журнала действий (recovery/journal_page.PLACES)."""
        data = record.get("data") or {}
        if place == "net_block":
            self.show_main("Сеть")
            self.net_tabs.setCurrentWidget(self.block_panel)
        elif place == "protect_journal":
            self.show_log("Журнал защиты")
        elif place == "autoruns":
            self.open_autoruns()
        elif place == "system_checks":
            self.open_recovery(2)
        elif place == "assoc":
            self.open_recovery(3)
        elif place == "false_positives":
            self.open_false_positives(data.get("path") or None)
        elif place in ("vpn_settings", "vpn_connect"):
            self.open_tool("vpn")
            window = self.tool_windows.get("vpn")
            if window is not None and hasattr(window, "show_section"):
                window.show_section("settings" if place == "vpn_settings" else "connect")
        elif place in ("drivers", "extensions"):
            self.open_tool(place)
        elif place == "usb":
            self.open_usb()
        elif place == "protection":
            self.show_main("Защита")
        elif place == "file":
            path = data.get("from") or data.get("to") or ""
            if path:
                self.open_analyzer(os.path.dirname(path))

    def on_undone(self, record: dict):
        """Действие отменено на странице журнала: обновляем окна, где оно было видно."""
        if self.autoruns_window is not None:
            self.autoruns_window.handle_undo(record)
        self.refresh_quarantine()
        self.refresh_dashboard()

    def recovery_journal_changed(self) -> None:
        if hasattr(self.journal_page, "refresh"):
            self.journal_page.refresh()

    # ---------- VPN ----------
    def check_trust_files(self):
        """Белый список, исключения и переопределения баз изменены не программой (trustseal):
        до решения пользователя действует прежнее, защищённое содержимое."""
        import trustseal
        files = {userdata.WHITELIST_FILE: "Белый список",
                 userdata.EXCLUSIONS_FILE: "Исключения",
                 userdata.OVERRIDES_FILE: "Исключения из баз (хэши, правила, программы)"}
        try:
            trustseal.finish_first_run(files)
            changed = trustseal.pending()
        except Exception as e:  # noqa: BLE001 — проверка не должна мешать запуску
            _dlog.warning("Проверка списков доверия не удалась: %s", e)
            return
        for path, title in files.items():
            if str(path) not in changed:
                continue
            activity.record("trust", f"{title}: файл изменён не программой", file=str(path))
            self.add_event(f"{title}: файл изменён не программой", "warning")
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Icon.Warning)
            box.setWindowTitle(appinfo.APP_NAME)
            box.setText(f"«{title}» изменён не программой")
            box.setInformativeText(
                "Файл в папке конфигурации изменила другая программа или его правили "
                "вручную. Так вредоносная программа может вписать себя в исключения.\n\n"
                "Пока вы не решите, действует прежнее содержимое.\n\n"
                "«Вернуть прежнее» — отменить чужие изменения (рекомендуется).\n"
                "«Принять» — если вы сами меняли этот файл.")
            back = box.addButton("Вернуть прежнее", QMessageBox.ButtonRole.AcceptRole)
            keep = box.addButton("Принять", QMessageBox.ButtonRole.DestructiveRole)
            box.addButton("Решить позже", QMessageBox.ButtonRole.RejectRole)
            box.setDefaultButton(back)
            box.exec()
            if box.clickedButton() is back:
                trustseal.reject(path)
                activity.record("trust", f"{title}: чужие изменения отменены")
            elif box.clickedButton() is keep:
                trustseal.accept(path)
                activity.record("trust", f"{title}: изменения приняты пользователем")
        if changed:
            self.refresh_dashboard()

    # ---------- вкладка «Белый список» ----------
    def _build_whitelist_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.wl_table = make_table([("Дата", 140), ("Путь при восстановлении", 380),
                                    ("SHA-256", 300)])
        layout.addWidget(self.wl_table)

        row = QHBoxLayout()
        remove_btn = QPushButton("Убрать из белого списка")
        remove_btn.clicked.connect(self.remove_from_wl)
        row.addWidget(remove_btn)
        row.addStretch()
        layout.addLayout(row)
        return tab

    def refresh_whitelist(self):
        self.wl_table.setRowCount(0)
        entries = sorted(load_whitelist().items(), key=lambda kv: kv[1].get("added_at", ""))
        for sha, info in entries:
            row = self.wl_table.rowCount()
            self.wl_table.insertRow(row)
            self.wl_table.setItem(row, 0, QTableWidgetItem(info.get("added_at", "")))
            self.wl_table.setItem(row, 1, QTableWidgetItem(info.get("path", "")))
            self.wl_table.setItem(row, 2, QTableWidgetItem(sha))

    def remove_from_wl(self):
        row = self.wl_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Белый список", "Сначала выберите запись в списке")
            return
        sha = self.wl_table.item(row, 2).text()
        answer = QMessageBox.question(
            self, "Белый список",
            "Файл с этим хэшем снова будет проверяться сканером. Продолжить?")
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            remove_from_whitelist(sha)
            self.statusBar().showMessage("Хэш убран из белого списка")
        except OSError as e:
            QMessageBox.critical(self, "Ошибка", str(e))
        self.refresh_whitelist()

    # бывшая вкладка «Карантин» теперь часть журнала защиты (ui/protect_journal.py)
    def refresh_quarantine(self):
        self.protect_journal.refresh()

    def restore_selected(self):
        self.protect_journal.restore_selected()

    def delete_selected(self):
        self.protect_journal.delete_selected()
