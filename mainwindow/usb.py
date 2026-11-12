"""Флешки: окно «USB-накопители» и автопроверка подключённых дисков. Часть главного окна: методы
MainWindow (gui.py)."""
import threading

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QSystemTrayIcon

from recovery import activity
from ui import settings as cfg
import appinfo


class UsbMixin:
    """Атрибуты и сигналы — у MainWindow (gui.py)."""

    # ---------- USB-накопители ----------
    def open_usb(self, root: str | None = None, report=None):
        if self.tool_blocked("btnUsb"):
            return
        from usbguard.window import UsbWindow
        if self.usb_window is None:
            self.usb_window = UsbWindow()
            self.usb_window.journal_changed.connect(self.journal_page.refresh)
            self.usb_window.quarantine_changed.connect(self.refresh_quarantine)
            self.usb_window.quarantine_changed.connect(self.refresh_dashboard)
            self.apply_on_top(cfg.get("general/on_top"))
        self.usb_window.show()
        self.usb_window.raise_()
        self.usb_window.activateWindow()
        if root:
            self.usb_window.show_drive(root, report)

    def start_usb_watch(self):
        """Раз в 2 секунды: появилась ли новая флешка. Проверка — в фоне."""
        self._usb_timer = QTimer(self)
        self._usb_timer.timeout.connect(self._poll_usb)
        self.usb_drives.connect(self._on_usb_drives)
        self._usb_timer.start(2000)
        if self.tray is not None:
            self.tray.messageClicked.connect(self._on_tray_message)
        self._poll_usb()  # флешки, вставленные до запуска, тоже проверяются

    def _poll_usb(self):
        """Опрос дисков — в фоне: GetVolumeInformation у засыпающей флешки или картридера
        отвечает секундами (зависание интерфейса 10,7 с в журнале 10.11.2026)."""
        if getattr(self, "_usb_polling", False):
            return
        self._usb_polling = True

        def job():
            from usbguard.scan import removable_drives
            try:
                drives = removable_drives()
            except Exception:  # noqa: BLE001 — следующий опрос через 2 с
                drives = None
            self._usb_polling = False
            if drives is not None:
                self.usb_drives.emit(drives)

        threading.Thread(target=job, daemon=True, name="usb-poll").start()

    def _on_usb_drives(self, found):
        drives = dict(found)
        new = set(drives) - self._usb_known
        self._usb_known = set(drives)
        if new and self.usb_window is not None and self.usb_window.isVisible():
            self.usb_window.refresh_drives()
        if self.monitor is None:  # защита флешек — часть защиты файлов
            return
        for root in sorted(new):
            threading.Thread(target=self._usb_job, args=(root, drives[root]),
                             daemon=True).start()

    def _usb_job(self, root: str, label: str):
        """Проверка флешки; вирус-ярлык лечится сразу (с откатом через журнал)."""
        from usbguard import repair
        from usbguard.window import auto_fixes, check_drive
        report = check_drive(root, label)
        cure = None
        fixes = auto_fixes(report)
        if fixes:
            done, errors = repair.apply(fixes, "Защита флешек: вирус-ярлык")
            cure = (done, errors, [f"{f.path}: {f.title}" for f in fixes])
        self.usb_checked.emit(report, cure)

    def _on_usb_checked(self, report, cure):
        from usbguard.window import summary
        problems = report.problems
        activity.record("usb", "Защита флешек: " + summary(report),
                        found=[f"{f.path}: {f.title}" for f in problems],
                        **({"cured": cure[2], "errors": cure[1]} if cure else {}))
        if not problems:
            self.statusBar().showMessage(summary(report), 8000)
            return
        if cure:
            done, errors, _ = cure
            text = (f"Флешка {report.root[:2]}: вирус-ярлык обезврежен — исправлено {done}"
                    + (f", не удалось {len(errors)}" if errors else "")
                    + ". Файлы возвращены на место. Отменить можно в «Журнале действий».")
            self.journal_page.refresh()
            self.refresh_quarantine()
            self.refresh_dashboard()
        else:
            text = summary(report) + ". Нажмите, чтобы посмотреть."
        self.add_event(text, "threat" if report.infected else "info")
        self._usb_pending = (report.root, report)
        if self.tray is not None:
            self.tray.showMessage(appinfo.SHORT_NAME, text,
                                  QSystemTrayIcon.MessageIcon.Warning, 10000)
