"""Проверки: быстрая и полная проверка дисков, плановая проверка. Часть главного окна: методы
MainWindow (gui.py)."""
import os
import threading
import time

from PySide6.QtCore import QTimer
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import QListWidgetItem, QSystemTrayIcon

from diag import features
from recovery import activity, threatlog
from ui import settings as cfg
from mainwindow.common import ID_ROLE


class ScansMixin:
    """Атрибуты и сигналы — у MainWindow (gui.py)."""

    def _on_folder_scanned(self):
        cfg.set_("stats/last_scan", time.strftime("%Y-%m-%d %H:%M"))
        self.refresh_dashboard()

    def quick_scan(self):
        """Кнопка главной: быстрая проверка (Windows, Users и программы на дисках)."""
        features.begin("home.quick_scan")
        self.shell.show_page("Защита")
        if self._full_cancel is None:
            self.toggle_full_scan("quick", all_drives=True)

    # ---------- плановая проверка ----------
    def start_schedule(self):
        page = self.protection_page
        page.schedule_now_btn.clicked.connect(lambda checked=False: self._schedule_now())
        page.schedule_postpone_btn.clicked.connect(lambda checked=False: self._schedule_postpone())
        page.schedule_skip_btn.clicked.connect(lambda checked=False: self._schedule_skip())
        self._schedule_timer = QTimer(self)
        self._schedule_timer.timeout.connect(self.check_schedule)
        self._schedule_timer.start(15 * 1000)
        QTimer.singleShot(15000, self.check_schedule)  # при запуске: не пропущена ли
        QTimer.singleShot(4000, self.check_trust_files)

    def check_schedule(self):
        from scanner import schedule
        now = time.time()
        if not cfg.get("schedule/enabled"):
            self.settings_page.set_schedule_text("Расписание выключено.")
            if self._schedule_due:  # выключили, пока шёл отсчёт
                self._schedule_due = 0.0
                self._hide_schedule_bar()
            return
        due = schedule.next_run(cfg.get("schedule/last_run"), cfg.get("schedule/period"),
                                cfg.get("schedule/time"), now, cfg.get("schedule/postponed"))
        kind = schedule.KINDS.get(cfg.get("schedule/kind"), "Полная проверка")
        self.settings_page.set_schedule_text(f"Следующая: {kind.lower()}, "
                                             f"{schedule.describe(due, now)}.")
        if self._full_cancel is not None:
            return  # проверка уже идёт
        if self._schedule_due:
            if now >= self._schedule_due:
                self._schedule_due = 0.0
                self._run_scheduled()
            else:
                self._show_schedule_bar(kind)
            return
        if now >= due - schedule.WARN_SECONDS:
            # пропущенная проверка (компьютер был выключен) тоже предупреждает за 10 минут
            self._schedule_due = max(due, now + schedule.WARN_SECONDS)
            self._remind(kind)

    def _remind(self, title: str):
        """Уведомление Windows с кнопками «Начать сейчас», «Отложить на час», «Пропустить»
        (ui/notify.py). Если оно недоступно — обычное уведомление через трей, щелчок по нему
        открывает «Защиту». Те же кнопки — в полосе на странице «Защита»."""
        shown = self.notifier.show(
            "Плановая проверка через 10 минут",
            f"Скоро начнётся {title.lower()}: она нагружает процессор и диск. Если вы играете "
            "или работаете в тяжёлой программе, сохраните работу.",
            [("Начать сейчас", "now"), ("Отложить на час", "postpone"),
             ("Пропустить", "skip")], self._on_schedule_toast)
        if not shown and self.tray is not None:
            self._tray_target = "schedule"
            self._usb_pending = None
            self.tray.showMessage(
                "Плановая проверка через 10 минут",
                f"Скоро начнётся {title.lower()}: она нагружает процессор и диск. Если вы "
                "играете или работаете в тяжёлой программе, сохраните работу. Нажмите, чтобы "
                "отложить или пропустить.",
                QSystemTrayIcon.MessageIcon.Information, 15000)
        self._show_schedule_bar(title)
        activity.record("schedule", f"Предупреждение: через 10 минут — {title.lower()}")

    def _on_schedule_toast(self, argument):
        """Кнопка в уведомлении Windows (None — закрыто без выбора: проверка начнётся)."""
        if not self._schedule_due:
            return  # уже решено кнопкой на странице «Защита»
        if argument == "now":
            self._schedule_now()
        elif argument == "postpone":
            self._schedule_postpone()
        elif argument == "skip":
            self._schedule_skip()
        elif argument == "":
            self.show_main("Защита")

    def _show_schedule_bar(self, title: str):
        page = self.protection_page
        minutes = max(1, round((self._schedule_due - time.time()) / 60))
        page.schedule_label.setText(f"Через {minutes} мин начнётся плановая "
                                    f"{title.lower()}.")
        page.schedule_bar.setVisible(True)

    def _hide_schedule_bar(self):
        self.protection_page.schedule_bar.setVisible(False)
        self._tray_target = ""

    def _schedule_now(self):
        self._schedule_due = 0.0
        self._hide_schedule_bar()
        self._run_scheduled()

    def _schedule_postpone(self, seconds: int = 3600):
        self._schedule_due = 0.0
        self._hide_schedule_bar()
        cfg.set_("schedule/postponed", time.time() + seconds)
        activity.record("schedule", "Плановая проверка отложена на час")
        self.check_schedule()

    def _schedule_skip(self):
        self._schedule_due = 0.0
        self._hide_schedule_bar()
        cfg.set_("schedule/last_run", time.time())  # следующая — через период
        cfg.set_("schedule/postponed", 0.0)
        activity.record("schedule", "Плановая проверка пропущена пользователем")
        self.check_schedule()

    def _run_scheduled(self):
        self._hide_schedule_bar()
        cfg.set_("schedule/last_run", time.time())
        cfg.set_("schedule/postponed", 0.0)
        kind = cfg.get("schedule/kind")
        activity.record("schedule", f"Плановая проверка начата ({kind})")
        self.add_event("Плановая проверка начата", "info")
        if self._full_cancel is None:
            self.toggle_full_scan("quick" if kind == "quick" else "full", all_drives=True)
        self.check_schedule()

    # ---------- полная проверка ----------
    def fill_drives(self):
        """Список дисков: заново при каждом показе страницы (флешку могли вставить)."""
        if self._full_cancel is not None:
            return
        from scanner import fullscan
        combo = self.protection_page.full_drive
        previous = combo.currentData()
        combo.clear()
        found = fullscan.drives()
        if len(found) > 1:
            combo.addItem(f"Все диски ({len(found)})", [d.root for d in found])
        for drive in found:
            combo.addItem(drive.title(), [drive.root])
        if not found:  # не Windows или диски не определились
            combo.addItem(os.path.abspath(os.sep), [os.path.abspath(os.sep)])
        index = combo.findData(previous)
        combo.setCurrentIndex(max(0, index))
        self._update_quick_visible()

    def _update_quick_visible(self):
        """Быстрая проверка — только системного диска: на других дисках кнопки и описания нет."""
        from scanner import fullscan
        page = self.protection_page
        roots = page.full_drive.currentData() or []
        visible = any(fullscan.is_system_drive(r) for r in roots)
        page.quick_btn.setVisible(visible)
        page.quick_hint.setVisible(visible)

    def toggle_full_scan(self, mode: str = "full", all_drives: bool = False):
        """mode: full | quick. all_drives — все локальные диски (плановая, с главной)."""
        page = self.protection_page
        if self._full_cancel is not None:
            self._full_cancel.set()
            button = page.quick_btn if self._full_mode == "quick" else page.full_btn
            button.setEnabled(False)
            button.setText("Останавливаю...")
            return
        from scanner import fullscan
        if mode == "quick":  # системный диск и папка пользователя (fullscan.quick_plan)
            roots = [item.path for item in fullscan.quick_plan()]
        elif all_drives:
            roots = [d.root for d in fullscan.drives() if not d.removable] or \
                [os.path.abspath(os.sep)]
        else:
            roots = page.full_drive.currentData() or []
        self._full_mode = mode
        features.begin("protect.full_scan").fact("режим", mode)
        cancel = self._full_cancel = threading.Event()
        active, other = ((page.quick_btn, page.full_btn) if mode == "quick"
                         else (page.full_btn, page.quick_btn))
        active.setText("Остановить проверку")
        other.setEnabled(False)
        page.full_drive.setEnabled(False)
        page.full_progress.setVisible(True)
        page.full_status.setVisible(True)
        page.full_status.setToolTip("")
        page.full_status.setText("Загружаю базы...")
        self._full_found_list: list[str] = []
        title = "Быстрая проверка" if mode == "quick" else "Полная проверка"
        activity.record("full_scan", f"{title} начата: " + ", ".join(roots))

        def job():
            try:
                stats = fullscan.run(roots, self.full_progress.emit,
                                     self.full_found.emit, cancel, mode)
            except Exception as e:  # базы не загрузились и т.п.
                stats = str(e)
            self.full_done.emit(stats, cancel.is_set())

        threading.Thread(target=job, daemon=True).start()

    @staticmethod
    def _full_text(stats) -> str:
        from analyzer.fileops import human_size
        text = (f"Проверено файлов: {stats.checked:,}. Пропущено: "
                f"{stats.skipped:,} ({human_size(stats.skipped_bytes)})"
                ).replace(",", " ")
        if stats.game_dirs:
            text += f", папок игр: {len(stats.game_dirs)}"
        extra = [f"записей автозапуска: {stats.autoruns}" if stats.autoruns else "",
                 "проверка системы выполнена" if stats.checks else "",
                 f"память процессов: {stats.processes}" if stats.processes else ""]
        if any(extra):
            text += ". Также: " + ", ".join(e for e in extra if e)
        text += f". Угроз: {stats.threats}, подозрительных: {stats.suspicious}."
        return text

    @staticmethod
    def _duration(started: float) -> str:
        seconds = int(time.time() - started)
        if seconds < 60:
            return f"{seconds} с"
        if seconds < 3600:
            return f"{seconds // 60} мин {seconds % 60} с"
        return f"{seconds // 3600} ч {seconds // 60 % 60} мин"

    def _on_full_progress(self, stats):
        if self._full_cancel is None or self._full_cancel.is_set():
            return
        self.protection_page.full_status.setText(
            f"{self._full_text(stats)} Идёт {self._duration(stats.started)}.\n"
            f"Сейчас: {stats.current}")

    def _on_full_found(self, path: str, level: str, text: str):
        where = f"{path}: {text}" if path else text  # запись системы или процесс без файла
        self._full_found_list.append(where)
        title = "Быстрая проверка" if self._full_mode == "quick" else "Полная проверка"
        threatlog.add(path, level, text, title)
        item = QListWidgetItem(f"{time.strftime('%H:%M:%S')}  [{title}] {where}")
        if path:
            item.setData(ID_ROLE, path)
            item.setToolTip("Правый клик: в карантин, открыть в сканере, показать в проводнике")
        item.setForeground(QBrush(QColor("red" if level == "threat" else "darkorange")))
        self.add_protect_item(item, threat=level == "threat")
        if level == "threat":
            self.add_event(f"Угроза: {os.path.basename(path)} ({text})" if path else f"Угроза: {text}",
                           "threat")

    def _on_full_done(self, stats, stopped: bool):
        page = self.protection_page
        self._full_cancel = None
        for button, text in ((page.full_btn, "Полная проверка"),
                             (page.quick_btn, "Быстрая проверка")):
            button.setEnabled(True)
            button.setText(text)
        page.full_drive.setEnabled(True)
        page.full_progress.setVisible(False)
        if isinstance(stats, str):
            page.full_status.setText(f"Полная проверка не удалась: {stats}")
            for fid in ("protect.full_scan", "home.quick_scan"):
                features.end_if_active(fid, False, error=stats)
            return
        for fid in ("protect.full_scan", "home.quick_scan"):
            features.end_if_active(fid, True, stopped=stopped, files=stats.files,
                                   checked=stats.checked, errors=stats.errors,
                                   threats=stats.threats, suspicious=stats.suspicious)
        title = "Быстрая проверка" if self._full_mode == "quick" else "Полная проверка"
        head = (f"{title} остановлена" if stopped else
                f"{title} завершена за {self._duration(stats.started)}")
        text = f"{head}. {self._full_text(stats)}"
        page.full_status.setText(text)
        if stats.game_dirs:
            shown = stats.game_dirs[:30]
            page.full_status.setToolTip(
                "Папки игр (проверены только программы и библиотеки):\n" + "\n".join(shown)
                + (f"\n...и ещё {len(stats.game_dirs) - 30}" if len(stats.game_dirs) > 30
                   else ""))
        activity.record("full_scan", text, found=list(self._full_found_list))
        self.add_event(head, "threat" if stats.threats else "info")
        self.statusBar().showMessage(text, 15000)
