"""Базы и отчёт о работе: обновление баз, счётчики, отчёт за период. Часть главного окна: методы
MainWindow (gui.py)."""
import threading
import time

from PySide6.QtCore import QTimer, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QMessageBox

from diag import features
from networkmonitor.ioc import load_ip_blocklist
from recovery import activity
from scanner import pool as scan_pool
from scanner.hashing import load_all_signatures
from scanner.yara_engine import count_rules
from ui import settings as cfg
import appinfo
import updater
from mainwindow.common import NETFEEDS_DIR, RULES_DIR, SIGNATURES, _dlog


class DatabasesMixin:
    """Атрибуты и сигналы — у MainWindow (gui.py)."""

    def start_activity_report(self):
        """Отчёт о работе: отсчёт периодов от первого запуска, проверка раз в час."""
        if not cfg.get("report/first_run"):
            cfg.set_("report/first_run", time.time())
        activity.record("program", f"Программа запущена ({appinfo.VERSION})")
        activity.trim()
        self.check_activity_report()
        self._report_timer = QTimer(self)
        self._report_timer.timeout.connect(self.check_activity_report)
        self._report_timer.start(3600 * 1000)

    def check_activity_report(self):
        first, last = cfg.get("report/first_run"), cfg.get("report/last_end")
        try:
            end = activity.prepare_outbox(first, last)
        except OSError:
            return
        if end != last:
            cfg.set_("report/last_end", end)
        self.debug_page.set_activity_state(first, end)

    # ---------- главная страница и настройки ----------
    def _database_stats(self) -> dict | None:
        """Счётчики баз. Считать их недёшево (тысячи файлов правил): в фоне и с кэшем;
        пока не посчитаны — None, по готовности главная обновится (db_stats_ready).
        В главном потоке подсчёт держал интерфейс ~2 с при входе в режим администратора."""
        if self._db_stats is None and not getattr(self, "_db_counting", False):
            self._db_counting = True

            def job():
                try:
                    db = load_all_signatures(SIGNATURES.parent)
                    rule_files, rules = count_rules(RULES_DIR)
                    md5 = sum(p.stat().st_size // 16
                              for p in (SIGNATURES.parent / "feeds").glob("*.md5.bin"))
                    stats = {"hashes": len(db), "md5": md5, "rules": rules,
                             "rule_files": rule_files,
                             "c2": len(load_ip_blocklist(NETFEEDS_DIR))}
                except Exception as e:  # noqa: BLE001
                    _dlog.warning("Счётчики баз не посчитаны: %s", e)
                    stats = None
                finally:
                    self._db_counting = False
                if stats is not None:
                    self.db_stats_ready.emit(stats)

            threading.Thread(target=job, daemon=True, name="db-stats").start()
        return self._db_stats

    def _on_db_stats(self, stats: dict) -> None:
        self._db_stats = stats
        self.refresh_dashboard()

    def check_updates(self):
        QDesktopServices.openUrl(QUrl(appinfo.RELEASES_URL))

    def start_auto_update(self):
        """Автообновление баз: при запуске и затем каждые полчаса проверяется, прошли ли
        сутки с последнего обновления (см. updater.update_due). Там же раз в сутки —
        новый выпуск программы (updatecheck.py), только сообщение."""
        self.auto_update_timer.start()
        QTimer.singleShot(5000, self.auto_update_check)  # окно успевает открыться
        QTimer.singleShot(20000, self.check_release)
        self._release_timer = QTimer(self)
        self._release_timer.timeout.connect(self.check_release)
        self._release_timer.start(6 * 3600 * 1000)

    # ---------- обновление программы ----------
    def check_release(self, manual: bool = False):
        if not manual and time.time() - cfg.get("update/last_check") < 24 * 3600:
            return
        if manual:
            self.about_page.update_btn.setEnabled(False)
            self.about_page.update_btn.setText("Проверяю...")

        def job():
            import updatecheck
            try:
                release = updatecheck.latest()
                cfg.set_("update/last_check", time.time())
                self.release_found.emit(release, "", manual)
            except Exception as e:  # noqa: BLE001 — нет сети, нет выпусков, лимит GitHub
                self.release_found.emit(None, str(e), manual)

        threading.Thread(target=job, daemon=True, name="release-check").start()

    def _on_release_found(self, release, error: str, manual: bool):
        import updatecheck
        self.about_page.update_btn.setEnabled(True)
        self.about_page.update_btn.setText("Проверить обновления")
        if release is None:
            if manual:
                QMessageBox.warning(self, "Обновление", f"Не удалось проверить: {error}")
            return
        if not updatecheck.newer(release.version):
            if manual:
                QMessageBox.information(self, "Обновление",
                                        f"Установлена последняя версия ({appinfo.VERSION}).")
            return
        if not manual:
            if cfg.get("update/skipped") == release.version:
                return
            self.add_event(f"Доступна версия {release.version} — «О программе» → «Проверить "
                           "обновления»", "info")
            return
        box = QMessageBox(self)
        box.setWindowTitle("Обновление")
        box.setText(f"Доступна версия {release.version} (сейчас {appinfo.VERSION}).")
        box.setInformativeText((release.notes[:1500] + "\n\n" if release.notes else "") +
                               "Установщик скачается, проверится по SHA256SUMS выпуска и "
                               "подписи и запустится — он сам попросит закрыть программу.")
        install = box.addButton("Скачать и установить", QMessageBox.ButtonRole.AcceptRole)
        page = box.addButton("Открыть страницу выпуска", QMessageBox.ButtonRole.ActionRole)
        skip = box.addButton("Пропустить эту версию", QMessageBox.ButtonRole.DestructiveRole)
        box.addButton("Позже", QMessageBox.ButtonRole.RejectRole)
        box.exec()
        if box.clickedButton() is page:
            QDesktopServices.openUrl(QUrl(release.page))
        elif box.clickedButton() is skip:
            cfg.set_("update/skipped", release.version)
        elif box.clickedButton() is install:
            self.about_page.update_btn.setEnabled(False)
            self.about_page.update_btn.setText("Скачиваю...")

            def job():
                try:
                    self.release_downloaded.emit(updatecheck.download(release), "")
                except Exception as e:  # noqa: BLE001 — показать причину
                    self.release_downloaded.emit(None, str(e))

            threading.Thread(target=job, daemon=True, name="release-download").start()

    def _on_release_downloaded(self, path, error: str):
        import updatecheck
        self.about_page.update_btn.setEnabled(True)
        self.about_page.update_btn.setText("Проверить обновления")
        if path is None:
            activity.record("program", f"Обновление не установлено: {error}")
            QMessageBox.warning(self, "Обновление", f"Установщик не запущен: {error}")
            return
        activity.record("program", f"Запущен установщик обновления: {path.name}")
        updatecheck.run_installer(path)

    def auto_update_check(self):
        if getattr(self, "service", None) is not None:
            return  # базы обновляет служба (service/core.py): окно без прав — не может
        if self._updating or not updater.needs_update(cfg.get("db/last_update")):
            return
        if not updater.can_update():
            if not getattr(self, "_update_denied", False):  # сообщить один раз за запуск
                self._update_denied = True
                self.add_event("Базы не обновлены: программа запущена без прав "
                               "администратора (папка баз закрыта от записи)", "warning")
            return
        self.update_databases(silent=True)

    def update_databases(self, silent: bool = True):
        """Обновление баз. Вручную его не запускают: только автообновление (silent),
        без сообщения об успехе. silent=False оставлен для отладки из консоли."""
        if self._updating:
            return
        self._updating = True
        self._db_fraction = 0.0
        features.begin("db.update")
        self._update_silent = silent
        if not silent:
            self.statusBar().showMessage("Обновляю базы (хэши, правила YARA, адреса C2)...")
        self.refresh_dashboard()
        threading.Thread(target=self._update_job, args=(silent,), daemon=True).start()

    def _update_job(self, silent: bool):
        import contextlib
        import io

        buffer = io.StringIO()
        ok = False
        try:
            with contextlib.redirect_stdout(buffer):
                ok = updater.update_all(progress=self.update_progress.emit,
                                        fraction=self.update_fraction.emit)
        except Exception as e:
            buffer.write(f"Ошибка: {e}\n")
        self.update_finished.emit(buffer.getvalue(), ok, silent)

    def _on_update_progress(self, text: str):
        if not self._update_silent:
            self.statusBar().showMessage(text)

    def _on_update_fraction(self, value: float):
        self._db_fraction = value
        self.dashboard.set_db_progress(value)

    def _on_update_finished(self, text: str, ok: bool, silent: bool):
        from analyzer.folderview import reset_bases
        from processmanager.memscan import reset_cache

        self._updating = False
        if ok:
            cfg.set_("db/last_update", time.time())
        reset_cache()  # правила для памяти и файлов перекомпилируются при следующей проверке
        reset_bases()
        scan_pool.reset()  # рабочие процессы проверки перезапустятся с новыми правилами
        for monitor in (self.monitor, self.net_monitor):
            if monitor is not None:
                monitor.reload_bases()
        self._db_stats = None
        self.refresh_dashboard()
        activity.record("update", "Базы обновлены" if ok else "Обновление баз не удалось")
        failed = [line.strip()[:220] for line in text.splitlines() if line.strip()]
        features.end_if_active("db.update", ok, error="" if ok else " | ".join(failed[-3:]))
        if ok:
            self.add_event("Базы сигнатур обновлены")
            self._update_retries = 0
        else:
            # частый случай — сеть перестраивается: обновление при запуске совпало с
            # подключением VPN (sing-box, WSAEACCES 10013 в журнале 11.11.2026); повтор через
            # 3 минуты, трижды, дальше — обычная проверка раз в полчаса
            self._update_retries = getattr(self, "_update_retries", 0) + 1
            if self._update_retries <= 3:
                QTimer.singleShot(3 * 60 * 1000, self.auto_update_check)
        if silent:  # автообновление: сообщение об успехе не показывается
            if not ok:
                self.statusBar().showMessage(
                    "Не удалось обновить базы: нет сети. Повторю позже", 8000)
            return
        self.statusBar().showMessage("Обновление баз завершено", 8000)
        QMessageBox.information(self, "Обновление баз", text.strip() or "Готово")
