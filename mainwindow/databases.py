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
        сутки с последнего обновления (см. updater.update_due)."""
        self.auto_update_timer.start()
        QTimer.singleShot(5000, self.auto_update_check)  # окно успевает открыться

    def auto_update_check(self):
        if not self._updating and updater.update_due(cfg.get("db/last_update")):
            self.update_databases(silent=True)

    def update_databases(self, silent: bool = True):
        """Обновление баз. Вручную его не запускают: только автообновление (silent),
        без сообщения об успехе. silent=False оставлен для отладки из консоли."""
        if self._updating:
            return
        self._updating = True
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
                ok = updater.update_all(progress=self.update_progress.emit)
        except Exception as e:
            buffer.write(f"Ошибка: {e}\n")
        self.update_finished.emit(buffer.getvalue(), ok, silent)

    def _on_update_progress(self, text: str):
        if not self._update_silent:
            self.statusBar().showMessage(text)

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
