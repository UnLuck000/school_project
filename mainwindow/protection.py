"""Защита: защита файлов, ловушки и шифровальщик, контроль запуска, стилеры, AMSI, журнал защиты
на странице, папки под наблюдением. Часть главного окна: методы MainWindow (gui.py)."""
from pathlib import Path
import json
import os
import threading
import time

from PySide6.QtCore import QUrl, Qt
from PySide6.QtGui import QBrush, QColor, QDesktopServices
from PySide6.QtWidgets import (
    QFileDialog,
    QListWidgetItem,
    QMenu,
    QMessageBox,
    QSystemTrayIcon,
    QWidget,
)

from monitor import RealtimeMonitor, system_folders
from processmanager.system import is_admin
from quarantine import QUARANTINE_DIR
from recovery import activity, threatlog
from ui import access, settings as cfg
import appinfo
from mainwindow.common import DEFAULT_WATCH, ID_ROLE, RULES_DIR, SIGNATURES, _dlog


class ProtectionMixin:
    """Атрибуты и сигналы — у MainWindow (gui.py)."""

    def apply_decoys(self):
        """Ловушки работают вместе с защитой файлов (настройка protect/decoys)."""
        from toolbox import decoys
        self.decoy_watcher.stop()
        if not cfg.get("protect/decoys"):
            decoys.remove_all()
        elif self.monitor is not None:
            try:
                decoys.ensure()
            except OSError as e:
                self.statusBar().showMessage(f"Ловушки для шифровальщиков не созданы: {e}", 8000)
            self.decoy_watcher.start()
        self._refresh_decoys_info()

    def _refresh_decoys_info(self):
        from toolbox import decoys
        manifest = decoys.load_manifest()
        tip = ""
        if not cfg.get("protect/decoys"):
            text = "Выключены в дополнительных настройках."
        elif not manifest:
            text = "Появятся, когда включится защита."
        else:
            state = "следят за изменениями" if self.decoy_watcher.running else \
                "ждут включения защиты"
            text = f"{len(manifest)} файлов-приманок, {state}. Папки скрыты в Проводнике."
            tip = "\n".join(str(d) for d in decoys.decoy_dirs(manifest))
        self.decoys_label.setText(text)
        self.decoys_label.setToolTip(tip)
        self.decoys_btn.setToolTip(tip)
        self.decoys_btn.setEnabled(bool(manifest))
        if hasattr(self, "protection_page"):
            self.protection_page.refit()

    def _open_decoys(self):
        from toolbox import decoys
        dirs = decoys.decoy_dirs()
        if dirs:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(dirs[0])))

    def _on_ransom_burst(self, files: list[str]):
        """Защита файлов увидела, что документы подряд становятся «шумом» (ransomguard)."""
        from toolbox import decoys
        from toolbox.windows import decoy_alarm
        culprit = self.decoy_watcher.find_culprit() if self.decoy_watcher.running else None
        if culprit:
            culprit["suspended"] = decoys.suspend(culprit["pid"])
        name = culprit["name"] if culprit else "неизвестная программа"
        self.add_event(f"Похоже на шифровальщик: {name} — документы становятся нечитаемыми",
                       "threat")
        for path in files[:20]:
            threatlog.add(path, "suspicious", "содержимое похоже на зашифрованное",
                          "Защита файлов")
        self._protect_line(f"[Шифровальщик?] за минуту изменено документов: {len(files)}, "
                           f"содержимое похоже на зашифрованное ({name})", "", "red")
        self.show_main()
        decoy_alarm(self, files, culprit, self.decoy_watcher, burst=True)
        self.refresh_quarantine()
        self._offer_shadow_restore(files)
        self.journal_page.refresh()

    def _offer_shadow_restore(self, files: list[str]):
        """После тревоги: вернуть испорченные документы из теневых копий Windows
        (recovery/shadow.py). Поиск версий — в фоне: список снимков идёт через PowerShell."""
        from recovery import shadow

        def job():
            known = shadow.shadows()
            have = [f for f in files
                    if shadow.previous_version(shadow.original_name(Path(f)), known)]
            self.shadow_found.emit(files, have, known)

        threading.Thread(target=job, name="shadow-search", daemon=True).start()

    def _on_shadow_found(self, files, have, known):
        from recovery import shadow
        from toolbox.windows import info_dialog
        if not have:
            why = ("в Windows нет теневых копий (выключена «Защита системы» или они удалены)"
                   if not known else "в теневых копиях нет прежних версий этих файлов")
            self._protect_line(f"[Шифровальщик?] вернуть документы не из чего: {why}", "",
                               "darkorange")
            return
        answer = QMessageBox.question(
            self, appinfo.APP_NAME,
            f"Прежние версии есть в теневой копии Windows для файлов: {len(have)} из "
            f"{len(files)}.\n\nВернуть их? Нынешние (испорченные) файлы останутся рядом с "
            f"окончанием «{shadow.DAMAGED_SUFFIX}», действие можно отменить в журнале.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if answer != QMessageBox.StandardButton.Yes:
            return
        done, missing = shadow.restore(have, known)
        activity.record("decoy", f"Возвращено из теневой копии: {len(done)}", missing=missing)
        info_dialog(self, "Файлы возвращены",
                    f"Возвращено файлов: {len(done)}.\n\n" + "\n".join(done[:30]) +
                    (f"\n\nНе удалось: {len(missing)}" if missing else ""), 720)
        self.journal_page.refresh()

    def _on_decoy_alarm(self, changed, culprit):
        from toolbox.windows import decoy_alarm
        name = culprit["name"] if culprit else "неизвестная программа"
        self.add_event(f"Ловушка для шифровальщиков: {name}", "threat")
        self.show_main()
        decoy_alarm(self, changed, culprit, self.decoy_watcher)
        self.refresh_quarantine()
        self.journal_page.refresh()

    def start_protection_on_launch(self):
        """Защита файлов и мониторинг сети включаются сразу при старте программы."""
        if self.monitor is None:
            self.toggle_protection()
        if self.net_monitor is None:
            self.toggle_network()

    # ---------- вкладка «Защита» (мониторинг) ----------
    def _build_protection_tab(self) -> QWidget:
        from ui.protection_page import ProtectionPage
        page = ProtectionPage(system_folders())
        self.protection_page = page
        self.watch_list = page.watch_list
        for folder in self._load_watch_folders():
            self._add_watch_item(folder)
        self.watch_add_btn = page.watch_add_btn
        self.watch_add_btn.clicked.connect(self.add_watch_folder)
        self.watch_remove_btn = page.watch_remove_btn
        self.watch_remove_btn.clicked.connect(self.remove_watch_folder)
        self.protect_btn = page.protect_btn
        self.protect_btn.clicked.connect(self.toggle_protection)
        self.protect_status = page.protect_status
        self.decoys_label = page.decoys_label
        self.decoys_btn = page.decoys_btn
        self.decoys_btn.clicked.connect(self._open_decoys)
        self.protect_log = page.protect_log
        self.protect_log.customContextMenuRequested.connect(self._protect_log_menu)
        self._refresh_decoys_info()
        self._full_cancel: threading.Event | None = None
        self._full_mode = "full"
        page.full_btn.clicked.connect(lambda checked=False: self.toggle_full_scan("full"))
        page.quick_btn.clicked.connect(lambda checked=False: self.toggle_full_scan("quick"))
        page.full_drive.currentIndexChanged.connect(lambda i: self._update_quick_visible())
        self.full_progress.connect(self._on_full_progress)
        self.full_found.connect(self._on_full_found)
        self.full_done.connect(self._on_full_done)
        self.fill_drives()
        return page

    # ---------- контроль запуска и защита от стилеров ----------
    def apply_guards(self):
        """Работают вместе с защитой файлов, каждый — если включён в настройках."""
        on = self.monitor is not None
        page = self.protection_page
        want_launch = on and cfg.get("protect/launch")
        if want_launch and self.launch_guard is None:
            from scanner.launchguard import LaunchGuard
            self.launch_guard = LaunchGuard(lambda k, i: self.launch_event.emit(k, i))
            self.launch_guard.start()
            page.launch_label.setText("Загружаю базы...")
        elif not want_launch and self.launch_guard is not None:
            guard, self.launch_guard = self.launch_guard, None
            threading.Thread(target=guard.stop, daemon=True).start()
        if not want_launch and on:
            page.launch_label.setText("Выключен в дополнительных настройках.")
        want_stealer = on and cfg.get("protect/stealer")
        if want_stealer and self.stealer_guard is None:
            from toolbox.stealerguard import StealerGuard
            self.stealer_guard = StealerGuard(
                lambda info: self.stealer_event.emit(info),
                lambda text: self.guard_status.emit("stealer", text))
            threading.Thread(target=self.stealer_guard.start, daemon=True).start()
        elif not want_stealer and self.stealer_guard is not None:
            guard, self.stealer_guard = self.stealer_guard, None
            threading.Thread(target=guard.stop, daemon=True).start()
        if not want_stealer and on:
            page.stealer_label.setText("Выключена в дополнительных настройках.")
        self._apply_amsi(on)
        page.refit()

    # ---------- AMSI: скрипты перед выполнением ----------
    def _apply_amsi(self, on: bool) -> None:
        """Сервер канала работает вместе с защитой файлов, если провайдер зарегистрирован."""
        from scanner import amsi
        label = self.protection_page.amsi_label
        server = self.amsi_server
        want = on and cfg.get("protect/amsi")
        if not want:
            if server is not None:
                self.amsi_server = None
                threading.Thread(target=server.stop, daemon=True).start()
            if on:
                label.setText("Выключена в дополнительных настройках.")
            return
        if server is not None:
            return
        if not amsi.registered():
            if is_admin() and amsi.dll_sources():
                try:
                    amsi.install()
                except OSError as e:
                    label.setText(f"Не удалось зарегистрировать провайдер: {e}")
                    return
            else:
                label.setText("Провайдер не зарегистрирован: нужны права администратора"
                              if amsi.dll_sources() else
                              "Нет библиотеки провайдера (native/amsi/bin)")
                return
        server = amsi.AmsiServer(lambda info: self.amsi_event.emit(info))
        if not server.start():
            label.setText(f"Не запущена: {server.error}")
            return
        self.amsi_server = server
        label.setText("PowerShell, VBScript/JScript и макросы Office проверяются перед "
                      "выполнением; вредоносное блокируется.")

    def set_amsi(self, on: bool) -> None:
        """Галочка в настройках: регистрация провайдера или её снятие."""
        from scanner import amsi
        if on:
            if not is_admin():
                QMessageBox.warning(self, "AMSI", "Чтобы зарегистрировать провайдер AMSI, "
                                    "перезапустите программу с правами администратора.")
                return
            answer = QMessageBox.question(
                self, "AMSI",
                "В Windows будет зарегистрирован провайдер AMSI программы: PowerShell, Windows "
                "Script Host и Office начнут передавать ей скрипты перед выполнением.\n\n"
                "Microsoft Defender и другие антивирусы могут предупредить о регистрации "
                "неподписанного провайдера AMSI — это ожидаемо. Отменить можно галочкой или в "
                "журнале действий.\n\nПродолжить?")
            if answer != QMessageBox.StandardButton.Yes:
                cfg.set_("protect/amsi", False)
                self.settings_page.load_values()
                return
            try:
                amsi.install()
            except OSError as e:
                QMessageBox.warning(self, "AMSI", f"Не удалось зарегистрировать провайдер:\n{e}")
                cfg.set_("protect/amsi", False)
                self.settings_page.load_values()
                return
            self.recovery_journal_changed()
        else:
            server, self.amsi_server = self.amsi_server, None
            if server is not None:
                server.stop()
            if amsi.registered() and is_admin():
                try:
                    amsi.uninstall()
                except OSError as e:
                    QMessageBox.warning(self, "AMSI", f"Не удалось снять регистрацию:\n{e}")
            self.recovery_journal_changed()
        self._apply_amsi(self.monitor is not None)
        self.protection_page.refit()

    def _on_amsi_event(self, info):
        name = info["name"] or info["app"].split("_")[0] or "скрипт"
        what = "заблокирован" if info["blocked"] else "подозрительный, выполнение не остановлено"
        text = f"AMSI: {info['reason']}"
        line = f"[Скрипт] {info['app'].split('_')[0]} (PID {info['pid']}): {name} {what} — " \
               f"{info['reason']}"
        level = "threat" if info["level"] == "threat" else "suspicious"
        activity.record("amsi", line, sha256=info["sha256"], blocked=info["blocked"])
        story, pid = self._story(info)
        story = (story + "\n\n" if story else "") + "Начало проверенного содержимого:\n" + \
            info["excerpt"]
        threatlog.add(info["name"] or f"{info['app']} (PID {info['pid']})", level, text,
                      "AMSI (скрипты)", story, pid)
        self.protect_journal.refresh()
        self._protect_line(line, "", "red" if level == "threat" else "darkorange")
        if info["blocked"]:
            self.add_event(f"Заблокирован вредоносный скрипт: {name}", "threat")
            if self.tray is not None:
                self.tray.showMessage("Заблокирован скрипт", line[:240],
                                      QSystemTrayIcon.MessageIcon.Critical, 10000)

    def _on_guard_status(self, which: str, text: str):
        label = (self.protection_page.launch_label if which == "launch"
                 else self.protection_page.stealer_label)
        label.setText(text.split(": ", 1)[-1][:1].upper() + text.split(": ", 1)[-1][1:])
        self.protection_page.refit()

    def _protect_line(self, text: str, path: str, color: str):
        item = QListWidgetItem(f"{time.strftime('%H:%M:%S')}  {text}")
        if path:
            item.setData(ID_ROLE, path)
            item.setToolTip("Правый клик: в карантин, открыть в сканере, показать в проводнике")
        item.setForeground(QBrush(QColor(color)))
        self.add_protect_item(item, threat=color == "red")

    def add_protect_item(self, item: QListWidgetItem, threat: bool = False) -> None:
        """Строка в журнал защиты, не мешая читать его.

        Журнал прокручивается вниз сам только при угрозе, или если он и так был внизу
        (смотрят новые события). Если пользователь листает выше, проверенные файлы его не
        двигают; удаление старых строк сверху (больше 500) не сдвигает видимую часть."""
        _dlog.log(30 if threat else 10, "Журнал защиты: %s", item.text())
        log = self.protect_log
        bar = log.verticalScrollBar()
        at_bottom = bar.value() >= bar.maximum() - 1
        log.addItem(item)
        if log.count() > 500:  # журнал не растёт бесконечно
            log.takeItem(0)
            if not at_bottom and not threat:
                bar.setValue(max(0, bar.value() - 1))  # строка сверху ушла: держим место
        if threat or at_bottom:
            log.scrollToBottom()

    def _on_launch_event(self, kind: str, info):
        if kind == "status":
            self._on_guard_status("launch", info)
            return
        if kind == "error":
            self._protect_line(f"[Запуск] {info}", "", "darkorange")
            return
        name, exe, text = info["name"], info["exe"], info["text"]
        if kind == "blocked":
            what = "завершён" if info.get("killed") else \
                "обнаружен (экстренное завершение отключено)"
            line = f"[Запуск] {name}: {text}. Процесс {what}"
            activity.record("launch", f"{exe}: {text}", killed=info.get("killed"),
                            parent=info.get("parent", ""))
            self.add_event(f"Угроза при запуске: {name}", "threat")
            threatlog.add(exe, "threat", text, "Контроль запуска", *self._story(info))
            self.protect_journal.refresh()
            self._protect_line(line, exe, "red")
            if self.tray is not None:
                self.tray.showMessage(
                    "Обнаружен вирус", f"{name}: {text}\nПравый клик в журнале защиты: "
                    "«В карантин».", QSystemTrayIcon.MessageIcon.Critical, 10000)
            self.refresh_dashboard()
            return
        level = "red" if kind == "threat" else "darkorange"
        activity.record("launch", f"{exe}: {text}")
        self._protect_line(f"[Запуск] {name}: {text}", exe, level)
        if exe:
            threatlog.add(exe, "threat" if kind == "threat" else "suspicious", text,
                          "Контроль запуска", *self._story(info))
        if kind == "threat":
            self.add_event(f"Угроза среди процессов: {name}", "threat")

    @staticmethod
    def _story(info) -> tuple[str, int]:
        """(сводка, PID) для журнала защиты: процесс к просмотру журнала обычно завершён."""
        pid = info.get("pid", 0) if isinstance(info, dict) else 0
        if not pid:
            return "", 0
        from processmanager import story
        try:
            return story.render(pid), pid
        except Exception:  # noqa: BLE001 — сводка не должна мешать записи находки
            from diag.log import swallowed
            swallowed("сводка по процессу")
            return "", pid

    def _on_stealer_event(self, info):
        from toolbox.windows import stealer_alarm
        self.add_event(f"Доступ к паролям браузеров: {info['name']}", "threat")
        self._protect_line(f"[Стилер?] {info['name']} открыл {info['kind']} ({info['owner']})",
                           info.get("exe", ""), "red")
        self.show_main()
        stealer_alarm(self, info, self.stealer_guard)

    def _threat_paths(self) -> list[str]:
        paths = []
        for item in self.protect_log.selectedItems():
            path = item.data(ID_ROLE)
            if path and path not in paths:
                paths.append(path)
        return paths

    def _protect_log_menu(self, pos):
        paths = [p for p in self._threat_paths() if os.path.exists(p)]
        if not paths:
            return
        menu = QMenu(self)
        menu.addAction(f"В карантин ({len(paths)})" if len(paths) > 1 else "В карантин",
                       lambda: self._quarantine_threats(paths))
        menu.addAction("Открыть в сканере", lambda: self.open_analyzer(paths[0]))
        from analyzer import fileops
        menu.addAction("Показать в проводнике", lambda: fileops.show_in_explorer(paths[0]))
        from diag import edition
        if self.debug_mode and edition.is_test():  # разбор ложных — только в тестовой версии
            menu.addAction("Разобрать срабатывание (ложное?)",
                           lambda: self.open_false_positives(paths[0]))
        menu.exec(self.protect_log.viewport().mapToGlobal(pos))

    def _quarantine_threats(self, paths: list[str]):
        from analyzer import fileops
        done, failed = 0, []
        for path in paths:
            try:
                qid = fileops.quarantine(path, "Защита: перемещено пользователем")
                threatlog.mark_path(path, threatlog.QUARANTINED, qid)
                done += 1
            except OSError as e:
                failed.append(f"{os.path.basename(path)}: {e}")
        self.refresh_quarantine()
        self.journal_page.refresh()
        self.refresh_dashboard()
        text = f"Перемещено в карантин: {done}"
        if failed:
            text += "\n\nНе удалось:\n" + "\n".join(failed[:10])
        QMessageBox.information(self, "Карантин", text)

    def _load_watch_folders(self) -> list[str]:
        raw = self.settings.value("monitor/folders", None)
        if raw:
            try:
                folders = json.loads(raw)
                if isinstance(folders, list):
                    return [str(f) for f in folders]
            except (TypeError, ValueError):
                pass
        return list(DEFAULT_WATCH)

    def _save_watch_folders(self):
        folders = [self.watch_list.item(i).text() for i in range(self.watch_list.count())]
        self.settings.setValue("monitor/folders", json.dumps(folders, ensure_ascii=False))

    def _add_watch_item(self, folder: str):
        item = QListWidgetItem(folder)
        item.setToolTip(folder)  # в списке длинный путь сокращён посередине
        self.watch_list.addItem(item)

    def add_watch_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Папка для наблюдения")
        if folder and not self.watch_list.findItems(folder, Qt.MatchFlag.MatchExactly):
            self._add_watch_item(folder)
            self._save_watch_folders()

    def remove_watch_folder(self):
        row = self.watch_list.currentRow()
        if row >= 0:
            self.watch_list.takeItem(row)
            self._save_watch_folders()

    def toggle_protection(self, force: bool = False):
        """force: выключить и при запрете (возврат состояния после замера ресурсов)."""
        if self.monitor is not None:
            if access.protection_locked() and not force:
                self._off_blocked("защиту файлов")
                return
            self.protect_btn.setEnabled(False)
            self.monitor.stop()
            self._protection_stopped()
            return

        # список может быть пустым: системные папки наблюдаются всегда
        folders = [self.watch_list.item(i).text() for i in range(self.watch_list.count())]

        self.monitor = RealtimeMonitor(
            folders,
            sig_dir=SIGNATURES.parent,
            rules_dir=RULES_DIR,
            exclude=[QUARANTINE_DIR, SIGNATURES.parent.resolve()],
            on_event=lambda kind, text: self.bridge.event.emit(kind, text),
        )
        self.monitor.start()
        self._set_protection_ui(True)
        self.apply_decoys()  # ловушки для шифровальщиков — часть защиты
        self.apply_guards()  # контроль запуска и защита от стилеров — тоже

    def _set_protection_ui(self, running: bool):
        self.protect_btn.setEnabled(True)
        self.protection_page.set_running(running)
        for w in (self.watch_list, self.watch_add_btn, self.watch_remove_btn):
            w.setEnabled(not running)
        self.protect_status.setText("Запускаю..." if running else
                                    "Новые и изменённые файлы не проверяются.")
        self.refresh_dashboard()
        self._apply_off_locks()

    def _protection_stopped(self):
        self.monitor = None
        self.decoy_watcher.stop()
        self.apply_guards()
        self._refresh_decoys_info()
        self._set_protection_ui(False)

    def on_monitor_event(self, kind: str, text: str):
        if kind == "status":  # «Защита включена» уже в заголовке страницы
            self.protect_status.setText(text.removeprefix("Защита включена. "))
            self.refresh_dashboard()
            return
        if kind == "stopped":
            self._protection_stopped()
            return
        if kind == "ransom":
            self._on_ransom_burst(text.split("\n"))
            return
        path = ""
        if kind == "threat":
            path, reason, action = (text.split("\t") + ["", ""])[:3]
            activity.record("threat", f"{path}: {reason}", action=action)
            threatlog.add(path, "threat", reason, "Защита файлов")
            text = f"[!] {path} ({reason}): {action}"
            self.refresh_quarantine()
            self.statusBar().showMessage(text)
            self.add_event(f"Угроза: {os.path.basename(path)} ({reason})", "threat")

        item = QListWidgetItem(f"{time.strftime('%H:%M:%S')}  {text}")
        if path:
            item.setData(ID_ROLE, path)
            item.setToolTip("Правый клик: в карантин, открыть в сканере, показать в проводнике")
        color = {"threat": "red", "error": "darkorange", "scanned": "gray"}.get(kind)
        if color:
            item.setForeground(QBrush(QColor(color)))
        self.add_protect_item(item, threat=kind == "threat")
