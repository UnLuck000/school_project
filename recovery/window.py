import re
import threading
from datetime import datetime

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import (
    QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit, QPushButton,
    QTabWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

import appinfo

from processmanager.system import is_admin

from recovery import actions
from recovery import assoc
from recovery import system as rsys
from recovery import checks
from recovery.assoc_panel import AssocPanel
from recovery.panels import FindingsPanel, PolicyPanel

from scanner import exclusions
from ui.widgets import make_tree


COMMANDS = {
    "sfc_verify": ("Проверка файлов (sfc /verifyonly)", ["sfc.exe", "/verifyonly"], False),
    "sfc_scan": ("Проверка и исправление (sfc /scannow)", ["sfc.exe", "/scannow"], True),
    "dism_check": ("DISM: быстрая проверка",
                   ["dism.exe", "/Online", "/Cleanup-Image", "/CheckHealth"], False),
    "dism_scan": ("DISM: полная проверка",
                  ["dism.exe", "/Online", "/Cleanup-Image", "/ScanHealth"], False),
    "dism_restore": ("DISM: восстановление",
                     ["dism.exe", "/Online", "/Cleanup-Image", "/RestoreHealth"], True),
}
CATEGORY_TEXT = {"hosts": "Файл hosts", "proxy": "Прокси", "defender": "Microsoft Defender",
                 "policy": "Политики", "system": "Система"}
LEVEL_COLORS = {"ok": (170, 230, 170), "info": (170, 204, 255),
                "warning": (255, 190, 110), "bad": (255, 128, 128)}
PROGRESS_RE = re.compile(r"\d+(?:[.,]\d+)?\s*%")
INDEX_ROLE = Qt.ItemDataRole.UserRole + 1
TAB_POINTS, TAB_INTEGRITY, TAB_CHECKS, TAB_ASSOC = 0, 1, 2, 3


class Bridge(QObject):
    result = Signal(str, object)
    failed = Signal(str, str)
    output = Signal(str)
    command_done = Signal(int)



class RecoveryWindow(QMainWindow):
    restart_requested = Signal()

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Центр восстановления")
        self.resize(1150, 720)

        self.bridge = Bridge()
        self.bridge.result.connect(self.on_result)
        self.bridge.failed.connect(self.on_failed)
        self.bridge.output.connect(self.on_output)
        self.bridge.command_done.connect(self.on_command_done)

        self._busy = False
        self._busy_buttons: list[QPushButton] = []
        self._proc = None
        self._partial = ""
        self._last_progress = False
        self._last_results = None
        self._last_assoc: list = []

        root = QWidget()
        layout = QVBoxLayout(root)
        layout.addWidget(self._build_admin_banner())
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_points_tab(), "Точки восстановления")
        self.tabs.addTab(self._build_integrity_tab(), "Целостность Windows")
        self.tabs.addTab(self._build_checks_tab(), "Проверка системы")
        self.tabs.addTab(self._build_assoc_tab(), "Файловые ассоциации")
        self.tabs.currentChanged.connect(self._on_tab_changed)
        layout.addWidget(self.tabs, 1)
        self.setCentralWidget(root)
        self.statusBar().showMessage("Готово")

    # ---------- общие элементы ----------

    def _build_admin_banner(self) -> QWidget:
        banner = QWidget()
        row = QHBoxLayout(banner)
        row.setContentsMargins(0, 0, 0, 0)
        label = QLabel("Без прав администратора большинство функций этого окна недоступно.")
        button = QPushButton("Перезапустить от имени администратора")
        button.clicked.connect(self.restart_requested.emit)
        row.addWidget(label, 1)
        row.addWidget(button)
        banner.setVisible(not is_admin())
        return banner

    def show_tab(self, index: int) -> None:
        if self.tabs.isTabVisible(index):
            self.tabs.setCurrentIndex(index)

    def set_allowed(self, restore_point: bool, sfc_dism: bool, checks: bool = True) -> None:
        """Запреты из дополнительных настроек (ui/access.py): вкладки запрещённых скрыты."""
        for index, on in ((0, restore_point), (1, sfc_dism), (2, checks)):
            self.tabs.setTabVisible(index, on)
        if not self.tabs.isTabVisible(self.tabs.currentIndex()):
            visible = [i for i in range(self.tabs.count()) if self.tabs.isTabVisible(i)]
            if visible:
                self.tabs.setCurrentIndex(visible[0])

    def _set_busy(self, busy: bool, message: str = "") -> None:
        self._busy = busy
        for button in self._busy_buttons:
            button.setEnabled(not busy)
        if message:
            self.statusBar().showMessage(message)

    def _async(self, kind: str, fn, message: str) -> None:
        if self._busy:
            self.statusBar().showMessage("Дождитесь окончания текущей операции", 5000)
            return
        self._set_busy(True, message)

        def job():
            try:
                result = fn()
            except (OSError, ValueError) as e:
                self.bridge.failed.emit(kind, str(e))
                return
            except Exception as e:  # любая ошибка должна дойти до окна, а не пропасть в потоке
                self.bridge.failed.emit(kind, f"Ошибка: {e}")
                return
            self.bridge.result.emit(kind, result)

        threading.Thread(target=job, daemon=True).start()

    def on_failed(self, kind: str, text: str) -> None:
        self._set_busy(False)
        hint = "" if is_admin() else "\n\nПопробуйте запустить программу от имени администратора."
        self.statusBar().showMessage("Операция не выполнена", 8000)
        QMessageBox.critical(self, "Центр восстановления", text + hint)

    def on_result(self, kind: str, payload) -> None:
        self._set_busy(False)
        if kind == "list":
            self._fill_points(payload)
            self.statusBar().showMessage(f"Точек восстановления: {len(payload)}", 8000)
        elif kind == "create":
            self.statusBar().showMessage(payload, 10000)
            QMessageBox.information(self, "Точка восстановления", payload)
            self.refresh_points()
        elif kind == "enable":
            self.statusBar().showMessage(payload, 10000)
            QMessageBox.information(self, "Защита системы", payload)
        elif kind == "checks":
            self._apply_results(payload)
        elif kind in ("fix", "unlock"):
            self.statusBar().showMessage(payload.splitlines()[0], 10000)
            QMessageBox.information(self, "Исправление", payload)
            self.run_system_check()
        elif kind == "assoc_check":
            self._apply_assoc_issues(payload)
        elif kind == "assoc_snapshot":
            self.assoc_panel.set_snapshots(payload)
            self.statusBar().showMessage("Снимок файловых ассоциаций сохранён", 8000)
        elif kind == "assoc_compare":
            self.assoc_panel.set_diffs(payload)
            self.statusBar().showMessage(f"Отличий от снимка: {len(payload)}", 8000)
        elif kind == "assoc_list":
            self.assoc_panel.set_extensions(payload)
            self.statusBar().showMessage(f"Расширений в системе: {len(payload)}", 8000)
        elif kind == "assoc_fix":
            self.statusBar().showMessage(payload.splitlines()[0], 10000)
            QMessageBox.information(self, "Файловые ассоциации", payload)
            self.run_assoc_check()
            if self.assoc_panel.snapshots.currentData() is not None:
                self.assoc_panel.btn_compare.click()

    # ---------- вкладка «Точки восстановления» ----------

    def _build_points_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(QLabel(
            "Точка восстановления позволяет вернуть системные файлы, драйверы и реестр к "
            "прежнему состоянию (личные файлы она не затрагивает). Восстановление выполняется "
            "мастером Windows."))
        row = QHBoxLayout()
        self.rp_desc = QLineEdit(
            f"{appinfo.SHORT_NAME}: перед изменениями ({datetime.now():%Y-%m-%d})")
        create = QPushButton("Создать точку восстановления")
        create.clicked.connect(self.create_restore_point)
        row.addWidget(self.rp_desc, 1)
        row.addWidget(create)
        layout.addLayout(row)

        row = QHBoxLayout()
        refresh = QPushButton("Обновить список")
        refresh.clicked.connect(self.refresh_points)
        enable = QPushButton("Включить защиту системы (диск C:)")
        enable.clicked.connect(self.enable_protection)
        wizard = QPushButton("Открыть восстановление системы Windows")
        wizard.clicked.connect(self.open_wizard)
        for b in (refresh, enable, wizard):
            row.addWidget(b)
        row.addStretch()
        layout.addLayout(row)
        self._busy_buttons += [create, refresh, enable]

        self.points_tree = make_tree(["№", "Создана", "Описание", "Тип"], [70, 170, 520, 200])
        layout.addWidget(self.points_tree)
        return tab

    def refresh_points(self) -> None:
        self._async("list", rsys.list_restore_points, "Получаю список точек восстановления...")

    def _fill_points(self, points) -> None:
        self.points_tree.clear()
        for p in points:
            self.points_tree.addTopLevelItem(
                QTreeWidgetItem([str(p.number), p.created, p.description, p.kind]))

    def create_restore_point(self) -> None:
        description = self.rp_desc.text().strip() or appinfo.SHORT_NAME
        answer = QMessageBox.question(
            self, "Точка восстановления",
            f"Создать точку восстановления «{description}»?\n\nСоздание занимает до минуты. "
            "По умолчанию Windows разрешает не более одной точки в сутки.")
        if answer == QMessageBox.StandardButton.Yes:
            self._async("create", lambda: rsys.create_restore_point(description),
                        "Создаю точку восстановления...")

    def enable_protection(self) -> None:
        self._async("enable", rsys.enable_system_protection, "Включаю защиту системы...")

    def open_wizard(self) -> None:
        try:
            rsys.open_restore_wizard()
        except OSError as e:
            QMessageBox.critical(self, "Восстановление системы", f"Не удалось открыть: {e}")

    # ---------- вкладка «Целостность Windows» ----------

    def _build_integrity_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(QLabel(
            "Проверка и восстановление системных файлов Windows (нужны права администратора). "
            "Операции со значком «исправление» меняют систему и могут идти 10–30 минут."))
        row = QHBoxLayout()
        self._cmd_buttons: list[QPushButton] = []
        for key, (title, _, modifies) in COMMANDS.items():
            button = QPushButton(title + (" *" if modifies else ""))
            button.clicked.connect(lambda checked=False, k=key: self.start_command(k))
            row.addWidget(button)
            self._cmd_buttons.append(button)
        layout.addLayout(row)

        row = QHBoxLayout()
        self.btn_cancel = QPushButton("Остановить")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self.cancel_command)
        row.addWidget(QLabel("* изменяет систему"))
        row.addStretch()
        row.addWidget(self.btn_cancel)
        layout.addLayout(row)

        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(self.font())
        self.output.setMaximumBlockCount(5000)
        layout.addWidget(self.output, 1)
        return tab

    def start_command(self, key: str) -> None:
        if self._proc is not None:
            QMessageBox.information(self, "Целостность Windows", "Операция уже выполняется")
            return
        title, args, modifies = COMMANDS[key]
        self._cmd_title = title
        if not is_admin():
            QMessageBox.warning(self, "Целостность Windows",
                                "Для этой операции нужны права администратора.")
            return
        if modifies:
            answer = QMessageBox.question(
                self, title,
                f"{title}\n\nОперация может идти 10–30 минут и изменит системные файлы. "
                "Не закрывайте программу до её окончания. Продолжить?")
            if answer != QMessageBox.StandardButton.Yes:
                return
        self.output.clear()
        self._partial, self._last_progress = "", False
        self.output.appendPlainText(f"> {' '.join(args)}")
        for button in self._cmd_buttons:
            button.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.statusBar().showMessage(f"Выполняется: {title}")
        threading.Thread(target=self._command_job, args=(args,), daemon=True).start()

    def _command_job(self, args: list[str]) -> None:
        try:
            code = rsys.run_command(args, self.bridge.output.emit, self._remember_proc)
        except OSError as e:
            self.bridge.output.emit(f"\nНе удалось запустить команду: {e}\n")
            code = -1
        self.bridge.command_done.emit(code)

    def _remember_proc(self, proc) -> None:
        self._proc = proc

    def cancel_command(self) -> None:
        if self._proc is not None:
            self._proc.terminate()
            self.statusBar().showMessage("Останавливаю команду...")

    def on_output(self, text: str) -> None:
        self._partial += text.replace("\r\n", "\n")
        segments = re.split(r"[\r\n]", self._partial)
        self._partial = segments.pop()  # последний кусок может быть неполным
        for part in segments:
            self._add_line(part)

    def _add_line(self, part: str) -> None:
        line = part.strip()
        if not line:
            return
        progress = bool(PROGRESS_RE.search(line))
        if progress and self._last_progress:  # строки хода работы заменяют друг друга
            cursor = self.output.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            cursor.movePosition(QTextCursor.MoveOperation.StartOfBlock,
                                QTextCursor.MoveMode.KeepAnchor)
            cursor.insertText(line)
        else:
            self.output.appendPlainText(line)
        self._last_progress = progress
        bar = self.output.verticalScrollBar()
        bar.setValue(bar.maximum())

    def on_command_done(self, code: int) -> None:
        self._add_line(self._partial)
        self._partial = ""
        self._proc = None
        for button in self._cmd_buttons:
            button.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        meaning = {0: "завершено успешно", 3010: "завершено, нужна перезагрузка"}.get(
            code, "завершено с ошибкой или остановлено")
        self.output.appendPlainText(f"\nКод возврата: {code} ({meaning})")
        from recovery import activity
        lines = [l for l in self.output.toPlainText().splitlines() if l.strip()][-6:-1]
        activity.record("integrity", f"{getattr(self, '_cmd_title', 'Команда')}: {meaning} "
                                     f"(код {code})", output=lines)
        self.output.appendPlainText(r"Подробности sfc: C:\Windows\Logs\CBS\CBS.log")
        self.statusBar().showMessage(f"Команда {meaning}", 10000)

    # ---------- вкладка «Проверка системы» ----------

    PANELS = [
        ("hosts", "hosts",
         "Файл hosts подменяет адреса сайтов. Показаны записи, перенаправляющие домены на "
         "внешние адреса, и записи, блокирующие домены защиты и обновлений. Обычные блокировки "
         "рекламы свёрнуты в одну строку."),
        ("proxy", "Прокси",
         "Прокси браузеров и системы (WinINET). Вредоносные программы включают прокси или PAC-скрипт, "
         "чтобы перехватывать трафик. Проверяются текущий пользователь и другие учётные записи."),
        ("winhttp", "WinHTTP-прокси",
         "WinHTTP-прокси используют службы Windows и многие программы в обход настроек браузера."),
        ("updates", "Обновления",
         "Политики, службы и задачи расписания Центра обновления Windows. Их отключают, чтобы "
         "система не получала исправления безопасности."),
        ("firewall", "Брандмауэр",
         "Состояние профилей брандмауэра и подозрительные правила: входящий доступ для программ из "
         "временных папок и блокировка программ защиты. Удаление правила применяется после "
         "перезапуска службы брандмауэра или перезагрузки."),
        ("bcd", "BCD",
         "Параметры загрузки Windows: тестовый режим драйверов, отключение проверок целостности и "
         "среды восстановления, безопасный режим. Нужны права администратора."),
    ]

    def _build_checks_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        row = QHBoxLayout()
        check = QPushButton("Проверить всё")
        check.clicked.connect(self.run_system_check)
        row.addWidget(check)
        row.addStretch()
        layout.addLayout(row)
        self._busy_buttons.append(check)

        self.check_tabs = QTabWidget()
        layout.addWidget(self.check_tabs, 1)
        self.panels: dict[str, FindingsPanel] = {}
        for category, title, hint in self.PANELS:
            panel = FindingsPanel(hint)
            panel.fix_requested.connect(self.fix_finding)
            panel.exclude_requested.connect(self.exclude_finding)
            self.panels[category] = panel
            self.check_tabs.addTab(panel, title)
        self.policy_panel = PolicyPanel()
        self.policy_panel.scan_requested.connect(self.run_system_check)
        self.policy_panel.unlock_hits_requested.connect(self.unlock_hits)
        self.policy_panel.unlock_names_requested.connect(self.unlock_names)
        self.policy_panel.exclude_hits_requested.connect(self.exclude_hits)
        self.check_tabs.addTab(self.policy_panel, "Политики и блокировки")
        return tab

    def run_system_check(self) -> None:
        self._async("checks", checks.run_all, "Проверяю систему...")

    def _apply_results(self, results) -> None:
        self._last_results = results
        data = exclusions.load()
        hidden = problems = 0
        for category, panel in self.panels.items():
            findings = []
            for f in results.findings.get(category, []):
                if exclusions.matches(data, "checks", exclusions.finding_key(f)):
                    hidden += 1
                else:
                    findings.append(f)
            panel.set_findings(findings)
            problems += sum(1 for f in findings if f.level in ("warning", "bad"))
        hits = []
        for h in results.hits:
            if exclusions.matches(data, "checks", exclusions.hit_key(h)):
                hidden += 1
            else:
                hits.append(h)
        self.policy_panel.set_hits(hits)
        problems += len(hits)
        message = f"Проверка завершена. Требуют внимания: {problems}"
        from recovery import activity
        found = [f"{f.category}: {f.title} — {f.status}"
                 for fs in results.findings.values() for f in fs if f.level in ("warning", "bad")]
        found += [f"политика: {h.title}" for h in hits]
        activity.record("system_check", message, found=found)
        if hidden:
            message += f". Скрыто исключений: {hidden}"
        if results.policy_error:
            message += f". Сканирование политик не удалось: {results.policy_error}"
        self.statusBar().showMessage(message, 12000)

    def _confirm_trust(self, text: str) -> bool:
        answer = QMessageBox.question(
            self, "Доверять",
            f"{text}\n\nДобавить в исключения? Это больше не будет показываться при проверках, "
            "пока оно не изменится. Управлять исключениями можно на странице «Исключения» "
            "главного окна.")
        return answer == QMessageBox.StandardButton.Yes

    def exclude_finding(self, findings) -> None:
        text = (f"{findings[0].title}\n{findings[0].status}" if len(findings) == 1
                else f"Находок: {len(findings)}\n" + "\n".join(f"• {f.title}" for f in findings[:10]))
        if self._confirm_trust(text):
            for finding in findings:
                exclusions.add("checks", exclusions.finding_key(finding), finding.title,
                               finding.detail or finding.status)
            if self._last_results is not None:
                self._apply_results(self._last_results)

    def exclude_hits(self, hits) -> None:
        if self._confirm_trust(f"Ограничений: {len(hits)}"):
            for h in hits:
                exclusions.add("checks", exclusions.hit_key(h), h.title,
                               f"{h.hive}\\{h.path}\\{h.name} = {h.value}")
            if self._last_results is not None:
                self._apply_results(self._last_results)

    def fix_finding(self, findings) -> None:
        if len(findings) == 1:
            finding = findings[0]
            title = finding.fix_title
            text = (f"{finding.title}\n{finding.status}\n{finding.detail}\n\n"
                    f"Выполнить: {finding.fix_title}?")
        else:
            title = "Исправление"
            text = (f"Исправить находки ({len(findings)})?\n\n"
                    + "\n".join(f"• {f.title}: {f.fix_title}" for f in findings[:10]))
        answer = QMessageBox.question(
            self, title, text + "\n\nИзменения попадут в журнал действий, их можно будет отменить.")
        if answer == QMessageBox.StandardButton.Yes:
            self._async("fix", lambda: self._fix_many(findings), "Выполняю исправление...")

    @staticmethod
    def _fix_many(findings) -> str:
        if len(findings) == 1:
            return actions.apply_fix(findings[0])
        done, errors = [], []
        for finding in findings:
            try:
                done.append(actions.apply_fix(finding))
            except (OSError, ValueError) as e:
                errors.append(f"{finding.title}: {e}")
        if not done:
            raise OSError("\n".join(errors[:10]))
        text = f"Исправлено: {len(done)}. Отменить можно в журнале действий."
        if errors:
            text += f"\nНе удалось: {len(errors)}\n" + "\n".join(errors[:10])
        return text

    def unlock_hits(self, hits) -> None:
        lines = "\n".join(f"• {h.title}" for h in hits[:8])
        more = f"\n...и ещё {len(hits) - 8}" if len(hits) > 8 else ""
        answer = QMessageBox.question(
            self, "Разблокировка",
            f"Снять ограничений: {len(hits)}?\n\n{lines}{more}\n\n"
            "Изменения попадут в журнал действий и отменяются одним действием.")
        if answer == QMessageBox.StandardButton.Yes:
            self._async("unlock", lambda: actions.unlock_hits(hits), "Снимаю ограничения...")

    def unlock_names(self, names) -> None:
        answer = QMessageBox.question(
            self, "Разблокировка",
            f"Найти и снять выбранные ограничения ({len(names)})?\n\n"
            "Изменения попадут в журнал действий и отменяются одним действием.")
        if answer == QMessageBox.StandardButton.Yes:
            self._async("unlock", lambda: actions.unlock_by_names(names),
                        "Снимаю ограничения...")

    # ---------- вкладка «Файловые ассоциации» ----------

    def _build_assoc_tab(self) -> QWidget:
        self.assoc_panel = AssocPanel()
        panel = self.assoc_panel
        panel.check_requested.connect(self.run_assoc_check)
        panel.fix_requested.connect(self.fix_assoc_issues)
        panel.exclude_requested.connect(self.exclude_assoc_issue)
        panel.snapshot_requested.connect(self.take_assoc_snapshot)
        panel.compare_requested.connect(self.compare_assoc)
        panel.restore_requested.connect(self.restore_assoc)
        panel.list_requested.connect(self.list_extensions)
        self._busy_buttons += [panel.btn_check, panel.btn_snapshot, panel.btn_list]
        panel.set_snapshots(assoc.list_snapshots())
        return panel

    def _on_tab_changed(self, index: int) -> None:
        if index == TAB_ASSOC and not self.assoc_panel.checked_once and not self._busy:
            self.run_assoc_check()

    def run_assoc_check(self) -> None:
        def job():
            if not assoc.list_snapshots():  # первый снимок, чтобы было с чем сравнивать
                assoc.take_snapshot("автоматически при первой проверке")
            return assoc.check_critical()
        self._async("assoc_check", job, "Проверяю файловые ассоциации...")

    def _apply_assoc_issues(self, issues) -> None:
        self._last_assoc = issues
        data = exclusions.load()
        shown = [i for i in issues if not exclusions.matches(data, "checks", i.key)]
        self.assoc_panel.set_issues(shown)
        self.assoc_panel.set_snapshots(assoc.list_snapshots())
        hidden = len(issues) - len(shown)
        problems = sum(1 for i in shown if i.level != "ok")
        message = f"Ассоциации проверены. Проблем: {problems}"
        if hidden:
            message += f". Скрыто исключений: {hidden}"
        self.statusBar().showMessage(message, 10000)

    def exclude_assoc_issue(self, issues) -> None:
        text = "\n".join(f"{i.ext}: {i.title}\n{i.detail}" for i in issues[:8])
        if self._confirm_trust(text):
            for issue in issues:
                exclusions.add("checks", issue.key, f"{issue.ext}: {issue.title}", issue.detail)
            self._apply_assoc_issues(self._last_assoc)

    def fix_assoc_issues(self, issues) -> None:
        lines = "\n".join(f"• {i.ext}: {i.title}" for i in issues[:10])
        more = f"\n...и ещё {len(issues) - 10}" if len(issues) > 10 else ""
        answer = QMessageBox.question(
            self, "Файловые ассоциации",
            f"Исправить ({len(issues)})?\n\n{lines}{more}\n\n"
            "Изменение попадёт в журнал действий и отменяется одним действием. "
            "Исправления в HKLM требуют прав администратора.")
        if answer == QMessageBox.StandardButton.Yes:
            ops = [op for i in issues for op in i.ops]
            title = "Файловые ассоциации: исправлено " + ", ".join(sorted({i.ext for i in issues}))
            self._async("assoc_fix", lambda: assoc.apply_ops(ops, title), "Исправляю...")

    def list_extensions(self) -> None:
        if self._busy:
            self.assoc_panel.listed_once = False  # загрузим при следующем открытии вкладки
        self._async("assoc_list", assoc.list_all,
                    "Собираю все расширения и их программы (несколько секунд)...")

    def take_assoc_snapshot(self) -> None:
        def job():
            assoc.take_snapshot()
            return assoc.list_snapshots()
        self._async("assoc_snapshot", job, "Сохраняю снимок ассоциаций...")

    def compare_assoc(self, path) -> None:
        self._async("assoc_compare", lambda: assoc.compare(assoc.load_snapshot(path)),
                    "Сравниваю со снимком...")

    def restore_assoc(self, diffs) -> None:
        answer = QMessageBox.question(
            self, "Файловые ассоциации",
            f"Вернуть к состоянию снимка отмеченные значения ({len(diffs)})?\n\n"
            "Удаляемые разделы сохраняются в резервную копию. Действие попадёт в журнал "
            "и отменяется одним действием.")
        if answer == QMessageBox.StandardButton.Yes:
            ops = [op for d in diffs for op in d.ops]
            title = ("Файловые ассоциации: восстановлено из снимка "
                     + ", ".join(sorted({d.ext for d in diffs}))[:120])
            self._async("assoc_fix", lambda: assoc.apply_ops(ops, title), "Восстанавливаю...")

    # ---------- завершение ----------

    def shutdown(self) -> None:
        """Вызывается при закрытии главного окна."""
        if self._proc is not None:
            self._proc.terminate()

    def closeEvent(self, event) -> None:
        if self._proc is not None:
            answer = QMessageBox.question(
                self, "Центр восстановления",
                "Операция ещё выполняется. Остановить её и закрыть окно?")
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self._proc.terminate()
        event.accept()