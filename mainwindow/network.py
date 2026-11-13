"""Сеть: мониторинг сети, оповещения и блокировки, VPN при запуске. Часть главного окна: методы
MainWindow (gui.py)."""

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMenu,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from networkmonitor.connections import LEVEL_TEXT, terminate_process
from networkmonitor.netmon import NetworkMonitor
from recovery import activity
from ui import access, settings as cfg
from ui.widgets import make_table
from mainwindow.common import NETFEEDS_DIR, RULES_DIR, SIGNATURES


class NetworkMixin:
    """Атрибуты и сигналы — у MainWindow (gui.py)."""

    def _build_network_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        row = QHBoxLayout()
        self.net_btn = QPushButton("Включить мониторинг сети")
        self.net_btn.clicked.connect(self.toggle_network)
        kill_btn = QPushButton("Завершить процесс")
        kill_btn.clicked.connect(self.kill_selected_process)
        clear_btn = QPushButton("Очистить")
        clear_btn.clicked.connect(self.clear_net_alerts)
        for w in (self.net_btn, kill_btn, clear_btn):
            row.addWidget(w)
        row.addStretch()
        layout.addLayout(row)

        self.net_status = QLabel("Мониторинг сети выключен")
        layout.addWidget(self.net_status)
        self.net_substatus = QLabel("")  # состояние DNS (ETW) и TLS (WinDivert)
        self.net_substatus.setWordWrap(True)
        self._net_sub: dict[str, str] = {}
        layout.addWidget(self.net_substatus)

        self.net_table = make_table(self.NET_COLUMNS)
        self.net_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.net_table.customContextMenuRequested.connect(self._net_alert_menu)

        from networkmonitor.panels import BeaconPanel, BlockPanel, DnsPanel, TlsPanel, NetBridgeSignals
        self.net_tabs = QTabWidget()
        self.net_tabs.addTab(self.net_table, "Оповещения")
        self.dns_panel = DnsPanel(lambda domain: self.net_monitor.addresses_of(domain)
                                  if self.net_monitor else [])
        self.tls_panel = TlsPanel()
        self.tls_panel.choose_dir.connect(self._set_windivert_dir)
        self.beacon_panel = BeaconPanel()
        self.block_panel = BlockPanel()
        for panel in (self.dns_panel, self.tls_panel):
            panel.blocked.connect(self.block_panel.refresh)
        self.net_tabs.addTab(self.dns_panel, "DNS-запросы")
        self.net_tabs.addTab(self.tls_panel, "TLS (SNI, JA3)")
        self.net_tabs.addTab(self.beacon_panel, "Маячки")
        self.net_tabs.addTab(self.block_panel, "Блокировки")
        self.net_tabs.currentChanged.connect(self._on_net_tab_changed)
        self._net_block_bridge = NetBridgeSignals()
        self._net_block_bridge.done.connect(self._on_net_blocked)
        layout.addWidget(self.net_tabs, 1)
        return tab

    def _on_net_tab_changed(self, index: int):
        if self.net_tabs.widget(index) is self.block_panel:
            self.block_panel.refresh()

    def _net_alert_menu(self, pos):
        row = self.net_table.rowAt(pos.y())
        if row < 0 or row >= len(self.net_alerts):
            return
        self.net_table.selectRow(row)
        alert = self.net_alerts[row]
        host = alert.remote.rsplit(":", 1)[0] if alert.remote.count(":") == 1 else alert.remote
        ips = [host] if host.replace(".", "").isdigit() or ":" in host else (
            self.net_monitor.addresses_of(host) if self.net_monitor else [])
        menu = QMenu(self)
        shown = f" ({', '.join(ips[:3])})" if ips else ""
        a_ip = menu.addAction("Заблокировать адрес брандмауэром" + shown)
        a_ip.setEnabled(bool(ips))
        a_exe = menu.addAction("Запретить программе выход в сеть")
        a_exe.setEnabled(bool(alert.exe))
        a_kill = menu.addAction("Завершить процесс")
        a_story = menu.addAction("Что делал процесс (кто запустил, что создал, куда подключался)")
        a_story.setEnabled(bool(alert.pid))
        a_scan = menu.addAction("Открыть файл программы в сканере")
        a_scan.setEnabled(bool(alert.exe))
        menu.addSeparator()
        a_skip = menu.addAction("Не оповещать об этой программе (исключение)")
        a_skip.setEnabled(bool(alert.exe) and self.net_monitor is not None)
        chosen = menu.exec(self.net_table.viewport().mapToGlobal(pos))
        if chosen is a_skip:
            self._exclude_net_program(alert)
            return
        from networkmonitor.panels import run_block
        if chosen is a_ip:
            run_block(self, self._net_block_bridge, ips, [])
        elif chosen is a_exe:
            run_block(self, self._net_block_bridge, [], [alert.exe])
        elif chosen is a_kill:
            self.kill_selected_process()
        elif chosen is a_story:
            from processmanager import story
            story.show(self, alert.pid)
        elif chosen is a_scan:
            self.open_analyzer(alert.exe)

    def _exclude_net_program(self, alert):
        """Исключение программы из оповещений мониторинга сети. В тестовой версии
        попадает в signatures/release_exclusions.json — и в релиз."""
        from diag import edition
        from scanner import exclusions
        key = self.net_monitor.program_key(alert.exe)
        if not key:
            # частый случай — установщик из временной папки: отработал и удалился
            QMessageBox.information(
                self, "Сеть",
                f"Файла программы уже нет:\n{alert.exe or alert.name}\n\nИсключение "
                "делается по подписи или SHA-256 файла, а без файла их не узнать. Так бывает "
                "с установщиками и временными программами — они удаляются после работы.")
            return
        how = ("по издателю подписи" if "|pub:" in key
               else "по SHA-256: после обновления файла оповещения вернутся")
        where = ("\n\nТестовая версия: исключение попадёт и в релизную."
                 if edition.is_test() else "")
        answer = QMessageBox.question(
            self, "Мониторинг сети",
            f"Не оповещать о сетевой активности {alert.name}?\n\n{alert.exe}\n\n"
            f"Исключение {how}. Если файл программы распознан как угроза, оповещения "
            f"будут всё равно. Убрать — «Журнал» → «Исключения».{where}")
        if answer != QMessageBox.StandardButton.Yes:
            return
        from diag.anon import anonymize_user  # файл может уйти в Git: без имени пользователя
        exclusions.add("network", key, alert.name, anonymize_user(alert.exe))
        activity.record("net_alert", f"Программа исключена из мониторинга сети: {alert.name}",
                        exe=alert.exe)
        self.exclusions_page.refresh()
        self.statusBar().showMessage(f"{alert.name}: оповещений сети больше не будет", 5000)

    def _on_net_blocked(self, text: str, ok: bool):
        (QMessageBox.information if ok else QMessageBox.warning)(self, "Блокировка", text)
        if ok:
            self.block_panel.refresh()
            self.journal_page.refresh()

    def _set_windivert_dir(self, folder: str):
        """Папка, закрытая от записи, — как есть; иначе — защищённая копия (с вопросом)."""
        import hashlib
        from pathlib import Path

        from networkmonitor import tls
        dll = Path(folder) / "WinDivert.dll"
        if not dll.is_file() or not (dll.parent / "WinDivert64.sys").is_file():
            QMessageBox.warning(self, "WinDivert", "В папке нет WinDivert.dll и "
                                                   "WinDivert64.sys.")
            return
        safe, reason = tls.windivert_safe(dll)
        if not safe:
            digest = hashlib.sha256(dll.read_bytes()).hexdigest()
            if QMessageBox.question(
                    self, "WinDivert",
                    f"В эту папку может писать не только администратор ({reason}).\n\n"
                    "Программа сделает копию WinDivert.dll и WinDivert64.sys в защищённую "
                    "папку и будет загружать её. Убедитесь, что это настоящий WinDivert "
                    f"(SHA-256 библиотеки: {digest}).\n\nСкопировать?") != \
                    QMessageBox.StandardButton.Yes:
                return
            try:
                folder = str(tls.trust_windivert(folder))
            except OSError as e:
                QMessageBox.warning(self, "WinDivert", f"Копия не сделана: {e}")
                return
            activity.record("network", f"WinDivert: защищённая копия из {dll.parent}",
                            sha256=digest)
        cfg.set_("net/windivert_dir", folder)
        QMessageBox.information(self, "WinDivert", "Папка сохранена. Выключите и снова "
                                                   "включите мониторинг сети.")

    def toggle_network(self, force: bool = False):
        """force: выключить и при запрете (возврат состояния после замера ресурсов)."""
        if self.net_monitor is not None:
            if access.network_locked() and not force:
                self._off_blocked("мониторинг сети")
                return
            self.net_btn.setEnabled(False)
            self.net_monitor.stop()
            self._net_stopped()
            return
        self.net_monitor = NetworkMonitor(
            sig_dir=SIGNATURES.parent, rules_dir=RULES_DIR, netfeeds_dir=NETFEEDS_DIR,
            on_event=lambda kind, payload: self.net_bridge.event.emit(kind, payload),
            windivert_dir=cfg.get("net/windivert_dir"),
        )
        self.net_monitor.start()
        self.net_btn.setText("Выключить мониторинг сети")
        self.net_status.setText("Запускаю...")
        self._apply_off_locks()
        self.refresh_dashboard()

    def _net_stopped(self):
        self.net_monitor = None
        self.net_btn.setEnabled(True)
        self.net_btn.setText("Включить мониторинг сети")
        self.net_status.setText("Мониторинг сети выключен")
        self._net_sub = {}
        self.net_substatus.setText("")
        self._apply_off_locks()
        self.refresh_dashboard()

    def on_net_event(self, kind: str, payload):
        if kind == "status":
            self.net_status.setText(payload)
        elif kind == "error":
            self.net_status.setText(f"Ошибка: {payload}")
        elif kind == "stopped":
            self._net_stopped()
        elif kind == "alert":
            self._add_net_alert(payload)
        elif kind == "substatus":
            self._net_sub[payload.split(":", 1)[0]] = payload
            self.net_substatus.setText("\n".join(self._net_sub.values()))
        elif kind == "dns":
            self.dns_panel.add(payload)
        elif kind == "tls":
            self.tls_panel.add(payload)
        elif kind == "beacon":
            self.beacon_panel.add(payload)

    def _add_net_alert(self, a):
        activity.record("net_alert", f"{a.name} (PID {a.pid}) → {a.remote}: {a.rule}",
                        detail=a.detail, exe=a.exe)
        row = self.net_table.rowCount()
        self.net_table.insertRow(row)
        values = [a.time, LEVEL_TEXT.get(a.level, a.level), a.name, str(a.pid),
                  a.remote, a.rule, a.detail]
        color = QColor("red") if a.level == "critical" else QColor("darkorange")
        for col, text in enumerate(values):
            item = QTableWidgetItem(text)
            item.setForeground(QBrush(color))
            self.net_table.setItem(row, col, item)
        self.net_alerts.append(a)
        if len(self.net_alerts) > 500:  # таблица и список обрезаются синхронно
            self.net_table.removeRow(0)
            self.net_alerts.pop(0)
        self.net_table.scrollToBottom()
        self.statusBar().showMessage(f"[Сеть] {a.name}: {a.detail}")

    def kill_selected_process(self):
        row = self.net_table.currentRow()
        if row < 0 or row >= len(self.net_alerts):
            QMessageBox.information(self, "Сеть", "Сначала выберите строку в списке")
            return
        alert = self.net_alerts[row]
        answer = QMessageBox.question(
            self, "Завершить процесс",
            f"Завершить {alert.name} (PID {alert.pid})?\n\n{alert.exe or 'путь неизвестен'}\n\n"
            "Несохранённые данные программы будут потеряны.")
        if answer == QMessageBox.StandardButton.Yes:
            message = terminate_process(alert)
            self.statusBar().showMessage(message)
            QMessageBox.information(self, "Сеть", message)

    def clear_net_alerts(self):
        self.net_table.setRowCount(0)
        self.net_alerts.clear()

    def start_vpn_on_launch(self):
        """Прокси, оставшийся после сбоя, возвращается; VPN подключается, если включено
        «Подключать VPN при запуске программы» (vpn/autostart) и инструмент разрешён."""
        from vpn import dnsguard, killswitch, procguard, xray
        # ядра VPN от прошлого запуска (программу сняли в диспетчере задач до привязки к
        # заданию Windows): туннель и порты заняты, а управлять ими нечем
        orphans = procguard.kill_orphans()
        if orphans:
            text = "Завершены ядра VPN, оставшиеся от прошлого запуска: " + ", ".join(orphans)
            self.add_event(text, "info")
            activity.record("vpn", text)
        if xray.recover_proxy():
            self.add_event("Системный прокси возвращён (VPN был отключён аварийно)", "info")
        # программа закрылась с подключённым VPN или упала: интернет не должен остаться
        # перекрытым, DNS — подменённым
        if killswitch.recover():
            self.add_event("Kill switch снят: VPN был отключён аварийно", "info")
            activity.record("vpn", "Kill switch снят при запуске (VPN был отключён аварийно)")
        if dnsguard.recover():
            self.add_event("DNS адаптеров возвращён (VPN был отключён аварийно)", "info")
        if not cfg.get("vpn/autostart") or not access.allowed("btnVpn"):
            return
        from vpn.window import VpnWindow
        window = self.tool_windows.get("vpn")
        if window is None:
            window = VpnWindow()  # без владельца: не держится поверх главного окна
            self.tool_windows["vpn"] = window
            self.apply_on_top(cfg.get("general/on_top"))
        if window.autoconnect():
            activity.record("vpn", "VPN подключается вместе с программой")
