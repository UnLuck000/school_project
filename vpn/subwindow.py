"""Окно «Подписки» (vpn/subscriptions.py): список, добавить, изменить, обновить, удалить.

Скачивание — в потоке (routingwindow.run_job); список профилей меняет само окно VPN
(VpnWindow.apply_subscription), здесь — только подписки.
"""
import time

from PySide6.QtWidgets import (
    QDialog, QFormLayout, QHBoxLayout, QLineEdit, QMessageBox, QPushButton, QTableWidgetItem,
    QVBoxLayout,
)

from ui.widgets import make_table
from vpn import subscriptions
from vpn.routingwindow import IntervalPicker, _buttons, _hint, run_job


class SubscriptionEdit(QDialog):
    def __init__(self, parent, sub: subscriptions.Subscription | None = None):
        super().__init__(parent)
        self.setWindowTitle("Подписка" if sub else "Новая подписка")
        self.resize(720, 0)
        layout = QVBoxLayout(self)
        layout.addWidget(_hint("Ссылка подписки от провайдера VPN (https://...): по ней "
                               "приходит список серверов. В ссылке обычно личный токен — она "
                               "хранится зашифрованной (DPAPI)."))
        form = QFormLayout()
        self.name = QLineEdit(sub.name if sub else "")
        self.name.setPlaceholderText("необязательно — возьмётся из адреса")
        form.addRow("Название:", self.name)
        self.url = QLineEdit(sub.url if sub else "")
        self.url.setPlaceholderText("https://...")
        form.addRow("Ссылка:", self.url)
        self.interval = IntervalPicker(sub.interval if sub else 24)
        form.addRow("Обновлять:", self.interval)
        layout.addLayout(form)
        layout.addWidget(_buttons(self, "Сохранить"))


class SubscriptionsDialog(QDialog):
    def __init__(self, window):
        super().__init__(window)
        self.window_ = window
        self.setWindowTitle("Подписки VPN")
        self.resize(1000, 460)
        self.subs = subscriptions.load()
        layout = QVBoxLayout(self)
        layout.addWidget(_hint("Серверы подписки появляются в списке профилей с её названием и "
                               "обновляются сами с выбранным периодом. Берутся ссылки vless://; "
                               "другие протоколы пропускаются."))
        self.table = make_table([("Название", 180), ("Серверов", 80), ("Обновлено", 130),
                                 ("Трафик и срок", 200), ("Ссылка", 300)])
        self.table.cellDoubleClicked.connect(lambda *_: self._edit())
        layout.addWidget(self.table, 1)
        row = QHBoxLayout()
        for text, slot in (("Добавить...", self._add), ("Изменить...", self._edit),
                           ("Обновить", self._update), ("Удалить", self._delete)):
            button = QPushButton(text)
            button.clicked.connect(slot)
            row.addWidget(button)
        row.addStretch()
        close = QPushButton("Закрыть")
        close.clicked.connect(self.accept)
        row.addWidget(close)
        layout.addLayout(row)
        self.status = _hint()
        layout.addWidget(self.status)
        self._fill()

    def _fill(self) -> None:
        self.table.setRowCount(0)
        for sub in self.subs:
            row = self.table.rowCount()
            self.table.insertRow(row)
            updated = time.strftime("%d.%m.%Y %H:%M", time.localtime(sub.updated)) \
                if sub.updated else "ещё нет"
            values = (sub.name, str(sub.count) + (f" (+{sub.skipped} др.)" if sub.skipped
                                                  else ""),
                      updated + (" — ошибка" if sub.error else ""), sub.usage(),
                      sub.url[:60] + ("…" if len(sub.url) > 60 else ""))
            for col, text in enumerate(values):
                item = QTableWidgetItem(text)
                item.setToolTip(sub.error if col == 2 and sub.error else text)
                self.table.setItem(row, col, item)

    def _selected(self) -> subscriptions.Subscription | None:
        row = self.table.currentRow()
        return self.subs[row] if 0 <= row < len(self.subs) else None

    def _add(self) -> None:
        dialog = SubscriptionEdit(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            sub = subscriptions.new(dialog.name.text(), dialog.url.text(),
                                    dialog.interval.hours())
        except ValueError as e:
            QMessageBox.warning(self, "Подписка", str(e))
            return
        self.subs.append(sub)
        subscriptions.save(self.subs)
        self._fill()
        self._run(sub)

    def _edit(self) -> None:
        sub = self._selected()
        if sub is None:
            return
        dialog = SubscriptionEdit(self, sub)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        url = dialog.url.text().strip()
        if not url.lower().startswith("https://"):
            QMessageBox.warning(self, "Подписка", "Ссылка подписки должна начинаться с "
                                                  "https://")
            return
        changed = url != sub.url
        sub.name, sub.url = dialog.name.text().strip() or sub.name, url
        sub.interval = dialog.interval.hours()
        subscriptions.save(self.subs)
        self._fill()
        if changed:
            self._run(sub)

    def _update(self) -> None:
        sub = self._selected()
        if sub is not None:
            self._run(sub)

    def _run(self, sub: subscriptions.Subscription) -> None:
        self.status.setText(f"Обновляю «{sub.name}»...")

        def done(result, error):
            text = self.window_.apply_subscription(sub, result, error)
            self.subs = subscriptions.load()
            self._fill()
            self.status.setText(text)

        run_job(self, lambda: subscriptions.fetch(sub), done)

    def _delete(self) -> None:
        sub = self._selected()
        if sub is None:
            return
        if QMessageBox.question(self, "Удалить", f"Удалить подписку «{sub.name}» вместе с её "
                                "серверами в списке профилей?") != QMessageBox.StandardButton.Yes:
            return
        self.window_.remove_subscription(sub)
        self.subs = subscriptions.load()
        self._fill()
