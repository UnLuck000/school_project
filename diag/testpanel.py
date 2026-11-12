"""Тестовая версия: панель в углу страниц и окон, страница «Тестирование», комментарии.

Панель в углу: функции этой страницы или окна (выпадающий список), «✓ Исправно» — эталон
(diag.features.mark_ok), «✎ Комментарий» — замечание к функции. Цветная точка — состояние:
зелёная — отмечено исправным, красная — последний запуск с ошибкой, серая — не проверялось.

Комментарии — reports/feedback/comments.jsonl (одна строка на комментарий) и рядом
<время>_<функция>.log (последние строки журнала) и .png (снимок окна). Их читает разработчик.
В релизной версии ничего из этого не создаётся (diag.edition.is_test()).
"""
import json
import time
from pathlib import Path

from PySide6.QtCore import QEvent, QObject, Qt, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFrame, QHBoxLayout, QLabel, QMessageBox,
    QPlainTextEdit, QPushButton, QTableWidgetItem, QVBoxLayout, QWidget,
)

from diag import features
from diag.log import get, tail

log = get("test")
FEEDBACK_DIR = Path("reports") / "feedback"
COMMENTS_FILE = FEEDBACK_DIR / "comments.jsonl"
KINDS = ["Не работает", "Работает не так, как надо", "Дополнить / пожелание", "Другое"]


class _Bridge(QObject):
    """Запуски завершаются и в фоновых потоках: в интерфейс — сигналом (очередь Qt)."""
    finished = Signal(str)


_bridge: _Bridge | None = None


def bridge() -> _Bridge:
    """Создать в главном потоке (install)."""
    global _bridge
    if _bridge is None:
        _bridge = _Bridge()
        features.listeners.append(_bridge.finished.emit)
    return _bridge


def features_for(area: str) -> list[str]:
    return [f.id for f in features.FEATURES.values() if f.area == area]


def status(fid: str) -> tuple[str, str]:
    """(цвет точки, подсказка)."""
    ref = features.baseline().get(fid)
    last = features.runs().get(fid)
    if last and last.get("ok") is False:
        return "#e05252", "Последний запуск — с ошибкой: " + "; ".join(last.get("errors") or [])
    if ref:
        return "#3fb950", f"Отмечено исправным {ref.get('verified_at')} (версия {ref.get('version')})"
    if last:
        return "#d0a020", "Запускалось без ошибок, но ещё не отмечено исправным"
    return "#8b949e", "Ещё не запускалось в этом сеансе и не отмечено"


def comments_count(fid: str) -> int:
    try:
        return sum(1 for line in COMMENTS_FILE.read_text(encoding="utf-8").splitlines()
                   if json.loads(line).get("feature") == fid)
    except (OSError, ValueError):
        return 0


class CommentDialog(QDialog):
    def __init__(self, parent: QWidget | None, fid: str, area_ids: list[str] | None = None,
                 shot_of: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Комментарий к функции")
        self.resize(560, 420)
        self.shot_of = shot_of
        lay = QVBoxLayout(self)
        self.cmb_feature = QComboBox()
        ids = area_ids or list(features.FEATURES)
        for i in ids:
            self.cmb_feature.addItem(features.title(i), i)
        if fid in ids:
            self.cmb_feature.setCurrentIndex(ids.index(fid))
        self.cmb_kind = QComboBox()
        self.cmb_kind.addItems(KINDS)
        self.text = QPlainTextEdit()
        self.text.setPlaceholderText("Что не так или что добавить: что делали, что ожидали, "
                                     "что получилось")
        self.chk_log = QCheckBox("Приложить последние строки журнала")
        self.chk_log.setChecked(True)
        self.chk_shot = QCheckBox("Приложить снимок окна")
        self.chk_shot.setChecked(shot_of is not None)
        self.chk_shot.setEnabled(shot_of is not None)
        for label, w in (("Функция", self.cmb_feature), ("Вид", self.cmb_kind)):
            row = QHBoxLayout()
            row.addWidget(QLabel(label))
            row.addWidget(w, 1)
            lay.addLayout(row)
        lay.addWidget(self.text, 1)
        lay.addWidget(self.chk_log)
        lay.addWidget(self.chk_shot)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save |
                                   QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)

    def _save(self):
        text = self.text.toPlainText().strip()
        if not text:
            QMessageBox.information(self, "Комментарий", "Напишите, что не так.")
            return
        fid = self.cmb_feature.currentData()
        save_comment(fid, self.cmb_kind.currentText(), text, self.chk_log.isChecked(),
                     self.shot_of if self.chk_shot.isChecked() else None)
        self.accept()


def save_comment(fid: str, kind: str, text: str, with_log: bool = True,
                 shot_of: QWidget | None = None) -> dict:
    import appinfo
    FEEDBACK_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    base = FEEDBACK_DIR / f"{stamp}_{fid}"
    item = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "feature": fid,
            "title": features.title(fid), "kind": kind, "text": text,
            "version": appinfo.VERSION, "last_run": features.runs().get(fid),
            "baseline": features.baseline().get(fid)}
    if with_log:
        base.with_suffix(".log").write_text("\n".join(tail(300)), encoding="utf-8")
        item["log"] = base.with_suffix(".log").name
    if shot_of is not None:
        try:
            if shot_of.grab().save(str(base.with_suffix(".png"))):
                item["screenshot"] = base.with_suffix(".png").name
        except Exception:  # noqa: S110 — снимок окна не удался — комментарий сохраняется без него
            pass
    with COMMENTS_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")
    log.info("Комментарий к «%s» (%s): %s", item["title"], kind, text)
    return item


class CornerPanel(QFrame):
    """Панель тестирования в правом нижнем углу хоста (страницы или окна)."""

    def __init__(self, host: QWidget, area: str = ""):
        super().__init__(host)
        self.host = host
        self.setObjectName("testCornerPanel")
        self.setStyleSheet(
            "#testCornerPanel { background: palette(window); border: 1px solid palette(mid);"
            " border-radius: 8px; } QPushButton { padding: 3px 8px; }")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(8, 4, 8, 4)
        lay.setSpacing(6)
        self.dot = QLabel("●")
        self.cmb = QComboBox()
        self.cmb.setMinimumWidth(220)
        self.btn_ok = QPushButton("✓ Исправно")
        self.btn_ok.setToolTip("Отметить выбранную функцию исправной на этом компьютере: "
                               "последний успешный запуск станет эталоном")
        self.btn_comment = QPushButton("✎ Комментарий")
        for w in (self.dot, self.cmb, self.btn_ok, self.btn_comment):
            lay.addWidget(w)
        self.btn_ok.clicked.connect(self._mark)
        self.btn_comment.clicked.connect(self._comment)
        self.cmb.currentIndexChanged.connect(lambda _: self.refresh())
        host.installEventFilter(self)
        bridge().finished.connect(self.refresh)
        self.set_area(area)

    def set_area(self, area: str) -> None:
        ids = features_for(area)
        self.cmb.blockSignals(True)
        self.cmb.clear()
        for i in ids:
            self.cmb.addItem(features.title(i), i)
        self.cmb.blockSignals(False)
        self.setVisible(bool(ids))
        self.refresh()
        self._place()

    def refresh(self, *_) -> None:
        fid = self.cmb.currentData()
        if not fid:
            return
        color, tip = status(fid)
        self.dot.setStyleSheet(f"color: {color}; font-size: 16px;")
        self.dot.setToolTip(tip)
        self.cmb.setToolTip(tip)

    def _place(self) -> None:
        self.adjustSize()
        self.move(self.host.width() - self.width() - 12, self.host.height() - self.height() - 12)
        self.raise_()

    def eventFilter(self, watched, event):
        if watched is self.host and event.type() in (QEvent.Type.Resize, QEvent.Type.Show):
            self._place()
        return False

    def _mark(self) -> None:
        fid = self.cmb.currentData()
        if fid:
            entry = features.mark_ok(fid)
            if not entry["had_run"]:
                QMessageBox.information(self, "Исправно", "Отмечено. В этом сеансе функция "
                                        "ещё не запускалась, поэтому эталон без шагов и времени: "
                                        "сверяться будет только отсутствие ошибок. Чтобы был "
                                        "полный эталон, запустите функцию и отметьте снова.")
            self.refresh()

    def _comment(self) -> None:
        fid = self.cmb.currentData()
        ids = [self.cmb.itemData(i) for i in range(self.cmb.count())]
        CommentDialog(self.window(), fid, ids, shot_of=self.window()).exec()


class TestingPage(QWidget):
    """Страница «Тестирование»: все функции, их состояние, эталоны и комментарии."""

    changed = Signal()

    def __init__(self):
        super().__init__()
        from ui.widgets import make_table
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 16)
        head = QLabel("Тестовая версия: отмечайте функции, которые на этом компьютере работают "
                      "правильно («✓ Исправно»), и пишите комментарии к неисправным. На других "
                      "компьютерах отклонение от отмеченной версии попадёт в журнал как ошибка.")
        head.setWordWrap(True)
        lay.addWidget(head)
        self.table = make_table([("", 28), ("Функция", 300), ("Где", 170),
                                 ("Последний запуск", 260), ("Эталон", 220), ("Комментарии", 90)])
        lay.addWidget(self.table, 1)
        row = QHBoxLayout()
        buttons = (("✓ Исправно", self._mark), ("Снять отметку", self._unmark),
                   ("✎ Комментарий", self._comment), ("Папка комментариев", self._open_feedback),
                   ("Открыть журнал", self._open_log))
        for text, slot in buttons:
            b = QPushButton(text)
            b.clicked.connect(slot)
            row.addWidget(b)
        row.addStretch(1)
        lay.addLayout(row)
        bridge().finished.connect(self.refresh)
        self.refresh()

    def _selected(self) -> str | None:
        row = self.table.currentRow()
        item = self.table.item(row, 1) if row >= 0 else None
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def refresh(self, *_) -> None:
        runs, ref = features.runs(), features.baseline()
        keep = self._selected()
        self.table.setRowCount(0)
        for f in features.FEATURES.values():
            r = self.table.rowCount()
            self.table.insertRow(r)
            color, tip = status(f.id)
            dot = QTableWidgetItem("●")
            dot.setForeground(QColor(color))
            dot.setToolTip(tip)
            name = QTableWidgetItem(f.title)
            name.setData(Qt.ItemDataRole.UserRole, f.id)
            last = runs.get(f.id)
            last_text = "—"
            if last:
                when = time.strftime("%d.%m %H:%M", time.localtime(last.get("time", 0)))
                last_text = f"{when}: {'исправно' if last.get('ok') else 'ошибка'}, " \
                            f"{last.get('duration')} с"
                if last.get("errors"):
                    last_text += " — " + "; ".join(last["errors"])
            b = ref.get(f.id)
            base_text = f"{b.get('verified_at')} (v{b.get('version')})" if b else "—"
            where = f.area if not f.area[0].isascii() else f"окно {f.area}"
            values = [dot, name, QTableWidgetItem(where), QTableWidgetItem(last_text),
                      QTableWidgetItem(base_text), QTableWidgetItem(str(comments_count(f.id)))]
            for col, item in enumerate(values):
                self.table.setItem(r, col, item)
            if f.id == keep:
                self.table.selectRow(r)

    def _mark(self):
        fid = self._selected()
        if fid:
            features.mark_ok(fid)
            self.refresh()

    def _unmark(self):
        fid = self._selected()
        if fid:
            features.unmark(fid)
            self.refresh()

    def _comment(self):
        fid = self._selected() or next(iter(features.FEATURES))
        if CommentDialog(self.window(), fid).exec():
            self.refresh()

    def _open_feedback(self):
        FEEDBACK_DIR.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(FEEDBACK_DIR.resolve())))

    def _open_log(self):
        from diag.log import LOG_FILE
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(LOG_FILE.resolve())))


class WindowAttacher(QObject):
    """Тестовая версия: панель в угол каждого окна инструмента при первом показе."""

    def __init__(self, app):
        super().__init__(app)
        self._done: set[int] = set()
        app.installEventFilter(self)

    def eventFilter(self, watched, event):
        if event.type() == QEvent.Type.Show and isinstance(watched, QWidget) and watched.isWindow():
            name = type(watched).__name__
            if features_for(name) and id(watched) not in self._done:
                self._done.add(id(watched))
                CornerPanel(watched, name)
        return False
