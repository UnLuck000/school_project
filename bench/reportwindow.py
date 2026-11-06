"""Окно «Отчёт и графики»: замер потребления ресурсов программой по сценариям нагрузки.
Перед замером включаются защита файлов и мониторинг сети (если были выключены), после
замера возвращается прежнее состояние."""
import threading

from PySide6.QtCharts import QChart, QChartView, QLineSeries, QValueAxis
from PySide6.QtCore import QObject, QPointF, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QHBoxLayout, QHeaderView, QLabel, QMainWindow, QMessageBox,
    QPushButton, QSpinBox, QSplitter, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from bench import resources
from bench.resources import Report, Sampler

PALETTE = ["#7f8c8d", "#2980b9", "#c0392b", "#27ae60", "#8e44ad", "#d35400", "#16a085",
           "#f39c12", "#2c3e50"]
SHORT = {  # подписи в легенде графиков: полные названия не помещаются
    "Фон (покой)": "Фон", "Загрузка баз и компиляция YARA": "Базы",
    "Проверка файлов (первая)": "Файлы", "Проверка файлов (повторная)": "Файлы (кэш)",
    "Проверка памяти процессов": "Память", "Проверка цифровых подписей": "Подписи",
    "Снимки процессов": "Процессы", "Снимки сетевых соединений": "Сеть",
}
SMOOTH = 7  # точек в скользящем среднем (по 250 мс: около 1,75 с)
HEADERS = ["Сценарий", "Время, с", "ЦП среднее, %", "ЦП пик, %", "Память пик, МБ",
           "Прирост памяти, МБ", "Прочитано, МБ", "Потоков", "Что делалось"]


class _Bridge(QObject):
    progress = Signal(str)
    done = Signal(bool)


class ResourceReportWindow(QMainWindow):
    def __init__(self, prepare=None, restore=None, parent=None):
        """prepare() включает фоновые функции программы и возвращает, что было включено;
        restore(состояние) возвращает всё как было."""
        super().__init__(parent)
        self.setWindowTitle("Отчёт и графики: потребление ресурсов")
        self.resize(1250, 820)
        self._prepare, self._restore = prepare, restore
        self._state = None
        self.report: Report | None = None
        self.sampler: Sampler | None = None
        self._cancel = threading.Event()
        self.bridge = _Bridge()
        self.bridge.progress.connect(lambda text: self.status.setText(text))
        self.bridge.done.connect(self._on_done)

        central = QWidget()
        layout = QVBoxLayout(central)
        hint = QLabel(
            "Замер показывает, сколько ресурсов забирает сама программа: процессор (доля от всех "
            "ядер, как в диспетчере задач), память и чтение с диска. По очереди запускаются "
            "функции, которые нагружают систему: загрузка баз, проверка файлов (первая и "
            "повторная), проверка памяти процессов, подписей, снимки процессов и соединений. "
            "Защита файлов и мониторинг сети на время замера включаются. Рабочие процессы "
            "проверки файлов учитываются вместе с программой.")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        row = QHBoxLayout()
        row.addWidget(QLabel("Файлов для проверки:"))
        self.files_spin = QSpinBox()
        self.files_spin.setRange(50, 3000)
        self.files_spin.setValue(400)
        row.addWidget(self.files_spin)
        self.start_btn = QPushButton("Запустить замер")
        self.start_btn.clicked.connect(self.start)
        row.addWidget(self.start_btn)
        self.stop_btn = QPushButton("Стоп")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(lambda: self._cancel.set())
        row.addWidget(self.stop_btn)
        self.save_btn = QPushButton("Сохранить CSV и графики")
        self.save_btn.setEnabled(False)
        self.save_btn.clicked.connect(self.save)
        row.addWidget(self.save_btn)
        self.smooth_cb = QCheckBox("Сглаживать графики")
        self.smooth_cb.setToolTip("Скользящее среднее: всплески от отдельных крупных файлов "
                                  "не заслоняют общую картину. В таблице и CSV — точные значения.")
        self.smooth_cb.setChecked(True)
        self.smooth_cb.toggled.connect(self._redraw)
        row.addWidget(self.smooth_cb)
        row.addStretch()
        layout.addLayout(row)
        self.status = QLabel("Замер ещё не запускался")
        layout.addWidget(self.status)

        splitter = QSplitter(Qt.Orientation.Vertical)
        self.table = QTableWidget(0, len(HEADERS))
        self.table.setHorizontalHeaderLabels(HEADERS)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        splitter.addWidget(self.table)

        charts = QWidget()
        charts_layout = QHBoxLayout(charts)
        charts_layout.setContentsMargins(0, 0, 0, 0)
        self.cpu_view = self._chart_view("Процессор, % от всех ядер")
        self.mem_view = self._chart_view("Память (рабочий набор), МБ")
        charts_layout.addWidget(self.cpu_view)
        charts_layout.addWidget(self.mem_view)
        splitter.addWidget(charts)
        splitter.setSizes([250, 500])
        layout.addWidget(splitter, 1)
        self.setCentralWidget(central)

        self.timer = QTimer(self)  # графики обновляются во время замера
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self._redraw)

    @staticmethod
    def _chart_view(title: str) -> QChartView:
        chart = QChart()
        chart.setTitle(title)
        chart.legend().setAlignment(Qt.AlignmentFlag.AlignBottom)
        view = QChartView(chart)
        view.setRenderHint(QPainter.RenderHint.Antialiasing)
        view.setMinimumHeight(300)
        return view

    # ---------- замер ----------
    def start(self):
        self._cancel = threading.Event()
        self.report = Report()
        self.sampler = Sampler(self.report)
        self.table.setRowCount(0)
        if self._prepare is not None:
            self._state = self._prepare()
        self.start_btn.setEnabled(False)
        self.save_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.sampler.start()
        self.timer.start()
        files = self.files_spin.value()
        threading.Thread(target=self._job, args=(files,), daemon=True).start()

    def _job(self, files: int):
        from ui import settings as cfg
        resources.run_all(self.report, self.sampler, self._cancel, self.bridge.progress.emit,
                          files=files, workers=int(cfg.get("scan/workers")))
        self.sampler.stop()
        self.bridge.done.emit(self._cancel.is_set())

    def _on_done(self, cancelled: bool):
        self.timer.stop()
        if self._restore is not None:
            self._restore(self._state)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.save_btn.setEnabled(True)
        self._redraw()
        self._fill_table()
        total = sum(s.seconds for s in self.report.summaries)
        peak = max((s.rss_peak for s in self.report.summaries), default=0)
        ram = self.report.total_ram or 1
        self.status.setText(
            ("Остановлено. " if cancelled else "Готово. ")
            + f"Общее время {total:.1f} с, пик памяти {peak / 1048576:.0f} МБ "
            f"({peak / ram * 100:.1f}% ОЗУ), ядер процессора: {self.report.cpu_count}")

    def _fill_table(self):
        self.table.setRowCount(0)
        for s in self.report.summaries:
            row = self.table.rowCount()
            self.table.insertRow(row)
            values = [s.scenario, f"{s.seconds:.2f}", f"{s.cpu_avg:.1f}", f"{s.cpu_peak:.1f}",
                      f"{s.rss_peak / 1048576:.0f}", f"{s.rss_delta / 1048576:+.0f}",
                      f"{s.read_mb:.1f}", str(s.threads_peak), s.note]
            for col, text in enumerate(values):
                item = QTableWidgetItem(text)
                if 0 < col < len(values) - 1:  # числа вправо, текст влево
                    item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                self.table.setItem(row, col, item)

    # ---------- графики ----------
    def _redraw(self):
        if self.report is None:
            return
        samples = list(self.report.samples)
        order = [title for title, _ in resources.SCENARIOS]
        for view, value, top_min in ((self.cpu_view, lambda s: s.cpu, 10.0),
                                     (self.mem_view, lambda s: s.rss / 1048576, 100.0)):
            chart = view.chart()
            chart.removeAllSeries()
            for axis in chart.axes():
                chart.removeAxis(axis)
            axis_x, axis_y = QValueAxis(), QValueAxis()
            axis_x.setTitleText("секунды")
            axis_x.setLabelFormat("%d")
            axis_y.setLabelFormat("%d")
            chart.addAxis(axis_x, Qt.AlignmentFlag.AlignBottom)
            chart.addAxis(axis_y, Qt.AlignmentFlag.AlignLeft)
            # отдельная линия на каждый сценарий: по цвету видно, что нагружает сильнее
            segments: dict[str, list[QPointF]] = {}
            for s in samples:
                if s.scenario != "—":
                    segments.setdefault(s.scenario, []).append(QPointF(s.t, value(s)))
            top = top_min
            for title, points in segments.items():
                if self.smooth_cb.isChecked():
                    points = _smooth(points)
                series = QLineSeries()
                series.setName(SHORT.get(title, title))
                index = order.index(title) if title in order else 0
                series.setPen(QPen(QColor(PALETTE[index % len(PALETTE)]), 2))
                series.append(points)
                chart.addSeries(series)
                series.attachAxis(axis_x)
                series.attachAxis(axis_y)
                top = max(top, max(p.y() for p in points))
            axis_x.setRange(0, max((s.t for s in samples), default=1))
            axis_y.setRange(0, top * 1.1)

    def save(self):
        if self.report is None:
            return
        summary, samples = resources.save_csv(self.report)
        base = str(summary).removesuffix("_summary.csv")
        self.cpu_view.grab().save(base + "_cpu.png")
        self.mem_view.grab().save(base + "_memory.png")
        QMessageBox.information(
            self, "Отчёт сохранён",
            f"Папка: {summary.parent}\n\n{summary.name}\n{samples.name}\n"
            f"{base.rsplit(chr(92), 1)[-1]}_cpu.png\n{base.rsplit(chr(92), 1)[-1]}_memory.png")

    def closeEvent(self, event):
        self._cancel.set()
        super().closeEvent(event)


def _smooth(points: list[QPointF], window: int = SMOOTH) -> list[QPointF]:
    """Центрированное скользящее среднее по значениям (время не меняется)."""
    if len(points) < 3:
        return points
    half = window // 2
    values = [p.y() for p in points]
    result = []
    for i, p in enumerate(points):
        part = values[max(0, i - half):i + half + 1]
        result.append(QPointF(p.x(), sum(part) / len(part)))
    return result
