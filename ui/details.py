"""Окно «Описание»: все сведения о строке списка и кнопки действий с ней.

Используется там, где в таблице оставлены только главные столбцы, а подробности (путь, хэши,
причина, ID...) открываются двойным щелчком или пунктом «Описание» правой кнопки:
журнал защиты, уязвимые драйверы, расширения браузеров, внедрённый код, ложные
срабатывания. Действие (label, callback): кнопка внизу; callback(dialog) может закрыть окно
(dialog.accept()) — например, если строки больше нет."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication, QDialog, QHBoxLayout, QPushButton, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout,
)


def main_window():
    """Главное окно программы (у окон инструментов нет родителя: они не держатся поверх)."""
    return next((w for w in QApplication.topLevelWidgets() if hasattr(w, "open_analyzer")
                 and hasattr(w, "show_main")), None)


def show_details(parent, title: str, rows: list[tuple[str, str]],
                 actions: list[tuple[str, object]] | None = None,
                 width: int = 760) -> QDialog:
    dialog = QDialog(parent)
    dialog.setWindowTitle(title)
    box = QVBoxLayout(dialog)
    tree = QTreeWidget()
    # ширина — по самому длинному значению (путь виден целиком), но не шире экрана
    metrics = tree.fontMetrics()
    # длинные описания переносятся по словам, их не учитываем — только пути и короткие строки
    longest = max((metrics.horizontalAdvance(line) for _, v in rows if v not in (None, "")
                   for line in str(v).splitlines() if len(line) <= 260), default=0)
    width = max(width, 190 + longest + 70)
    screen = dialog.screen() or QApplication.primaryScreen()
    if screen is not None:
        width = min(width, screen.availableGeometry().width() - 80)
    dialog.resize(width, min(560, 120 + 26 * max(len(rows), 4)))
    tree.setHeaderLabels(["Свойство", "Значение"])
    tree.setRootIsDecorated(False)
    tree.setWordWrap(True)
    tree.setColumnWidth(0, 190)
    tree.setTextElideMode(Qt.TextElideMode.ElideMiddle)
    for key, value in rows:
        if value in (None, ""):
            continue
        item = QTreeWidgetItem([key, str(value)])
        item.setToolTip(1, str(value))
        tree.addTopLevelItem(item)
    box.addWidget(tree, 1)

    row = QHBoxLayout()
    for label, callback in actions or []:
        button = QPushButton(label)
        button.clicked.connect(lambda checked=False, c=callback: c(dialog))
        row.addWidget(button)
    row.addStretch()
    copy = QPushButton("Копировать")
    copy.setToolTip("Все сведения — в буфер обмена")
    copy.clicked.connect(lambda: QApplication.clipboard().setText(
        "\n".join(f"{k}: {v}" for k, v in rows if v not in (None, ""))))
    close = QPushButton("Закрыть")
    close.clicked.connect(dialog.reject)
    row.addWidget(copy)
    row.addWidget(close)
    box.addLayout(row)
    dialog.show()
    return dialog
