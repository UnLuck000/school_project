from pathlib import Path

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPixmap
from PySide6.QtWidgets import QMenu, QSystemTrayIcon

import appinfo

ASSETS_DIR = Path(__file__).resolve().parent / "assets"


def _draw_icon() -> QIcon:
    icon = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(0, 120, 215))
        radius = size * 0.22
        painter.drawRoundedRect(QRectF(0, 0, size, size), radius, radius)
        font = QFont("Segoe UI")
        font.setBold(True)
        font.setPixelSize(max(6, int(size * 0.44)))
        painter.setFont(font)
        painter.setPen(QColor("white"))
        painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, "AV")
        painter.end()
        icon.addPixmap(pixmap)
    return icon


def load_app_icon() -> QIcon:
    """Значок из ui/assets/icon.ico или icon.png, иначе нарисованный в коде."""
    for name in ("icon.ico", "icon.png"):
        path = ASSETS_DIR / name
        if path.exists():
            return QIcon(str(path))
    return _draw_icon()


class TrayIcon(QSystemTrayIcon):
    def __init__(self, window, icon: QIcon):
        super().__init__(icon, window)
        self.window_ref = window
        self.setToolTip(appinfo.SHORT_NAME)

        menu = QMenu()
        main_action = menu.addAction(appinfo.SHORT_NAME)
        font = main_action.font()
        font.setBold(True)
        main_action.setFont(font)
        main_action.triggered.connect(lambda checked=False: window.show_main())
        menu.addSeparator()

        tools = menu.addMenu("Инструменты")  # подменю раскрывается при наведении
        items = (
            ("Сканер автозапуска", window.open_autoruns),
            ("Диспетчер процессов", window.open_process_manager),
            ("Сканирование папки/файла", lambda: window.run_feature("btnFileAnalyzer")),
            ("Проверка системы", lambda: window.run_feature("btnSystemChecks")),
        )
        for text, handler in items:
            tools.addAction(text).triggered.connect(
                lambda checked=False, h=handler: h())

        self.settings_action = menu.addAction("Настройки")  # виден только в режиме отладки
        self.settings_action.triggered.connect(
            lambda checked=False: window.show_main("Настройки"))
        menu.addSeparator()
        menu.addAction("Выход").triggered.connect(lambda checked=False: window.quit_app())

        self.setContextMenu(menu)
        self._menu = menu  # меню должно жить, пока жив значок
        self.activated.connect(self._on_activated)

    def _on_activated(self, reason):
        if reason in (QSystemTrayIcon.ActivationReason.Trigger,
                      QSystemTrayIcon.ActivationReason.DoubleClick):
            self.window_ref.show_main()