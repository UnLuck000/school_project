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
        self.tool_actions = {}  # кнопка инструмента → пункт меню (скрыт, если запрещён)
        for button_id, text in (("btnAutoruns", "Сканер автозапуска"),
                                ("btnProcessManager", "Диспетчер процессов"),
                                ("btnFileAnalyzer", "Сканирование папки/файла"),
                                ("btnSystemChecks", "Проверка системы"),
                                ("btnUsb", "USB-накопители")):
            action = tools.addAction(text)
            action.triggered.connect(lambda checked=False, b=button_id: window.run_feature(b))
            self.tool_actions[button_id] = action

        self.settings_action = menu.addAction("Настройки")
        self.settings_action.triggered.connect(
            lambda checked=False: window.show_main("Настройки"))
        menu.addSeparator()
        self.exit_action = menu.addAction("Выход")
        self.exit_action.triggered.connect(lambda checked=False: window.quit_app())

        self.setContextMenu(menu)
        self._menu = menu  # меню должно жить, пока жив значок
        self.activated.connect(self._on_activated)

    def set_exit_allowed(self, allowed: bool) -> None:
        """Запрет закрытия программы (general/block_exit): пункт «Выход» неактивен."""
        self.exit_action.setEnabled(allowed)
        self.exit_action.setText("Выход" if allowed else "Выход (запрещён в настройках)")

    def _on_activated(self, reason):
        if reason in (QSystemTrayIcon.ActivationReason.Trigger,
                      QSystemTrayIcon.ActivationReason.DoubleClick):
            self.window_ref.show_main()