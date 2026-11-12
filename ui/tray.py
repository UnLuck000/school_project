import time
from pathlib import Path

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPixmap
from PySide6.QtWidgets import QMenu, QSystemTrayIcon

import appinfo
from diag.log import get

log = get("tray")
# меню открывается над курсором, «Выход» — последний пункт, прямо под ним: отпускание
# кнопки или второй щелчок сразу после открытия меню выходом не считаются
EXIT_GUARD_SEC = 0.6

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


RECOVERY = "recovery"  # центр восстановления целиком (вкладки — отдельные инструменты)
RECOVERY_TOOLS = ("btnRestorePoint", "btnSfcDism", "btnSystemChecks")
# все инструменты страницы «Инструменты»; первыми — восстановление, автозапуск, процессы
TRAY_TOOLS = ((RECOVERY, "Восстановление системы"),
              ("btnAutoruns", "Сканер автозапуска"),
              ("btnProcessManager", "Диспетчер процессов"),
              ("-", ""),
              ("btnFileAnalyzer", "Сканирование папки/файла"),
              ("btnMemoryDeep", "Поиск внедрённого кода"),
              ("btnUsb", "USB-накопители"),
              ("btnDrivers", "Уязвимые драйверы"),
              ("btnExtensions", "Расширения браузеров"),
              ("btnLinkCheck", "Проверка ссылки и файла"),
              ("btnPasswordLeak", "Проверка пароля по утечкам"),
              ("btnVpn", "VPN"),
              ("-", ""),
              ("btnRestorePoint", "Создать точку восстановления"),
              ("btnSfcDism", "Проверка целостности (SFC/DISM)"),
              ("btnSystemChecks", "Проверка системы"),
              ("btnUndoJournal", "Журнал"))


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
        for button_id, text in TRAY_TOOLS:
            if button_id == "-":
                tools.addSeparator()
                continue
            action = tools.addAction(text)
            if button_id == RECOVERY:
                action.triggered.connect(lambda checked=False: window.open_recovery_center())
            else:
                action.triggered.connect(
                    lambda checked=False, b=button_id: window.run_feature(b))
            self.tool_actions[button_id] = action

        self.settings_action = menu.addAction("Настройки")
        self.settings_action.triggered.connect(
            lambda checked=False: window.show_main("Настройки"))
        menu.addSeparator()
        self.exit_action = menu.addAction("Выход")
        self.exit_action.triggered.connect(self._on_exit)
        self._menu_shown = 0.0
        menu.aboutToShow.connect(self._on_menu_shown)

        self.setContextMenu(menu)
        self._menu = menu  # меню должно жить, пока жив значок
        self.activated.connect(self._on_activated)

    def apply_access(self, allowed) -> None:
        """Запрещённые инструменты (ui/access.allowed) в меню не показываются."""
        for button_id, action in self.tool_actions.items():
            visible = (any(map(allowed, RECOVERY_TOOLS)) if button_id == RECOVERY
                       else allowed(button_id))
            action.setVisible(visible)

    def set_exit_allowed(self, allowed: bool) -> None:
        """Запрет закрытия программы (general/block_exit): пункт «Выход» неактивен."""
        self.exit_action.setEnabled(allowed)
        self.exit_action.setText("Выход" if allowed else "Выход (запрещён в настройках)")

    def _on_menu_shown(self):
        self._menu_shown = time.monotonic()
        log.info("Открыто меню значка в трее")

    def _on_exit(self, checked=False):
        since = time.monotonic() - self._menu_shown
        if since < EXIT_GUARD_SEC:
            log.warning("«Выход» нажат через %.2f с после открытия меню — похоже на случайный "
                        "щелчок, не выходим", since)
            return
        self.window_ref.quit_app()

    def _on_activated(self, reason):
        log.debug("Значок в трее: %s", getattr(reason, "name", reason))
        if reason in (QSystemTrayIcon.ActivationReason.Trigger,
                      QSystemTrayIcon.ActivationReason.DoubleClick):
            self.window_ref.show_main()
