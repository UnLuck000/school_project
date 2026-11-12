"""Темы оформления.

Все темы рисуются стилем Fusion: стиль Windows 11 в Qt игнорирует смену палитры на лету
(часть виджетов оставалась в старых цветах до перезапуска). «Системная» выбирает светлую
или тёмную палитру по настройке Windows и сама переключается, когда настройка меняется.
"""
from dataclasses import dataclass

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QStyleFactory, QToolTip


@dataclass(frozen=True)
class Spec:
    window: str
    text: str
    base: str
    alt: str
    button: str
    highlight: str
    highlight_text: str
    link: str
    disabled: str
    dark: bool


SPECS = {
    "light": Spec("#f3f3f3", "#1b1b1b", "#ffffff", "#f7f7f7", "#fbfbfb", "#0067c0",
                  "#ffffff", "#0063b1", "#9a9a9a", False),
    "dark": Spec("#2d2d30", "#f0f0f0", "#1e1e1e", "#2a2a2d", "#3c3c40", "#0078d7",
                 "#ffffff", "#50a0ff", "#7a7a7a", True),
    "night": Spec("#0d1117", "#c9d1d9", "#010409", "#0d1117", "#161b22", "#1f6feb",
                  "#ffffff", "#58a6ff", "#5b636c", True),
    "contrast_dark": Spec("#000000", "#ffffff", "#000000", "#101010", "#000000", "#1aebff",
                          "#000000", "#ffff00", "#3ff23f", True),
    "contrast_light": Spec("#ffffff", "#000000", "#ffffff", "#f0f0f0", "#ffffff", "#37006e",
                           "#ffffff", "#00009f", "#600000", False),
    "sepia": Spec("#f1e7d0", "#433422", "#fbf4e4", "#f4ead3", "#eadcbf", "#a0522d",
                  "#ffffff", "#8b4513", "#a39274", False),
    "ocean": Spec("#1b2b34", "#d8dee9", "#14222a", "#1f313b", "#24394a", "#2a9d8f",
                  "#ffffff", "#7fdbca", "#62737e", True),
}

# (идентификатор, название в настройках); порядок совпадает с пунктами списка
THEMES = [
    ("system", "Системная"),
    ("light", "Светлая"),
    ("dark", "Тёмная"),
    ("night", "Ночная"),
    ("ocean", "Морская"),
    ("sepia", "Сепия (тёплая)"),
    ("contrast_dark", "Высокая контрастность (тёмная)"),
    ("contrast_light", "Высокая контрастность (светлая)"),
]
THEME_IDS = [t for t, _ in THEMES]

_current = "system"
_connected = False


def build_palette(spec: Spec) -> QPalette:
    p = QPalette()
    R, G = QPalette.ColorRole, QPalette.ColorGroup
    button = QColor(spec.button)
    shade = 160 if spec.dark else 120
    colors = {
        R.Window: spec.window, R.WindowText: spec.text, R.Base: spec.base,
        R.AlternateBase: spec.alt, R.ToolTipBase: spec.base, R.ToolTipText: spec.text,
        R.PlaceholderText: spec.disabled, R.Text: spec.text, R.Button: spec.button,
        R.ButtonText: spec.text, R.BrightText: "#ff5555", R.Link: spec.link,
        R.LinkVisited: spec.link, R.Highlight: spec.highlight,
        R.HighlightedText: spec.highlight_text, R.Accent: spec.highlight,
    }
    for role, value in colors.items():
        p.setColor(role, QColor(value))
    # рамки и тени Fusion берёт из этих ролей
    p.setColor(R.Light, button.lighter(shade))
    p.setColor(R.Midlight, button.lighter(115))
    p.setColor(R.Mid, button.darker(shade))
    p.setColor(R.Dark, button.darker(shade + 40))
    p.setColor(R.Shadow, QColor("#000000"))
    for role in (R.Text, R.ButtonText, R.WindowText, R.HighlightedText):
        p.setColor(G.Disabled, role, QColor(spec.disabled))
    p.setColor(G.Disabled, R.Highlight, QColor(spec.disabled))
    p.setColor(G.Inactive, R.Highlight, QColor(spec.highlight))
    return p


def system_is_dark(app) -> bool:
    return app.styleHints().colorScheme() == Qt.ColorScheme.Dark


def resolve(app, theme: str) -> str:
    """Тема, которая будет нарисована на самом деле (системная → светлая или тёмная)."""
    if theme == "system":
        return "dark" if system_is_dark(app) else "light"
    return theme if theme in SPECS else "light"


def _on_system_scheme_changed(*_) -> None:
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance()
    if app is not None and _current == "system" and not _applying:
        _apply(app, "system")


_applying = False


def _apply(app, theme: str) -> None:
    global _applying
    _applying = True  # смена схемы ниже сама вызывает colorSchemeChanged
    try:
        hints = app.styleHints()
        if theme == "system":
            hints.unsetColorScheme()  # снова следовать за Windows (и за её сменой темы)
        spec = SPECS[resolve(app, theme)]
        if theme != "system":  # заголовки окон Windows тоже станут светлыми или тёмными
            hints.setColorScheme(Qt.ColorScheme.Dark if spec.dark else Qt.ColorScheme.Light)
    finally:
        _applying = False
    # новый объект стиля: Qt заново оформляет все виджеты, старые цвета не остаются
    app.setStyle(_make_style())
    palette = build_palette(spec)
    app.setPalette(palette)
    QToolTip.setPalette(palette)
    for widget in app.allWidgets():
        # виджет с собственной таблицей стилей (меню слева, заголовки страниц) запоминает
        # палитру при первом оформлении: стиль нужно назначить заново, иначе остаются цвета
        # прежней темы (тёмное меню в светлой теме, белый заголовок на белом фоне)
        sheet = widget.styleSheet()
        if sheet:
            widget.setStyleSheet("")
            widget.setStyleSheet(sheet)
        widget.update()
    global _dark
    _dark = spec.dark
    _install_title_bar_filter(app)
    _refresh_title_bars(app)
    # Qt обрабатывает смену схемы позже и может вернуть заголовкам прежний цвет: повторяем
    from PySide6.QtCore import QTimer
    for delay in (100, 400):
        QTimer.singleShot(delay, lambda: _refresh_title_bars(app))


def _make_style():
    """Fusion с флажками строк списков, видными на любом фоне (_ItemCheckStyle)."""
    from PySide6.QtWidgets import QProxyStyle, QStyle

    class _ItemCheckStyle(QProxyStyle):
        """Флажок в строке дерева или таблицы: светлый квадрат с тёмной рамкой, отмеченный —
        синий с белой галочкой. У Fusion флажок берёт цвета палитры: в тёмных темах на
        цветных строках («Политики и блокировки») чёрная галочка не видна."""

        def drawPrimitive(self, element, option, painter, widget=None):
            if element != QStyle.PrimitiveElement.PE_IndicatorItemViewItemCheck:
                super().drawPrimitive(element, option, painter, widget)
                return
            from PySide6.QtCore import QPointF, QRectF
            from PySide6.QtGui import QPainter, QPainterPath, QPen
            rect = QRectF(option.rect)
            side = min(rect.width(), rect.height(), 16.0) - 2
            box = QRectF(rect.center().x() - side / 2, rect.center().y() - side / 2, side, side)
            on = bool(option.state & QStyle.StateFlag.State_On)
            partial = bool(option.state & QStyle.StateFlag.State_NoChange)
            enabled = bool(option.state & QStyle.StateFlag.State_Enabled)
            accent = QColor("#2f7ed8") if enabled else QColor("#8a9bb0")
            painter.save()
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            painter.setPen(QPen(accent if on or partial else QColor("#5f6368"), 1.2))
            painter.setBrush(accent if on or partial else QColor("#ffffff"))
            painter.drawRoundedRect(box, 3, 3)
            painter.setPen(QPen(QColor("#ffffff"), max(1.6, side / 8)))
            if on:
                path = QPainterPath(QPointF(box.left() + side * 0.22, box.top() + side * 0.52))
                path.lineTo(box.left() + side * 0.42, box.top() + side * 0.72)
                path.lineTo(box.left() + side * 0.78, box.top() + side * 0.30)
                painter.setBrush(Qt.BrushStyle.NoBrush)
                painter.drawPath(path)
            elif partial:
                y = box.center().y()
                painter.drawLine(QPointF(box.left() + side * 0.25, y),
                                 QPointF(box.right() - side * 0.25, y))
            painter.restore()

    global _style
    _style = _ItemCheckStyle(QStyleFactory.create("Fusion"))
    return _style


_style = None


def _refresh_title_bars(app) -> None:
    for widget in app.topLevelWidgets():
        set_title_bar(widget, _dark)


# ---------- заголовок окна Windows ----------
# Qt выбирает светлый или тёмный заголовок только при создании окна: при смене темы на ходу
# заголовок оставался прежним. Цвет задаётся напрямую через DWM.
_dark = False
_filter = None


def set_title_bar(widget, dark: bool) -> None:
    import sys
    if sys.platform != "win32" or not widget.isWindow() \
            or not widget.testAttribute(Qt.WidgetAttribute.WA_WState_Created):
        return
    try:
        import ctypes
        hwnd = ctypes.c_void_p(int(widget.winId()))
        value = ctypes.c_int(1 if dark else 0)
        # 20 = DWMWA_USE_IMMERSIVE_DARK_MODE (Windows 10 20H1 и новее)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(value), 4)
        # перерисовать рамку: SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED
        ctypes.windll.user32.SetWindowPos(hwnd, None, 0, 0, 0, 0, 0x1 | 0x2 | 0x4 | 0x10 | 0x20)
    except (OSError, AttributeError, ValueError):
        pass


def _install_title_bar_filter(app) -> None:
    """Окна, открытые позже (диспетчер процессов, диалоги), получают заголовок текущей темы."""
    global _filter
    if _filter is not None:
        return
    from PySide6.QtCore import QEvent, QObject

    class TitleBarFilter(QObject):
        def eventFilter(self, watched, event):
            if event.type() == QEvent.Type.Show and getattr(watched, "isWindow", None) \
                    and watched.isWindow():
                set_title_bar(watched, _dark)
            return False

    _filter = TitleBarFilter(app)
    app.installEventFilter(_filter)


def apply_theme(app, theme: str) -> None:
    """Применяет тему без перезапуска программы. theme: идентификатор из THEMES."""
    global _current, _connected
    _current = theme if theme in THEME_IDS else "system"
    if not _connected:
        app.styleHints().colorSchemeChanged.connect(_on_system_scheme_changed)
        _connected = True
    _apply(app, _current)
