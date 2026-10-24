from PySide6.QtGui import QColor, QPalette

_default_style: str | None = None


def _dark_palette() -> QPalette:
    p = QPalette()
    R, G = QPalette.ColorRole, QPalette.ColorGroup
    p.setColor(R.Window, QColor(45, 45, 48))
    p.setColor(R.WindowText, QColor("white"))
    p.setColor(R.Base, QColor(30, 30, 30))
    p.setColor(R.AlternateBase, QColor(45, 45, 48))
    p.setColor(R.ToolTipBase, QColor(60, 60, 64))
    p.setColor(R.ToolTipText, QColor("white"))
    p.setColor(R.Text, QColor("white"))
    p.setColor(R.Button, QColor(60, 60, 64))
    p.setColor(R.ButtonText, QColor("white"))
    p.setColor(R.BrightText, QColor("red"))
    p.setColor(R.Link, QColor(80, 160, 255))
    p.setColor(R.Highlight, QColor(0, 120, 215))
    p.setColor(R.HighlightedText, QColor("white"))
    for role in (R.Text, R.ButtonText, R.WindowText):
        p.setColor(G.Disabled, role, QColor(128, 128, 128))
    return p


def apply_theme(app, theme: str) -> None:
    """theme: system | light | dark."""
    global _default_style
    if _default_style is None:
        _default_style = app.style().objectName()
    if theme == "dark":
        app.setStyle("Fusion")
        app.setPalette(_dark_palette())
    elif theme == "light":
        app.setStyle("Fusion")
        app.setPalette(app.style().standardPalette())
    else:
        app.setStyle(_default_style)
        app.setPalette(app.style().standardPalette())