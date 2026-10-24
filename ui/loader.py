from pathlib import Path

from PySide6.QtCore import QFile
from PySide6.QtUiTools import QUiLoader
from PySide6.QtWidgets import QWidget

DESIGNER_DIR = Path(__file__).resolve().parent / "designer"


def load_ui(name: str, parent: QWidget | None = None) -> QWidget:
    """Загружает интерфейс из ui/designer/<name>.ui (файл редактируется в Qt Designer)."""
    path = DESIGNER_DIR / f"{name}.ui"
    file = QFile(str(path))
    if not file.open(QFile.OpenModeFlag.ReadOnly):
        raise FileNotFoundError(f"Не найден файл интерфейса: {path}")
    loader = QUiLoader()
    try:
        widget = loader.load(file, parent)
    finally:
        file.close()
    if widget is None:
        raise RuntimeError(f"Не удалось загрузить {path.name}: {loader.errorString()}")
    return widget


def child(root: QWidget, cls, name: str):
    """Элемент по имени (objectName в Designer); понятная ошибка, если его переименовали."""
    found = root.findChild(cls, name)
    if found is None:
        raise LookupError(f"В .ui не найден элемент {cls.__name__} с именем «{name}»")
    return found