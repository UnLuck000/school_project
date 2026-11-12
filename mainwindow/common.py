"""Общее для gui.py и примесей главного окна (mainwindow/*): пути баз, мосты сигналов,
имена страниц."""
from pathlib import Path

from PySide6.QtCore import QObject, Qt, Signal

from diag.log import get

_dlog = get("app")

SIGNATURES = Path("signatures/hashes.txt")
RULES_DIR = Path("signatures/rules")
NETFEEDS_DIR = Path("signatures/netfeeds")
ID_ROLE = Qt.ItemDataRole.UserRole
DEFAULT_WATCH = [str(Path.home() / "Downloads")]


class NetBridge(QObject):
    event = Signal(str, object)


class MonitorBridge(QObject):
    """Передаёт события из потока монитора в главный поток."""
    event = Signal(str, str)


SCAN_PAGE = "Сканирование папки/файла"
LOG_PAGE = "Журнал"  # журнал защиты, действия, исключения
