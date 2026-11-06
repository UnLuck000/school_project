"""Запреты в дополнительных настройках (раздел «Запреты», открывается только паролем).

У каждого инструмента своя галочка «Запретить ...» (TOOL_LOCKS). По умолчанию запрещены
точка восстановления, SFC/DISM, память, USB-накопители и уязвимые драйверы, остальные разрешены. Запрещённый
инструмент на странице «Инструменты» неактивен с подсказкой LOCKED_TIP, другие пути к нему
(страницы меню, кнопки главной, пункты трея, вкладки окон) скрыты, а открыть его по
ссылке из другого окна нельзя (MainWindow.tool_blocked). Отдельные галочки запрещают выключать защиту и мониторинг сети.
"""
from ui import settings as cfg

TOOL_LOCKS = {  # кнопка «Инструментов» → настройка запрета (порядок — как на странице)
    "btnAutoruns": "lock/autoruns",
    "btnMemoryDeep": "lock/memory",
    "btnUsb": "lock/usb",
    "btnDrivers": "lock/drivers",
    "btnExtensions": "lock/extensions",
    "btnFileAnalyzer": "lock/file_analyzer",
    "btnProcessManager": "lock/process_manager",
    "btnLinkCheck": "lock/link_check",
    "btnPasswordLeak": "lock/password_leak",
    "btnVpn": "lock/vpn",
    "btnRestorePoint": "lock/restore_point",
    "btnSfcDism": "lock/sfc_dism",
    "btnSystemChecks": "lock/system_checks",
    "btnUndoJournal": "lock/journal",
}
LOCKED_TIP = ('Инструмент запрещён в дополнительных настройках\n'
              '(Снять запрет можно только с паролем администратора)')
OFF_LOCKED_TIP = ('Выключение запрещено в дополнительных настройках\n'
                  '(Снять запрет можно только с паролем администратора)')


def allowed(button_id: str) -> bool:
    key = TOOL_LOCKS.get(button_id)
    return key is None or not cfg.get(key)


def protection_locked() -> bool:
    """Нельзя выключить защиту файлов."""
    return bool(cfg.get("lock/protection"))


def network_locked() -> bool:
    """Нельзя выключить мониторинг сети."""
    return bool(cfg.get("lock/network"))
