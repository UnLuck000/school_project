from dataclasses import dataclass

from PySide6.QtGui import QColor


@dataclass(frozen=True)
class Category:
    id: str
    title: str
    rgb: tuple[int, int, int]
    description: str


# порядок = приоритет: цвет получает первое совпадение сверху
CATEGORIES = [
    Category("yara", "Найдено в памяти (YARA)", (255, 0, 0),
             "В памяти процесса сработало правило YARA. Высший приоритет."),
    Category("masq", "Маскировка под системный процесс", (153, 0, 0),
             "Имя как у системного процесса (svchost.exe, lsass.exe и т.п.), но файл лежит "
             "не в System32 и не в SysWOW64. Приём вредоносных программ."),
    Category("untrusted", "Недействительная подпись", (255, 128, 128),
             "Подпись есть, но недействительна: файл изменён или издатель не доверенный."),
    Category("packed", "Упакованный или зашифрованный", (255, 20, 147),
             "Эвристика PE: высокая энтропия кода, секции упаковщиков, почти нет импортов."),
    Category("suspended", "Приостановлен", (120, 120, 120),
             "Все потоки процесса приостановлены."),
    Category("service", "Службы Windows", (204, 255, 255),
             "Процесс размещает одну или несколько служб (например, svchost.exe)."),
    Category("system", "Системные процессы", (170, 204, 255),
             "Работают от системных учётных записей (SYSTEM, LOCAL SERVICE, "
             "NETWORK SERVICE и т.п.) либо относятся к ядру Windows."),
    Category("elevated", "Повышенные права", (255, 170, 0),
             "Процесс запущен с правами администратора (повышенный токен)."),
    Category("dotnet", "Программы .NET", (223, 255, 0),
             "Управляемый код .NET (таблица импорта содержит mscoree)."),
    Category("wow64", "32-разрядные программы", (190, 140, 140),
             "32-битный процесс на 64-битной Windows (WOW64)."),
    Category("own", "Ваши процессы", (255, 255, 170),
             "Запущены от вашей учётной записи."),
]

BY_ID = {c.id: c for c in CATEGORIES}


def classify(p, mem_match: bool) -> str | None:
    flags = {
        "yara": mem_match,
        "masq": p.masq,
        "untrusted": p.sig_status in ("invalid", "revoked"),
        "packed": p.packed,
        "suspended": p.status == "stopped",
        "service": p.service,
        "system": p.sys_account or p.core,
        "elevated": p.elevated is True,
        "dotnet": p.dotnet,
        "wow64": p.wow64,
        "own": p.own,
    }
    for category in CATEGORIES:
        if flags.get(category.id):
            return category.id
    return None


def text_color(rgb: tuple[int, int, int]) -> QColor:
    """Чёрный или белый текст в зависимости от яркости фона."""
    r, g, b = rgb
    return QColor("white") if 0.299 * r + 0.587 * g + 0.114 * b < 140 else QColor("black")