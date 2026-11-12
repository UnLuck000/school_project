from dataclasses import dataclass

from recovery.registry import hives_to_scan, list_subkeys, list_values, read_value

EXPLORER = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
SYSTEM = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
ACTIVE_DESKTOP = r"Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop"
GP_SYSTEM = r"Software\Policies\Microsoft\Windows\System"
GP_MMC = r"Software\Policies\Microsoft\MMC"
GP_RESTORE = r"Software\Policies\Microsoft\Windows NT\SystemRestore"
IFEO = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"

CRITICAL = {"EnableLUA", "ConsentPromptBehaviorAdmin", "DisableSR", "DisableConfig"}


@dataclass(frozen=True)
class Restriction:
    name: str
    description: str
    keys: tuple                       # разделы, где значение может лежать
    default: int | None = None        # если задано, значение устанавливается, а не удаляется
    bad: tuple | None = None          # плохие значения; None = любое ненулевое


CATALOG = [
    Restriction("DisableTaskMgr", "Блокировка диспетчера задач", (SYSTEM,)),
    Restriction("DisableRegistryTools", "Блокировка редактора реестра", (SYSTEM,)),
    Restriction("DisableCMD", "Блокировка командной строки", (GP_SYSTEM, SYSTEM)),
    Restriction("RestrictToPermittedSnapins", "Блокировка MMC", (GP_MMC,)),
    Restriction("NoControlPanel", "Блокировка панели управления и параметров Windows", (EXPLORER,)),
    Restriction("NoRun", "Блокировка окна «Выполнить»", (EXPLORER,)),
    Restriction("NoViewOnDrive", "Блокировка доступа к диску из проводника", (EXPLORER,)),
    Restriction("NoDrives", "Скрытие дисков из проводника", (EXPLORER,)),
    Restriction("NoFind", "Блокировка поиска в меню «Пуск»", (EXPLORER,)),
    Restriction("NoViewContextMenu", "Блокировка контекстного меню", (EXPLORER,)),
    Restriction("NoFolderOptions", "Блокировка настройки папок", (EXPLORER,)),
    Restriction("NoSecurityTab", "Блокировка вкладки «Безопасность»", (EXPLORER,)),
    Restriction("NoFileMenu", "Скрытие меню «Файл»", (EXPLORER,)),
    Restriction("NoClose", "Блокировка выключения компьютера через «Пуск»", (EXPLORER,)),
    Restriction("NoCommonGroups", "Скрытие общих разделов в меню «Пуск»", (EXPLORER,)),
    Restriction("StartMenuLogOff", "Скрытие выхода из системы в меню «Пуск»", (EXPLORER,)),
    Restriction("NoChangingWallPaper", "Запрет смены обоев", (SYSTEM, ACTIVE_DESKTOP)),
    Restriction("NoWinKeys", "Отключение горячих клавиш Windows", (EXPLORER,)),
    Restriction("NoSetTaskbar", "Запрет изменения настроек панели задач и «Пуск»", (EXPLORER,)),
    Restriction("DisableLockWorkstation", "Запрет блокировки компьютера", (SYSTEM,)),
    Restriction("DisableChangePassword", "Запрет смены пароля", (SYSTEM,)),
    Restriction("NoTrayContextMenu", "Запрет контекстных меню панели задач", (EXPLORER,)),
    Restriction("DenyUsersFromMachGP", "Запрет обновления групповой политики пользователями",
                (GP_SYSTEM,)),
    Restriction("HidePowerOptions", "Скрытие команд выключения, перезагрузки и сна", (EXPLORER,)),
    Restriction("DisableContextMenusInStart", "Запрет контекстных меню в «Пуск»", (EXPLORER,)),
    Restriction("DisableSR", "Отключение восстановления системы", (GP_RESTORE,)),
    Restriction("DisableConfig", "Отключение настройки защиты системы", (GP_RESTORE,)),
    Restriction("NoLogoff", "Блокировка выхода из системы", (EXPLORER,)),
    Restriction("DisallowRun", "Включена блокировка запуска программ по списку", (EXPLORER,)),
    Restriction("RestrictRun", "Разрешён запуск только программ из списка", (EXPLORER,)),
    # признаки ослабления защиты, которых нет в обычных списках блокировок
    Restriction("EnableLUA", "UAC (контроль учётных записей) выключен", (SYSTEM,),
                default=1, bad=(0,)),
    Restriction("ConsentPromptBehaviorAdmin", "UAC не запрашивает подтверждение у администратора",
                (SYSTEM,), default=5, bad=(0,)),
]


@dataclass
class PolicyHit:
    restriction_name: str       # имя из каталога; пусто для записей списков запрета и IFEO
    title: str
    hive: str
    path: str
    name: str
    value: object
    reg_type: int
    kind: str                   # policy | disallow | restrictrun | ifeo
    default: int | None = None  # значение, которое нужно установить вместо удаления


def _is_bad(restriction: Restriction, value) -> bool:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return False
    if restriction.bad is not None:
        return number in restriction.bad
    return number != 0


def _scan_app_blocks(hive: str) -> list[PolicyHit]:
    hits = []
    for key_name, text, kind in (("DisallowRun", "Блокировка приложения", "disallow"),
                                 ("RestrictRun", "Запуск разрешён только для", "restrictrun")):
        path = EXPLORER + "\\" + key_name
        for name, (value, reg_type) in list_values(hive, path).items():
            if isinstance(value, str) and value.strip():
                hits.append(PolicyHit("", f"{text} «{value}» [{key_name}]", hive, path,
                                      name, value, reg_type, kind))
    return hits


def _scan_ifeo() -> list[PolicyHit]:
    """Перехват запуска программы через Image File Execution Options (параметр Debugger).
    Иногда это делают и законные программы, например замена диспетчера задач."""
    hits = []
    for sub in list_subkeys("HKLM", IFEO):
        path = IFEO + "\\" + sub
        exists, value, reg_type = read_value("HKLM", path, "Debugger")
        if exists and str(value).strip():
            hits.append(PolicyHit("", f"Перехват запуска «{sub}» (IFEO Debugger): {value}",
                                  "HKLM", path, "Debugger", value, reg_type, "ifeo"))
    return hits


def scan_restrictions() -> list[PolicyHit]:
    """Ищет ограничения во всех известных местах: HKLM, HKCU и разделах других пользователей."""
    hits: list[PolicyHit] = []
    for hive in hives_to_scan():
        for restriction in CATALOG:
            for sub in restriction.keys:
                exists, value, reg_type = read_value(hive, sub, restriction.name)
                if exists and _is_bad(restriction, value):
                    hits.append(PolicyHit(restriction.name, restriction.description, hive, sub,
                                          restriction.name, value, reg_type, "policy",
                                          restriction.default))
        hits += _scan_app_blocks(hive)
    hits += _scan_ifeo()
    return hits
