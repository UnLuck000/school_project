import os

try:
    import winreg
except ImportError:  # не Windows
    winreg = None

LOGON_WINDOW = 35.0  # секунд после запуска Проводника, когда стартует автозапуск
CONSOLE_PARENTS = {"cmd.exe", "powershell.exe", "pwsh.exe", "windowsterminal.exe",
                   "wt.exe", "conhost.exe", "bash.exe", "wsl.exe"}
TASK_PARENTS = {"taskhostw.exe", "taskeng.exe"}

ORIGINS = {
    "user": "Запущен пользователем",
    "user_maybe": "Запущен пользователем (вероятно)",
    "autostart": "Автозапуск",
    "autostart_maybe": "Автозапуск (вероятно)",
    "child": "Дочерний процесс",
    "console": "Из консоли",
    "task": "Планировщик задач",
    "service": "Служба Windows",
    "system": "Системный",
    "other_user": "Другая учётная запись",
    "unknown": "Не определено",
}

# (название в списке, какие способы запуска показывать; None = все)
FILTERS = [
    ("Все процессы", None),
    ("Запущены пользователем", {"user", "user_maybe"}),
    ("Автозапуск", {"autostart", "autostart_maybe"}),
    ("Системные, службы, планировщик", {"system", "service", "task"}),
    ("Дочерние процессы", {"child"}),
    ("Из консоли", {"console"}),
]

HELP = [
    ("user", "Родитель: Проводник (двойной щелчок, «Пуск», панель задач, Win+R), старт "
             "позже 2 минут после входа."),
    ("user_maybe", "Родитель уже завершился (лаунчеры вроде Update.exe), старт позже "
                   "2 минут после входа."),
    ("autostart", "Есть запись в Run, RunOnce или папке автозагрузки, и процесс стартовал "
                  "в первые 2 минуты после входа."),
    ("autostart_maybe", "Записи нет, но старт в первые 2 минуты после входа от Проводника "
                        "или при завершённом родителе."),
    ("child", "Запущен другой программой (рабочие процессы браузера, Discord и т.п.)."),
    ("console", "Родитель: cmd, PowerShell или Windows Terminal."),
    ("task", "Родитель: служба «Планировщик заданий» или taskhostw.exe."),
    ("service", "Процесс размещает службу или запущен services.exe."),
    ("system", "Ядро Windows и процессы системных учётных записей."),
    ("other_user", "Процесс другой учётной записи."),
    ("unknown", "Не хватает данных (часто нет прав администратора)."),
]


def _run_sources():
    if winreg is None:
        return []
    base = r"Software\Microsoft\Windows\CurrentVersion"
    approved = base + r"\Explorer\StartupApproved"
    return [
        (winreg.HKEY_CURRENT_USER, base + r"\Run", approved + r"\Run"),
        (winreg.HKEY_CURRENT_USER, base + r"\RunOnce", None),
        (winreg.HKEY_LOCAL_MACHINE, base + r"\Run", approved + r"\Run"),
        (winreg.HKEY_LOCAL_MACHINE, base + r"\RunOnce", None),
        (winreg.HKEY_LOCAL_MACHINE,
         r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", approved + r"\Run32"),
    ]


def _disabled_names(hive, subkey) -> set[str]:
    """Записи автозапуска, отключённые пользователем в «Автозагрузке» диспетчера задач."""
    names: set[str] = set()
    try:
        with winreg.OpenKey(hive, subkey) as key:
            i = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(key, i)
                except OSError:
                    break
                i += 1
                if isinstance(data, bytes) and data and data[0] & 1:  # нечётный = отключено
                    names.add(name)
    except OSError:
        pass
    return names


def _command_exe(command: str) -> str:
    """Путь к exe из строки запуска вида: "C:\\Program Files\\X\\x.exe" --flag"""
    command = os.path.expandvars(command.strip())
    if command.startswith('"'):
        end = command.find('"', 1)
        return command[1:end] if end > 0 else command[1:]
    parts = command.split(" ")
    for i in range(len(parts), 0, -1):
        candidate = " ".join(parts[:i])
        if os.path.isfile(candidate):
            return candidate
    return parts[0] if parts else ""



def load_autostart() -> tuple[set[str], set[str]]:
    """(нормализованные пути exe из реестра, имена ярлыков из папок автозагрузки)."""
    exes: set[str] = set()
    names: set[str] = set()
    if winreg is None:
        return exes, names

    for hive, path, approved in _run_sources():
        disabled = _disabled_names(hive, approved) if approved else set()
        try:
            with winreg.OpenKey(hive, path) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    i += 1
                    if name in disabled or not isinstance(value, str):
                        continue
                    exe = _command_exe(value)
                    if exe:
                        exes.add(os.path.normcase(os.path.normpath(exe)))
        except OSError:
            continue

    startup = r"Microsoft\Windows\Start Menu\Programs\Startup"
    for base in (os.environ.get("APPDATA", ""), os.environ.get("PROGRAMDATA", "")):
        try:
            for entry in os.scandir(os.path.join(base, startup)):
                stem = os.path.splitext(entry.name)[0].lower()
                if stem != "desktop":
                    names.add(stem)
        except OSError:
            continue
    return exes, names


def _in_autostart(exe: str, name: str, exes: set[str], names: set[str]) -> bool:
    if not exe:
        return False
    norm = os.path.normcase(os.path.normpath(exe))
    if norm in exes:
        return True
    if os.path.splitext(name)[0].lower() in names:
        return True
    # приложения-обёртки (Update.exe --processStart ...): процесс лежит в папке записи
    system_root = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows"))
    for entry in exes:
        folder = os.path.dirname(entry)
        if folder.startswith(system_root) or len(folder.split(os.sep)) < 4:
            continue
        if norm.startswith(folder + os.sep):
            return True
    return False


def _origin(p, by_pid, t0, exes, names, own_user, task_pid) -> str:
    if p.core:
        return "system"
    if p.service:
        return "service"
    if not p.user:
        return "unknown"
    if own_user and p.user != own_user:
        return "system" if p.sys_account else "other_user"

    parent = by_pid.get(p.ppid)
    if parent is not None and parent.pid not in (0, 4) and parent.created > p.created:
        parent = None  # PID родителя уже занят другой программой
    parent_name = parent.name.lower() if parent else ""

    if parent is not None and (parent.pid == task_pid or parent_name in TASK_PARENTS):
        return "task"
    if parent_name == "services.exe":
        return "service"
    if parent_name in CONSOLE_PARENTS:
        return "console"

    in_window = t0 > 0 and 0 <= p.created - t0 <= LOGON_WINDOW
    from_shell = parent_name == "explorer.exe"
    listed = _in_autostart(p.exe if p.has_file else "", p.name, exes, names)

    if in_window and listed:
        return "autostart"
    if from_shell or parent is None:
        if in_window:
            return "autostart_maybe"
        return "user" if from_shell else "user_maybe"
    return "child"


def assign_origins(procs, own_user: str, autostart, task_pid: int) -> None:
    """Заполняет p.origin для каждого процесса."""
    exes, names = autostart
    by_pid = {p.pid: p for p in procs}
    # момент входа в систему: самый ранний Проводник этой учётной записи
    t0 = min((p.created for p in procs
              if p.name.lower() == "explorer.exe" and p.created
              and (not own_user or p.user == own_user)), default=0.0)
    for p in procs:
        p.origin = _origin(p, by_pid, t0, exes, names, own_user, task_pid)