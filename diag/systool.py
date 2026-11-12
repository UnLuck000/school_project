"""Сбои системных программ: PowerShell, netsh, schtasks, icacls, logman, WMI...

Часть функций программы работает через системные утилиты Windows. Их запуск может запретить
другой антивирус (Kaspersky, ESET, Dr.Web — так было на ПК с Windows 10 IoT 12.11.2026:
WinError 5 у PowerShell), политика организации (AppLocker, SRP, WDAC), урезанная сборка
Windows или сломанный WMI. Тогда функция молча теряла часть сведений. Теперь обёртка запуска
(diag/proc) передаёт сюда каждую неудачу системной программы; diagnose() узнаёт причину по
коду ошибки запуска, коду выхода и тексту ошибки, а report():
  * пишет подробности в app.log (команда, причина, что делать);
  * добавляет запись «сбой» в журнал действий (journal.log_notice: без отмены, по двойному
    щелчку — подробное описание);
  * сообщает слушателям (главное окно показывает предупреждение — один раз за запуск на
    программу и причину).
Неудача без узнаваемой причины (обычный ненулевой код: «задание не найдено» у schtasks)
предупреждением не считается — она только в app.log, как и раньше.
"""
import os
import re
import threading
from dataclasses import dataclass

from diag.log import get

log = get("systool")

# системные программы, за которыми следим (имя файла в нижнем регистре)
TOOLS = {
    "powershell.exe": "PowerShell", "pwsh.exe": "PowerShell 7", "netsh.exe": "netsh",
    "schtasks.exe": "Планировщик заданий (schtasks)", "icacls.exe": "icacls",
    "logman.exe": "logman (сеансы ETW)", "reg.exe": "reg", "sc.exe": "sc (службы)",
    "wmic.exe": "WMIC", "vssadmin.exe": "vssadmin", "bcdedit.exe": "bcdedit",
    "cmd.exe": "cmd", "wevtutil.exe": "wevtutil", "sfc.exe": "SFC", "dism.exe": "DISM",
    "certutil.exe": "certutil", "rundll32.exe": "rundll32", "regsvr32.exe": "regsvr32",
}
# NTSTATUS в коде выхода: процесс не дали запустить или сняли в самом начале
STATUS = {
    0xC0000022: "blocked",       # STATUS_ACCESS_DENIED
    0xC0000142: "init_failed",   # STATUS_DLL_INIT_FAILED — часто внедрение антивируса
    0xC0000135: "missing_dll",   # STATUS_DLL_NOT_FOUND
    0xC000007B: "missing_dll",   # STATUS_INVALID_IMAGE_FORMAT
    0xC0000409: "killed",        # STATUS_STACK_BUFFER_OVERRUN (принудительное завершение)
}
WINERROR = {5: "blocked", 1260: "policy", 4551: "policy", 225: "av_file", 226: "av_file",
            2: "missing", 3: "missing", 193: "missing_dll", 1450: "resources", 1455: "resources"}
# текст ошибки (английская и русская Windows)
PATTERNS = [
    ("amsi", r"malicious content|blocked by your antivirus|вредоносное содержимое|"
             r"заблокирован.{0,40}антивирус"),
    ("constrained", r"ConstrainedLanguage|language mode|Method invocation is supported only on "
                    r"core types|режиме языка|режим.{0,20}ограниченного языка"),
    ("exec_policy", r"running scripts is disabled|execution polic|выполнение сценариев отключено|"
                    r"политик.{0,20}выполнения"),
    ("cmdlet", r"is not recognized as (the name of )?a cmdlet|не распознано как имя командлета"),
    ("wmi", r"Invalid class|Invalid namespace|0x8004100[0-9A-F]|Недопустимый класс|"
            r"Недопустимое пространство имен|RPC server is unavailable|Сервер RPC недоступен"),
    # «Access is denied» в ответе — не признак: так отвечает и обычный отказ (защищённое
    # задание без прав администратора). Запуск, запрещённый антивирусом, узнаётся по ошибке
    # запуска (WinError 5) и кодам ядра (STATUS).
    ("policy", r"blocked by group policy|заблокирован.{0,30}групповой политик|0x800704EC"),
]

CAUSES = {
    "blocked": (
        "Запуск запрещён",
        ["Другой антивирус (Kaspersky, ESET, Dr.Web, Avast и др.) блокирует эту системную "
         "программу — так защищаются от вредоносов, которые ею пользуются.",
         "Политика ограничения программ (AppLocker, SRP) на компьютере организации.",
         "Программа запущена без прав администратора, а действие их требует."],
        ["Добавьте StretchBIT в исключения другого антивируса (раздел «Исключения» или "
         "«Доверенные программы»), либо разрешите ему запускать эту программу.",
         "Запустите StretchBIT от имени администратора.",
         "На компьютере организации — обратитесь к администратору."]),
    "policy": (
        "Запрещено политикой",
        ["Групповая политика AppLocker / SRP или управление приложениями WDAC запрещает "
         "запуск этой программы."],
        ["Обратитесь к администратору компьютера: нужна разрешающая запись для системной "
         "программы или для StretchBIT."]),
    "av_file": (
        "Антивирус считает файл заражённым",
        ["Другой антивирус пометил системную программу (или её копию) как угрозу."],
        ["Проверьте журнал другого антивируса: если файл — оригинальный файл Windows, "
         "восстановите его (sfc /scannow) и добавьте в исключения."]),
    "init_failed": (
        "Процесс не смог запуститься",
        ["Антивирус внедряется в новые процессы и отменил запуск (STATUS_DLL_INIT_FAILED).",
         "Не хватает системных ресурсов (рабочий стол, память)."],
        ["Добавьте StretchBIT в исключения другого антивируса.",
         "Закройте лишние программы или перезагрузите компьютер."]),
    "killed": (
        "Процесс принудительно завершён",
        ["Другой антивирус или средство защиты сняло процесс сразу после запуска."],
        ["Посмотрите журнал другого антивируса и добавьте StretchBIT в исключения."]),
    "missing": (
        "Программа не найдена",
        ["Урезанная сборка Windows (компоненты удалены).",
         "Файл удалён или повреждён."],
        ["Восстановите системные файлы: «Инструменты» → «Восстановление системы» → SFC/DISM.",
         "В урезанной сборке Windows — установите компонент (например, Windows PowerShell)."]),
    "missing_dll": (
        "Не хватает системных библиотек",
        ["Повреждены или удалены системные файлы, нужные программе."],
        ["Восстановите системные файлы: SFC/DISM в «Восстановлении системы»."]),
    "resources": (
        "Не хватает ресурсов",
        ["Мало свободной памяти или системных ресурсов."],
        ["Закройте лишние программы или перезагрузите компьютер."]),
    "amsi": (
        "Другой антивирус заблокировал скрипт программы (AMSI)",
        ["Скрипты StretchBIT управляют брандмауэром, сетью и заданиями — антивирус, "
         "проверяющий скрипты через AMSI, может принять их за вредоносные."],
        ["Добавьте StretchBIT в исключения другого антивируса.",
         "Если это Microsoft Defender — «Защита от вирусов и угроз» → «Исключения»."]),
    "constrained": (
        "PowerShell в ограниченном режиме языка",
        ["Включён режим ConstrainedLanguage: AppLocker, WDAC или переменная окружения "
         "__PSLockdownPolicy. В нём не работают нужные программе вызовы .NET."],
        ["Обратитесь к администратору компьютера.",
         "Дома — проверьте, не задана ли системная переменная __PSLockdownPolicy, и "
         "удалите её."]),
    "exec_policy": (
        "Политика выполнения PowerShell запрещает скрипты",
        ["Политика выполнения задана групповой политикой (обычный запрет программа обходит "
         "сама: скрипт передаётся командой, а не файлом)."],
        ["Обратитесь к администратору или проверьте: Get-ExecutionPolicy -List."]),
    "cmdlet": (
        "Нет нужной команды PowerShell",
        ["Урезанная сборка Windows: модуль PowerShell удалён (например, NetSecurity, "
         "ScheduledTasks, CimCmdlets).", "Старая версия Windows PowerShell."],
        ["Восстановите компоненты Windows (DISM /RestoreHealth) или установите полную "
         "сборку Windows."]),
    "wmi": (
        "Служба WMI недоступна или повреждена",
        ["Служба «Инструментарий управления Windows» (Winmgmt) остановлена или её "
         "хранилище повреждено.", "Антивирус запрещает обращения к WMI."],
        ["Перезапустите службу Winmgmt или компьютер.",
         "Проверьте хранилище: winmgmt /verifyrepository (от администратора)."]),
}


@dataclass(frozen=True)
class Failure:
    tool: str          # имя файла, нижний регистр
    cause: str         # ключ CAUSES
    command: str       # команда для журнала (без значений переменных окружения)
    detail: str        # код ошибки или строка из вывода
    where: str = ""    # какая функция программы (подставляет вызвавший код, если знает)

    @property
    def title(self) -> str:
        return CAUSES[self.cause][0]

    @property
    def tool_name(self) -> str:
        return TOOLS.get(self.tool, self.tool)

    def short_text(self) -> str:
        reasons = CAUSES[self.cause][1]
        return (f"{self.tool_name}: {self.title.lower()}.\n\nЧасть функций программы "
                f"работает через эту системную программу и может работать не полностью"
                + (f" ({self.where})" if self.where else "") + ".\n\nВозможные причины:\n"
                + "\n".join(f"• {r}" for r in reasons)
                + "\n\nПодробности и что делать — в «Журнал» → «Действия» (двойной щелчок по "
                  "записи о сбое).")

    def details(self) -> str:
        _title, reasons, fixes = CAUSES[self.cause]
        lines = [f"Программа: {self.tool_name} ({self.tool})", f"Что случилось: {self.title}"]
        if self.where:
            lines.append(f"Функция: {self.where}")
        return "\n".join([*lines, f"Команда: {self.command}", f"Ответ: {self.detail}", "",
                          "Возможные причины:", *[f"• {r}" for r in reasons], "",
                          "Что сделать:", *[f"• {f}" for f in fixes]])


def tool_of(args) -> str:
    """Имя системной программы из команды или "" — не системная и не из списка."""
    first = args[0] if isinstance(args, (list, tuple)) and args else args
    if not isinstance(first, str):
        return ""
    name = os.path.basename(first.strip('"')).lower()
    if not name.endswith(".exe"):
        name += ".exe"
    if name not in TOOLS:
        return ""
    folder = os.path.dirname(first.strip('"')).lower()
    windows = os.environ.get("SystemRoot", r"C:\Windows").lower()
    return name if not folder or folder.startswith(windows) else ""


def diagnose(args, error: BaseException | None = None, returncode: int | None = None,
             output: str = "", command: str = "") -> Failure | None:
    tool = tool_of(args)
    if not tool:
        return None
    cause, detail = "", ""
    if isinstance(error, OSError):
        code = getattr(error, "winerror", None) or error.errno
        cause = WINERROR.get(code, "")
        detail = f"не запустилась: {error}"
    elif returncode:
        status = returncode & 0xFFFFFFFF
        cause = STATUS.get(status, "")
        detail = f"код выхода 0x{status:08X}" if cause else f"код выхода {returncode}"
        if not cause and output:
            for key, pattern in PATTERNS:
                found = re.search(pattern, output, re.I)
                if found:
                    cause = key
                    line = next((s for s in output.splitlines() if found.group(0) in s), "")
                    detail = f"код выхода {returncode}: {line.strip()[:300]}"
                    break
    if not cause:
        return None
    return Failure(tool, cause, command[:500], detail)


_listeners: list = []
_pending: list[Failure] = []   # случились до появления слушателя (ранний запуск)
_seen: set[tuple[str, str]] = set()
_lock = threading.Lock()
_where = threading.local()


def add_listener(callback) -> None:
    """callback(Failure) — из любого потока; первое появление программы и причины за запуск.
    Сбои, случившиеся раньше (запуск программы), передаются сразу."""
    with _lock:
        _listeners.append(callback)
        pending, _pending[:] = list(_pending), []
    for failure in pending:
        callback(failure)


class context:
    """with systool.context("Сканер автозапуска"): ... — какая функция запускала программу."""

    def __init__(self, where: str):
        self.where = where

    def __enter__(self):
        self._prev = getattr(_where, "name", "")
        _where.name = self.where
        return self

    def __exit__(self, *exc):
        _where.name = self._prev
        return False


def report(failure: Failure) -> None:
    where = getattr(_where, "name", "")
    if where and not failure.where:
        failure = Failure(failure.tool, failure.cause, failure.command, failure.detail, where)
    log.warning("Сбой системной программы — %s\n%s", failure.title, failure.details())
    key = (failure.tool, failure.cause)
    with _lock:
        first = key not in _seen
        _seen.add(key)
    if not first:
        return
    try:
        from recovery import activity, journal
        activity.record("systool", f"{failure.tool_name}: {failure.title}",
                        command=failure.command, detail=failure.detail)
        journal.log_notice(f"Сбой: {failure.tool_name} — {failure.title.lower()}",
                           "notice_systool",
                           {"tool": failure.tool, "cause": failure.cause,
                            "details": failure.details()})
    except Exception:  # noqa: BLE001 — запись о сбое не должна ломать сам вызов
        from diag.log import swallowed
        swallowed("systool: запись в журнал")
    with _lock:
        listeners = list(_listeners)
        if not listeners:
            _pending.append(failure)
    for callback in listeners:
        try:
            callback(failure)
        except Exception:  # noqa: BLE001 — слушатель не должен ломать вызов
            from diag.log import swallowed
            swallowed("systool: слушатель")


def reset() -> None:
    """Для тестов: забыть показанные предупреждения."""
    with _lock:
        _seen.clear()
        _pending.clear()
