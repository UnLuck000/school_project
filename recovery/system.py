import codecs
import json
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

try:
    import winreg
except ImportError:  # не Windows
    winreg = None

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
SYSTEM_ROOT = os.environ.get("SystemRoot", r"C:\Windows")
HOSTS_FILE = Path(SYSTEM_ROOT) / "System32" / "drivers" / "etc" / "hosts"
PROJECT_DIR = Path(__file__).resolve().parent.parent
HIVES = ({"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
         if winreg else {})
REG_DWORD = 4

LOOPBACK = {"0.0.0.0", "127.0.0.1", "::1"}
SECURITY_DOMAINS = (
    "microsoft", "windowsupdate", "defender", "kaspersky", "eset", "avast", "avg.",
    "malwarebytes", "bitdefender", "norton", "mcafee", "virustotal", "symantec", "sophos",
    "drweb", "trendmicro", "avira", "comodo", "panda", "f-secure", "360",
)
RESTORE_TYPES = {0: "Установка программы", 1: "Удаление программы", 10: "Установка драйвера",
                 12: "Изменение параметров", 13: "Отменённая операция"}


@dataclass
class Finding:
    category: str       # hosts | proxy | defender | policy | system
    title: str
    status: str
    detail: str
    level: str          # ok | info | warning | bad
    fix_title: str = ""
    fix: dict | None = None


@dataclass
class RestorePoint:
    number: int
    description: str
    created: str
    kind: str


# ---------- запуск PowerShell и команд ----------
def run_powershell(script: str, env_extra: dict | None = None,
                   timeout: int = 60) -> tuple[int, str, str]:
    """(код возврата, stdout, stderr). Значения передаются через переменные окружения,
    а не подставляются в текст скрипта: так исключена подмена команды."""
    env = dict(os.environ)
    env.update(env_extra or {})
    full = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
            "$ProgressPreference='SilentlyContinue';" + script)
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", full],
            capture_output=True, timeout=timeout, creationflags=NO_WINDOW, env=env)
    except subprocess.TimeoutExpired:
        return -1, "", "Время ожидания истекло"
    except OSError as e:
        return -1, "", str(e)
    return (result.returncode, result.stdout.decode("utf-8-sig", "replace"),
            result.stderr.decode("utf-8", "replace"))


def run_command(args: list[str], on_text, on_start=None) -> int:
    """Запускает команду и передаёт вывод в on_text по мере появления.
    sfc выводит текст в UTF-16, dism в кодировке консоли: определяем по содержимому."""
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            creationflags=NO_WINDOW)
    if on_start:
        on_start(proc)
    decoder = None
    while True:
        chunk = proc.stdout.read1(4096)
        if not chunk:
            break
        if decoder is None:
            name = "utf-16-le" if b"\x00" in chunk else "oem"
            try:
                decoder = codecs.getincrementaldecoder(name)(errors="replace")
            except LookupError:  # не Windows
                decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        text = decoder.decode(chunk).replace("\ufeff", "")
        if text:
            on_text(text)
    return proc.wait()


# ---------- точки восстановления ----------
def _parse_wmi_time(value) -> str:
    try:
        return datetime.strptime(str(value)[:14], "%Y%m%d%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return str(value)


def list_restore_points() -> list[RestorePoint]:
    script = ("$ErrorActionPreference='Stop';"
              "$r=@(Get-ComputerRestorePoint | ForEach-Object {"
              "[PSCustomObject]@{n=$_.SequenceNumber;d=$_.Description;"
              "t=$_.CreationTime;k=$_.RestorePointType}});"
              "ConvertTo-Json -Compress -InputObject $r")
    code, out, err = run_powershell(script)
    if code != 0:
        raise OSError(err.strip() or "Не удалось получить список (нужны права администратора)")
    data = json.loads(out.strip() or "[]")
    if isinstance(data, dict):
        data = [data]
    points = [RestorePoint(int(d["n"]), d.get("d") or "", _parse_wmi_time(d.get("t")),
                           RESTORE_TYPES.get(d.get("k"), str(d.get("k"))))
              for d in data]
    return sorted(points, key=lambda p: p.number, reverse=True)


def create_restore_point(description: str) -> str:
    """Создаёт точку восстановления. При неудаче бросает OSError с пояснением."""
    before = {p.number for p in list_restore_points()}
    script = ("$ErrorActionPreference='Stop';"
              "Checkpoint-Computer -Description $env:AV_DESC "
              "-RestorePointType MODIFY_SETTINGS 3>&1 | Out-String")
    code, out, err = run_powershell(script, {"AV_DESC": description}, timeout=180)
    if code != 0:
        raise OSError(err.strip() or "Не удалось создать точку восстановления")
    created = [p for p in list_restore_points() if p.number not in before]
    if created:
        return f"Точка восстановления создана: «{created[0].description}»"
    raise OSError(out.strip() or
                  "Windows не создала точку. По умолчанию разрешена одна точка в 24 часа, "
                  "а защита системы должна быть включена для диска C:.")


def enable_system_protection() -> str:
    drive = os.environ.get("SystemDrive", "C:") + "\\"
    code, _, err = run_powershell(
        "$ErrorActionPreference='Stop';Enable-ComputerRestore -Drive $env:AV_DRIVE",
        {"AV_DRIVE": drive})
    if code != 0:
        raise OSError(err.strip() or "Не удалось включить защиту системы")
    return f"Защита системы включена для диска {drive}"


def open_restore_wizard() -> None:
    subprocess.Popen(["rstrui.exe"])


# ---------- реестр ----------
def read_value(hive: str, path: str, name: str):
    """(существует, значение, тип)."""
    if winreg is None:
        return False, None, None
    try:
        with winreg.OpenKey(HIVES[hive], path) as key:
            value, reg_type = winreg.QueryValueEx(key, name)
            return True, value, reg_type
    except OSError:
        return False, None, None


# ---------- проверки ----------
def check_hosts() -> list[Finding]:
    try:
        text = HOSTS_FILE.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return [Finding("hosts", "Файл hosts", "Не удалось прочитать", str(e), "warning")]

    entries = []
    for raw in text.splitlines():
        content = raw.split("#", 1)[0].strip()
        parts = content.split()
        if len(parts) >= 2:
            entries.append((parts[0], parts[1:], raw.strip()))
    if not entries:
        return [Finding("hosts", "Файл hosts", "Чисто",
                        "Активных записей нет (стандартное состояние)", "ok")]

    findings: list[Finding] = []
    quiet = 0  # обычные блокировки рекламы и трекеров
    for ip, names, raw in entries:
        security = any(d in n.lower() for n in names for d in SECURITY_DOMAINS)
        blocking = ip in LOOPBACK
        if not security and blocking:
            quiet += 1
            continue
        if security:
            status = ("Заблокирован домен защиты или обновлений" if blocking
                      else "Перенаправлен домен защиты или обновлений")
            level = "bad"
        else:
            status, level = "Перенаправление на внешний адрес", "warning"
        if len(findings) < 100:
            findings.append(Finding("hosts", f"hosts: {', '.join(names)[:80]}", status, raw,
                                    level, "Удалить строку из hosts",
                                    {"op": "hosts_remove", "raw": raw}))
    if quiet:
        findings.append(Finding(
            "hosts", "hosts: блокировки доменов", f"{quiet} записей",
            "Домены направлены на 0.0.0.0 или 127.0.0.1 (так работают списки блокировки "
            "рекламы). Среди них нет доменов защиты и обновлений.", "info"))
    return findings


def check_proxy() -> list[Finding]:
    path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    enabled = read_value("HKCU", path, "ProxyEnable")
    server = read_value("HKCU", path, "ProxyServer")
    pac = read_value("HKCU", path, "AutoConfigURL")
    findings: list[Finding] = []
    if enabled[0] and enabled[1] == 1:
        findings.append(Finding(
            "proxy", "Прокси-сервер", "Включён", f"Адрес: {server[1] or 'не указан'}", "warning",
            "Отключить прокси",
            {"op": "reg_set", "hive": "HKCU", "path": path, "name": "ProxyEnable",
             "value": 0, "type": REG_DWORD}))
    if pac[0] and pac[1]:
        findings.append(Finding(
            "proxy", "Скрипт автоконфигурации (PAC)", "Задан", str(pac[1]), "warning",
            "Удалить адрес скрипта",
            {"op": "reg_delete", "hive": "HKCU", "path": path, "name": "AutoConfigURL"}))
    if not findings:
        findings.append(Finding("proxy", "Прокси", "Не настроены",
                                "Системный прокси и PAC-скрипт не заданы", "ok"))
    return findings


def _inside_project(value: str) -> bool:
    try:
        return os.path.normcase(os.path.abspath(value)).startswith(
            os.path.normcase(str(PROJECT_DIR)))
    except (OSError, ValueError):
        return False


def check_defender() -> list[Finding]:
    script = ("$ErrorActionPreference='Stop';$p=Get-MpPreference;$s=Get-MpComputerStatus;"
              "[PSCustomObject]@{av=$s.AntivirusEnabled;rtp=$s.RealTimeProtectionEnabled;"
              "tamper=$s.IsTamperProtected;"
              "sig=$s.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd HH:mm');"
              "paths=@($p.ExclusionPath | Where-Object {$_});"
              "exts=@($p.ExclusionExtension | Where-Object {$_});"
              "procs=@($p.ExclusionProcess | Where-Object {$_})} | ConvertTo-Json -Compress")
    code, out, err = run_powershell(script, timeout=45)
    if code != 0:
        return [Finding("defender", "Microsoft Defender", "Недоступен",
                        (err.strip() or "Не удалось получить состояние")[:300], "info")]
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return [Finding("defender", "Microsoft Defender", "Не удалось разобрать ответ", "", "info")]

    def as_list(v) -> list[str]:
        return [] if v is None else [v] if isinstance(v, str) else [str(x) for x in v]

    findings: list[Finding] = []
    if data.get("rtp"):
        findings.append(Finding("defender", "Защита в реальном времени", "Включена", "", "ok"))
    elif not data.get("av"):
        findings.append(Finding("defender", "Microsoft Defender", "Отключён",
                                "Вероятно, работает другой антивирус", "info"))
    else:
        findings.append(Finding(
            "defender", "Защита в реальном времени", "ВЫКЛЮЧЕНА",
            "Defender включён, но постоянная защита отключена", "bad", "Включить защиту",
            {"op": "defender_realtime"}))
    findings.append(Finding("defender", "Защита от подделки (Tamper Protection)",
                            "Включена" if data.get("tamper") else "Выключена", "",
                            "ok" if data.get("tamper") else "info"))
    try:
        age = (datetime.now() - datetime.strptime(data["sig"], "%Y-%m-%d %H:%M")).days
        findings.append(Finding("defender", "Базы Defender", f"Обновлены {data['sig']}",
                                f"{age} дн. назад", "warning" if age > 7 else "ok"))
    except (KeyError, ValueError):
        pass

    kinds = (("Path", "paths"), ("Extension", "exts"), ("Process", "procs"))
    names = {"Path": "папка/файл", "Extension": "расширение", "Process": "процесс"}
    for kind, field in kinds:
        values = as_list(data.get(field))
        if any(v.startswith("N/A") for v in values):
            findings.append(Finding("defender", "Исключения Defender", "Не видны",
                                    "Для просмотра исключений нужны права администратора", "info"))
            break
        for value in values:
            mine = kind == "Path" and _inside_project(value)
            findings.append(Finding(
                "defender", f"Исключение ({names[kind]})", value,
                "Папка проекта: добавлено для работы с тестовыми файлами?" if mine
                else "Исключения часто добавляет вредоносное ПО, чтобы не быть замеченным",
                "info" if mine else "warning", "Удалить исключение",
                {"op": "defender_exclusion_remove", "kind": kind, "value": value}))
    return findings


POLICIES = [
    # (куст, путь, значение, признак плохого значения, значение для исправления или None, описание, уровень)
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr",
     lambda v: v == 1, None, "Диспетчер задач отключён политикой", "warning"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableRegistryTools",
     lambda v: v in (1, 2), None, "Редактор реестра отключён политикой", "warning"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableCMD",
     lambda v: v in (1, 2), None, "Командная строка отключена политикой", "warning"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA",
     lambda v: v == 0, 1, "UAC (контроль учётных записей) выключен", "bad"),
    ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware",
     lambda v: v == 1, None, "Defender отключён политикой", "bad"),
    ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiVirus",
     lambda v: v == 1, None, "Антивирус Defender отключён политикой", "bad"),
    ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
     "DisableRealtimeMonitoring", lambda v: v == 1, None,
     "Постоянная защита Defender отключена политикой", "bad"),
    ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
     "DisableBehaviorMonitoring", lambda v: v == 1, None,
     "Поведенческий анализ Defender отключён политикой", "bad"),
]


def check_policies() -> list[Finding]:
    findings: list[Finding] = []
    for hive, path, name, is_bad, fix_value, text, level in POLICIES:
        exists, value, _ = read_value(hive, path, name)
        if not (exists and is_bad(value)):
            continue
        if fix_value is None:
            fix = {"op": "reg_delete", "hive": hive, "path": path, "name": name}
            fix_title = "Убрать политику"
        else:
            fix = {"op": "reg_set", "hive": hive, "path": path, "name": name,
                   "value": fix_value, "type": REG_DWORD}
            fix_title = "Вернуть стандартное значение"
        findings.append(Finding("policy", text, f"{name} = {value}", f"{hive}\\{path}",
                                level, fix_title, fix))
    if not findings:
        findings.append(Finding("policy", "Политики", "Чисто",
                                "Ограничений диспетчера задач, реестра, командной строки, UAC "
                                "и Defender не найдено", "ok"))
    return findings


def run_all_checks() -> list[Finding]:
    findings: list[Finding] = []
    for check in (check_hosts, check_proxy, check_defender, check_policies):
        try:
            findings += check()
        except Exception as e:  # сбой одной проверки не отменяет остальные
            findings.append(Finding("system", check.__name__, "Проверка не выполнена",
                                    str(e), "warning"))
    return findings