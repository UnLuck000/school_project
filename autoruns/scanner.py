import json
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

import psutil

from autoruns.model import Entry, raise_level
from processmanager.origin import _command_exe, _disabled_names
from scanner.engine import check_file
from scanner.signature import describe, inspect_signature

try:
    import winreg
except ImportError:  # не Windows
    winreg = None

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
SYSTEM_ROOT = os.environ.get("SystemRoot", r"C:\Windows")
TASKS_DIR = Path(SYSTEM_ROOT) / "System32" / "Tasks"
TASK_NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
HIVES = ({"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
         if winreg else {})

CV = r"Software\Microsoft\Windows\CurrentVersion"
RUN_KEYS = [
    ("HKCU", CV + r"\Run"),
    ("HKCU", CV + r"\RunOnce"),
    ("HKCU", CV + r"\Policies\Explorer\Run"),
    ("HKLM", CV + r"\Run"),
    ("HKLM", CV + r"\RunOnce"),
    ("HKLM", CV + r"\Policies\Explorer\Run"),
    ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
]
APPROVED = CV + r"\Explorer\StartupApproved"

SUSPICIOUS_CMD = re.compile(
    r"(-enc(odedcommand)?\b|frombase64string|downloadstring|downloadfile|"
    r"invoke-expression|\biex\b|mshta|wscript|cscript|regsvr32.*(http|scrobj)|"
    r"rundll32.*javascript|bitsadmin|certutil.*-urlcache|https?://)", re.IGNORECASE)
USER_DIRS = ("\\appdata\\local\\temp\\", "\\downloads\\", "\\users\\public\\")


def _resolve_exe(path: str) -> str:
    path = os.path.expandvars((path or "").strip().strip('"'))
    if not path:
        return ""
    if os.path.isabs(path):
        return os.path.normpath(path)
    found = shutil.which(path)
    return os.path.normpath(found) if found else ""


def _powershell(script: str, env_extra: dict | None = None, timeout: int = 20) -> str:
    env = dict(os.environ)
    env.update(env_extra or {})
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, timeout=timeout, creationflags=NO_WINDOW, env=env)
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.decode("utf-8-sig", errors="replace")


def resolve_shortcuts(paths: list[str]) -> dict[str, tuple[str, str]]:
    """{путь ярлыка: (целевой файл, аргументы)}. Один вызов PowerShell на все ярлыки."""
    if not paths:
        return {}
    script = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
              "$sh=New-Object -ComObject WScript.Shell;"
              "$r=@($env:AV_LNKS -split '\\|' | ForEach-Object {"
              "$s=$sh.CreateShortcut($_);"
              "[PSCustomObject]@{path=$_;target=$s.TargetPath;args=$s.Arguments}});"
              "ConvertTo-Json -Compress -InputObject $r")
    out = _powershell(script, {"AV_LNKS": "|".join(paths)})
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return {}
    if isinstance(data, dict):
        data = [data]
    return {d["path"]: (d.get("target") or "", d.get("args") or "") for d in data}


# ---------- реестр ----------
def collect_registry() -> list[Entry]:
    entries: list[Entry] = []
    for hive_name, path in RUN_KEYS:
        hive = HIVES[hive_name]
        approved = None
        if "WOW6432Node" in path:
            approved = APPROVED + r"\Run32"
        elif path.endswith(r"CurrentVersion\Run"):
            approved = APPROVED + r"\Run"
        disabled = _disabled_names(hive, approved) if approved else set()
        try:
            key = winreg.OpenKey(hive, path)
        except OSError:
            continue
        with key:
            i = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(key, i)
                except OSError:
                    break
                i += 1
                if not isinstance(data, str):
                    continue
                entries.append(Entry(
                    kind="run", name=name or "(по умолчанию)",
                    location=f"{hive_name}\\{path}", command=data,
                    exe=_resolve_exe(_command_exe(data)), enabled=name not in disabled,
                    extra={"hive": hive_name, "path": path, "value": name}))
    return entries


def collect_winlogon() -> list[Entry]:
    path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    defaults = {"Shell": "explorer.exe",
                "Userinit": os.path.join(SYSTEM_ROOT, "system32", "userinit.exe").lower()}
    entries = []
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
    except OSError:
        return entries
    with key:
        for value, default in defaults.items():
            try:
                data, _ = winreg.QueryValueEx(key, value)
            except OSError:
                continue
            parts = [p.strip().lower() for p in str(data).split(",") if p.strip()]
            if parts == [default]:
                continue
            entries.append(Entry(
                kind="winlogon", name=value, location=f"HKLM\\{path}", command=str(data),
                exe=_resolve_exe(_command_exe(str(data).split(",")[0])),
                flags=["значение отличается от стандартного"]))
    return entries


# ---------- папки автозагрузки ----------
def collect_startup() -> list[Entry]:
    tail = r"Microsoft\Windows\Start Menu\Programs\Startup"
    folders = [(Path(os.environ.get("APPDATA", "")) / tail, "Автозагрузка (пользователь)"),
               (Path(os.environ.get("PROGRAMDATA", "")) / tail, "Автозагрузка (все пользователи)")]
    files = []
    for folder, label in folders:
        if folder.is_dir():
            files += [(f, label) for f in folder.iterdir()
                      if f.is_file() and f.name.lower() != "desktop.ini"]
    targets = resolve_shortcuts([str(f) for f, _ in files if f.suffix.lower() == ".lnk"])

    entries = []
    for f, label in files:
        if f.suffix.lower() == ".lnk":
            target, args = targets.get(str(f), ("", ""))
            command = f'"{target}" {args}'.strip() if target else str(f)
            exe = target
        else:
            command, exe = str(f), str(f)
        entries.append(Entry(kind="startup", name=f.name, location=label, command=command,
                             exe=_resolve_exe(exe), extra={"file": str(f)}))
    return entries


# ---------- службы ----------
def _service_values(name: str) -> tuple[str, int, int]:
    """(ServiceDll, Start, DelayedAutostart) из реестра."""
    base = rf"SYSTEM\CurrentControlSet\Services\{name}"
    dll, start, delayed = "", 2, 0
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as key:
            start = winreg.QueryValueEx(key, "Start")[0]
            try:
                delayed = winreg.QueryValueEx(key, "DelayedAutostart")[0]
            except OSError:
                pass
    except OSError:
        pass
    for sub in (base + r"\Parameters", base):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sub) as key:
                dll = winreg.QueryValueEx(key, "ServiceDll")[0]
                break
        except OSError:
            continue
    return _resolve_exe(dll), int(start), int(delayed)


def collect_services() -> list[Entry]:
    entries = []
    try:
        services = list(psutil.win_service_iter())
    except (AttributeError, psutil.Error, OSError):
        return entries
    for service in services:
        try:
            info = service.as_dict()
        except (psutil.Error, OSError):
            continue
        if info.get("start_type") != "automatic":
            continue
        binpath = info.get("binpath") or ""
        host = _resolve_exe(_command_exe(binpath))
        dll, start, delayed = _service_values(info["name"])
        mode = "delayed-auto" if start == 2 and delayed else "auto"
        entries.append(Entry(
            kind="service", name=info["name"],
            location=f"Служба: {info.get('display_name', '')}", command=binpath,
            exe=dll or host,  # для svchost проверяем настоящую библиотеку службы
            extra={"service": info["name"], "start_mode": mode}))
    return entries


# ---------- планировщик заданий ----------
def collect_tasks() -> tuple[list[Entry], int]:
    entries: list[Entry] = []
    unreadable = 0
    if not TASKS_DIR.is_dir():
        return entries, 0
    for file in TASKS_DIR.rglob("*"):
        try:
            if not file.is_file():
                continue
            root = ET.parse(file).getroot()
        except OSError:
            unreadable += 1
            continue
        except ET.ParseError:
            continue
        name = "\\" + str(file.relative_to(TASKS_DIR)).replace("/", "\\")
        enabled = root.findtext("t:Settings/t:Enabled", "true", TASK_NS).lower() != "false"
        trigger_el = root.find("t:Triggers", TASK_NS)
        triggers = [c.tag.split("}")[-1] for c in trigger_el] if trigger_el is not None else []
        for exec_el in root.findall("t:Actions/t:Exec", TASK_NS):
            command = (exec_el.findtext("t:Command", "", TASK_NS) or "").strip()
            args = (exec_el.findtext("t:Arguments", "", TASK_NS) or "").strip()
            if not command:
                continue
            where = "Планировщик заданий"
            if triggers:
                where += f" ({', '.join(triggers)})"
            entries.append(Entry(
                kind="task", name=name, location=where, command=f"{command} {args}".strip(),
                exe=_resolve_exe(_command_exe(command)), enabled=enabled,
                extra={"task": name}))
            break  # одна запись на задачу
    return entries, unreadable


# ---------- подписки WMI ----------
def collect_wmi() -> list[Entry]:
    script = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8;$r=@();"
              "foreach($c in 'CommandLineEventConsumer','ActiveScriptEventConsumer'){"
              "$r+=Get-CimInstance -Namespace root/subscription -ClassName $c "
              "-ErrorAction SilentlyContinue | ForEach-Object {"
              "[PSCustomObject]@{cls=$c;name=$_.Name;cmd=$_.CommandLineTemplate;"
              "script=$_.ScriptText}}};ConvertTo-Json -Compress -InputObject $r")
    try:
        data = json.loads(_powershell(script))
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]
    entries = []
    for d in data:
        command = d.get("cmd") or (d.get("script") or "")[:300]
        entries.append(Entry(kind="wmi", name=d.get("name") or "?",
                             location=f"WMI ({d.get('cls')})", command=command,
                             exe=_resolve_exe(_command_exe(command)) if d.get("cmd") else ""))
    return entries


def collect_all() -> tuple[list[Entry], list[str]]:
    """Собирает записи автозапуска (быстро, без проверки файлов) и заметки для пользователя."""
    if winreg is None:
        return [], ["Сканер автозапуска работает только в Windows"]
    notes: list[str] = []
    entries = collect_registry() + collect_winlogon() + collect_startup() + collect_services()
    tasks, unreadable = collect_tasks()
    entries += tasks
    if unreadable:
        notes.append(f"Не удалось прочитать задач планировщика: {unreadable} "
                     "(нужны права администратора)")
    entries += collect_wmi()
    return entries, notes


# ---------- оценка ----------
@dataclass
class Context:
    signatures: set
    rules: object
    whitelist: set
    cache: dict = field(default_factory=dict)  # путь -> (подпись, статус, вердикт)


def assess(e: Entry, ctx: Context) -> None:
    """Проверяет файл записи и выставляет уровень риска. Медленная функция."""
    level = "normal"
    flags = e.flags
    if e.kind == "wmi":
        level = raise_level(level, "suspicious")
        flags.append("подписка WMI: редкий способ закрепления")
    if e.kind == "winlogon":
        level = raise_level(level, "suspicious")

    exe = e.exe
    if exe and os.path.isfile(exe):
        cached = ctx.cache.get(exe)
        if cached is None:
            sig = inspect_signature(Path(exe))
            try:
                verdict = check_file(Path(exe), ctx.signatures, ctx.rules, ctx.whitelist) or ""
            except OSError:
                verdict = ""
            cached = ctx.cache[exe] = (describe(sig), sig.status, verdict)
        e.sig, e.sig_status, e.verdict = cached
        if e.verdict:
            level = raise_level(level, "threat")
            flags.append(f"обнаружено: {e.verdict}")
        elif e.sig_status == "invalid":
            level = raise_level(level, "suspicious")
            flags.append("подпись недействительна")
        elif e.sig_status == "unsigned":
            level = raise_level(level, "check")
            flags.append("нет подписи")
    elif e.kind in ("run", "startup", "service", "task", "winlogon"):
        level = raise_level(level, "check")
        flags.append("файл не найден")

    if SUSPICIOUS_CMD.search(e.command):
        level = raise_level(level, "suspicious")
        flags.append("подозрительная команда")
    if any(marker in exe.lower() for marker in USER_DIRS):
        level = raise_level(level, "check" if e.sig_status == "valid" else "suspicious")
        flags.append("файл во временной или пользовательской папке")

    e.level, e.assessed = level, True