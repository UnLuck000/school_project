"""Системные программы по полному пути.

Имя без пути («powershell») Windows ищет сначала в папке самой программы: подложенный туда
powershell.exe запустился бы с её правами (а они — администратора). Поэтому — только
System32. Там же общий запуск PowerShell для модулей, которым не нужен свой разбор ответа.
"""
import os
import subprocess

CREATE_NO_WINDOW = 0x08000000
SYSTEM32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
POWERSHELL = os.path.join(SYSTEM32, "WindowsPowerShell", "v1.0", "powershell.exe")
PS_ARGS = [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command"]


def system_exe(name: str) -> str:
    """Полный путь программы Windows из System32 (netsh.exe, schtasks.exe...)."""
    return os.path.join(SYSTEM32, name)


_resolved: dict[str, str] = {}


def resolve(args):
    """Команда с именем программы без пути («schtasks», «reg.exe», «explorer») → с полным
    путём из System32 или папки Windows. Чужое и своё (xray.exe по полному пути, java из
    PATH) не трогается. Вызывается обёрткой diag/proc для каждого запуска."""
    if not isinstance(args, (list, tuple)) or not args or not isinstance(args[0], str):
        return args
    name = args[0]
    if os.sep in name or "/" in name or ":" in name:
        return args
    full = _resolved.get(name.lower())
    if full is None:
        file = name if name.lower().endswith((".exe", ".com")) else name + ".exe"
        full = ""
        for folder in (SYSTEM32, os.path.dirname(SYSTEM32)):
            candidate = os.path.join(folder, file)
            if os.path.isfile(candidate):
                full = candidate
                break
        _resolved[name.lower()] = full
    return [full, *args[1:]] if full else args


def powershell(script: str, env: dict | None = None, timeout: float | None = 120,
               strict: bool = True) -> subprocess.CompletedProcess:
    """Скрипт PowerShell с выводом в UTF-8. Значения — только через env (не в текст).
    Может бросить OSError (запуск запрещён другим антивирусом) и TimeoutExpired."""
    head = "[Console]::OutputEncoding = [Text.Encoding]::UTF8; "
    if strict:
        head += "$ErrorActionPreference = 'Stop'; "
    return subprocess.run(PS_ARGS + [head + script], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout,
                          env={**os.environ, **(env or {})}, creationflags=CREATE_NO_WINDOW)
