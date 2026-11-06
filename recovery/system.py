import codecs
import json
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from recovery.registry import NO_WINDOW, REG_DWORD, read_value  # noqa: F401  (для совместимости)

SYSTEM_ROOT = os.environ.get("SystemRoot", r"C:\Windows")
HOSTS_FILE = Path(SYSTEM_ROOT) / "System32" / "drivers" / "etc" / "hosts"
RESTORE_TYPES = {0: "Установка программы", 1: "Удаление программы", 10: "Установка драйвера",
                 12: "Изменение параметров", 13: "Отменённая операция"}


@dataclass
class Finding:
    category: str       # hosts | proxy | winhttp | updates | firewall | bcd
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


def decode_console(data: bytes) -> str:
    try:
        return data.decode("oem", "replace")
    except LookupError:  # не Windows
        return data.decode("utf-8", "replace")


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


def run_tool(args: list[str], timeout: int = 30) -> str:
    """Запускает консольную программу (netsh, sc, bcdedit...). При ошибке бросает OSError."""
    try:
        result = subprocess.run(args, capture_output=True, timeout=timeout,
                                creationflags=NO_WINDOW)
    except subprocess.TimeoutExpired as e:
        raise OSError("Время ожидания истекло") from e
    output = decode_console(result.stdout) + decode_console(result.stderr)
    if result.returncode != 0:
        raise OSError(output.strip() or f"команда завершилась с кодом {result.returncode}")
    return output


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
                           RESTORE_TYPES.get(d.get("k"), f"{d.get('k')}"))
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