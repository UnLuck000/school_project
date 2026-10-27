import uuid
from pathlib import Path

from recovery import journal
from recovery import system as rsys
from recovery.journal import undo_op
from recovery.system import Finding, winreg

EXCLUSION_PARAMS = {"Path": "ExclusionPath", "Extension": "ExclusionExtension",
                    "Process": "ExclusionProcess"}


def _ser(data):
    return {"hex": data.hex()} if isinstance(data, bytes) else data


def _de(data):
    return bytes.fromhex(data["hex"]) if isinstance(data, dict) else data


# ---------- реестр ----------
def _apply_reg(fix: dict) -> str:
    hive, path, name = fix["hive"], fix["path"], fix["name"]
    existed, old, reg_type = rsys.read_value(hive, path, name)
    deleting = fix["op"] == "reg_delete"
    with winreg.CreateKeyEx(rsys.HIVES[hive], path, 0,
                            winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE) as key:
        if deleting:
            winreg.DeleteValue(key, name)
        else:
            winreg.SetValueEx(key, name, 0, fix["type"], fix["value"])
    journal.log_action(
        f"Реестр: {hive}\\{path}\\{name} {'удалено' if deleting else 'изменено'}",
        "reg_restore",
        {"hive": hive, "path": path, "name": name, "existed": existed,
         "type": reg_type, "data": _ser(old)})
    return f"Параметр {name} исправлен. Отменить можно в журнале действий."


@undo_op("reg_restore")
def _undo_reg(d: dict) -> str:
    with winreg.CreateKeyEx(rsys.HIVES[d["hive"]], d["path"], 0, winreg.KEY_SET_VALUE) as key:
        if d["existed"]:
            winreg.SetValueEx(key, d["name"], 0, d["type"], _de(d["data"]))
        else:
            try:
                winreg.DeleteValue(key, d["name"])
            except FileNotFoundError:
                pass
    return f"Параметр {d['name']} возвращён к прежнему состоянию"


# ---------- hosts ----------
def _apply_hosts(fix: dict) -> str:
    original = rsys.HOSTS_FILE.read_bytes()
    if b"\x00" in original:
        raise OSError("Файл hosts в нестандартной кодировке: исправьте его вручную")
    target = fix["raw"].strip()
    lines = original.splitlines(keepends=True)
    kept = [ln for ln in lines if ln.decode("utf-8", "replace").strip() != target]
    if len(kept) == len(lines):
        raise OSError("Этой строки уже нет в файле hosts")

    folder = journal.BACKUP_DIR / uuid.uuid4().hex
    folder.mkdir(parents=True)
    backup = folder / "hosts.bak"
    backup.write_bytes(original)  # копия до изменения
    rsys.HOSTS_FILE.write_bytes(b"".join(kept))
    journal.log_action(f"Файл hosts: удалена строка «{target[:60]}»", "hosts_restore",
                       {"backup": str(backup)})
    return "Строка удалена из hosts. Отменить можно в журнале действий."


@undo_op("hosts_restore")
def _undo_hosts(d: dict) -> str:
    backup = Path(d["backup"])
    if not backup.is_file():
        raise ValueError("Резервная копия hosts не найдена")
    rsys.HOSTS_FILE.write_bytes(backup.read_bytes())
    return "Файл hosts возвращён к состоянию до исправления"


# ---------- Defender ----------
def _powershell_or_raise(script: str, env: dict | None = None) -> None:
    code, _, err = rsys.run_powershell("$ErrorActionPreference='Stop';" + script, env)
    if code != 0:
        raise OSError(err.strip() or "Команда PowerShell завершилась с ошибкой")


def _apply_exclusion_remove(fix: dict) -> str:
    param = EXCLUSION_PARAMS[fix["kind"]]
    _powershell_or_raise(f"Remove-MpPreference -{param} $env:AV_VALUE", {"AV_VALUE": fix["value"]})
    journal.log_action(f"Defender: удалено исключение «{fix['value']}»",
                       "defender_exclusion_add", {"kind": fix["kind"], "value": fix["value"]})
    return "Исключение удалено. Отменить можно в журнале действий."


@undo_op("defender_exclusion_add")
def _undo_exclusion(d: dict) -> str:
    param = EXCLUSION_PARAMS[d["kind"]]
    _powershell_or_raise(f"Add-MpPreference -{param} $env:AV_VALUE", {"AV_VALUE": d["value"]})
    return f"Исключение «{d['value']}» возвращено"


def _apply_realtime(fix: dict) -> str:
    # в журнал не пишется: откат означал бы выключение защиты
    _powershell_or_raise("Set-MpPreference -DisableRealtimeMonitoring $false")
    return "Защита в реальном времени включена."


# ---------- вход ----------
def apply_fix(finding: Finding) -> str:
    fix = finding.fix
    if not fix:
        raise ValueError("Для этой находки исправление не предусмотрено")
    op = fix["op"]
    if op in ("reg_set", "reg_delete"):
        return _apply_reg(fix)
    if op == "hosts_remove":
        return _apply_hosts(fix)
    if op == "defender_exclusion_remove":
        return _apply_exclusion_remove(fix)
    if op == "defender_realtime":
        return _apply_realtime(fix)
    raise ValueError(f"Неизвестное исправление: {op}")