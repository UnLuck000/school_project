import uuid
from pathlib import Path

from recovery import journal
from recovery import system as rsys
from recovery.journal import undo_op
from recovery.policies import PolicyHit, scan_restrictions
from recovery.registry import REG_DWORD, read_value, resolve, winreg
from recovery.system import Finding, run_tool


def _ser(data):
    return {"hex": data.hex()} if isinstance(data, bytes) else data


def _de(data):
    return bytes.fromhex(data["hex"]) if isinstance(data, dict) else data


# ---------- реестр ----------
def _restore_one(d: dict) -> None:
    root, full = resolve(d["hive"], d["path"])
    if d["existed"]:
        with winreg.CreateKeyEx(root, full, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, d["name"], 0, d["type"], _de(d["data"]))
    else:
        try:
            with winreg.OpenKey(root, full, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, d["name"])
        except OSError:  # раздела или значения уже нет
            pass


@undo_op("reg_restore")
def _undo_reg(d: dict) -> str:
    _restore_one(d)
    return f"Параметр {d['name']} возвращён к прежнему состоянию"


@undo_op("reg_restore_many")
def _undo_reg_many(d: dict) -> str:
    for item in d["items"]:
        _restore_one(item)
    return f"Возвращено параметров: {len(d['items'])}"


def _apply_reg(fix: dict) -> str:
    hive, path, name = fix["hive"], fix["path"], fix["name"]
    existed, old, reg_type = read_value(hive, path, name)
    root, full = resolve(hive, path)
    deleting = fix["op"] == "reg_delete"
    if deleting:
        with winreg.OpenKey(root, full, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, name)
    else:
        with winreg.CreateKeyEx(root, full, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, name, 0, fix["type"], fix["value"])
    journal.log_action(
        f"Реестр: {hive}\\{path}\\{name} {'удалено' if deleting else 'изменено'}",
        "reg_restore",
        {"hive": hive, "path": path, "name": name, "existed": existed,
         "type": reg_type, "data": _ser(old)})
    return f"Параметр {name} исправлен. Отменить можно в журнале действий."


# ---------- массовая разблокировка ограничений ----------
def unlock_hits(hits: list[PolicyHit]) -> str:
    """Снимает ограничения одним действием журнала (отменяется целиком)."""
    if not hits:
        raise ValueError("Нет ограничений для разблокировки")
    items, failed = [], []
    for hit in hits:
        try:
            existed, old, reg_type = read_value(hit.hive, hit.path, hit.name)
            root, full = resolve(hit.hive, hit.path)
            if hit.default is not None:
                with winreg.CreateKeyEx(root, full, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, hit.name, 0, REG_DWORD, hit.default)
            else:
                with winreg.OpenKey(root, full, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, hit.name)
        except OSError as e:
            failed.append(f"{hit.hive}\\{hit.path}\\{hit.name}: {e}")
            continue
        items.append({"hive": hit.hive, "path": hit.path, "name": hit.name,
                      "existed": existed, "type": reg_type, "data": _ser(old)})
    if not items:
        raise OSError("Не удалось снять ограничения (возможно, нужны права администратора): "
                      + "; ".join(failed[:3]))
    journal.log_action(f"Разблокировано ограничений: {len(items)}", "reg_restore_many",
                       {"items": items})
    message = f"Снято ограничений: {len(items)}. Отменить можно в журнале действий."
    if failed:
        message += f"\nНе удалось снять: {len(failed)} (возможно, нужны права администратора)."
    return message


def unlock_by_names(names: list[str]) -> str:
    wanted = set(names)
    hits = [h for h in scan_restrictions() if h.restriction_name in wanted]
    if not hits:
        raise ValueError("Выбранные ограничения не обнаружены: разблокировать нечего")
    return unlock_hits(hits)


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


# ---------- службы, задачи, брандмауэр, BCD ----------
def _apply_service_mode(fix: dict) -> str:
    run_tool(["sc.exe", "config", fix["name"], "start=", fix["mode"]])
    journal.log_action(f"Служба «{fix['name']}»: тип запуска изменён на {fix['mode']}",
                       "service_mode", {"name": fix["name"], "mode": fix["prev"]})
    return "Тип запуска службы изменён. Отменить можно в журнале действий."


@undo_op("service_mode")
def _undo_service_mode(d: dict) -> str:
    run_tool(["sc.exe", "config", d["name"], "start=", d["mode"]])
    return f"Службе «{d['name']}» возвращён прежний тип запуска"


def _set_task(name: str, enable: bool) -> None:
    run_tool(["schtasks.exe", "/Change", "/TN", name, "/ENABLE" if enable else "/DISABLE"])


def _apply_task_enabled(fix: dict) -> str:
    _set_task(fix["name"], fix["enable"])
    journal.log_action(f"Задача «{fix['name']}»: {'включена' if fix['enable'] else 'отключена'}",
                       "task_enabled", {"name": fix["name"], "enable": not fix["enable"]})
    return "Задача изменена. Отменить можно в журнале действий."


@undo_op("task_enabled")
def _undo_task(d: dict) -> str:
    _set_task(d["name"], d["enable"])
    return f"Задача «{d['name']}» возвращена в прежнее состояние"


def _apply_firewall_state(fix: dict) -> str:
    run_tool(["netsh.exe", "advfirewall", "set", f"{fix['profile']}profile", "state", fix["state"]])
    journal.log_action(f"Брандмауэр ({fix['profile']}): состояние {fix['state']}",
                       "firewall_state", {"profile": fix["profile"], "state": fix["prev"]})
    return "Состояние брандмауэра изменено. Отменить можно в журнале действий."


@undo_op("firewall_state")
def _undo_firewall(d: dict) -> str:
    run_tool(["netsh.exe", "advfirewall", "set", f"{d['profile']}profile", "state", d["state"]])
    return f"Состояние брандмауэра ({d['profile']}) возвращено"


def _bcd(element: str, value) -> None:
    if value is None:
        run_tool(["bcdedit.exe", "/deletevalue", "{current}", element])
    else:
        run_tool(["bcdedit.exe", "/set", "{current}", element, value])


def _apply_bcd(fix: dict) -> str:
    _bcd(fix["element"], fix["value"])
    journal.log_action(f"BCD: параметр {fix['element']} изменён", "bcd_set",
                       {"element": fix["element"], "value": fix["prev"]})
    return "Параметр загрузки изменён. Отменить можно в журнале действий."


@undo_op("bcd_set")
def _undo_bcd(d: dict) -> str:
    _bcd(d["element"], d["value"])
    return f"Параметр BCD {d['element']} возвращён"


# ---------- вход ----------
HANDLERS = {
    "reg_set": _apply_reg, "reg_delete": _apply_reg, "hosts_remove": _apply_hosts,
    "service_mode": _apply_service_mode, "task_enabled": _apply_task_enabled,
    "firewall_state": _apply_firewall_state, "bcd_set": _apply_bcd,
}


def apply_fix(finding: Finding) -> str:
    fix = finding.fix
    if not fix:
        raise ValueError("Для этой находки исправление не предусмотрено")
    handler = HANDLERS.get(fix["op"])
    if handler is None:
        raise ValueError(f"Неизвестное исправление: {fix['op']}")
    return handler(fix)