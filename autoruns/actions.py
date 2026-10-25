import os
import shutil
import subprocess
import uuid
from pathlib import Path

from autoruns.model import Entry
from autoruns.scanner import HIVES, SYSTEM_ROOT, winreg
from recovery import journal
from recovery.journal import undo_op

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# (текст кнопки, пояснение в окне подтверждения)
REMEDIATION = {
    "run": ("Удалить запись",
            "Запись будет удалена из реестра. Вернуть её можно на вкладке «Журнал действий»."),
    "startup": ("Убрать из автозагрузки",
                "Файл будет перемещён в резервную папку. Вернуть его можно на вкладке "
                "«Журнал действий»."),
    "service": ("Отключить службу",
                "Тип запуска службы станет «Отключена» (вступит в силу после остановки "
                "службы или перезагрузки). Вернуть можно на вкладке «Журнал действий»."),
    "task": ("Отключить задачу",
             "Задача будет отключена в планировщике. Вернуть можно на вкладке "
             "«Журнал действий»."),
}


def _run(args: list[str]) -> str:
    result = subprocess.run(args, capture_output=True, text=True, encoding="oem",
                            errors="replace", timeout=30, creationflags=NO_WINDOW)
    output = (result.stdout or "") + (result.stderr or "")
    if result.returncode != 0:
        raise OSError(output.strip() or f"команда завершилась с кодом {result.returncode}")
    return output


def _ser(data):
    return {"hex": data.hex()} if isinstance(data, bytes) else data


def _de(data):
    return bytes.fromhex(data["hex"]) if isinstance(data, dict) else data


def _is_windows_component(e: Entry) -> bool:
    exe = os.path.normcase(e.exe)
    return (bool(exe) and exe.startswith(os.path.normcase(SYSTEM_ROOT))
            and e.sig_status == "valid")


# ---------- что разрешено ----------
def can_remediate(e: Entry) -> tuple[bool, str]:
    if not e.assessed:
        return False, "Запись ещё проверяется"
    if e.kind in ("winlogon", "wmi"):
        return False, "Только просмотр: изменение этого механизма не поддерживается"
    if e.kind in ("service", "task"):
        if _is_windows_component(e):
            return False, "Компонент Windows с действительной подписью: изменение запрещено"
        if (e.kind == "task" and e.name.lower().startswith("\\microsoft\\windows\\")
                and e.level not in ("threat", "suspicious")):
            return False, "Системная задача Windows: изменение запрещено"
    return True, ""


def can_quarantine(e: Entry) -> tuple[bool, str]:
    if not e.assessed:
        return False, "Запись ещё проверяется"
    if e.kind in ("winlogon", "wmi"):
        return False, "Для этого механизма карантин файла не предусмотрен"
    if not e.exe or not os.path.isfile(e.exe):
        return False, "Файл не найден"
    if _is_windows_component(e):
        return False, "Компонент Windows с действительной подписью"
    return True, ""


# ---------- реестр ----------
def remove_registry_value(e: Entry) -> str:
    x = e.extra
    # значение читается заново: оно могло измениться после сканирования
    with winreg.OpenKey(HIVES[x["hive"]], x["path"], 0,
                        winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE) as key:
        data, reg_type = winreg.QueryValueEx(key, x["value"])
        winreg.DeleteValue(key, x["value"])
    journal.log_action(
        f"Удалена запись автозапуска «{e.name}» ({x['hive']}\\{x['path']})", "reg_set",
        {"hive": x["hive"], "path": x["path"], "value": x["value"],
         "type": reg_type, "data": _ser(data), "entry_key": e.key})
    return f"Запись «{e.name}» удалена. Отменить можно на вкладке «Журнал действий»."


@undo_op("reg_set")
def _undo_reg_set(d: dict) -> str:
    with winreg.CreateKeyEx(HIVES[d["hive"]], d["path"], 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, d["value"], 0, d["type"], _de(d["data"]))
    return f"Значение «{d['value']}» возвращено в {d['hive']}\\{d['path']}"


# ---------- папка автозагрузки ----------
def move_startup_file(e: Entry) -> str:
    src = Path(e.extra["file"])
    folder = journal.BACKUP_DIR / uuid.uuid4().hex
    folder.mkdir(parents=True)
    dst = folder / (src.name + ".bak")  # расширение .bak: копию нельзя случайно запустить
    shutil.move(str(src), dst)
    journal.log_action(f"Файл автозагрузки «{src.name}» перемещён в резервную папку",
                       "move_back", {"src": str(dst), "dst": str(src), "entry_key": e.key})
    return f"Файл «{src.name}» убран из автозагрузки. Отменить можно в журнале."


@undo_op("move_back")
def _undo_move(d: dict) -> str:
    dst = Path(d["dst"])
    if dst.exists():
        raise FileExistsError(f"По пути {dst} уже есть файл")
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(d["src"], dst)
    return f"Файл возвращён: {dst}"


# ---------- службы ----------
def disable_service(e: Entry) -> str:
    name, mode = e.extra["service"], e.extra["start_mode"]
    _run(["sc.exe", "config", name, "start=", "disabled"])
    journal.log_action(f"Служба «{name}» отключена (прежний тип запуска: {mode})",
                       "service_start", {"name": name, "mode": mode, "entry_key": e.key})
    return f"Служба «{name}» отключена. Отменить можно в журнале."


@undo_op("service_start")
def _undo_service(d: dict) -> str:
    _run(["sc.exe", "config", d["name"], "start=", d["mode"]])
    return f"Службе «{d['name']}» возвращён прежний тип запуска"


# ---------- планировщик ----------
def disable_task(e: Entry) -> str:
    name = e.extra["task"]
    _run(["schtasks.exe", "/Change", "/TN", name, "/DISABLE"])
    journal.log_action(f"Задача планировщика «{name}» отключена", "task_enable", {"name": name, "entry_key": e.key})
    return f"Задача «{name}» отключена. Отменить можно в журнале."


@undo_op("task_enable")
def _undo_task(d: dict) -> str:
    _run(["schtasks.exe", "/Change", "/TN", d["name"], "/ENABLE"])
    return f"Задача «{d['name']}» снова включена"


# ---------- карантин файла ----------
def quarantine_target(e: Entry) -> str:
    from quarantine import quarantine_file
    path = Path(e.exe)
    item_id = quarantine_file(path, reason=f"Автозапуск: {e.name}")
    journal.log_action(f"Файл «{path.name}» перемещён в карантин (автозапуск: {e.name})",
                       "quarantine_restore", {"id": item_id, "entry_key": e.key})
    return f"Файл «{path.name}» перемещён в карантин. Отменить можно в журнале."


@undo_op("quarantine_restore")
def _undo_quarantine(d: dict) -> str:
    from quarantine import restore_file
    dest = restore_file(d["id"], whitelist=False)  # откат не считается решением «файл безопасен»
    return f"Файл восстановлен: {dest}"


# ---------- вход ----------
def remediate(e: Entry) -> str:
    allowed, reason = can_remediate(e)
    if not allowed:
        raise PermissionError(reason)
    handlers = {"run": remove_registry_value, "startup": move_startup_file,
                "service": disable_service, "task": disable_task}
    return handlers[e.kind](e)