"""Файловые ассоциации: снимок, сравнение с текущим состоянием, восстановление через журнал
и проверка критичных расширений на перехват.

Windows собирает HKCR из двух мест: HKLM\\Software\\Classes (для всех) и HKCU\\Software\\Classes
(для пользователя, имеет приоритет). Вредоносные программы перехватывают запуск файлов,
записывая свой обработчик в HKCU (права администратора не нужны) или выбор программы в
...\\Explorer\\FileExts\\<расширение>\\UserChoice.
"""
import json
import os
import re
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from recovery import journal
from recovery.actions import _de, _restore_one, _ser
from recovery.journal import undo_op
from recovery.registry import list_subkeys, list_values, read_value, resolve, winreg

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
SNAPSHOT_DIR = journal.JOURNAL_DIR / "assoc_snapshots"
CLASSES = r"Software\Classes"
FILE_EXTS = r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"
USER_CHOICE_KEYS = ("UserChoice", "UserChoiceLatest")
VERBS = ("open", "runas")
REG_SZ = 1

# расширение: (ожидаемый ProgID, допустимые команды open; пустой список = команды быть не должно)
CRITICAL = {
    ".exe": ("exefile", ['"%1" %*']),
    ".com": ("comfile", ['"%1" %*']),
    ".bat": ("batfile", ['"%1" %*', '"%systemroot%\\system32\\cmd.exe" /c "%1" %*']),
    ".cmd": ("cmdfile", ['"%1" %*', '"%systemroot%\\system32\\cmd.exe" /c "%1" %*']),
    ".scr": ("scrfile", ['"%1" /s']),
    ".lnk": ("lnkfile", []),
    ".reg": ("regfile", ['regedit.exe "%1"', '"%systemroot%\\regedit.exe" "%1"']),
}
# правильные значения для восстановления
DEFAULT_COMMANDS = {"exefile": '"%1" %*', "comfile": '"%1" %*', "batfile": '"%1" %*',
                    "cmdfile": '"%1" %*', "scrfile": '"%1" /S', "regfile": 'regedit.exe "%1"'}
# в снимок дополнительно попадают расширения, которые часто используют для запуска кода
SNAPSHOT_EXTS = sorted(set(CRITICAL) | {
    ".pif", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".msi", ".hta", ".cpl",
    ".msc", ".jar", ".url", ".txt", ".html", ".htm", ".pdf", ".zip", ".docx", ".xlsx",
    ".jpg", ".png", ".mp4"})


def _norm_cmd(text) -> str:
    text = os.path.expandvars(str(text or "")).lower()
    root = os.environ.get("SystemRoot", r"C:\Windows").lower()
    text = text.replace(root, "%systemroot%")
    return re.sub(r"\s+", " ", text).strip()


def _cmd_ok(command, allowed: list[str]) -> bool:
    return _norm_cmd(command) in {_norm_cmd(a) for a in allowed}


def _key_exists(hive: str, path: str) -> bool:
    if winreg is None:
        return False
    try:
        root, full = resolve(hive, path)
        winreg.OpenKey(root, full).Close()
        return True
    except OSError:
        return False


# ---------- состояние одного расширения ----------
def _fields(ext: str) -> dict[str, tuple[str, str, str]]:
    """{название поля: (куст, раздел, имя значения)} для расширения и его ProgID."""
    fields = {
        "ProgID (HKLM)": ("HKLM", f"{CLASSES}\\{ext}", ""),
        "ProgID (HKCU)": ("HKCU", f"{CLASSES}\\{ext}", ""),
    }
    for name in USER_CHOICE_KEYS:
        fields[f"Выбор пользователя ({name})"] = ("HKCU", f"{FILE_EXTS}\\{ext}\\{name}", "ProgId")
    progids = set()
    for hive in ("HKLM", "HKCU"):
        exists, value, _ = read_value(hive, f"{CLASSES}\\{ext}", "")
        if exists and value:
            progids.add(str(value))
    for name in USER_CHOICE_KEYS:
        exists, value, _ = read_value("HKCU", f"{FILE_EXTS}\\{ext}\\{name}", "ProgId")
        if exists and value:
            progids.add(str(value))
    if ext in CRITICAL:
        progids.add(CRITICAL[ext][0])
    for progid in sorted(progids):
        for verb in VERBS:
            for hive in ("HKLM", "HKCU"):
                path = f"{CLASSES}\\{progid}\\shell\\{verb}\\command"
                fields[f"{progid}: команда {verb} ({hive})"] = (hive, path, "")
    return fields


def read_state(ext: str) -> dict[str, dict]:
    """{поле: {hive, path, name, key, exists, value, type}}."""
    state = {}
    for label, (hive, path, name) in _fields(ext).items():
        exists, value, reg_type = read_value(hive, path, name)
        state[label] = {"hive": hive, "path": path, "name": name,
                        "key": exists or _key_exists(hive, path), "exists": exists,
                        "value": _ser(value) if exists else None,
                        "type": reg_type if exists else None}
    return state


def _user_extensions() -> list[str]:
    """Расширения, для которых у пользователя есть свои настройки в HKCU."""
    found = {n.lower() for n in list_subkeys("HKCU", CLASSES) if n.startswith(".")}
    for n in list_subkeys("HKCU", FILE_EXTS):
        if n.startswith(".") and any(_key_exists("HKCU", f"{FILE_EXTS}\\{n}\\{c}")
                                     for c in USER_CHOICE_KEYS):
            found.add(n.lower())
    return sorted(found)


def all_extensions() -> list[str]:
    """Все расширения, известные системе: HKLM, HKCU и выбор пользователя."""
    found = {n.lower() for n in list_subkeys("HKLM", CLASSES) if n.startswith(".")}
    return sorted(found | set(_user_extensions()))


# ---------- все расширения и их программы ----------
ASSOCF_NOTRUNCATE, ASSOCF_INIT_IGNOREUNKNOWN = 0x20, 0x400
ASSOCSTR_COMMAND, ASSOCSTR_EXECUTABLE = 1, 2
ASSOCSTR_FRIENDLYDOCNAME, ASSOCSTR_FRIENDLYAPPNAME = 3, 4
_assoc_query = None


def _query(ext: str, what: int) -> str:
    """Что Проводник сделает с файлом (AssocQueryStringW учитывает HKCU, HKLM и UserChoice)."""
    global _assoc_query
    if _assoc_query is None:
        import ctypes
        from ctypes import wintypes
        fn = ctypes.WinDLL("shlwapi").AssocQueryStringW
        fn.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR,
                       wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        fn.restype = ctypes.c_long

        def call(e: str, w: int) -> str:
            buf = ctypes.create_unicode_buffer(2048)
            size = wintypes.DWORD(2048)
            ok = fn(ASSOCF_NOTRUNCATE | ASSOCF_INIT_IGNOREUNKNOWN, w, e, None, buf,
                    ctypes.byref(size)) == 0
            return buf.value if ok else ""
        _assoc_query = call
    return _assoc_query(ext, what)


@dataclass
class ExtInfo:
    ext: str
    type_name: str      # описание типа файла
    progid: str
    source: str         # откуда взят обработчик
    app: str            # название программы
    exe: str            # исполняемый файл программы
    command: str
    level: str = "ok"   # ok | warning | bad
    note: str = ""


USER_DIRS = ("\\appdata\\local\\temp\\", "\\downloads\\", "\\users\\public\\")


def list_all(progress=None) -> list[ExtInfo]:
    """Все расширения с программами, которые их открывают. Медленно (секунды)."""
    result: list[ExtInfo] = []
    exts = all_extensions()
    for i, ext in enumerate(exts):
        if progress and i % 100 == 0:
            progress(f"Расширений обработано: {i} из {len(exts)}")
        progid, source = "", ""
        for name in USER_CHOICE_KEYS:
            exists, value, _ = read_value("HKCU", f"{FILE_EXTS}\\{ext}\\{name}", "ProgId")
            if exists and value:
                progid, source = str(value), "выбор пользователя"
                break
        if not progid:
            for hive, label in (("HKCU", "HKCU (пользователь)"), ("HKLM", "HKLM (система)")):
                exists, value, _ = read_value(hive, f"{CLASSES}\\{ext}", "")
                if exists and value:
                    progid, source = str(value), label
                    break
        exe = _query(ext, ASSOCSTR_EXECUTABLE)
        command = _query(ext, ASSOCSTR_COMMAND)
        app = _query(ext, ASSOCSTR_FRIENDLYAPPNAME)
        info = ExtInfo(ext, _query(ext, ASSOCSTR_FRIENDLYDOCNAME), progid, source or "—",
                       app, exe, command)
        if exe.strip('"') in ("%1", ""):
            info.exe = "запускается сам файл" if exe else ""
        elif not os.path.isfile(exe):
            if "\\" in exe:
                info.level, info.note = "warning", "программа не найдена на диске"
        elif any(d in exe.lower() for d in USER_DIRS):
            info.level, info.note = "warning", "программа во временной или пользовательской папке"
        result.append(info)
    if progress:
        progress(f"Расширений: {len(result)}")
    return result


# ---------- снимки ----------
def take_snapshot(comment: str = "") -> Path:
    exts = sorted(set(SNAPSHOT_EXTS) | set(all_extensions()))
    data = {"time": datetime.now().isoformat(timespec="seconds"), "comment": comment,
            "extensions": {ext: read_state(ext) for ext in exts}}
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    target = SNAPSHOT_DIR / f"assoc_{datetime.now():%Y%m%d_%H%M%S}.json"
    tmp = target.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, target)
    return target


def list_snapshots() -> list[tuple[Path, str, str, int]]:
    """[(файл, время, комментарий, число расширений)], новые первыми."""
    result = []
    for f in sorted(SNAPSHOT_DIR.glob("assoc_*.json"), reverse=True):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        result.append((f, data.get("time", ""), data.get("comment", ""),
                       len(data.get("extensions", {}))))
    return result


def load_snapshot(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# ---------- операции восстановления ----------
@dataclass
class Op:
    kind: str           # set | delete_value | delete_key
    hive: str
    path: str
    name: str = ""
    reg_type: int | None = None
    value: object = None


def _show(value) -> str:
    if value is None:
        return "нет"
    if isinstance(value, dict) and "hex" in value:
        return f"двоичные данные ({len(value['hex']) // 2} байт)"
    return str(value) if value != "" else "(пусто)"


def _reg_exe(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["reg.exe", *args], capture_output=True, timeout=30,
                          creationflags=NO_WINDOW)


def _full_name(hive: str, path: str) -> str:
    return ("HKEY_CURRENT_USER" if hive == "HKCU" else "HKEY_LOCAL_MACHINE") + "\\" + path


def apply_ops(ops: list[Op], title: str) -> str:
    """Выполняет операции одним действием журнала (отменяется целиком)."""
    if not ops:
        raise ValueError("Нечего восстанавливать")
    backup_dir = journal.BACKUP_DIR / "assoc"
    backup_dir.mkdir(parents=True, exist_ok=True)
    values, exports, failed = [], [], []
    for op in ops:
        try:
            if op.kind == "delete_key":
                if not _key_exists(op.hive, op.path):
                    continue
                backup = backup_dir / f"{uuid.uuid4().hex}.reg"
                result = _reg_exe("export", _full_name(op.hive, op.path), str(backup), "/y")
                if result.returncode != 0 or not backup.exists():
                    raise OSError("не удалось сохранить резервную копию раздела")
                result = _reg_exe("delete", _full_name(op.hive, op.path), "/f")
                if result.returncode != 0:
                    backup.unlink(missing_ok=True)
                    raise OSError(result.stderr.decode("oem", "replace").strip() or "отказано")
                exports.append(str(backup))
                continue
            existed, old, old_type = read_value(op.hive, op.path, op.name)
            root, full = resolve(op.hive, op.path)
            if op.kind == "set":
                with winreg.CreateKeyEx(root, full, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, op.name, 0, op.reg_type or REG_SZ, _de(op.value))
            elif existed:
                with winreg.OpenKey(root, full, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, op.name)
            else:
                continue
            values.append({"hive": op.hive, "path": op.path, "name": op.name,
                           "existed": existed, "type": old_type, "data": _ser(old)})
        except (OSError, subprocess.SubprocessError) as e:
            failed.append(f"{op.hive}\\{op.path}: {e}")
    if not values and not exports:
        if failed:
            raise OSError("Не удалось восстановить (возможно, нужны права администратора): "
                          + "; ".join(failed[:3]))
        return "Изменений не потребовалось: состояние уже совпадает."
    journal.log_action(title, "assoc_restore", {"values": values, "exports": exports})
    message = (f"Готово: изменено значений {len(values)}, удалено разделов {len(exports)}. "
               "Отменить можно в журнале действий.")
    if failed:
        message += f"\nНе удалось: {len(failed)}\n" + "\n".join(failed[:5])
    return message


@undo_op("assoc_restore")
def _undo_assoc(d: dict) -> str:
    for file in d.get("exports", []):
        result = _reg_exe("import", file)
        if result.returncode != 0:
            raise OSError(f"Не удалось вернуть раздел из {file}")
    for item in reversed(d.get("values", [])):
        _restore_one(item)
    return "Файловые ассоциации возвращены к состоянию до восстановления"


# ---------- сравнение со снимком ----------
@dataclass
class AssocDiff:
    ext: str
    field: str
    before: str
    now: str
    ops: list[Op] = field(default_factory=list)
    note: str = ""      # почему нельзя восстановить автоматически

    @property
    def restorable(self) -> bool:
        return bool(self.ops)


def _ops_to(old: dict, cur: dict) -> tuple[list[Op], str]:
    """Операции, возвращающие поле из состояния cur в состояние old."""
    hive, path, name = cur["hive"], cur["path"], cur["name"]
    user_choice = any(path.endswith("\\" + c) for c in USER_CHOICE_KEYS)
    if not old["key"] and cur["key"]:
        if hive == "HKCU":
            return [Op("delete_key", hive, path)], ""
        if old["value"] is None and cur["exists"]:
            return [Op("delete_value", hive, path, name)], ""
    if user_choice:
        return [], ("Выбор программы защищён хэшем Windows: верните его в «Параметры → "
                    "Приложения → Приложения по умолчанию»")
    if old["exists"]:
        return [Op("set", hive, path, name, old["type"], old["value"])], ""
    if cur["exists"]:
        return [Op("delete_value", hive, path, name)], ""
    return [], ""


def compare(snapshot: dict) -> list[AssocDiff]:
    diffs: list[AssocDiff] = []
    saved = snapshot.get("extensions", {})
    exts = sorted(set(saved) | set(SNAPSHOT_EXTS) | set(all_extensions()))
    empty = {"key": False, "exists": False, "value": None, "type": None}
    for ext in exts:
        now = read_state(ext)
        before = saved.get(ext, {})
        for label in sorted(set(now) | set(before)):
            cur = now.get(label)
            old = before.get(label)
            if cur is None:  # поле было в снимке, ProgID больше не используется: читаем заново
                exists, value, reg_type = read_value(old["hive"], old["path"], old["name"])
                cur = {**old, "key": exists or _key_exists(old["hive"], old["path"]),
                       "exists": exists, "value": _ser(value) if exists else None,
                       "type": reg_type if exists else None}
            if old is None:
                if ext not in saved:
                    continue  # расширения не было в снимке: сравнивать не с чем
                old = {**cur, **empty}
            if (old["exists"], old["value"]) == (cur["exists"], cur["value"]) and \
                    old["key"] == cur["key"]:
                continue
            ops, note = _ops_to(old, cur)
            before_text = _show(old["value"]) if old["exists"] else (
                "раздел без значения" if old["key"] else "нет")
            now_text = _show(cur["value"]) if cur["exists"] else (
                "раздел без значения" if cur["key"] else "нет")
            if before_text == now_text and not ops:
                continue
            diffs.append(AssocDiff(ext, label, before_text, now_text, ops, note))
    return diffs


# ---------- проверка критичных расширений ----------
@dataclass
class AssocIssue:
    ext: str
    title: str
    detail: str
    level: str          # ok | warning | bad
    ops: list[Op] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"assoc|{self.ext}|{self.title}|{self.detail}"


def check_critical() -> list[AssocIssue]:
    issues: list[AssocIssue] = []
    for ext, (progid, allowed) in CRITICAL.items():
        found = len(issues)
        exists, value, _ = read_value("HKLM", f"{CLASSES}\\{ext}", "")
        if not exists or str(value).lower() != progid:
            issues.append(AssocIssue(
                ext, "Тип файла в HKLM изменён", f"{ext} → {value if exists else 'нет'} "
                f"(должно быть {progid})", "bad",
                [Op("set", "HKLM", f"{CLASSES}\\{ext}", "", REG_SZ, progid)]))

        exists, value, _ = read_value("HKCU", f"{CLASSES}\\{ext}", "")
        if exists and str(value).strip() and str(value).lower() != progid:
            issues.append(AssocIssue(
                ext, "Перехват в HKCU: свой тип файла",
                f"HKCU\\{CLASSES}\\{ext} = {value}", "bad",
                [Op("delete_value", "HKCU", f"{CLASSES}\\{ext}", "")]))

        for name in USER_CHOICE_KEYS:
            path = f"{FILE_EXTS}\\{ext}\\{name}"
            if _key_exists("HKCU", path):
                _, choice, _ = read_value("HKCU", path, "ProgId")
                level = "warning" if ext in (".bat", ".cmd", ".reg") else "bad"
                issues.append(AssocIssue(
                    ext, "Перехват в HKCU: выбор программы (UserChoice)",
                    f"{ext} открывается через {choice or '?'}. Для {ext} Windows такой выбор "
                    "не создаёт", level, [Op("delete_key", "HKCU", path)]))

        for verb in VERBS:
            path = f"{CLASSES}\\{progid}\\shell\\{verb}\\command"
            if _key_exists("HKCU", path):
                _, value, _ = read_value("HKCU", path, "")
                issues.append(AssocIssue(
                    ext, f"Перехват в HKCU: команда «{verb}» для {progid}",
                    f"HKCU\\{path} = {value or '(пусто)'}", "bad",
                    [Op("delete_key", "HKCU", f"{CLASSES}\\{progid}\\shell\\{verb}")]))

        exists, value, _ = read_value("HKLM", f"{CLASSES}\\{progid}\\shell\\open\\command", "")
        if allowed and exists and not _cmd_ok(value, allowed):
            issues.append(AssocIssue(
                ext, f"Команда запуска {progid} изменена (HKLM)",
                f"{value} (стандартно: {allowed[0]})", "bad",
                [Op("set", "HKLM", f"{CLASSES}\\{progid}\\shell\\open\\command", "", REG_SZ,
                    DEFAULT_COMMANDS[progid])]))
        elif allowed and not exists:
            issues.append(AssocIssue(
                ext, f"Нет команды запуска {progid} (HKLM)", "Файлы этого типа не запустятся",
                "bad", [Op("set", "HKLM", f"{CLASSES}\\{progid}\\shell\\open\\command", "",
                           REG_SZ, DEFAULT_COMMANDS[progid])]))
        elif not allowed and exists:
            issues.append(AssocIssue(
                ext, f"У {progid} появилась команда запуска (HKLM)", str(value), "bad",
                [Op("delete_key", "HKLM", f"{CLASSES}\\{progid}\\shell\\open")]))
        if ext == ".lnk" and not list_values("HKLM", f"{CLASSES}\\lnkfile").get("IsShortcut"):
            issues.append(AssocIssue(
                ext, "У lnkfile нет признака IsShortcut", "Ярлыки отображаются неправильно",
                "warning", [Op("set", "HKLM", f"{CLASSES}\\lnkfile", "IsShortcut", REG_SZ, "")]))

        if len(issues) == found:
            issues.append(AssocIssue(ext, "Ассоциация в порядке", f"{ext} → {progid}", "ok"))
    return issues
