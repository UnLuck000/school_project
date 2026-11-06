"""Восстановление флешки после вируса-ярлыка. Каждое действие — в журнал с откатом.

quarantine — ярлыки, autorun.inf, скрипты, программы (через analyzer.fileops.quarantine);
unhide — снять атрибуты «скрытый» и «системный»; restore_folder — перенести файлы из
папки без имени обратно в корень и показать их; vaccinate — защитная папка autorun.inf.
"""
import ctypes
import os
import shutil

from recovery import journal
from recovery.journal import undo_op
from usbguard.scan import HIDDEN, SYSTEM, Finding, attributes

READONLY = 0x1


def set_attributes(path: str, attrs: int) -> None:
    if not ctypes.windll.kernel32.SetFileAttributesW(str(path), attrs or 0x80):  # NORMAL
        raise ctypes.WinError()


def unhide(path: str) -> bool:
    """Снимает «скрытый» и «системный». False — снимать было нечего."""
    old = attributes(path)
    if not old & (HIDDEN | SYSTEM):
        return False
    set_attributes(path, old & ~(HIDDEN | SYSTEM | READONLY) & 0xFFFF)
    journal.log_action(f"Флешка: показан «{os.path.basename(path) or path}»",
                       "usb_attrs", {"path": path, "attrs": old})
    return True


@undo_op("usb_attrs")
def _undo_attrs(d: dict) -> str:
    set_attributes(d["path"], d["attrs"])
    return f"Атрибуты «{os.path.basename(d['path'])}» возвращены"


def _free_name(folder: str, name: str) -> str:
    target = os.path.join(folder, name)
    base, ext = os.path.splitext(name)
    n = 2
    while os.path.exists(target):
        target = os.path.join(folder, f"{base} ({n}){ext}")
        n += 1
    return target


def restore_folder(folder: str) -> int:
    """Переносит содержимое папки без имени в корень диска. Возвращает число элементов."""
    root = os.path.dirname(os.path.normpath(folder))
    moves, attrs = [], {}
    for entry in list(os.scandir(folder)):
        if entry.name.lower().endswith((".vbs", ".js", ".bat", ".cmd", ".wsf", ".vbe")):
            continue  # скрипты вируса не возвращаем: их уберёт карантин
        old = attributes(entry.path)
        target = _free_name(root, entry.name)
        shutil.move(entry.path, target)
        moves.append([entry.path, target])
        if old & (HIDDEN | SYSTEM):
            attrs[target] = old
            set_attributes(target, old & ~(HIDDEN | SYSTEM | READONLY) & 0xFFFF)
    if moves:
        journal.log_action(f"Флешка: возвращено файлов из скрытой папки — {len(moves)}",
                           "usb_moves", {"moves": moves, "attrs": attrs})
    return len(moves)


@undo_op("usb_moves")
def _undo_moves(d: dict) -> str:
    failed = []
    for src, dst in reversed(d["moves"]):
        try:
            if dst in d.get("attrs", {}):
                set_attributes(dst, d["attrs"][dst])
            os.makedirs(os.path.dirname(src), exist_ok=True)
            shutil.move(dst, src)
        except OSError as e:
            failed.append(f"{os.path.basename(dst)}: {e}")
    if failed:
        raise OSError("Не все файлы возвращены: " + "; ".join(failed[:5]))
    return f"Файлы перенесены обратно в скрытую папку: {len(d['moves'])}"


def vaccinate(root: str) -> bool:
    """Папка autorun.inf (скрытая, системная) не даёт вирусу создать такой файл."""
    path = os.path.join(root, "autorun.inf")
    if os.path.exists(path):
        return False
    os.mkdir(path)
    set_attributes(path, HIDDEN | SYSTEM | READONLY)
    journal.log_action(f"Флешка {root[:2]}: защитная папка autorun.inf", "usb_unvaccinate",
                       {"path": path})
    return True


@undo_op("usb_unvaccinate")
def _undo_vaccinate(d: dict) -> str:
    set_attributes(d["path"], 0)
    os.rmdir(d["path"])
    return "Защитная папка autorun.inf удалена"


def apply(findings: list[Finding], reason: str = "Флешка: вирус-ярлык") -> tuple[int, list[str]]:
    """Выполняет fix каждой находки. Сначала карантин: так скрипты не попадут в корень."""
    from analyzer import fileops
    done, errors = 0, []
    order = {"quarantine": 0, "restore_folder": 1, "unhide": 2}
    for f in sorted(findings, key=lambda f: order.get(f.fix, 3)):
        try:
            if f.fix == "quarantine" and os.path.isfile(f.path):
                set_attributes(f.path, 0)  # скрытый и «только чтение» мешают переносу
                fileops.quarantine(f.path, f"{reason}: {f.title}")
            elif f.fix == "restore_folder" and os.path.isdir(f.path):
                restore_folder(f.path)
                unhide(f.path)
            elif f.fix == "unhide":
                unhide(f.path)
            else:
                continue
            done += 1
        except OSError as e:
            errors.append(f"{os.path.basename(f.path) or f.path}: {e}")
    return done, errors
