r"""Возврат файлов из теневых копий Windows (после шифровальщика).

Windows хранит снимки диска — теневые копии (их делают точки восстановления и «Защита
системы»). В снимке файл лежит таким, каким был в момент снимка. После тревоги «похоже на
шифровальщик» (toolbox/ransomguard.py, ловушки) испорченные документы можно вернуть оттуда.

  shadows()            — снимки: диск, путь устройства, время (нужны права администратора);
  previous_version(p)  — самый свежий снимок, где файл есть и отличается от нынешнего;
  restore(paths)       — нынешний файл остаётся рядом как «имя.sbit-damaged», на его место —
                         версия из снимка; действие в журнале, отмена возвращает как было.

Если «Защита системы» выключена, снимков нет — тогда вернуть нечего (многие шифровальщики
к тому же удаляют снимки командой vssadmin; такую команду ловит контроль запуска).
Список снимков берётся через CIM (Win32_ShadowCopy): вывод vssadmin зависит от языка Windows.
"""
import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

import syscmd
from recovery import journal

DAMAGED_SUFFIX = ".sbit-damaged"
SCRIPT = (
    "$vols = @{}; Get-CimInstance Win32_Volume | ForEach-Object { if ($_.DriveLetter) "
    "{ $vols[$_.DeviceID] = $_.DriveLetter } }; "
    "$r = @(Get-CimInstance Win32_ShadowCopy | ForEach-Object { [pscustomobject]@{"
    "drive = $vols[$_.VolumeName]; device = $_.DeviceObject; "
    "created = $_.InstallDate.ToString('yyyy-MM-dd HH:mm:ss') } }); "
    "ConvertTo-Json -Compress -InputObject $r")


@dataclass
class Shadow:
    drive: str      # «C:»
    device: str     # \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3
    created: str    # 2026-11-12 03:00:11


def parse(text: str) -> list[Shadow]:
    try:
        data = json.loads(text or "[]")
    except ValueError:
        return []
    if isinstance(data, dict):
        data = [data]
    found = [Shadow((d.get("drive") or "").upper(), d.get("device") or "", d.get("created") or "")
             for d in data if isinstance(d, dict)]
    return sorted((s for s in found if s.drive and s.device), key=lambda s: s.created,
                  reverse=True)


def shadows() -> list[Shadow]:
    """Снимки, свежие первыми. Без прав администратора или при ошибке — пусто."""
    try:
        result = syscmd.powershell(SCRIPT, timeout=60)
    except (OSError, Exception):  # noqa: BLE001 — нет PowerShell, тайм-аут: снимков «нет»
        return []
    return parse(result.stdout) if result.returncode == 0 else []


def shadow_path(shadow: Shadow, path) -> Path:
    """Путь файла внутри снимка."""
    drive, tail = os.path.splitdrive(os.path.abspath(str(path)))
    return Path(shadow.device.rstrip("\\") + tail)


def _same(a: Path, b: Path) -> bool:
    try:
        sa, sb = a.stat(), b.stat()
    except OSError:
        return False
    return sa.st_size == sb.st_size and sa.st_mtime_ns == sb.st_mtime_ns


def previous_version(path, known: list[Shadow] | None = None) -> tuple[Shadow, Path] | None:
    """(снимок, путь в нём) — самая свежая версия файла, отличная от нынешней."""
    path = Path(path)
    drive = os.path.splitdrive(os.path.abspath(str(path)))[0].upper()
    for shadow in (shadows() if known is None else known):
        if shadow.drive != drive:
            continue
        old = shadow_path(shadow, path)
        try:
            if old.is_file() and not _same(old, path):
                return shadow, old
        except OSError:
            continue
    return None


def original_name(path: Path) -> Path:
    """Шифровальщик дописал расширение (отчёт.docx.locked) — версия в снимке без него."""
    from toolbox.ransomguard import document_ext
    ext, renamed = document_ext(path.name)
    return path.with_suffix("") if renamed else path


def restore(paths, known: list[Shadow] | None = None) -> tuple[list[str], list[str]]:
    """Вернуть файлы из снимков. Возвращает (восстановленные, для которых версии нет)."""
    known = shadows() if known is None else known
    done, missing, records = [], [], []
    for raw in paths:
        damaged = Path(raw)
        target = original_name(damaged)
        found = previous_version(target, known)
        if found is None:
            missing.append(str(damaged))
            continue
        shadow, old = found
        kept = ""
        try:
            if target.exists():
                kept = str(target) + DAMAGED_SUFFIX
                os.replace(target, kept)
            shutil.copy2(old, target)
        except OSError:
            if kept and not target.exists():
                os.replace(kept, target)
            missing.append(str(damaged))
            continue
        done.append(str(target))
        records.append({"path": str(target), "damaged": kept, "from": shadow.created})
    if records:
        journal.log_action(f"Возвращены файлы из теневой копии Windows ({len(records)})",
                           "shadow_restore", {"files": records})
    return done, missing


@journal.undo_op("shadow_restore")
def _undo_restore(d: dict) -> str:
    count = 0
    for item in d.get("files", []):
        target, damaged = Path(item["path"]), item.get("damaged") or ""
        try:
            if damaged and os.path.exists(damaged):
                os.replace(damaged, target)
            else:
                target.unlink(missing_ok=True)
            count += 1
        except OSError:
            pass
    return f"Возвращено прежнее состояние файлов: {count}"
