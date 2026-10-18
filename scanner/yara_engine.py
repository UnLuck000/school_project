import re
from itertools import chain
from pathlib import Path

import yara

from datetime import datetime


LOG_FILE = Path(__file__).resolve().parent.parent / "logs" / "yara_errors.log"
MAX_FILE_SIZE = 100 * 1024 * 1024  # файлы больше 100 МБ пропускаем


def _dump_errors(errors: list[str]) -> None:
    """Пишет ошибки компиляции правил в лог-файл (перезаписывает при каждой загрузке)."""
    if not errors:
        return
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        header = f"# {datetime.now():%Y-%m-%d %H:%M:%S}, правил пропущено: {len(errors)}\n"
        LOG_FILE.write_text(header + "\n".join(errors) + "\n", encoding="utf-8")
    except OSError:
        pass  # лог не критичен


def _externals(path: Path | None = None) -> dict:
    return {
        "filename": path.name if path else "",
        "filepath": str(path) if path else "",
        "extension": path.suffix.lower() if path else "",
        "filetype": "",
        "owner": "",
    }


def load_rules(rules_dir: Path):
    """Компилирует все .yar/.yara из папки. Возвращает (rules | None, список ошибок).

    Каждый файл проверяется отдельно: одно битое правило не ломает остальные.
    """
    sources: dict[str, str] = {}
    errors: list[str] = []
    files = sorted(chain(rules_dir.rglob("*.yar"), rules_dir.rglob("*.yara")))

    for i, path in enumerate(files):
        try:
            yara.compile(filepath=str(path))  # пробная компиляция
        except yara.Error as e:
            errors.append(f"{path.name}: {e}")
            continue
        namespace = f"{i}_{re.sub(r'\W', '_', path.stem)}"
        sources[namespace] = str(path)
    _dump_errors(errors)

    if not sources:
        return None, errors
    return yara.compile(filepaths=sources), errors


def match_file(rules, path: Path, timeout: int = 30) -> list[str]:
    """Возвращает названия сработавших правил (пустой список, если ничего нет)."""
    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            return []
        matches = rules.match(str(path), timeout=timeout)
    except (yara.Error, OSError):  # TimeoutError тоже наследуется от yara.Error
        return []
    return [m.rule for m in matches]
