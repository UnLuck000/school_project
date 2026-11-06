"""Исключения: то, чему пользователь доверяет.

Два файла:
• signatures/exclusions.json — локальные (автозапуск, находки проверки системы): зависят от
  конкретного компьютера, в Git и релиз не попадают;
• signatures/release_exclusions.json — RELEASE_CATEGORIES: заранее известные безвредные
  файлы, которые базы помечают вредоносными (winws.exe и WinDivert из zapret, MsIo64.sys от
  MSI): drivers — для окна уязвимых драйверов, programs — для всех проверок файлов
  (whitelist.trusted_hashes). Хранится в Git и попадает в релиз. Белый список пользователя
  (signatures/whitelist.json: файлы, возвращённые из карантина) — только на этом компьютере.
"""
import json
import os
import threading
from datetime import datetime
from pathlib import Path

EXCLUSIONS_FILE = Path(__file__).resolve().parent.parent / "signatures" / "exclusions.json"
RELEASE_FILE = EXCLUSIONS_FILE.with_name("release_exclusions.json")
RELEASE_CATEGORIES = {"drivers", "programs"}
CATEGORY_TEXT = {"autoruns": "Автозапуск", "checks": "Проверка системы",
                 "drivers": "Драйверы (в релизе)", "programs": "Программы (в релизе)"}
_lock = threading.Lock()


def fingerprint(path) -> list | None:
    """[размер, время изменения] файла. Исключение действует, пока файл не менялся."""
    if not path:
        return None
    try:
        st = os.stat(path)
    except OSError:
        return None
    return [st.st_size, st.st_mtime_ns]


def entry_key(e) -> str:
    return f"{e.kind}|{e.location}|{e.name}|{e.command}"


def finding_key(f) -> str:
    return f"{f.category}|{f.title}|{f.status}|{f.detail}"


def hit_key(h) -> str:
    return f"policy|{h.hive}|{h.path}|{h.name}|{h.value}"


def _file(category: str) -> Path:
    return RELEASE_FILE if category in RELEASE_CATEGORIES else EXCLUSIONS_FILE


def _read_file(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _read() -> dict:
    """Оба файла вместе: категории в них не пересекаются."""
    data = _read_file(EXCLUSIONS_FILE)
    for category, entries in _read_file(RELEASE_FILE).items():
        if category in RELEASE_CATEGORIES:
            data[category] = entries
    return data


def _save(data: dict, path: Path = EXCLUSIONS_FILE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)  # запись через временный файл


def load() -> dict:
    """Все исключения. Читается один раз на проверку, дальше используется matches()."""
    with _lock:
        return _read()


def matches(data: dict, category: str, key: str, fp=None) -> bool:
    item = data.get(category, {}).get(key)
    return item is not None and item.get("fp") == fp


def add(category: str, key: str, title: str, detail: str = "", fp=None) -> None:
    with _lock:
        path = _file(category)
        data = _read_file(path)
        data.setdefault(category, {})[key] = {
            "title": title, "detail": detail, "fp": fp,
            "added": datetime.now().isoformat(timespec="seconds")}
        _save(data, path)


def remove(category: str, key: str) -> bool:
    with _lock:
        path = _file(category)
        data = _read_file(path)
        if data.get(category, {}).pop(key, None) is None:
            return False
        _save(data, path)
        return True


def items() -> list[dict]:
    """Плоский список для показа: категория, ключ, название, подробности, дата."""
    result = []
    for category, entries in load().items():
        for key, item in entries.items():
            result.append({"category": category, "key": key, "title": item.get("title", ""),
                           "detail": item.get("detail", ""), "added": item.get("added", "")})
    return sorted(result, key=lambda i: i["added"], reverse=True)