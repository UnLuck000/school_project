import json
import shutil
import uuid
from datetime import datetime
from pathlib import Path

from scanner.hashing import sha256_of

QUARANTINE_DIR = Path("quarantine_data").resolve()


def _meta_path(item_id: str) -> Path:
    return QUARANTINE_DIR / f"{item_id}.json"


def _stored_path(item_id: str) -> Path:
    return QUARANTINE_DIR / f"{item_id}.quar"


def quarantine_file(path: Path, reason: str) -> str:
    """Перемещает файл в карантин и возвращает его идентификатор."""
    QUARANTINE_DIR.mkdir(exist_ok=True)
    path = Path(path).resolve()

    item_id = uuid.uuid4().hex
    meta = {
        "id": item_id,
        "original_path": str(path),
        "sha256": sha256_of(path),
        "size": path.stat().st_size,
        "reason": reason,
        "quarantined_at": datetime.now().isoformat(timespec="seconds"),
    }

    # Сначала метаданные, потом перемещение: если move упадёт, откатываем запись
    _meta_path(item_id).write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    try:
        shutil.move(str(path), _stored_path(item_id))
    except Exception:
        _meta_path(item_id).unlink(missing_ok=True)
        raise
    return item_id


def list_quarantine() -> list[dict]:
    if not QUARANTINE_DIR.exists():
        return []
    items = []
    for meta_file in QUARANTINE_DIR.glob("*.json"):
        items.append(json.loads(meta_file.read_text(encoding="utf-8")))
    return sorted(items, key=lambda m: m["quarantined_at"])


def restore_file(item_id: str, overwrite: bool = False) -> Path:
    """Возвращает файл на исходное место после проверки целостности."""
    meta = json.loads(_meta_path(item_id).read_text(encoding="utf-8"))
    stored = _stored_path(item_id)

    if sha256_of(stored) != meta["sha256"]:
        raise ValueError("Хэш изменился: файл в карантине повреждён")

    dest = Path(meta["original_path"])
    if dest.exists() and not overwrite:
        raise FileExistsError(f"По пути {dest} уже есть файл")

    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(stored), dest)
    _meta_path(item_id).unlink()
    return dest


def delete_file(item_id: str) -> None:
    """Окончательно удаляет файл из карантина."""
    _stored_path(item_id).unlink(missing_ok=True)
    _meta_path(item_id).unlink(missing_ok=True)