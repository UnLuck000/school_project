from pathlib import Path

from scanner.hashing import sha256_of
from scanner.yara_engine import match_file


def scan_tree(root: Path, signatures: set[str], rules=None,
              exclude: list[Path] | None = None, on_file=None, stop=None):
    """Обходит папку и выдаёт пары (путь, причина) для подозрительных файлов."""
    excluded = [e.resolve() for e in (exclude or [])]

    for p in root.rglob("*"):
        if stop is not None and stop.is_set():
            return
        try:
            if not p.is_file():
                continue
            rp = p.resolve()
            if any(e in rp.parents for e in excluded):
                continue
            if on_file:
                on_file(p)

            if sha256_of(p) in signatures:
                yield p, "hash match"
                continue  # уже нашли, YARA не нужна

            if rules is not None:
                names = match_file(rules, p)
                if names:
                    yield p, "YARA: " + ", ".join(names)
        except (PermissionError, OSError):
            continue