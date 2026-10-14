import hashlib
from pathlib import Path


def sha256_of(path: Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(chunk):
            h.update(block)
    return h.hexdigest()


def load_signatures(db: Path) -> set[str]:
    sigs = set()
    for line in db.read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):  # пропускаем пустые строки и комментарии
            sigs.add(line)
    return sigs


def scan_dir(root: Path, signatures: set[str], exclude: Path | None = None,
             on_file=None, stop=None):
    exclude = exclude.resolve() if exclude else None
    for p in root.rglob("*"):
        if stop is not None and stop.is_set():
            return
        if not p.is_file():
            continue
        if exclude and exclude in p.resolve().parents:
            continue
        if on_file:
            on_file(p)
        try:
            if sha256_of(p) in signatures:
                yield p
        except (PermissionError, OSError):
            continue

def load_all_signatures(sig_dir: Path) -> set[str]:
    """hashes.txt плюс все файлы из signatures/feeds/*.txt."""
    sigs: set[str] = set()
    main = sig_dir / "hashes.txt"
    if main.exists():
        sigs |= load_signatures(main)
    feeds = sig_dir / "feeds"
    if feeds.is_dir():
        for f in feeds.glob("*.txt"):
            sigs |= load_signatures(f)
    return sigs