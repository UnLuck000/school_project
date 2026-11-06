import hashlib
import mmap
import re
from pathlib import Path

HEX_RE = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{64}$")


def sha256_of(path: Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(chunk):
            h.update(block)
    return h.hexdigest()


def file_hashes(path: Path, chunk: int = 1024 * 1024) -> tuple[str, str]:
    """(SHA-256, MD5) за одно чтение файла: базы VirusShare хранят только MD5."""
    sha, md5 = hashlib.sha256(), hashlib.md5(usedforsecurity=False)
    with path.open("rb") as f:
        while block := f.read(chunk):
            sha.update(block)
            md5.update(block)
    return sha.hexdigest(), md5.hexdigest()


def load_signatures(db: Path) -> set[str]:
    sigs = set()
    for line in db.read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):  # пропускаем пустые строки и комментарии
            sigs.add(line)
    return sigs


class _BinFile:
    """Отсортированные записи фиксированной длины (16 байт MD5 или 32 байта SHA-256).
    Поиск двоичным поиском прямо в отображённом файле: память не тратится."""

    def __init__(self, path: Path, record: int):
        self.name = path.name
        self.record = record
        size = path.stat().st_size
        self.count = size // record
        with path.open("rb") as f:
            self._mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) if size else b""

    def __contains__(self, key: bytes) -> bool:
        r, mm = self.record, self._mm
        lo, hi = 0, self.count
        while lo < hi:
            mid = (lo + hi) // 2
            value = mm[mid * r:(mid + 1) * r]
            if value < key:
                lo = mid + 1
            elif value > key:
                hi = mid
            else:
                return True
        return False


class HashDB:
    """База хэшей: текстовые списки (SHA-256 или MD5 по строке) держатся в памяти,
    большие двоичные (feeds/*.md5.bin, feeds/*.sha256.bin) ищутся прямо в файле.
    Поддерживает «hash in db» для SHA-256 и MD5 в шестнадцатеричном виде и len(db)."""

    def __init__(self):
        self.text: dict[str, str] = {}  # хэш -> файл базы, из которого он взят
        self._bins: dict[int, list[_BinFile]] = {16: [], 32: []}
        self._stamp = hashlib.sha256()

    def _note(self, path: Path) -> None:
        st = path.stat()
        self._stamp.update(f"{path.name}|{st.st_size}|{st.st_mtime_ns}\n".encode())

    @property
    def version(self) -> str:
        """Отпечаток файлов базы: меняется после обновления (для кэша вердиктов)."""
        return self._stamp.hexdigest()[:16]

    def add_text(self, path: Path) -> None:
        self._note(path)
        for digest in load_signatures(path):
            self.text.setdefault(digest, path.name)

    def add_bin(self, path: Path) -> None:
        record = 16 if path.name.endswith(".md5.bin") else 32
        try:
            self._bins[record].append(_BinFile(path, record))
            self._note(path)
        except (OSError, ValueError):
            pass  # файл пишется обновлением или повреждён: пропускаем

    def source(self, digest: str) -> str:
        """Из какого файла базы хэш (пустая строка, если его нет)."""
        digest = digest.lower()
        if digest in self.text:
            return self.text[digest]
        if not HEX_RE.match(digest):
            return ""
        key = bytes.fromhex(digest)
        return next((b.name for b in self._bins[len(key)] if key in b), "")

    @property
    def has_md5(self) -> bool:
        return bool(self._bins[16]) or any(len(h) == 32 for h in self.text)

    def __contains__(self, digest: str) -> bool:
        digest = digest.lower()
        if digest in self.text:
            return True
        if not HEX_RE.match(digest):
            return False
        key = bytes.fromhex(digest)
        return any(key in b for b in self._bins[len(key)])

    def __len__(self) -> int:
        return len(self.text) + sum(b.count for bins in self._bins.values() for b in bins)

    def __bool__(self) -> bool:
        return len(self) > 0


def load_all_signatures(sig_dir: Path) -> HashDB:
    """hashes.txt плюс все базы из signatures/feeds/ (*.txt и двоичные *.bin)."""
    db = HashDB()
    main = sig_dir / "hashes.txt"
    if main.exists():
        db.add_text(main)
    feeds = sig_dir / "feeds"
    if feeds.is_dir():
        for f in sorted(feeds.glob("*.txt")):
            db.add_text(f)
        for f in sorted(feeds.glob("*.bin")):
            db.add_bin(f)
    return db
