import ipaddress
from pathlib import Path


def load_ip_blocklist(feeds_dir: Path) -> set[str]:
    """Читает все *.txt из папки: по одному IP на строку, # — комментарии."""
    ips: set[str] = set()
    if not feeds_dir.is_dir():
        return ips
    for f in feeds_dir.glob("*.txt"):
        for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                ips.add(str(ipaddress.ip_address(line)))
            except ValueError:
                continue
    return ips