"""Репутация файла по хэшу: VirusTotal API v3 (ключ пользователя).

Для неизвестных базам неподписанных файлов — что о нём думают другие антивирусы. Уходит
только SHA-256, сам файл — никогда. Ключ (бесплатный, из учётной записи virustotal.com)
хранится под DPAPI (как профили VPN): прочитать его может только эта учётная запись.
Бесплатный ключ — 4 запроса в минуту и 500 в сутки: ответы помнятся сутки (CACHE_FILE),
«слишком часто» (429) — понятной ошибкой, без повторов.
"""
import json
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass

import datadirs
import userdata

API = "https://www.virustotal.com/api/v3/files/"
KEY_FILE = userdata.CONFIG_DIR / "virustotal.key"
CACHE_FILE = datadirs.CACHE / "reputation.json"
CACHE_AGE = 24 * 3600
_lock = threading.Lock()


@dataclass
class Reputation:
    sha256: str
    found: bool = False          # VirusTotal знает файл
    malicious: int = 0
    suspicious: int = 0
    total: int = 0               # сколько движков ответило
    label: str = ""              # popular_threat_classification
    first_seen: float = 0.0
    checked: float = 0.0

    @property
    def level(self) -> str:
        if self.malicious >= 5:
            return "threat"
        if self.malicious or self.suspicious >= 3:
            return "suspicious"
        return "clean" if self.found else "unknown"

    def text(self) -> str:
        if not self.found:
            return "VirusTotal не знает этот файл (ни разу не проверялся)"
        result = f"вредоносным считают {self.malicious} из {self.total}"
        if self.suspicious:
            result += f", подозрительным — {self.suspicious}"
        if self.label:
            result += f" ({self.label})"
        return result


def _dpapi(data: bytes, protect: bool) -> bytes:
    from vpn.profiles import _dpapi as dpapi
    return dpapi(data, protect)


def get_key() -> str:
    try:
        return _dpapi(KEY_FILE.read_bytes(), protect=False).decode("utf-8").strip()
    except (OSError, ValueError, UnicodeDecodeError):
        return ""


def set_key(key: str) -> None:
    key = key.strip()
    if not key:
        KEY_FILE.unlink(missing_ok=True)
        return
    KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    KEY_FILE.write_bytes(_dpapi(key.encode("utf-8"), protect=True))


def _cache() -> dict:
    try:
        data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _remember(rep: Reputation) -> None:
    with _lock:
        data = {k: v for k, v in _cache().items()
                if time.time() - float(v.get("checked", 0)) < CACHE_AGE}
        data[rep.sha256] = asdict(rep)
        try:
            CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            tmp = CACHE_FILE.with_suffix(".tmp")
            tmp.write_text(json.dumps(data), encoding="utf-8")
            tmp.replace(CACHE_FILE)
        except OSError:
            from diag.log import swallowed
            swallowed("reputation: кэш")


def parse(sha256: str, doc: dict) -> Reputation:
    attrs = (doc.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    label = ((attrs.get("popular_threat_classification") or {})
             .get("suggested_threat_label") or "")
    return Reputation(sha256=sha256, found=True, malicious=int(stats.get("malicious", 0)),
                      suspicious=int(stats.get("suspicious", 0)),
                      total=sum(int(v) for v in stats.values() if isinstance(v, int)),
                      label=label, first_seen=float(attrs.get("first_submission_date") or 0),
                      checked=time.time())


def lookup(sha256: str, key: str | None = None, timeout: float = 15.0) -> Reputation:
    """Репутация по SHA-256. ValueError — нет ключа, неверный ключ, лимит запросов."""
    sha256 = sha256.lower()
    hit = _cache().get(sha256)
    if hit and time.time() - float(hit.get("checked", 0)) < CACHE_AGE:
        return Reputation(**hit)
    key = key or get_key()
    if not key:
        raise ValueError("не задан ключ VirusTotal")
    request = urllib.request.Request(API + sha256, headers={
        "x-apikey": key, "User-Agent": "StretchBIT/1.0", "Accept": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
            rep = parse(sha256, json.loads(response.read(4 * 1024 * 1024).decode("utf-8")))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            rep = Reputation(sha256=sha256, found=False, checked=time.time())
        elif e.code == 401:
            raise ValueError("ключ VirusTotal не подошёл") from None
        elif e.code == 429:
            raise ValueError("слишком часто: бесплатный ключ — 4 запроса в минуту") from None
        else:
            raise ValueError(f"VirusTotal ответил {e.code}") from None
    _remember(rep)
    return rep
