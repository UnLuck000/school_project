"""Зеркало баз abuse.ch для программы (запускает GitHub Actions: .github/workflows/feeds-mirror.yml).

Зачем: MalwareBazaar, ThreatFox и URLhaus отдают выгрузки только по ключу abuse.ch (Auth-Key), а
ключ в программе перехватывается из заголовка — у пользователей его нет. Feodo Tracker из РФ без
VPN не открывается. Задание раз в сутки скачивает эти источники с ключом из GitHub Secrets и
выкладывает ответы КАК ЕСТЬ (сжатыми gzip) в выпуск репозитория; программа (updater.py) качает
их с github.com без ключа и разбирает тем же кодом, что и прямые ответы.

    python tools/feeds_mirror.py <папка>     ключ — переменная окружения ABUSECH_AUTH_KEY

В папке: <вид>-<метка>.<расш>.gz (новое имя на каждый запуск: клиент, прочитавший прежний
manifest.json, не получит половину нового файла), manifest.json (последним: имена, SHA-256,
время) и SHA256SUMS. Ключ не печатается и не попадает в файлы: в ошибках — только тип.
Скрипт самостоятельный (без модулей проекта): его можно положить и в отдельный репозиторий.
"""
import gzip
import hashlib
import json
import os
import re
import sys
import time
import urllib.request
from pathlib import Path

MANIFEST_VERSION = 1
MB_RECENT = "https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
THREATFOX_DAYS = 7
URLHAUS_ONLINE = "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/online.csv"
FEODO = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
SSLBL_IPS = "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"
SSLBL_JA3 = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"


def _download(url: str, data: bytes | None = None, headers: dict | None = None,
              timeout: int = 300) -> bytes:
    req = urllib.request.Request(url, data=data,
                                 headers={"User-Agent": "StretchBIT-feeds-mirror/1.0",
                                          **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _expect(marker: str):
    """Проверка ответа: пришла нужная выгрузка, а не страница ошибки."""
    def check(raw: bytes) -> None:
        if marker.encode() not in raw[:4096]:
            raise ValueError("неожиданный ответ сервера")
    return check


def _mb_check(raw: bytes) -> None:
    """Выгрузка MalwareBazaar: заголовок с названием или хотя бы строки с SHA-256 (точный
    вид заголовка у выгрузки может меняться)."""
    head = raw[:4096]
    if b"MalwareBazaar" not in head and not re.search(rb"\b[0-9a-f]{64}\b", head):
        raise ValueError("неожиданный ответ сервера")


def _threatfox_check(raw: bytes) -> None:
    if json.loads(raw).get("query_status") != "ok":
        raise ValueError("ThreatFox ответил не ok")


# вид -> (расширение, нужен ли ключ, загрузка(ключ), проверка ответа)
SOURCES = {
    "malwarebazaar": ("csv", True, lambda key: _download(MB_RECENT.format(key=key)),
                      _mb_check),
    "threatfox": ("json", True, lambda key: _download(
        THREATFOX_API, data=json.dumps({"query": "get_iocs", "days": THREATFOX_DAYS}).encode(),
        headers={"Auth-Key": key}), _threatfox_check),
    "urlhaus": ("csv", True, lambda key: _download(URLHAUS_ONLINE.format(key=key)),
                _expect("URLhaus")),
    "feodo": ("txt", False, lambda key: _download(FEODO), _expect("Feodo Tracker")),
    "sslbl": ("txt", False, lambda key: _download(SSLBL_IPS), _expect("SSLBL")),
    "ja3": ("csv", False, lambda key: _download(SSLBL_JA3), _expect("ja3_md5")),
}


def build(out: Path, key: str, sources: dict | None = None, now: float | None = None) -> dict:
    """Скачать источники в папку out, вернуть manifest. Сбой одного источника — в errors
    (только тип ошибки: в адресе MalwareBazaar и URLhaus ключ)."""
    sources = SOURCES if sources is None else sources
    now = time.time() if now is None else now
    stamp = time.strftime("%Y%m%d%H%M", time.gmtime(now))
    out.mkdir(parents=True, exist_ok=True)
    manifest = {"version": MANIFEST_VERSION, "generated": int(now), "files": {}, "errors": {}}
    for kind, (ext, needs_key, fetch, check) in sources.items():
        if needs_key and not key:
            manifest["errors"][kind] = "нет ключа ABUSECH_AUTH_KEY"
            continue
        try:
            raw = fetch(key)
            check(raw)
        except Exception as e:  # noqa: BLE001 — любой сбой источника: остальные идут дальше
            manifest["errors"][kind] = type(e).__name__
            continue
        if key and key.encode() in raw:  # на всякий случай: ключ не выкладываем ни в каком виде
            manifest["errors"][kind] = "в ответе ключ"
            continue
        packed = gzip.compress(raw, compresslevel=9, mtime=0)
        name = f"{kind}-{stamp}.{ext}.gz"
        (out / name).write_bytes(packed)
        manifest["files"][kind] = {"name": name, "sha256": hashlib.sha256(packed).hexdigest(),
                                   "size": len(raw)}
    sums = "".join(f"{v['sha256']}  {v['name']}\n" for v in manifest["files"].values())
    (out / "SHA256SUMS").write_text(sums, encoding="utf-8")
    (out / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=1),
                                       encoding="utf-8")
    return manifest


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    key = os.environ.get("ABUSECH_AUTH_KEY", "").strip()
    manifest = build(Path(argv[1]), key)
    for kind, info in manifest["files"].items():
        print(f"{kind}: {info['name']}, {info['size']} байт")
    for kind, error in manifest["errors"].items():
        print(f"{kind}: НЕ скачано — {error}")
    return 0 if manifest["files"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
