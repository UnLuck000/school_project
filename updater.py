"""Обновление баз: хэши вредоносных файлов, правила YARA, адреса серверов управления (C2).

Источники (все бесплатные):
- хэши: MalwareBazaar и ThreatFox (abuse.ch, нужен Auth-Key), VirusShare (списки MD5,
  по 131 072 хэша в файле, без ключа);
- правила YARA: signature-base (Neo23x0), ReversingLabs, Elastic, bartblaze;
- C2: Feodo Tracker, SSLBL, ThreatFox (abuse.ch), C2IntelFeeds.

Зеркало (14.11.2026): у пользователей ключа abuse.ch нет (в программе его перехватили бы из
заголовка), а Feodo из РФ без VPN не открывается. Поэтому MalwareBazaar, ThreatFox, URLhaus,
Feodo, SSLBL и JA3 сначала берутся из ветки «feeds» на GitHub (его раз в сутки собирает
GitHub Actions с ключом из Secrets: tools/feeds_mirror.py, .github/workflows/feeds-mirror.yml) —
ответы источников как есть, разбор тот же. С ключом (signatures/.abusech_key,
ABUSECH_AUTH_KEY) — сначала напрямую, зеркало — запасной путь; без ключа источники с ключом —
только зеркало, остальные — напрямую, если зеркало недоступно.

Запуск вручную: python updater.py [all|hashes|rules|ips|domains]
"""
import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import shutil
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SIG_DIR = BASE_DIR / "signatures"


def can_update() -> bool:
    """Можно ли писать в папку баз. У установленной программы она закрыта от записи
    (installer.iss): без прав администратора базы не обновляются."""
    try:
        SIG_DIR.mkdir(parents=True, exist_ok=True)
        probe = SIG_DIR / f".probe-{os.getpid()}"
        probe.write_bytes(b"")
        probe.unlink()
        return True
    except OSError:
        return False
FEEDS_DIR = SIG_DIR / "feeds"
NETFEEDS_DIR = SIG_DIR / "netfeeds"
DOMAINS_DIR = NETFEEDS_DIR / "domains"   # вредоносные домены: по одному на строку
JA3_DIR = NETFEEDS_DIR / "ja3"           # отпечатки TLS-клиентов: md5<TAB>описание
COMMUNITY_RULES_DIR = SIG_DIR / "rules" / "community"
KEY_FILE = SIG_DIR / ".abusech_key"

UPDATE_INTERVAL = 24 * 3600  # автообновление раз в сутки, секунд
SHA256_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
MD5_LINE_RE = re.compile(rb"^[0-9a-fA-F]{32}$")
MB_URL = "https://mb-api.abuse.ch/v2/files/exports/{key}/{name}"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
THREATFOX_DAYS = 7          # больше API не отдаёт
C2_KEEP_DAYS = 30           # адрес C2 из ThreatFox хранится столько дней после последнего упоминания
VIRUSSHARE_URL = "https://virusshare.com/hashfiles/VirusShare_{n:05d}.md5"
VIRUSSHARE_FILES = 50       # сколько последних списков VirusShare держать (~6,5 млн MD5)
VIRUSSHARE_FIRST_GUESS = 505
RULE_SOURCES = {  # папка в community/ -> (архив, часть пути внутри архива)
    "signature-base": ("https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip",
                       "/yara/"),
    "reversinglabs": ("https://github.com/reversinglabs/reversinglabs-yara-rules/archive/"
                      "refs/heads/develop.zip", "/yara/"),
    "elastic": ("https://github.com/elastic/protections-artifacts/archive/refs/heads/main.zip",
                "/yara/rules/"),
    "bartblaze": ("https://github.com/bartblaze/Yara-rules/archive/refs/heads/master.zip",
                  "/rules/"),
}
# вид в зеркале у списков C2 (C2IntelFeeds — на GitHub и так)
C2_MIRROR = {"feodo.txt": "feodo", "sslbl.txt": "sslbl"}
C2_TEXT_FEEDS = {  # файл в netfeeds/ -> (адрес, строка, по которой узнаём нужный ответ)
    "feodo.txt": ("https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "Feodo Tracker"),
    "sslbl.txt": ("https://sslbl.abuse.ch/blacklist/sslipblacklist.txt", "SSLBL"),
    "c2intel.txt": ("https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/"
                    "IPC2s-30day.csv", "#ip,ioc"),
}

# URLhaus: ссылки, которые сейчас раздают вредоносы (выгрузка только по ключу abuse.ch)
URLHAUS_EXPORT = "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/online.csv"
SSLBL_JA3 = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9_-]{1,63}\.)+[a-z][a-z0-9-]{1,62}$")

# зеркало: ветка «feeds» репозитория программы (tools/feeds_mirror.py; в выпусках его нет —
# пользователю в «Releases» оно не нужно)
MIRROR_BRANCH = "feeds"
MIRROR_MAX_AGE = 3 * 86400      # старше — задание зеркала сломано: не берём, идём напрямую
MIRROR_MAX_SIZE = 512 * 2**20   # распакованный файл зеркала — не больше (защита от gzip-бомбы)
MIRROR_MANIFEST_VERSION = 1


# ---------- общее ----------
def _download(url: str, timeout: int = 120, data: bytes | None = None,
              headers: dict | None = None) -> bytes:
    req = urllib.request.Request(url, data=data, headers={"User-Agent": "StretchBIT-updater/1.0",
                                                          **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


# ---------- зеркало на GitHub ----------
class MirrorError(Exception):
    pass


_manifest_cache: dict = {}


def mirror_base() -> str:
    """Адрес файлов ветки «feeds»: https://raw.githubusercontent.com/<владелец>/<репозиторий>/
    refs/heads/feeds/ (репозиторий — appinfo.REPO_URL; refs/heads/ — чтобы не спутать с
    меткой того же имени)."""
    import appinfo
    repo = appinfo.REPO_URL.rstrip("/").removesuffix(".git").split("github.com/", 1)[-1]
    return f"https://raw.githubusercontent.com/{repo}/refs/heads/{MIRROR_BRANCH}/"


def reset_mirror() -> None:
    """Перечитать manifest.json при следующем обращении (новое обновление баз)."""
    _manifest_cache.clear()


def _mirror_manifest() -> dict:
    if "data" in _manifest_cache:
        return _manifest_cache["data"]
    if "error" in _manifest_cache:
        raise MirrorError(_manifest_cache["error"])
    try:
        data = json.loads(_download(mirror_base() + "manifest.json", timeout=60))
        if data.get("version") != MIRROR_MANIFEST_VERSION or not isinstance(
                data.get("files"), dict):
            raise MirrorError("незнакомый manifest.json")
        age = time.time() - float(data.get("generated", 0))
        if age > MIRROR_MAX_AGE:
            raise MirrorError(f"зеркало не обновлялось {int(age // 86400)} дн.")
    except MirrorError as e:
        _manifest_cache["error"] = str(e)
        raise
    except Exception as e:  # нет сети, 404 (выпуска ещё нет), битый JSON
        _manifest_cache["error"] = _error(e)
        raise MirrorError(_manifest_cache["error"]) from e
    _manifest_cache["data"] = data
    return data


def _gunzip(packed: bytes, limit: int = MIRROR_MAX_SIZE) -> bytes:
    import zlib
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    raw = d.decompress(packed, limit + 1)
    if len(raw) > limit or d.unconsumed_tail:
        raise MirrorError("файл зеркала больше допустимого")
    if not d.eof:
        raise MirrorError("файл зеркала обрезан")
    return raw


def mirror_file(kind: str) -> bytes:
    """Ответ источника из зеркала (распакованный), с проверкой SHA-256 по manifest.json."""
    entry = _mirror_manifest()["files"].get(kind)
    if not entry:
        raise MirrorError("в зеркале нет (задание зеркала не скачало)")
    name = str(entry.get("name", ""))
    if not re.fullmatch(r"[a-z0-9_-]+-\d{12}\.[a-z]+\.gz", name):
        raise MirrorError("странное имя файла в manifest.json")
    packed = _download(mirror_base() + name, timeout=300)
    if hashlib.sha256(packed).hexdigest() != str(entry.get("sha256", "")).lower():
        raise MirrorError("SHA-256 не совпал")
    return _gunzip(packed)


def _fetch(kind: str, direct, check=None, prefer_direct: bool = False) -> tuple[bytes, str]:
    """Ответ источника: из зеркала или напрямую (direct — функция без аргументов или None,
    если напрямую нельзя: нет ключа). check(raw) поднимает исключение на чужой ответ — тогда
    пробуется следующий путь. (данные, откуда). Ошибки прямого пути — только тип: в адресе
    MalwareBazaar и URLhaus ключ."""
    ways = [("напрямую", direct), ("зеркало", lambda: mirror_file(kind))]
    if not prefer_direct:
        ways.reverse()
    errors = []
    for where, get in ways:
        if get is None:
            continue
        try:
            raw = get()
            if check is not None:
                check(raw)
            return raw, where
        except MirrorError as e:
            errors.append(f"{where}: {e}")
        except Exception as e:  # noqa: BLE001 — любой сбой пути: пробуем следующий
            errors.append(f"{where}: {type(e).__name__}" if where == "напрямую"
                          else f"{where}: {_error(e)}")
    raise MirrorError("; ".join(errors) or "нет источника")


def _marker(text: str, where: int = 4096):
    def check(raw: bytes) -> None:
        if text.encode() not in raw[:where]:
            raise ValueError("неожиданный ответ сервера")
    return check


def _get_key() -> str:
    key = os.environ.get("ABUSECH_AUTH_KEY", "").strip()
    if not key and KEY_FILE.exists():
        key = KEY_FILE.read_text(encoding="utf-8").strip()
    return key


def _write_atomic(path: Path, data: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    if isinstance(data, str):
        tmp.write_text(data, encoding="utf-8")
    else:
        tmp.write_bytes(data)
    os.replace(tmp, path)


def _read_hash_lines(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {line.strip().lower() for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")}


def _merge_hashes(path: Path, title: str, new: set[str]) -> tuple[int, int]:
    """Добавляет хэши в текстовую базу (она накапливается). (новых, всего)."""
    old = _read_hash_lines(path)
    merged = old | new
    _write_atomic(path, f"# {title}\n" + "\n".join(sorted(merged)) + "\n")
    return len(merged - old), len(merged)


def _error(e: Exception) -> str:
    return f"{type(e).__name__}: {e}"


# ---------- хэши ----------
def update_hashes(export_name: str = "recent.csv") -> bool:
    """MalwareBazaar: файлы за последние двое суток (с ключом abuse.ch или из зеркала)."""
    key = _get_key()
    direct = (lambda: _download(MB_URL.format(key=key, name=export_name))) if key else None
    try:
        raw, where = _fetch("malwarebazaar", direct, prefer_direct=bool(key))
    except MirrorError as e:  # ключ в сообщение не выводим: в адресе он есть, в тексте ошибки нет
        print(f"MalwareBazaar: не удалось скачать ({e})")
        return False
    new = set()
    for line in raw.decode("utf-8", errors="ignore").splitlines():
        if line.startswith("#"):
            continue
        m = SHA256_RE.search(line)
        if m:
            new.add(m.group(0).lower())
    added, total = _merge_hashes(FEEDS_DIR / "malwarebazaar.txt", "MalwareBazaar (abuse.ch)", new)
    print(f"MalwareBazaar ({where}): получено {len(new)}, новых {added}, всего {total}")
    return True


def _threatfox_check(raw: bytes) -> None:
    status = json.loads(raw).get("query_status")
    if status != "ok":
        raise ValueError(f"ответ {status!r}")


def _threatfox_iocs(key: str) -> tuple[list[dict], str]:
    """IOC за неделю: (список, откуда). Без ключа — только зеркало."""
    body = json.dumps({"query": "get_iocs", "days": THREATFOX_DAYS}).encode()
    direct = (lambda: _download(THREATFOX_API, data=body, headers={"Auth-Key": key})) \
        if key else None
    raw, where = _fetch("threatfox", direct, _threatfox_check, prefer_direct=bool(key))
    return json.loads(raw).get("data") or [], where


def update_threatfox() -> bool:
    """ThreatFox: хэши файлов (SHA-256, MD5) и адреса C2 (ip:port) за неделю."""
    try:
        iocs, where = _threatfox_iocs(_get_key())
    except MirrorError as e:
        print(f"ThreatFox: не удалось скачать ({e})")
        return False
    print(f"ThreatFox ({where}): записей {len(iocs)}")

    hashes, c2, domains = set(), {}, {}
    today = time.strftime("%Y-%m-%d")
    for ioc in iocs:
        kind, value = ioc.get("ioc_type"), str(ioc.get("ioc", "")).strip().lower()
        if kind in ("sha256_hash", "md5_hash"):
            hashes.add(value)
        elif kind == "ip:port":
            ip = _parse_ip(value.rsplit(":", 1)[0])
            if ip:
                c2[ip] = today
        elif kind in ("domain", "url"):
            host = _host(value)
            if host:
                domains[host] = today
    added, total = _merge_hashes(FEEDS_DIR / "threatfox.txt", "ThreatFox (abuse.ch)", hashes)
    print(f"ThreatFox: хэшей новых {added}, всего {total}")

    # адреса C2 живут недолго: храним, пока их упоминали за последние C2_KEEP_DAYS дней
    state = _keep_recent(NETFEEDS_DIR / "threatfox_state.json", c2)
    _write_atomic(NETFEEDS_DIR / "threatfox.txt",
                  "# ThreatFox (abuse.ch), ip:port\n" + "\n".join(sorted(state)) + "\n")
    print(f"ThreatFox: адресов C2 {len(state)}")
    kept = _keep_recent(NETFEEDS_DIR / "threatfox_domains_state.json", domains)
    _write_atomic(DOMAINS_DIR / "threatfox.txt",
                  "# ThreatFox (abuse.ch), домены\n" + "\n".join(sorted(kept)) + "\n")
    print(f"ThreatFox: доменов {len(kept)}")
    return True


def _keep_recent(state_file: Path, seen: dict[str, str]) -> dict[str, str]:
    """Значение -> день последнего упоминания; старше C2_KEEP_DAYS дней выбрасываются."""
    try:
        state = json.loads(state_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        state = {}
    state.update(seen)
    border = time.strftime("%Y-%m-%d", time.localtime(time.time() - C2_KEEP_DAYS * 86400))
    state = {k: day for k, day in state.items() if day >= border}
    _write_atomic(state_file, json.dumps(state, indent=0, sort_keys=True))
    return state


def _host(value: str) -> str | None:
    """Домен из ioc ThreatFox: «evil.com», «evil.com:443», «https://evil.com/path»."""
    value = value.strip().lower()
    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0].split("@")[-1].rsplit(":", 1)[0].strip(".")
    if _parse_ip(value) or not DOMAIN_RE.match(value):
        return None
    from networkmonitor.domains import shared_service
    if shared_service(value):  # GitHub, Discord и т. п.: опасна ссылка, а не весь домен
        return None
    return value


def _virusshare_exists(n: int) -> bool:
    req = urllib.request.Request(VIRUSSHARE_URL.format(n=n), method="HEAD",
                                 headers={"User-Agent": "StretchBIT-updater/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30):
            return True
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        raise


def _virusshare_last(hint: int) -> int:
    """Номер последнего списка: идём вверх от известного, пока файлы есть."""
    n = max(0, hint)
    while not _virusshare_exists(n) and n > 0:  # подсказка из будущего (сбой состояния)
        n -= 1
    step = 1
    while _virusshare_exists(n + step):
        n += step
        step *= 2
    while step > 1:  # уточняем двоичным поиском
        step //= 2
        if _virusshare_exists(n + step):
            n += step
    return n


def md5_bin(raw: bytes) -> bytes:
    """Текстовый список MD5 -> отсортированные 16-байтные записи (для поиска в mmap)."""
    lines = (line.strip() for line in raw.splitlines())
    items = {bytes.fromhex(line.decode()) for line in lines if MD5_LINE_RE.match(line)}
    return b"".join(sorted(items))


def update_virusshare(files: int = VIRUSSHARE_FILES, progress=None) -> bool:
    """VirusShare: списки MD5. Каждый список не меняется, поэтому качаем только новые.
    Хранятся двоичными файлами feeds/virusshare_NNNNN.md5.bin."""
    state_file = FEEDS_DIR / "virusshare.json"
    try:
        state = json.loads(state_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        state = {}
    try:
        last = _virusshare_last(int(state.get("last", VIRUSSHARE_FIRST_GUESS)))
    except Exception as e:
        print(f"VirusShare: сайт недоступен: {_error(e)}")
        return False
    wanted = list(range(last, max(-1, last - files), -1))
    FEEDS_DIR.mkdir(parents=True, exist_ok=True)
    have = {int(m.group(1)) for p in FEEDS_DIR.glob("virusshare_*.md5.bin")
            if (m := re.match(r"virusshare_(\d+)\.md5\.bin$", p.name))}
    missing = [n for n in wanted if n not in have]
    loaded, failed = 0, 0
    for i, n in enumerate(missing, 1):
        if progress:
            progress(f"VirusShare: список {i} из {len(missing)}")
        try:
            data = md5_bin(_download(VIRUSSHARE_URL.format(n=n), timeout=300))
        except Exception as e:
            failed += 1
            print(f"VirusShare {n:05d}: {_error(e)}")
            continue
        _write_atomic(FEEDS_DIR / f"virusshare_{n:05d}.md5.bin", data)
        loaded += 1
    for n in have - set(wanted):  # вышедшие за окно старые списки
        try:
            (FEEDS_DIR / f"virusshare_{n:05d}.md5.bin").unlink()
        except OSError:
            pass  # файл открыт сканером: удалится при следующем обновлении
    _write_atomic(state_file, json.dumps({"last": last}))
    total = sum(p.stat().st_size // 16 for p in FEEDS_DIR.glob("virusshare_*.md5.bin"))
    print(f"VirusShare: списков скачано {loaded}" + (f", с ошибкой {failed}" if failed else "")
          + f", MD5 всего {total}")
    return failed < len(missing) or not missing


# ---------- правила YARA ----------
def update_rules() -> bool:
    ok_any = False
    COMMUNITY_RULES_DIR.mkdir(parents=True, exist_ok=True)
    for name, (url, inner) in RULE_SOURCES.items():
        try:
            data = _download(url, timeout=300)
        except Exception as e:
            print(f"Правила {name}: не удалось скачать: {_error(e)}")
            continue
        target = COMMUNITY_RULES_DIR / name
        fresh = COMMUNITY_RULES_DIR / f".{name}.new"
        shutil.rmtree(fresh, ignore_errors=True)
        fresh.mkdir(parents=True)
        count = 0
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for item in zf.namelist():
                if item.lower().endswith((".yar", ".yara")) and inner in item:
                    # пишем под собственным именем, пути из архива не используем
                    out = fresh / Path(item).name
                    if out.exists():
                        out = fresh / f"{Path(item).parent.name}_{Path(item).name}"
                    out.write_bytes(zf.read(item))
                    count += 1
        if count == 0:
            shutil.rmtree(fresh, ignore_errors=True)
            print(f"Правила {name}: в архиве нет файлов правил, оставлены прежние")
            continue
        shutil.rmtree(target, ignore_errors=True)
        fresh.rename(target)
        ok_any = True
        print(f"Правила {name}: файлов {count}")
    # прежняя версия складывала signature-base прямо в community/
    for old in list(COMMUNITY_RULES_DIR.glob("*.yar")) + list(COMMUNITY_RULES_DIR.glob("*.yara")):
        if (COMMUNITY_RULES_DIR / "signature-base").is_dir():
            old.unlink()
    return ok_any


# ---------- адреса C2 ----------
def _parse_ip(text: str) -> str | None:
    try:
        ip = ipaddress.ip_address(text.strip().strip("[]"))
    except ValueError:
        return None
    return None if (ip.is_private or ip.is_loopback or ip.is_unspecified) else ip.compressed


def update_ips() -> bool:
    ok_any = False
    for filename, (url, marker) in C2_TEXT_FEEDS.items():
        kind = C2_MIRROR.get(filename)
        try:
            if kind:  # Feodo из РФ без VPN не открывается: сначала зеркало
                raw, _where = _fetch(kind, lambda u=url: _download(u), _marker(marker, 1 << 20))
                text = raw.decode("utf-8", errors="ignore")
            else:
                text = _download(url).decode("utf-8", errors="ignore")
        except Exception as e:
            print(f"C2 {filename}: не удалось скачать: {e if kind else _error(e)}")
            continue
        if marker not in text:  # защита: пришла не та страница
            print(f"C2 {filename}: неожиданный ответ сервера, файл не изменён")
            continue
        ips = set()
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                ip = _parse_ip(line.split(",")[0])
                if ip:
                    ips.add(ip)
        _write_atomic(NETFEEDS_DIR / filename, f"# {url}\n" + "\n".join(sorted(ips)) + "\n")
        ok_any = True
        print(f"C2 {filename}: адресов {len(ips)}")
    return ok_any


# ---------- домены и отпечатки TLS ----------
def update_domains() -> bool:
    """URLhaus: домены, с которых раздают вредоносы (с ключом abuse.ch или из зеркала);
    SSLBL: отпечатки JA3 вредоносных TLS-клиентов (зеркало, затем напрямую)."""
    ok = False
    key = _get_key()
    direct = (lambda: _download(URLHAUS_EXPORT.format(key=key), timeout=300)) if key else None
    try:
        raw, where = _fetch("urlhaus", direct, _marker("URLhaus", 500),
                            prefer_direct=bool(key))
    except MirrorError as e:  # ключ в адресе: в тексте ошибки только тип
        print(f"Домены URLhaus: не удалось скачать ({e})")
    else:
        try:
            text = raw.decode("utf-8", errors="ignore")
            hosts = set()
            rows = csv.reader(line for line in text.splitlines() if not line.startswith("#"))
            for row in rows:  # id, dateadded, url, url_status, ...
                if len(row) > 2:
                    host = _host(row[2])
                    if host:
                        hosts.add(host)
            _write_atomic(DOMAINS_DIR / "urlhaus.txt",
                          "# URLhaus (abuse.ch), домены из ссылок online\n"
                          + "\n".join(sorted(hosts)) + "\n")
            print(f"Домены URLhaus ({where}): {len(hosts)}")
            ok = True
        except Exception as e:
            print(f"Домены URLhaus: не удалось разобрать: {type(e).__name__}")
    try:
        raw, _where = _fetch("ja3", lambda: _download(SSLBL_JA3), _marker("ja3_md5", 1 << 20))
        text = raw.decode("utf-8", errors="ignore")
        rows = []
        for line in text.splitlines():
            parts = line.strip().split(",")
            if len(parts) >= 4 and re.fullmatch(r"[0-9a-f]{32}", parts[0]):
                rows.append(f"{parts[0]}\t{parts[3].strip()}")
        _write_atomic(JA3_DIR / "sslbl.txt", f"# {SSLBL_JA3}\n" + "\n".join(sorted(rows)) + "\n")
        print(f"Отпечатки JA3 SSLBL: {len(rows)}")
        ok = True
    except Exception as e:
        print(f"Отпечатки JA3 SSLBL: не удалось скачать: {_error(e)}")
    return ok


# ---------- уязвимые драйверы ----------
LOLDRIVERS_URL = "https://www.loldrivers.io/api/drivers.json"


def update_drivers() -> bool:
    """LOLDrivers: уязвимые и вредоносные драйверы (без ключа) → feeds/loldrivers.tsv."""
    import json
    from scanner.drivers import convert_loldrivers
    try:
        items = json.loads(_download(LOLDRIVERS_URL, timeout=300))
    except Exception as e:
        print(f"LOLDrivers: не удалось скачать: {_error(e)}")
        return False
    text = convert_loldrivers(items)
    _write_atomic(FEEDS_DIR / "loldrivers.tsv", text)
    print(f"LOLDrivers: драйверов {len(items)}, образцов {text.count(chr(10)) - 1}")
    return True


# ---------- всё сразу ----------
def update_all(progress=None) -> bool:
    """Обновляет все базы. True, если удалось хоть что-то (иначе нет сети)."""
    reset_mirror()  # manifest.json зеркала — один раз за обновление
    steps = [("адреса C2", update_ips), ("домены и JA3", update_domains),
             ("правила YARA", update_rules), ("уязвимые драйверы", update_drivers),
             ("MalwareBazaar", update_hashes), ("ThreatFox", update_threatfox),
             ("VirusShare", lambda: update_virusshare(progress=progress))]
    ok = False
    for title, step in steps:
        if progress:
            progress(f"Обновляю: {title}...")
        try:
            ok = step() or ok
        except Exception as e:  # сбой одного источника не мешает остальным
            print(f"{title}: ошибка {_error(e)}")
    return ok


def bases_missing() -> bool:
    """На диске нет скачанных баз (ни правил YARA, ни списков хэшей VirusShare). Время
    последнего обновления хранится отдельно (у службы — в ProgramData, у окна — в
    настройках) и переживает переустановку и перенос папки программы, а базы — нет: так
    13.11.2026 после переезда из Program Files (x86) служба сутки считала базы свежими."""
    try:
        has_rules = any(COMMUNITY_RULES_DIR.rglob("*.yar*")) if COMMUNITY_RULES_DIR.is_dir() \
            else False
        has_md5 = any(FEEDS_DIR.glob("*.md5.bin")) if FEEDS_DIR.is_dir() else False
    except OSError:
        return False
    return not (has_rules or has_md5)


def needs_update(last_update: float, now: float | None = None) -> bool:
    """Пора обновлять: прошли сутки или баз на диске нет."""
    return update_due(last_update, now) or bases_missing()


def update_due(last_update: float, now: float | None = None) -> bool:
    """Пора ли обновлять: прошло не меньше суток с последнего обновления. Отсчёт без
    обновлений ведётся от 1 января 1970 года (last_update = 0), поэтому первый запуск
    программы всегда обновляет базы."""
    now = time.time() if now is None else now
    return now - last_update >= UPDATE_INTERVAL or last_update > now  # часы перевели назад


if __name__ == "__main__":
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    if what == "all":
        update_all(progress=print)
    if what == "hashes":
        update_hashes()
        update_threatfox()
        update_virusshare(progress=print)
    if what == "rules":
        update_rules()
    if what == "ips":
        update_ips()
        update_domains()
        update_threatfox()
    if what == "domains":
        update_domains()
    if what == "drivers":
        update_drivers()
