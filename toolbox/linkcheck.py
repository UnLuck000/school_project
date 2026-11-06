"""Проверка ссылки и скачанного по ней файла до запуска.

1. Адрес: домен и его родители — по спискам netfeeds/domains (URLhaus, ThreatFox), IP —
   по спискам C2, признаки сгенерированного имени (DGA), подмена доменов (punycode,
   «@» в адресе), http без шифрования.
2. Файл скачивается в DOWNLOAD_DIR (кэш программы), помечается как загруженный из
   интернета (Zone.Identifier, как у браузера) и проверяется всеми слоями сканера.
   Скачанное не запускается.
"""
import ipaddress
import os
import re
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from networkmonitor import domains as dom

BASE_DIR = Path(__file__).resolve().parent.parent
NETFEEDS_DIR = BASE_DIR / "signatures" / "netfeeds"
DOWNLOAD_DIR = BASE_DIR / "cache" / "downloads"
MAX_SIZE = 300 * 1024 * 1024
CHUNK = 256 * 1024
RISKY_EXTS = {".exe", ".scr", ".msi", ".bat", ".cmd", ".vbs", ".js", ".hta", ".ps1", ".lnk",
              ".iso", ".img", ".zip", ".rar", ".7z", ".jar", ".apk"}


@dataclass
class UrlVerdict:
    url: str
    host: str = ""
    level: str = "clean"          # danger | warning | clean
    notes: list[str] = field(default_factory=list)


def normalize(url: str) -> str:
    url = url.strip()
    if url and "://" not in url:
        url = "https://" + url
    return url


def check_url(url: str, domain_list: dict | None = None, ip_list: set | None = None) -> UrlVerdict:
    from networkmonitor.ioc import load_ip_blocklist
    url = normalize(url)
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    verdict = UrlVerdict(url, host)
    if parts.scheme not in ("http", "https") or not host:
        verdict.level = "warning"
        verdict.notes.append("Это не ссылка на сайт (нужен адрес вида https://...)")
        return verdict

    def warn(text: str, level: str = "warning"):
        verdict.notes.append(text)
        if level == "danger" or verdict.level == "clean":
            verdict.level = level

    if domain_list is None:
        domain_list = dom.load_domains(NETFEEDS_DIR / "domains")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if ip_list is None:
            ip_list = load_ip_blocklist(NETFEEDS_DIR)
        if str(ip) in ip_list:
            warn(f"Адрес {ip} — в списках серверов управления вредоносами (C2)", "danger")
        else:
            warn("Ссылка ведёт на IP-адрес, а не на имя сайта — так часто раздают вредоносы")
    else:
        hit = dom.lookup(domain_list, host)
        if hit:
            warn(f"Домен {hit[0]} — в списке вредоносных ({hit[1]})", "danger")
        if dom.shared_service(host):
            verdict.notes.append("Общий сервис (GitHub, облако и т. п.): сам сайт безопасен, "
                                 "но файлы на нём выкладывает кто угодно — проверьте файл")
        generated = dom.looks_generated(host)
        if generated:
            warn("Имя сайта " + generated)
        if any(label.startswith("xn--") for label in host.split(".")):
            warn("Имя сайта записано punycode: буквы могут подменять похожие (раsрberry)")
    if "@" in parts.netloc:
        warn("В адресе есть «@»: всё до него — обман, настоящий сайт — " + host)
    if parts.scheme == "http":
        verdict.notes.append("Соединение без шифрования (http)")
    ext = os.path.splitext(parts.path)[1].lower()
    if ext in RISKY_EXTS:
        verdict.notes.append(f"Ссылка на файл {ext}: перед запуском его стоит проверить")
    if not verdict.notes:
        verdict.notes.append("В списках вредоносных адресов не найден")
    return verdict


def _file_name(response, url: str) -> str:
    disposition = response.headers.get("Content-Disposition", "")
    match = re.search(r"filename\*=UTF-8''([^;]+)", disposition, re.I) or \
        re.search(r'filename="?([^";]+)"?', disposition, re.I)
    name = urllib.parse.unquote(match.group(1)) if match else \
        urllib.parse.unquote(os.path.basename(urllib.parse.urlsplit(response.url).path))
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).strip(" .") or "download.bin"
    return name[:150]


def download(url: str, progress=None, cancel=None) -> Path:
    """Скачивает файл в DOWNLOAD_DIR. progress(получено, всего). OSError — ошибка сети."""
    url = normalize(url)
    request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 study-av/1.0"})
    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(request, timeout=30) as response:
        total = int(response.headers.get("Content-Length") or 0)
        if total > MAX_SIZE:
            raise OSError(f"Файл слишком большой: {total // 2**20} МБ (не больше "
                          f"{MAX_SIZE // 2**20} МБ)")
        target = DOWNLOAD_DIR / f"{time.strftime('%Y%m%d_%H%M%S')}_{_file_name(response, url)}"
        got = 0
        try:
            with target.open("wb") as f:
                while True:
                    if cancel is not None and cancel.is_set():
                        raise OSError("Скачивание остановлено")
                    chunk = response.read(CHUNK)
                    if not chunk:
                        break
                    got += len(chunk)
                    if got > MAX_SIZE:
                        raise OSError("Файл слишком большой")
                    f.write(chunk)
                    if progress:
                        progress(got, total)
        except BaseException:
            target.unlink(missing_ok=True)
            raise
    mark_downloaded(target, url)
    return target


def mark_downloaded(path: Path, url: str) -> None:
    """Метка «из интернета» (Mark of the Web): Windows предупредит при запуске."""
    try:
        with open(f"{path}:Zone.Identifier", "w", encoding="utf-8") as f:
            f.write(f"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl={url}\r\n")
    except OSError:
        pass
