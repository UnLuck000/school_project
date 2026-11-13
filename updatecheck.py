"""Обновление программы: последний выпуск GitHub (appinfo.REPO_URL), проверка и установщик.

latest() — версия и файлы последнего выпуска (api.github.com, без прокси из переменных
окружения). download() скачивает установщик своей версии (StretchBIT[-test]-<версия>-
setup.exe) и проверяет:
  * SHA-256 — по файлу SHA256SUMS того же выпуска (его пишет build_release.py);
  * подпись Authenticode — если текущая программа подписана, установщик должен быть подписан
    действительной подписью того же издателя; если не подписана — подпись установщика, если
    она есть, должна быть действительной.
Без SHA256SUMS или при несовпадении установщик не запускается. Хэш с той же страницы
защищает от порчи и подмены по дороге, но не от взлома самой страницы — от этого защищает
только подпись (build_release.py --sign).
"""
import hashlib
import json
import re
import subprocess
import sys
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import appinfo
import datadirs

API = "https://api.github.com/repos/{repo}/releases/latest"
MAX_INSTALLER = 512 * 1024 * 1024
DOWNLOAD_DIR = datadirs.CACHE / "update"


@dataclass
class Release:
    version: str
    page: str
    notes: str = ""
    assets: dict = field(default_factory=dict)   # имя файла → ссылка на скачивание


def repo() -> str:
    m = re.match(r"^https://github\.com/([^/]+/[^/]+?)/?$", appinfo.REPO_URL)
    return m[1] if m else ""


def version_key(text: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", text)[:4])


def newer(candidate: str, current: str = appinfo.VERSION) -> bool:
    return version_key(candidate) > version_key(current)


def _open(url: str, timeout: float, accept: str = "application/octet-stream"):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, headers={"User-Agent": f"{appinfo.APP_NAME}/"
                                                                 f"{appinfo.VERSION}",
                                                   "Accept": accept})
    return opener.open(request, timeout=timeout)


def latest(timeout: float = 15.0) -> Release:
    name = repo()
    if not name:
        raise ValueError("в appinfo.REPO_URL нет адреса репозитория GitHub")
    with _open(API.format(repo=name), timeout, "application/vnd.github+json") as response:
        doc = json.loads(response.read(2 * 1024 * 1024).decode("utf-8"))
    return Release(version=str(doc.get("tag_name") or doc.get("name") or "").lstrip("vV"),
                   page=doc.get("html_url") or appinfo.RELEASES_URL,
                   notes=(doc.get("body") or "")[:4000],
                   assets={a["name"]: a["browser_download_url"] for a in doc.get("assets", [])
                           if a.get("name") and a.get("browser_download_url")})


def installer_name(version: str) -> str:
    from diag import edition
    return f"{appinfo.APP_NAME}{'-test' if edition.is_test() else ''}-{version}-setup.exe"


def parse_sums(text: str) -> dict[str, str]:
    """SHA256SUMS: «хэш  имя» по строке (как sha256sum)."""
    sums = {}
    for line in text.splitlines():
        m = re.match(r"^([0-9a-fA-F]{64})\s+\*?(.+?)\s*$", line)
        if m:
            sums[m[2]] = m[1].lower()
    return sums


def _signature(path: Path):
    from scanner import signature
    return signature.inspect_signature(Path(path))


def verify(path: Path, expected_sha: str, current_exe: str | None = None) -> None:
    """ValueError — установщик запускать нельзя."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    if h.hexdigest() != expected_sha.lower():
        raise ValueError("SHA-256 установщика не совпал с SHA256SUMS выпуска")
    current_exe = current_exe or (sys.executable if getattr(sys, "frozen", False) else "")
    mine = _signature(Path(current_exe)) if current_exe else None
    theirs = _signature(path)
    if mine is not None and mine.status == "valid":
        if theirs.status != "valid":
            raise ValueError("программа подписана, а установщик — нет или подпись недействительна")
        if (theirs.publisher or "") != (mine.publisher or ""):
            raise ValueError(f"установщик подписал другой издатель: {theirs.publisher}")
    elif theirs.status not in ("valid", "unsigned"):
        raise ValueError(f"подпись установщика недействительна ({theirs.status})")


def download(release: Release, progress=None) -> Path:
    name = installer_name(release.version)
    if name not in release.assets:
        raise ValueError(f"в выпуске {release.version} нет файла {name}")
    if "SHA256SUMS" not in release.assets:
        raise ValueError("в выпуске нет SHA256SUMS — проверить установщик нечем")
    with _open(release.assets["SHA256SUMS"], 30) as response:
        sums = parse_sums(response.read(64 * 1024).decode("utf-8", "replace"))
    if name not in sums:
        raise ValueError(f"в SHA256SUMS нет строки для {name}")
    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
    target = DOWNLOAD_DIR / name
    tmp = target.with_suffix(".part")
    total = 0
    with _open(release.assets[name], 60) as response, open(tmp, "wb") as out:
        size = int(response.headers.get("Content-Length") or 0)
        while chunk := response.read(1 << 20):
            total += len(chunk)
            if total > MAX_INSTALLER:
                raise ValueError("установщик слишком большой")
            out.write(chunk)
            if progress and size:
                progress(int(total * 100 / size))
    try:
        verify(tmp, sums[name])
    except ValueError:
        tmp.unlink(missing_ok=True)
        raise
    tmp.replace(target)
    return target


def run_installer(path: Path) -> None:
    """Запустить установщик: он сам попросит закрыть программу (CloseApplications)."""
    subprocess.Popen([str(path)], close_fds=True)
