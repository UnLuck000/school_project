"""Подписки VPN: ссылка, по которой провайдер отдаёт список серверов.

Обычный формат — base64 (или просто текст) со ссылками по одной на строку; берутся vless://,
остальное (vmess, trojan, ss...) пропускается с пометкой. Заголовок Subscription-Userinfo
(upload, download, total, expire) — трафик и срок, если провайдер их сообщает. Профили
подписки помечены Profile.subscription = id; при обновлении они заменяются новыми, а режим и
«подключать при запуске» переносятся на тот же сервер (UUID + адрес + порт). Хранение —
subscriptions.dat под DPAPI рядом с профилями: в ссылке подписки обычно личный токен.
"""
import base64
import binascii
import json
import re
import time
import urllib.parse
import urllib.request
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

from vpn import profiles

FILE = profiles.PROFILES_FILE.with_name("subscriptions.dat")
MAX_SIZE = 4 * 1024 * 1024


@dataclass
class Subscription:
    id: str
    name: str
    url: str
    interval: int = 24              # часы между обновлениями
    updated: float = 0.0
    error: str = ""
    count: int = 0                  # серверов в последнем ответе
    skipped: int = 0                # ссылок других протоколов
    info: dict = field(default_factory=dict)  # upload, download, total, expire

    def usage(self) -> str:
        """«12,3 ГБ из 100 ГБ, до 01.12.2026» — если провайдер сообщил."""
        from analyzer.fileops import human_size
        parts = []
        used = int(self.info.get("upload", 0)) + int(self.info.get("download", 0))
        total = int(self.info.get("total", 0))
        if used or total:
            parts.append(human_size(used) + (f" из {human_size(total)}" if total else ""))
        expire = int(self.info.get("expire", 0))
        if expire:
            parts.append("до " + time.strftime("%d.%m.%Y", time.localtime(expire)))
        return ", ".join(parts)


def load(path: Path = FILE) -> list[Subscription]:
    try:
        items = json.loads(profiles._dpapi(path.read_bytes(), protect=False).decode("utf-8"))
    except (OSError, ValueError):
        return []
    known = set(Subscription.__dataclass_fields__)
    return [Subscription(**{k: v for k, v in item.items() if k in known}) for item in items
            if isinstance(item, dict)]


def save(subs: list[Subscription], path: Path = FILE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps([asdict(s) for s in subs], ensure_ascii=False).encode("utf-8")
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(profiles._dpapi(data, protect=True))
    tmp.replace(path)


def new(name: str, url: str, interval: int = 24) -> Subscription:
    url = url.strip()
    if urllib.parse.urlsplit(url).scheme != "https":
        raise ValueError("Ссылка подписки должна начинаться с https://")
    host = urllib.parse.urlsplit(url).hostname or "подписка"
    return Subscription(id=uuid.uuid4().hex[:12], name=name.strip() or host, url=url,
                        interval=max(1, int(interval)))


def parse_info(header: str) -> dict:
    """Subscription-Userinfo: upload=1; download=2; total=3; expire=4."""
    info = {}
    for part in (header or "").split(";"):
        key, _, value = part.strip().partition("=")
        if key in ("upload", "download", "total", "expire") and value.strip().isdigit():
            info[key] = int(value.strip())
    return info


def parse_links(data: bytes) -> tuple[list[str], int]:
    """(ссылки vless://, сколько ссылок других протоколов)."""
    text = data.decode("utf-8", "replace").strip()
    if "://" not in text:
        compact = re.sub(r"\s+", "", text)
        try:
            text = base64.b64decode(compact + "=" * (-len(compact) % 4),
                                    altchars=b"-_" if "-" in compact or "_" in compact
                                    else None).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            raise ValueError("ответ подписки — не список ссылок и не base64") from None
    links, skipped = [], 0
    for line in text.splitlines():
        line = line.strip()
        if not line or "://" not in line:
            continue
        if line.lower().startswith("vless://"):
            links.append(line)
        else:
            skipped += 1
    return links, skipped


def fetch(sub: Subscription, timeout: float = 30.0) -> tuple[list[str], int, dict]:
    """Скачать подписку (без прокси из переменных окружения): (ссылки, пропущено, сведения)."""
    request = urllib.request.Request(sub.url, headers={"User-Agent": "StretchBIT/1.0 (v2ray)"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=timeout) as response:
        data = response.read(MAX_SIZE + 1)
        info = parse_info(response.headers.get("Subscription-Userinfo", ""))
    if len(data) > MAX_SIZE:
        raise ValueError("ответ подписки слишком большой")
    links, skipped = parse_links(data)
    if not links:
        raise ValueError("в подписке нет серверов VLESS" +
                         (f" (других протоколов: {skipped})" if skipped else ""))
    return links, skipped, info


def _key(p: profiles.Profile) -> tuple:
    try:
        from vpn import xray
        v = xray.parse_vless(p.config)
        return v["id"], v["address"].lower(), v["port"]
    except ValueError:
        return p.config,


def merge(current: list[profiles.Profile], sub: Subscription,
          links: list[str]) -> tuple[list[profiles.Profile], int]:
    """Профили подписки заменяются новыми на том же месте списка; режим и автоподключение
    тех же серверов сохраняются. Возвращает (новый список, сколько добавлено)."""
    old = {_key(p): p for p in current if p.subscription == sub.id}
    others = [p for p in current if p.subscription != sub.id]
    names = [p.name for p in others]
    fresh = []
    for link in links:
        try:
            p = profiles.from_text("", link)
        except ValueError:
            continue
        p.subscription = sub.id
        prev = old.get(_key(p))
        if prev is not None:
            p.mode, p.auto_connect, p.created = prev.mode, prev.auto_connect, prev.created
        p.name = profiles.unique_name(p.name, names)
        names.append(p.name)
        fresh.append(p)
    first = next((i for i, p in enumerate(current) if p.subscription == sub.id), len(others))
    position = sum(1 for p in current[:first] if p.subscription != sub.id)
    return others[:position] + fresh + others[position:], len(fresh)


def due(subs: list[Subscription], now: float | None = None) -> list[Subscription]:
    now = time.time() if now is None else now
    return [s for s in subs if s.updated + max(1, s.interval) * 3600 <= now]
