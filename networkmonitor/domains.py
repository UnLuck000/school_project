"""Проверка доменов: списки вредоносных доменов (ThreatFox, URLhaus) и признаки
сгенерированных имён (DGA — domain generation algorithm: вредонос каждый день перебирает
сотни случайных имён, а владелец регистрирует одно из них)."""
import math
import re
from collections import Counter
from pathlib import Path

VOWELS = set("aeiouy")
# домены, которые выглядят случайными, но принадлежат крупным сервисам (CDN, облака)
DGA_SAFE_SUFFIXES = (
    "amazonaws.com", "cloudfront.net", "akamaiedge.net", "akamai.net", "azureedge.net",
    "googleusercontent.com", "googlevideo.com", "gvt1.com", "1e100.net", "windows.net",
    "msedge.net", "trafficmanager.net", "cloudflare.net", "fastly.net", "office.net",
    "microsoft.com", "live.com", "yandex.net", "yandex.ru", "vk.com", "userapi.com",
    "steamcontent.com", "steamserver.net", "discord.gg", "discord.media", "local", "arpa",
)
# Общие сервисы: злоумышленники выкладывают файлы на GitHub, Discord, Google Drive и т. п.,
# и такие ссылки попадают в URLhaus и ThreatFox. Опасна конкретная ссылка, а не домен:
# по домену их не судим, иначе любой браузер, Discord или сама программа (обновление баз
# с GitHub) выглядят как вредоносы.
SHARED_SERVICES = (
    "github.com", "githubusercontent.com", "github.io", "gitlab.com", "bitbucket.org",
    "discord.com", "discordapp.com", "discordapp.net", "discord.gg", "discord.media",
    "google.com", "googleapis.com", "googleusercontent.com", "gstatic.com", "youtube.com",
    "goo.gl", "microsoft.com", "live.com", "office.com", "sharepoint.com", "onedrive.com",
    "1drv.ms", "windows.net", "azurewebsites.net", "azureedge.net", "amazonaws.com",
    "cloudfront.net", "cloudflare.com", "workers.dev", "pages.dev", "r2.dev",
    "dropbox.com", "dropboxusercontent.com", "mediafire.com", "mega.nz", "telegram.org",
    "t.me", "yandex.ru", "yandex.net", "disk.yandex.ru", "mail.ru", "vk.com", "userapi.com",
    "apple.com", "icloud.com", "mozilla.org", "abuse.ch", "virusshare.com", "ngrok.io",
    "ngrok-free.app", "sourceforge.net", "archive.org", "pastebin.com", "transfer.sh",
)
DGA_MIN_LEN = 10      # короче — слишком мало данных для оценки
DGA_THRESHOLD = 3.0   # баллы, с которых имя считается сгенерированным


def load_domains(folder: Path) -> dict[str, str]:
    """Домен -> файл списка, из которого он взят."""
    result: dict[str, str] = {}
    if not folder.is_dir():
        return result
    for f in sorted(folder.glob("*.txt")):
        for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip().lower()
            if line and not line.startswith("#"):
                result.setdefault(line, f.stem)
    return result


def shared_service(name: str) -> bool:
    """Домен общего сервиса (GitHub, Discord, облака): по нему самому не судим."""
    name = name.strip().lower().rstrip(".")
    return any(name == s or name.endswith("." + s) for s in SHARED_SERVICES)


def lookup(domains: dict[str, str], name: str) -> tuple[str, str] | None:
    """Есть ли домен или любой его родитель в списках. (найденный домен, источник).
    Общие сервисы (SHARED_SERVICES) не учитываются, даже если попали в список."""
    name = name.strip().lower().rstrip(".")
    if shared_service(name):
        return None
    parts = name.split(".")
    for i in range(len(parts) - 1):  # a.b.evil.com -> b.evil.com -> evil.com (без зоны)
        candidate = ".".join(parts[i:])
        if candidate in domains:
            return candidate, domains[candidate]
    return None


def _entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values())


def dga_score(name: str) -> tuple[float, str]:
    """Насколько имя похоже на сгенерированное: (баллы, объяснение).
    Оценивается самая длинная метка без зоны: у «qxkzvtrplm.example.com» — «qxkzvtrplm»."""
    name = name.strip().lower().rstrip(".")
    if not name or name.endswith(DGA_SAFE_SUFFIXES) or re.fullmatch(r"[\d.:]+", name):
        return 0.0, ""
    labels = name.split(".")[:-1] or [name]
    label = max(labels, key=len)
    letters = re.sub(r"[^a-z]", "", label)
    if len(label) < DGA_MIN_LEN or len(letters) < DGA_MIN_LEN // 2:
        return 0.0, ""
    score, reasons = 0.0, []
    entropy = _entropy(label)
    if entropy > 3.5:
        score += 1.5 if entropy > 3.9 else 1.0
        reasons.append(f"энтропия {entropy:.1f}")
    vowels = sum(ch in VOWELS for ch in letters) / len(letters)
    if vowels < 0.25:
        score += 1.5
        reasons.append(f"гласных {vowels:.0%}")
    run = max((len(m) for m in re.findall(r"[^aeiouy\d-]+", label)), default=0)
    if run >= 5:
        score += 1.0
        reasons.append(f"{run} согласных подряд")
    digits = sum(ch.isdigit() for ch in label) / len(label)
    if 0.2 < digits < 0.8:
        score += 1.0
        reasons.append(f"цифр {digits:.0%}")
    if len(label) >= 20:
        score += 0.5
        reasons.append(f"длина {len(label)}")
    return score, ", ".join(reasons)


def looks_generated(name: str) -> str:
    """Описание, если имя похоже на DGA, иначе пустая строка."""
    score, reasons = dga_score(name)
    return f"похоже на сгенерированное имя ({reasons})" if score >= DGA_THRESHOLD else ""


def load_ja3(folder: Path) -> dict[str, str]:
    """Отпечаток JA3 (md5) -> описание (семейство вредоноса)."""
    result: dict[str, str] = {}
    if not folder.is_dir():
        return result
    for f in sorted(folder.glob("*.txt")):
        for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("#") or not line.strip():
                continue
            digest, _, reason = line.strip().partition("\t")
            result.setdefault(digest.lower(), f"{reason or 'вредонос'} ({f.stem})")
    return result
