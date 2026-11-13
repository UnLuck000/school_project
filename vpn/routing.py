"""Профили маршрутизации VPN: что идёт через туннель, что напрямую, что блокируется.

Профиль — папка в %APPDATA%\\StretchBitConfiguration\\vpn_routing\\<id>: profile.json и files\\
(свои файлы .dat в формате geosite/geoip Xray — например, списки runetfreedom). «Default»
есть всегда (его нельзя удалить, файлов в нём нет); при первом запуске в него переносятся
прежние настройки vpn/route_ru, block_ads, block_quic, block_udp и vpn/rules_*. Выбранный
профиль — настройка vpn/routing_profile; действует со следующего подключения во всех режимах
VLESS (TUN, системный и локальный прокси): правила применяет Xray (xray.apply_options).

В профиле: встроенные правила (QUIC, UDP, российские сайты, реклама geosite, AdBlock — список
AdGuard DNS, скачивается и обновляется раз в сутки), WARP (vpn/warp.py), свои строки
«Туннель» / «Обход» / «Блокировать» и «Дополнительно» — правила с полями Xray (входящее,
домены, адреса, порты, сеть, протокол, источник), как в Throne.

Экспорт — .json (без файлов) или .zip (profile.json + files/). Импорт — файлы (профили .json /
.zip и файлы .dat — несколько сразу) или ссылка (GitHub blob превращается в raw): у ссылки
запоминаются адрес и период автообновления (1, 12, 24 часа или своё), их можно поменять
(sources: "" — сам профиль, имя файла — файл). update_due обновляет то, чему пора.
"""
import hashlib
import io
import json
import os
import re
import shutil
import threading
import time
import urllib.parse
import urllib.request
import uuid
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

import userdata
from vpn import warp

FORMAT = "sbit-routing"
ROUTING_DIR = userdata.CONFIG_DIR / "vpn_routing"
ASSETS_DIR = Path("cache") / "vpn" / "assets"   # geo-файлы для Xray (XRAY_LOCATION_ASSET)
DEFAULT_ID = "default"
DEFAULT_NAME = "Default"
ADBLOCK_URL = "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
ADBLOCK_MAX_AGE = 24 * 3600
MAX_FILE = 128 * 1024 * 1024         # файл .dat или профиль по ссылке
MAX_ADBLOCK = 32 * 1024 * 1024
INTERVALS = {1: "Каждый час", 12: "Каждые 12 часов", 24: "Каждые 24 часа"}  # + своё (часы)
OUTBOUNDS = {"proxy": "Туннель", "direct": "Обход (напрямую)", "block": "Блокировать",
             "vpn": "Только VPN, без WARP"}
INBOUNDS = {"tun": "TUN (весь трафик)", "proxy": "Системный прокси",
            "local-socks": "Локальный SOCKS5", "local-http": "Локальный HTTP"}
NETWORKS = {"": "Любая", "tcp": "TCP", "udp": "UDP", "tcp,udp": "TCP и UDP"}
PROTOCOLS = ("http", "tls", "quic", "bittorrent")
RULE_KEYS = ("name", "enabled", "outbound", "inbound", "domain", "ip", "port", "source_port",
             "network", "protocol", "source")
PORT_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+"
                       r"[a-z0-9-]{2,63}$")
_lock = threading.RLock()


@dataclass
class RoutingProfile:
    id: str
    name: str
    block_quic: bool = True
    block_udp: bool = False
    route_ru: bool = True
    block_ads: bool = False
    adblock: bool = False
    adblock_url: str = ADBLOCK_URL
    warp: dict = field(default_factory=warp.default)
    rules_proxy: list = field(default_factory=list)    # «Туннель»
    rules_direct: list = field(default_factory=list)   # «Обход»
    rules_block: list = field(default_factory=list)    # «Блокировать»
    advanced: list = field(default_factory=list)       # «Дополнительно»: словари RULE_KEYS
    sources: dict = field(default_factory=dict)        # "" | имя файла → url, interval, ...
    created: float = field(default_factory=time.time)

    @property
    def is_default(self) -> bool:
        return self.id == DEFAULT_ID

    @property
    def folder(self) -> Path:
        return ROUTING_DIR / self.id

    @property
    def files_dir(self) -> Path:
        return self.folder / "files"

    def files(self) -> list[Path]:
        if self.is_default or not self.files_dir.is_dir():
            return []
        return sorted((f for f in self.files_dir.iterdir()
                       if f.is_file() and f.suffix.lower() == ".dat"),
                      key=lambda f: f.name.lower())

    def summary(self) -> str:
        parts = [title for key, title in (
            ("block_quic", "QUIC блокируется"), ("block_udp", "весь UDP блокируется"),
            ("route_ru", "российские сайты напрямую"), ("block_ads", "реклама блокируется"),
            ("adblock", "AdBlock")) if getattr(self, key)]
        if self.block_udp and "QUIC блокируется" in parts:
            parts.remove("QUIC блокируется")
        if self.warp.get("enabled"):
            parts.append("WARP: " + ("VPN → WARP" if self.warp.get("chain") == "over_vpn"
                                     else "WARP → VPN"))
        own = sum(len(clean_lines(getattr(self, k)))
                  for k in ("rules_proxy", "rules_direct", "rules_block"))
        if own:
            parts.append(f"своих правил: {own}")
        active = sum(1 for r in self.advanced if r.get("enabled", True))
        if active:
            parts.append(f"дополнительно: {active}")
        files = self.files()
        if files:
            parts.append(f"файлов: {len(files)}")
        if self.sources.get(""):
            parts.append("по ссылке")
        return " · ".join(parts) or "без правил: всё через туннель"


# ---------------- имена, строки, правила ----------------
def unique_name(name: str, names) -> str:
    """Имя, которого ещё нет: «Имя», затем «Имя (1)», «Имя (2)»... (регистр не важен)."""
    name = " ".join(str(name).split()) or "Профиль"
    taken = {str(n).casefold() for n in names}
    if name.casefold() not in taken:
        return name
    base = re.sub(r"\s*\(\d+\)$", "", name) or name
    n = 1
    while f"{base} ({n})".casefold() in taken:
        n += 1
    return f"{base} ({n})"


def clean_lines(lines) -> list[str]:
    """Строки правил без пустых и комментариев (# — до конца строки)."""
    if isinstance(lines, str):
        lines = lines.splitlines()
    result = []
    for line in lines or []:
        line = str(line).split("#", 1)[0].strip()
        if line:
            result.append(line)
    return result


def _list(value) -> list[str]:
    if isinstance(value, str):
        value = re.split(r"[\n,]+", value)
    return [str(v).strip() for v in (value or []) if str(v).strip()]


def normalize_rule(rule: dict) -> dict:
    """Правило «Дополнительно» в едином виде (списки — списками, лишние ключи убраны)."""
    r = {key: rule.get(key) for key in RULE_KEYS}
    r["name"] = str(r["name"] or "").strip()
    r["enabled"] = r["enabled"] is not False
    r["outbound"] = r["outbound"] if r["outbound"] in OUTBOUNDS else "proxy"
    r["inbound"] = [i for i in _list(r["inbound"]) if i in INBOUNDS]
    for key in ("domain", "ip", "source"):
        r[key] = _list(r[key])
    for key in ("port", "source_port"):
        r[key] = str(r[key] or "").replace(" ", "")
    r["network"] = r["network"] if r["network"] in NETWORKS else ""
    r["protocol"] = [p for p in _list(r["protocol"]) if p in PROTOCOLS]
    return r


def rule_problems(rule: dict) -> list[str]:
    """Что в правиле не так (пусто — можно сохранять)."""
    import ipaddress
    r = normalize_rule(rule)
    errors = []
    for key, title in (("port", "Порт"), ("source_port", "Порт источника")):
        if r[key] and (not PORT_RE.match(r[key]) or any(
                not 0 < int(p) <= 65535 for p in re.split(r"[,-]", r[key]))):
            errors.append(f"{title}: числа 1–65535, диапазон через «-», список через запятую")
    for key, title in (("ip", "Адрес"), ("source", "Адрес источника")):
        for entry in r[key]:
            if entry.lower().startswith(("geoip:", "ext:")):
                continue
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError:
                errors.append(f"{title}: «{entry}» — не IP, не сеть CIDR и не geoip:")
    for entry in r["domain"]:
        if " " in entry:
            errors.append(f"Домен: «{entry}» с пробелом")
    return errors


def rule_text(rule: dict) -> str:
    """Короткое описание условия правила для таблицы."""
    r = normalize_rule(rule)
    parts = []
    if r["inbound"]:
        parts.append("вход: " + ", ".join(INBOUNDS[i] for i in r["inbound"]))
    for key, title in (("domain", "домены"), ("ip", "адреса"), ("source", "источник")):
        if r[key]:
            shown = ", ".join(r[key][:3]) + (f" и ещё {len(r[key]) - 3}" if len(r[key]) > 3
                                             else "")
            parts.append(f"{title}: {shown}")
    if r["port"]:
        parts.append(f"порт {r['port']}")
    if r["source_port"]:
        parts.append(f"порт источника {r['source_port']}")
    if r["network"]:
        parts.append(NETWORKS[r["network"]])
    if r["protocol"]:
        parts.append(", ".join(r["protocol"]))
    return "; ".join(parts) or "любой трафик"


# ---------------- хранение ----------------
def from_dict(data: dict, pid: str | None = None) -> RoutingProfile:
    known = set(RoutingProfile.__dataclass_fields__)
    values = {k: v for k, v in data.items() if k in known}
    values["id"] = pid or str(values.get("id") or new_id())
    values["name"] = " ".join(str(values.get("name") or "Профиль").split())
    p = RoutingProfile(**values)
    for key in ("block_quic", "block_udp", "route_ru", "block_ads", "adblock"):
        setattr(p, key, bool(getattr(p, key)))
    p.adblock_url = str(p.adblock_url or ADBLOCK_URL)
    p.warp = warp.normalize(p.warp if isinstance(p.warp, dict) else {})
    for key in ("rules_proxy", "rules_direct", "rules_block"):
        value = getattr(p, key)
        setattr(p, key, [str(s) for s in (value.splitlines() if isinstance(value, str)
                                          else value or [])])
    p.advanced = [normalize_rule(r) for r in (p.advanced or []) if isinstance(r, dict)]
    p.sources = {str(k): dict(v) for k, v in (p.sources or {}).items() if isinstance(v, dict)}
    return p


def to_dict(p: RoutingProfile, keys: bool = True) -> dict:
    data = asdict(p)
    if not keys:
        data["warp"] = dict(data["warp"], private_key="")
    return data


def new_id() -> str:
    return uuid.uuid4().hex[:12]


def save(p: RoutingProfile) -> None:
    with _lock:
        p.folder.mkdir(parents=True, exist_ok=True)
        path = p.folder / "profile.json"
        tmp = path.with_name("profile.json.tmp")
        tmp.write_text(json.dumps(to_dict(p), ensure_ascii=False, indent=1), encoding="utf-8")
        tmp.replace(path)


def _migrated_default() -> RoutingProfile:
    """Default из прежних настроек окна VPN (до профилей маршрутизации)."""
    p = RoutingProfile(id=DEFAULT_ID, name=DEFAULT_NAME, created=0.0)
    try:
        from ui import settings as cfg
        for key in ("block_quic", "block_udp", "route_ru", "block_ads"):
            setattr(p, key, bool(cfg.get(f"vpn/{key}")))
        for kind in ("proxy", "direct", "block"):
            setattr(p, f"rules_{kind}",
                    [s for s in str(cfg.get(f"vpn/rules_{kind}") or "").splitlines() if s.strip()])
    except Exception:
        from diag.log import swallowed
        swallowed("routing: прежние настройки маршрутизации")
    return p


def load_all() -> list[RoutingProfile]:
    """Все профили: Default первым, остальные — по времени создания."""
    items: list[RoutingProfile] = []
    with _lock:
        if ROUTING_DIR.is_dir():
            for folder in ROUTING_DIR.iterdir():
                path = folder / "profile.json"
                if not path.is_file():
                    continue
                try:
                    items.append(from_dict(json.loads(path.read_text(encoding="utf-8")),
                                           folder.name))
                except (OSError, ValueError, TypeError):
                    from diag.log import swallowed
                    swallowed(f"routing: профиль {folder.name}")
        if not any(p.is_default for p in items):
            default = _migrated_default()
            save(default)
            items.append(default)
    items.sort(key=lambda p: (not p.is_default, p.created, p.name.lower()))
    return items


def get(pid: str) -> RoutingProfile | None:
    return next((p for p in load_all() if p.id == pid), None)


def active() -> RoutingProfile:
    """Выбранный профиль (vpn/routing_profile), иначе Default."""
    try:
        from ui import settings as cfg
        pid = str(cfg.get("vpn/routing_profile") or DEFAULT_ID)
    except Exception:
        pid = DEFAULT_ID
    profiles = load_all()
    return next((p for p in profiles if p.id == pid),
                next(p for p in profiles if p.is_default))


def set_active(pid: str) -> None:
    from ui import settings as cfg
    cfg.set_("vpn/routing_profile", pid)


def create(name: str, names) -> RoutingProfile:
    p = RoutingProfile(id=new_id(), name=unique_name(name or "Новый профиль", names))
    save(p)
    return p


def duplicate(p: RoutingProfile, names) -> RoutingProfile:
    data = to_dict(p)
    data.update(id=None, name=unique_name(p.name, names), created=time.time())
    copy = from_dict(data, new_id())
    save(copy)
    if p.files():
        shutil.copytree(p.files_dir, copy.files_dir, dirs_exist_ok=True)
    return copy


def delete(p: RoutingProfile) -> None:
    if p.is_default:
        raise ValueError("Профиль Default удалить нельзя")
    with _lock:
        shutil.rmtree(p.folder, ignore_errors=True)
    try:
        from ui import settings as cfg
        if cfg.get("vpn/routing_profile") == p.id:
            set_active(DEFAULT_ID)
    except Exception:
        from diag.log import swallowed
        swallowed("routing: выбор Default после удаления")


# ---------------- файлы .dat ----------------
def _varint(buf, i: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if i >= len(buf):
            raise ValueError("файл .dat обрезан")
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if b < 0x80:
            return result, i
        shift += 7
        if shift > 63:
            raise ValueError("не файл .dat")


def _entry_kind(sub) -> str:
    """Первый элемент списка: CIDR (поле 1 — 4 или 16 байт адреса) или домен."""
    key, j = _varint(sub, 0)
    if key == 0x0A:
        size, _ = _varint(sub, j)
        if size in (4, 16):
            return "geoip"
    return "geosite"


_dat_cache: dict[tuple, tuple[str, list[str]]] = {}


def dat_info(path) -> tuple[str, list[str]]:
    """Вид файла (geosite | geoip) и метки внутри (country_code). Формат — protobuf
    GeoSiteList / GeoIPList Xray: повторяющееся поле 1, в нём строка 1 — метка, поле 2 —
    домены или подсети. ValueError — не такой файл."""
    path = Path(path)
    st = path.stat()
    key = (str(path), st.st_size, st.st_mtime_ns)
    if key in _dat_cache:
        return _dat_cache[key]
    data = path.read_bytes()
    tags, kind, i = [], "", 0
    while i < len(data):
        head, i = _varint(data, i)
        if head != 0x0A:
            raise ValueError("не файл .dat (geosite или geoip Xray)")
        size, i = _varint(data, i)
        end = i + size
        if end > len(data):
            raise ValueError("файл .dat обрезан")
        j, code = i, ""
        while j < end and not (code and kind):
            k, j = _varint(data, j)
            number, wire = k >> 3, k & 7
            if wire == 2:
                length, j = _varint(data, j)
                if number == 1 and not code:
                    code = data[j:j + length].decode("utf-8", "replace")
                elif number == 2 and not kind:
                    kind = _entry_kind(data[j:j + length])
                j += length
            elif wire == 0:
                _, j = _varint(data, j)
            elif wire == 5:
                j += 4
            elif wire == 1:
                j += 8
            else:
                raise ValueError("не файл .dat (geosite или geoip Xray)")
        if not code:
            raise ValueError("не файл .dat: у записи нет метки")
        tags.append(code)
        i = end
    if not tags:
        raise ValueError("пустой файл .dat")
    result = (kind or "geosite", tags)
    _dat_cache[key] = result
    return result


def _safe_file_name(name: str) -> str:
    name = os.path.basename(str(name).replace("\\", "/")).strip()
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)
    if not name or name in (".", ".."):
        raise ValueError("пустое имя файла")
    if not name.lower().endswith(".dat"):
        name += ".dat"
    return name


def _write_file(p: RoutingProfile, name: str, data: bytes) -> str:
    """Файл .dat в профиль: проверка формата до записи, замена атомарно."""
    if p.is_default:
        raise ValueError("В профиль Default файлы не добавляются — создайте свой профиль")
    if len(data) > MAX_FILE:
        raise ValueError(f"{name}: больше {MAX_FILE // (1024 * 1024)} МБ")
    name = _safe_file_name(name)
    p.files_dir.mkdir(parents=True, exist_ok=True)
    tmp = p.files_dir / (name + ".tmp")
    tmp.write_bytes(data)
    try:
        dat_info(tmp)
    except ValueError as e:
        tmp.unlink(missing_ok=True)
        raise ValueError(f"{name}: {e}") from None
    tmp.replace(p.files_dir / name)
    return name


def add_files(p: RoutingProfile, paths) -> list[str]:
    """Файлы .dat в профиль (одноимённые заменяются). Возвращает имена."""
    added = []
    for path in paths:
        path = Path(path)
        if path.stat().st_size > MAX_FILE:
            raise ValueError(f"{path.name}: больше {MAX_FILE // (1024 * 1024)} МБ")
        added.append(_write_file(p, path.name, path.read_bytes()))
        p.sources.pop(added[-1], None)  # заменён вручную — прежняя ссылка ни при чём
    save(p)
    return added


def remove_file(p: RoutingProfile, name: str) -> None:
    (p.files_dir / _safe_file_name(name)).unlink(missing_ok=True)
    p.sources.pop(name, None)
    save(p)


def file_kinds(p: RoutingProfile) -> dict[str, str]:
    """Имя файла (строчными) → geosite | geoip; битые файлы пропускаются."""
    kinds = {}
    for f in p.files():
        try:
            kinds[f.name.lower()] = dat_info(f)[0]
        except (OSError, ValueError):
            continue
    return kinds


def assets_dir(p: RoutingProfile, bin_dir) -> str:
    """Папка geo-файлов для Xray (XRAY_LOCATION_ASSET), если у профиля есть свои файлы:
    geoip.dat и geosite.dat рядом с xray.exe + файлы профиля (одноимённые — главнее).
    Жёсткие ссылки, иначе копии; без файлов — "" (Xray берёт файлы из своей папки)."""
    files = p.files()
    if not files:
        return ""
    target = ASSETS_DIR / p.id
    target.mkdir(parents=True, exist_ok=True)
    wanted = {name: Path(bin_dir) / name for name in ("geoip.dat", "geosite.dat")
              if (Path(bin_dir) / name).is_file()}
    wanted.update({f.name: f for f in files})
    for old in target.iterdir():
        if old.name not in wanted:
            old.unlink(missing_ok=True)
    for name, src in wanted.items():
        dst = target / name
        st = src.stat()
        if dst.exists():
            dt = dst.stat()
            if dt.st_size == st.st_size and int(dt.st_mtime) == int(st.st_mtime):
                continue
            dst.unlink()
        try:
            os.link(src, dst)
        except OSError:
            shutil.copy2(src, dst)
    return str(target.resolve())


# ---------------- экспорт и импорт ----------------
def export(p: RoutingProfile, path, keys: bool = False) -> Path:
    """.zip с файлами или .json без них (по расширению path; файлы есть — всегда .zip).
    keys=False — закрытый ключ WARP не попадает в файл."""
    path = Path(path)
    data = json.dumps({"format": FORMAT, "version": 1, "profile": to_dict(p, keys)},
                      ensure_ascii=False, indent=1)
    files = p.files()
    if files and path.suffix.lower() != ".zip":
        path = path.with_suffix(".zip")
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("profile.json", data)
            for f in files:
                z.write(f, "files/" + f.name)
    else:
        path.write_text(data, encoding="utf-8")
    return path


def read_blob(data: bytes) -> tuple[dict, dict[str, bytes]]:
    """Профиль из .json или .zip: (поля профиля, файлы .dat). ValueError — не профиль."""
    files: dict[str, bytes] = {}
    if data[:4] == b"PK\x03\x04":
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            total = 0
            text = None
            for info in z.infolist():
                total += info.file_size
                if total > 4 * MAX_FILE:
                    raise ValueError("архив слишком большой")
                name = info.filename.replace("\\", "/")
                if name == "profile.json":
                    text = z.read(info).decode("utf-8")
                elif name.startswith("files/") and name.lower().endswith(".dat") and \
                        "/" not in name[6:] and info.file_size <= MAX_FILE:
                    files[_safe_file_name(name[6:])] = z.read(info)
            if text is None:
                raise ValueError("в архиве нет profile.json")
    else:
        text = data.decode("utf-8-sig")
    try:
        doc = json.loads(text)
    except ValueError:
        raise ValueError("не профиль маршрутизации (не JSON)") from None
    if not isinstance(doc, dict) or doc.get("format") != FORMAT or \
            not isinstance(doc.get("profile"), dict):
        raise ValueError("не профиль маршрутизации StretchBIT")
    return doc["profile"], files


def _new_from(data: dict, files: dict[str, bytes], names) -> RoutingProfile:
    data = dict(data, created=time.time())
    data.pop("id", None)
    p = from_dict(data, new_id())
    p.name = unique_name(p.name if p.name.casefold() != DEFAULT_NAME.casefold()
                         else "Default (импорт)", names)
    p.sources = {k: v for k, v in p.sources.items() if k == "" or k in files}
    save(p)
    for name, raw in files.items():
        _write_file(p, name, raw)
    return p


def import_paths(paths, current: RoutingProfile | None, names) -> tuple[RoutingProfile, list[str]]:
    """Импорт файлов: профили (.json, .zip) — каждый новым профилем; файлы .dat — в текущий
    профиль, а если он Default — в первый импортированный или в новый «Импорт».
    Возвращает (профиль, который показать, сообщения)."""
    names = list(names)
    notes, dats, shown = [], [], None
    for path in paths:
        path = Path(path)
        if path.suffix.lower() == ".dat":
            dats.append(path)
            continue
        if path.stat().st_size > 4 * MAX_FILE:
            raise ValueError(f"{path.name}: слишком большой файл")
        data, files = read_blob(path.read_bytes())
        p = _new_from(data, files, names)
        names.append(p.name)
        notes.append(f"Профиль «{p.name}» из {path.name}" +
                     (f" (файлов: {len(files)})" if files else ""))
        shown = shown or p
    if dats:
        target = current if current is not None and not current.is_default else shown
        if target is None:
            target = create("Импорт", names)
            names.append(target.name)
        added = add_files(target, dats)
        notes.append(f"В профиль «{target.name}» добавлены файлы: {', '.join(added)}")
        shown = shown or target
    if shown is None:
        raise ValueError("Не выбрано ни одного файла")
    return shown, notes


def raw_url(url: str) -> str:
    """Ссылка на страницу файла GitHub (…/blob/ветка/путь) → прямая (raw.githubusercontent)."""
    url = url.strip()
    m = re.match(r"^https?://github\.com/([^/]+)/([^/]+)/blob/(.+)$", url)
    if m:
        return f"https://raw.githubusercontent.com/{m[1]}/{m[2]}/{m[3]}"
    return url


def fetch(url: str, limit: int = MAX_FILE, timeout: float = 30.0) -> bytes:
    """Скачать по http(s) — без прокси из переменных окружения (они могут указывать на чужой
    клиент); не больше limit байт."""
    url = raw_url(url)
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        raise ValueError("Ссылка должна начинаться с https://")
    request = urllib.request.Request(url, headers={"User-Agent": "StretchBIT/1.0"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=timeout) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"по ссылке больше {limit // (1024 * 1024)} МБ")
    return data


def _file_name_from(url: str) -> str:
    path = urllib.parse.unquote(urllib.parse.urlsplit(raw_url(url)).path)
    return _safe_file_name(path.rstrip("/").rsplit("/", 1)[-1] or "list.dat")


def _source(url: str, interval: int) -> dict:
    return {"url": url.strip(), "interval": max(1, int(interval)), "updated": time.time(),
            "error": ""}


def import_url(url: str, interval: int, current: RoutingProfile | None, names,
               to_new: bool = False, data: bytes | None = None) -> tuple[RoutingProfile, str]:
    """Импорт по ссылке: профиль (.json/.zip) — новым профилем; файл .dat — в текущий
    (не Default и не to_new) или в новый профиль с именем файла. Ссылка и период
    обновления запоминаются в профиле."""
    data = fetch(url) if data is None else data
    try:
        fields, files = read_blob(data)
    except (ValueError, zipfile.BadZipFile, UnicodeDecodeError) as profile_error:
        name = _file_name_from(url)
        tmp_profile = current if current is not None and not current.is_default and \
            not to_new else None
        try:
            if tmp_profile is None:
                tmp_profile = create(Path(name).stem, names)
            name = _write_file(tmp_profile, name, data)
        except ValueError as e:
            if tmp_profile is not None and (current is None or tmp_profile.id != current.id):
                delete(tmp_profile)
            raise ValueError(f"По ссылке не профиль маршрутизации ({profile_error}) и не файл "
                             f".dat ({e})") from None
        tmp_profile.sources[name] = _source(url, interval)
        save(tmp_profile)
        return tmp_profile, f"Файл {name} добавлен в профиль «{tmp_profile.name}»"
    p = _new_from(fields, files, names)
    p.sources[""] = _source(url, interval)
    save(p)
    return p, f"Профиль «{p.name}» загружен по ссылке"


def set_source(p: RoutingProfile, key: str, url: str, interval: int) -> None:
    """Изменить ссылку или период обновления (строка с адресом в окне профиля)."""
    old = p.sources.get(key) or {}
    p.sources[key] = dict(old, url=url.strip(), interval=max(1, int(interval)))
    if old.get("url") != url.strip():
        p.sources[key]["updated"] = 0.0  # новая ссылка — скачать при ближайшей проверке
    save(p)


def update_source(p: RoutingProfile, key: str, data: bytes | None = None) -> str:
    """Скачать заново: "" — сам профиль (настройки и правила заменяются, имя, ключ WARP и
    ссылки остаются), имя файла — файл .dat. Ошибка запоминается в источнике и
    пробрасывается."""
    src = p.sources.get(key)
    if not src or not src.get("url"):
        raise ValueError("у этого источника нет ссылки")
    try:
        raw = fetch(src["url"]) if data is None else data
        if key == "":
            fields, files = read_blob(raw)
            fresh = from_dict(dict(fields), p.id)
            keep_warp = dict(fresh.warp)
            if not keep_warp.get("private_key") and p.warp.get("private_key"):
                for k in ("private_key", "address_v4", "address_v6", "reserved",
                          "peer_public_key", "endpoint"):
                    keep_warp[k] = p.warp[k]
            for name in RoutingProfile.__dataclass_fields__:
                if name not in ("id", "name", "sources", "created"):
                    setattr(p, name, getattr(fresh, name))
            p.warp = keep_warp
            for name, blob in files.items():
                if name not in p.sources:  # свои ссылки на файлы главнее
                    _write_file(p, name, blob)
            text = f"Профиль «{p.name}» обновлён по ссылке"
        else:
            _write_file(p, key, raw)
            text = f"Файл {key} профиля «{p.name}» обновлён"
    except Exception as e:
        p.sources[key] = dict(src, error=str(e)[:300], updated=time.time())
        save(p)
        raise
    p.sources[key] = dict(src, error="", updated=time.time())
    save(p)
    return text


def due(p: RoutingProfile, now: float | None = None) -> list[str]:
    now = time.time() if now is None else now
    return [key for key, src in p.sources.items() if src.get("url") and
            float(src.get("updated") or 0) + max(1, int(src.get("interval") or 24)) * 3600 <= now]


# ---------------- AdBlock ----------------
def adblock_file(url: str) -> Path:
    return ROUTING_DIR / "adblock" / (hashlib.sha1(url.encode()).hexdigest()[:16] + ".txt")


def parse_adblock(text: str) -> list[str]:
    """Домены из списка AdBlock (||домен^), hosts (0.0.0.0 домен) или простого списка.
    Исключения @@||домен^ убирают такой же домен; правила с * и путями пропускаются."""
    block, allow = set(), set()
    for line in text.splitlines():
        s = line.strip()
        if not s or s[0] in "!#[":
            continue
        exception = s.startswith("@@")
        if exception:
            s = s[2:]
        if s.startswith("||"):
            body, _, mods = s[2:].partition("$")
            if mods and any(m.strip() not in ("important", "") for m in mods.split(",")):
                continue
            domain = body.removesuffix("^").removesuffix("|")
        elif s.startswith(("0.0.0.0 ", "127.0.0.1 ", "::1 ", "0.0.0.0\t", "127.0.0.1\t")):
            domain = s.split()[1] if len(s.split()) > 1 else ""
        elif " " not in s and "/" not in s and not s.startswith(("|", "@", "/")):
            domain = s
        else:
            continue
        domain = domain.strip().strip(".").lower()
        if not DOMAIN_RE.match(domain) or domain in ("localhost", "local"):
            continue
        (allow if exception else block).add(domain)
    return sorted(block - allow)


def refresh_adblock(url: str) -> int:
    text = fetch(url, MAX_ADBLOCK).decode("utf-8", "replace")
    domains = parse_adblock(text)
    if len(domains) < 10:
        raise ValueError("по ссылке не список AdBlock (доменов не найдено)")
    path = adblock_file(url)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)
    return len(domains)


def adblock_domains(url: str, log=None, download: bool = True) -> list[str]:
    """Домены AdBlock из сохранённого списка; списка нет — скачать (download)."""
    say = log or (lambda text: None)
    path = adblock_file(url)
    if not path.is_file() and download:
        try:
            say(f"AdBlock: загружаю список ({refresh_adblock(url)} доменов)")
        except Exception as e:
            say(f"AdBlock: список не загружен: {e}")
    if not path.is_file():
        return []
    return parse_adblock(path.read_text(encoding="utf-8", errors="replace"))


def update_due(log=None) -> list[str]:
    """Обновить всё, чему пора: ссылки профилей и файлов (по их периоду) и списки AdBlock
    (раз в сутки). Возвращает сообщения; ошибки — тоже сообщениями."""
    say = log or (lambda text: None)
    notes = []
    lists = set()
    for p in load_all():
        if p.adblock:
            lists.add(p.adblock_url)
        for key in due(p):
            try:
                notes.append(update_source(p, key))
            except Exception as e:
                notes.append(f"«{p.name}»: {key or 'профиль'} не обновлён: {e}")
    for url in sorted(lists):
        path = adblock_file(url)
        if path.is_file() and time.time() - path.stat().st_mtime < ADBLOCK_MAX_AGE:
            continue
        try:
            notes.append(f"AdBlock: список обновлён ({refresh_adblock(url)} доменов)")
        except Exception as e:
            notes.append(f"AdBlock: список не обновлён: {e}")
    for note in notes:
        say(note)
    return notes


# ---------------- для конфигурации ----------------
def options(p: RoutingProfile, log=None, download: bool = True) -> dict:
    """Настройки профиля для xray.apply_options. WARP без ключа — ValueError."""
    say = log or (lambda text: None)
    o = {key: getattr(p, key) for key in ("route_ru", "block_ads", "block_quic", "block_udp")}
    for kind in ("proxy", "direct", "block"):
        o[f"rules_{kind}"] = clean_lines(getattr(p, f"rules_{kind}"))
    o["advanced"] = [r for r in p.advanced if r.get("enabled", True)]
    o["ip_files"] = {name for name, kind in file_kinds(p).items() if kind == "geoip"}
    o["adblock"] = adblock_domains(p.adblock_url, say, download) if p.adblock else []
    w = warp.normalize(p.warp)
    if w["enabled"]:
        errors = warp.problems(w)
        if errors:
            raise ValueError("WARP: " + "; ".join(errors))
        o["warp"] = w
    return o
