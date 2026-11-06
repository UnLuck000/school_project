"""Профили VPN: импорт конфигураций WireGuard (.conf) и OpenVPN (.ovpn), хранение.

Конфигурации содержат закрытые ключи, поэтому файл профилей (PROFILES_FILE) шифруется
DPAPI Windows (CryptProtectData): расшифровать его может только та же учётная запись на
этом компьютере. Папка vpn_profiles/ не хранится в Git.
"""
import ctypes
import json
import re
import sys
import time
from ctypes import wintypes
from dataclasses import asdict, dataclass, field
from pathlib import Path

PROFILES_FILE = Path("vpn_profiles") / "profiles.dat"
KINDS = {"wireguard": "WireGuard", "openvpn": "OpenVPN", "demo": "Демо (без сервера)"}


@dataclass
class Profile:
    name: str
    kind: str                 # wireguard | openvpn | demo
    config: str = ""          # текст конфигурации
    server: str = ""          # адрес сервера (для показа)
    created: float = field(default_factory=time.time)
    auto_connect: bool = False

    @property
    def title(self) -> str:
        return f"{self.name} — {KINDS.get(self.kind, self.kind)}"


def parse_wireguard(text: str) -> dict:
    """Endpoint, Address, DNS и наличие ключей из .conf WireGuard."""
    info = {}
    for line in text.splitlines():
        key, _, value = line.partition("=")
        key, value = key.strip().lower(), value.strip()
        if key in ("endpoint", "address", "dns", "allowedips") and key not in info:
            info[key] = value
        if key == "privatekey":
            info["private_key"] = bool(value)
    return info


def parse_openvpn(text: str) -> dict:
    """remote, proto, dev из .ovpn."""
    info = {}
    for line in text.splitlines():
        parts = line.strip().split()
        if not parts or parts[0].startswith(("#", ";")):
            continue
        if parts[0] == "remote" and "remote" not in info and len(parts) >= 2:
            info["remote"] = parts[1] + (f":{parts[2]}" if len(parts) > 2 else "")
        if parts[0] in ("proto", "dev") and parts[0] not in info and len(parts) >= 2:
            info[parts[0]] = parts[1]
    return info


def detect_kind(text: str, filename: str = "") -> str:
    low = text.lower()
    if "[interface]" in low and "[peer]" in low:
        return "wireguard"
    if filename.lower().endswith(".ovpn") or re.search(r"^\s*remote\s+\S+", text, re.M):
        return "openvpn"
    raise ValueError("Не похоже на конфигурацию WireGuard (.conf) или OpenVPN (.ovpn)")


def from_text(name: str, text: str, filename: str = "") -> Profile:
    kind = detect_kind(text, filename)
    if kind == "wireguard":
        info = parse_wireguard(text)
        if not info.get("private_key"):
            raise ValueError("В конфигурации WireGuard нет закрытого ключа (PrivateKey)")
        server = info.get("endpoint", "")
    else:
        server = parse_openvpn(text).get("remote", "")
    if not server:
        raise ValueError("В конфигурации не найден адрес сервера")
    return Profile(name=name, kind=kind, config=text, server=server)


def import_file(path: str) -> Profile:
    p = Path(path)
    if p.stat().st_size > 1024 * 1024:
        raise ValueError("Файл слишком большой для конфигурации VPN")
    return from_text(p.stem, p.read_text(encoding="utf-8", errors="replace"), p.name)


def demo_profile() -> Profile:
    return Profile(name="Демо-сервер", kind="demo", server="demo.example:51820")


# ---------- хранение (DPAPI) ----------
class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data: bytes, protect: bool) -> bytes:
    if sys.platform != "win32":
        return data
    crypt32 = ctypes.WinDLL("crypt32")
    kernel32 = ctypes.WinDLL("kernel32")
    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = _Blob()
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    if protect:
        ok = fn(ctypes.byref(blob_in), "myav vpn", None, None, None, 0, ctypes.byref(blob_out))
    else:
        ok = fn(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out))
    if not ok:
        raise OSError("DPAPI: не удалось " + ("зашифровать" if protect else "расшифровать"))
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def load(path: Path = PROFILES_FILE) -> list[Profile]:
    try:
        raw = _dpapi(path.read_bytes(), protect=False)
        items = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError):
        return []
    fields = set(Profile.__dataclass_fields__)
    return [Profile(**{k: v for k, v in item.items() if k in fields}) for item in items
            if isinstance(item, dict)]


def save(profiles: list[Profile], path: Path = PROFILES_FILE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps([asdict(p) for p in profiles], ensure_ascii=False).encode("utf-8")
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(_dpapi(data, protect=True))
    tmp.replace(path)
