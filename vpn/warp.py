"""Cloudflare WARP в профиле маршрутизации: выход в интернет через WireGuard-сервер Cloudflare.

Цепочки (Xray, исходящее «wireguard»):
• over_vpn — «VPN → WARP»: WireGuard идёт внутри VPN (sockopt.dialerProxy = proxy), сайты
  видят адрес Cloudflare, а не сервера VPN;
• under_vpn — «WARP → VPN»: соединение с сервером VPN идёт внутри WARP (у VLESS dialerProxy =
  warp), провайдер видит только обмен с Cloudflare.

Протокол: WireGuard или AmneziaWG. У серверов Cloudflare нет параметров AmneziaWG (S1, S2,
H1–H4), поэтому от AmneziaWG берётся только «шум» перед рукопожатием — Jc пакетов случайной
длины Jmin–Jmax (исходящее freedom с noises, через него WireGuard и подключается); это
помогает, когда провайдер узнаёт WireGuard по первому пакету. Шум имеет смысл только в цепочке
under_vpn: в over_vpn WireGuard и так спрятан внутри VPN.

Ключ: «Получить ключ» регистрирует новое устройство WARP (api.cloudflareclient.com, как wgcf и
warp-plus): ключи x25519 создаются здесь же (без пакета cryptography, RFC 7748), закрытый
ключ никуда не отправляется. Либо вставляется готовая конфигурация WireGuard / AmneziaWG
([Interface] PrivateKey, Address, Jc..., [Peer] PublicKey, Endpoint, Reserved).
"""
import base64
import datetime
import json
import os
import re
import urllib.request

WARP_PEER = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="  # открытый ключ серверов WARP
ENDPOINT = "162.159.192.1:2408"   # адрес, а не engage.cloudflareclient.com: без DNS до туннеля
API = "https://api.cloudflareclient.com/v0a2158/reg"
PROTOCOLS = {"wireguard": "WireGuard", "amneziawg": "AmneziaWG (шум перед рукопожатием)"}
CHAINS = {"over_vpn": "VPN → WARP: сайты видят адрес Cloudflare, а не сервера VPN",
          "under_vpn": "WARP → VPN: провайдер видит только обмен с Cloudflare"}


def default() -> dict:
    return {"enabled": False, "protocol": "wireguard", "chain": "over_vpn",
            "private_key": "", "peer_public_key": WARP_PEER, "endpoint": ENDPOINT,
            "address_v4": "172.16.0.2/32", "address_v6": "", "reserved": [0, 0, 0],
            "mtu": 1280, "jc": 4, "jmin": 40, "jmax": 70}


def normalize(w: dict | None) -> dict:
    result = default()
    for key, value in (w or {}).items():
        if key in result:
            result[key] = value
    if result["protocol"] not in PROTOCOLS:
        result["protocol"] = "wireguard"
    if result["chain"] not in CHAINS:
        result["chain"] = "over_vpn"
    return result


# ---------------- ключи x25519 (RFC 7748) ----------------
_P = 2 ** 255 - 19
_A24 = 121665


def x25519(scalar: bytes, point: bytes) -> bytes:
    """Умножение точки кривой Curve25519 (лестница Монтгомери, RFC 7748 §5)."""
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    n = int.from_bytes(k, "little")
    u = int.from_bytes(point, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, u, 1, 0
    for t in reversed(range(255)):
        bit = (n >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % _P, (x2 - z2) % _P
        aa, bb = a * a % _P, b * b % _P
        e = (aa - bb) % _P
        c, d = (x3 + z3) % _P, (x3 - z3) % _P
        da, cb = d * a % _P, c * b % _P
        x3, z3 = (da + cb) ** 2 % _P, u * (da - cb) ** 2 % _P
        x2, z2 = aa * bb % _P, e * (aa + _A24 * e) % _P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


def public_key(private_b64: str) -> str:
    raw = base64.b64decode(private_b64)
    if len(raw) != 32:
        raise ValueError("закрытый ключ WireGuard — 32 байта в base64")
    return base64.b64encode(x25519(raw, (9).to_bytes(32, "little"))).decode()


def keypair() -> tuple[str, str]:
    raw = bytearray(os.urandom(32))
    raw[0] &= 248
    raw[31] = (raw[31] & 127) | 64
    private = base64.b64encode(bytes(raw)).decode()
    return private, public_key(private)


# ---------------- регистрация и конфигурации ----------------
def register(timeout: float = 20.0) -> dict:
    """Новое устройство WARP: ключи — здесь, Cloudflare получает только открытый ключ.
    Возвращает поля для профиля (private_key, address_v4/v6, peer_public_key, reserved,
    endpoint). Прокси из переменных окружения не используется."""
    private, public = keypair()
    body = json.dumps({
        "key": public, "install_id": "", "fcm_token": "", "model": "PC", "serial_number": "",
        "locale": "en_US",
        "tos": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    }).encode()
    request = urllib.request.Request(API, data=body, method="POST", headers={
        "User-Agent": "okhttp/3.12.1", "CF-Client-Version": "a-6.10-2158",
        "Content-Type": "application/json; charset=UTF-8"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=timeout) as response:
        data = json.loads(response.read(1 << 20).decode("utf-8"))
    return from_registration(data, private)


def from_registration(data: dict, private: str) -> dict:
    config = data.get("config") or {}
    peer = (config.get("peers") or [{}])[0]
    addresses = (config.get("interface") or {}).get("addresses") or {}
    if not addresses.get("v4"):
        raise ValueError("Cloudflare не выдал адрес WARP: " + str(data)[:200])
    reserved = [0, 0, 0]
    if config.get("client_id"):
        raw = base64.b64decode(config["client_id"])
        reserved = list(raw[:3]) + [0] * (3 - len(raw[:3]))
    host = ((peer.get("endpoint") or {}).get("host") or "")
    port = host.rsplit(":", 1)[-1] if ":" in host else "2408"
    return {"private_key": private, "peer_public_key": peer.get("public_key") or WARP_PEER,
            "address_v4": addresses["v4"].split("/")[0] + "/32",
            "address_v6": (addresses["v6"].split("/")[0] + "/128") if addresses.get("v6") else "",
            "reserved": reserved, "endpoint": ENDPOINT.split(":")[0] + ":" + port}


def parse_conf(text: str) -> dict:
    """Конфигурация WireGuard или AmneziaWG (.conf) → поля WARP. Параметры AmneziaWG S1, S2,
    H1–H4 не переносятся: Xray их не поддерживает (они нужны только серверам AmneziaWG)."""
    section, values = "", {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        key, sep, value = line.partition("=")
        if sep:
            values.setdefault(f"{section}.{key.strip().lower()}", value.strip())
    private = values.get("interface.privatekey", "")
    if not private:
        raise ValueError("В конфигурации нет [Interface] PrivateKey")
    public_key(private)  # проверка формата
    result = {"private_key": private}
    v4, v6 = [], []
    for addr in values.get("interface.address", "").split(","):
        addr = addr.strip()
        if addr:
            (v6 if ":" in addr else v4).append(addr if "/" in addr else
                                               addr + ("/128" if ":" in addr else "/32"))
    if not v4 and not v6:
        raise ValueError("В конфигурации нет [Interface] Address")
    result["address_v4"] = v4[0] if v4 else ""
    result["address_v6"] = v6[0] if v6 else ""
    if values.get("peer.publickey"):
        result["peer_public_key"] = values["peer.publickey"]
    if values.get("peer.endpoint"):
        result["endpoint"] = values["peer.endpoint"]
    if values.get("interface.mtu", "").isdigit():
        result["mtu"] = int(values["interface.mtu"])
    reserved = values.get("peer.reserved") or values.get("interface.reserved", "")
    if reserved:
        parts = [p for p in re.split(r"[,\s]+", reserved) if p]
        if len(parts) == 3 and all(p.isdigit() for p in parts):
            result["reserved"] = [int(p) % 256 for p in parts]
        else:  # base64 client_id
            raw = base64.b64decode(reserved + "=" * (-len(reserved) % 4))
            result["reserved"] = list(raw[:3])
    junk = {k: values.get(f"interface.{k}", "") for k in ("jc", "jmin", "jmax")}
    if all(v.isdigit() for v in junk.values()):
        result.update({k: int(v) for k, v in junk.items()})
        result["protocol"] = "amneziawg"
    return result


def problems(w: dict) -> list[str]:
    """Чего не хватает для подключения (пусто — можно)."""
    errors = []
    try:
        public_key(w.get("private_key") or "")
    except (ValueError, TypeError):
        errors.append("нет ключа WARP (кнопка «Получить ключ» или «Вставить конфигурацию»)")
    if not re.match(r"^\S+:\d{1,5}$", str(w.get("endpoint") or "")):
        errors.append("адрес сервера WARP — вида 162.159.192.1:2408")
    if not (w.get("address_v4") or w.get("address_v6")):
        errors.append("нет адреса WARP (IPv4 или IPv6)")
    if w.get("protocol") == "amneziawg" and not (
            0 < int(w.get("jc") or 0) <= 128 and 0 < int(w.get("jmin") or 0)
            <= int(w.get("jmax") or 0) <= 1280):
        errors.append("шум AmneziaWG: Jc 1–128, 0 < Jmin ≤ Jmax ≤ 1280")
    return errors


def outbounds(w: dict, interface: str = "", log=None) -> list[dict]:
    """Исходящие Xray для WARP: «warp» (WireGuard) и, для AmneziaWG в цепочке under_vpn,
    «warp-noise» (freedom с шумом), через который WireGuard подключается."""
    say = log or (lambda text: None)
    w = normalize(w)
    address = [a for a in (w["address_v4"], w["address_v6"]) if a]
    warp = {"tag": "warp", "protocol": "wireguard", "settings": {
        "secretKey": w["private_key"], "address": address,
        "peers": [{"publicKey": w["peer_public_key"], "endpoint": w["endpoint"],
                   "allowedIPs": ["0.0.0.0/0", "::/0"], "keepAlive": 25}],
        "reserved": [int(x) % 256 for x in (w["reserved"] or [0, 0, 0])][:3],
        "mtu": int(w["mtu"] or 1280), "noKernelTun": True,
        "domainStrategy": "ForceIP" if w["address_v6"] else "ForceIPv4"}}
    result = [warp]
    sockopt: dict = {}
    if w["chain"] == "over_vpn":
        sockopt["dialerProxy"] = "proxy"
        if w["protocol"] == "amneziawg":
            say("WARP: шум AmneziaWG не нужен — WireGuard идёт внутри VPN")
    else:
        if interface:  # TUN через Xray: до Cloudflare — через настоящий адаптер
            sockopt["interface"] = interface
        if w["protocol"] == "amneziawg":
            noise = {"type": "rand", "packet": f"{int(w['jmin'])}-{int(w['jmax'])}",
                     "delay": "5-10"}
            freedom = {"tag": "warp-noise", "protocol": "freedom",
                       "settings": {"noises": [dict(noise) for _ in range(int(w["jc"]))]}}
            if interface:
                freedom["streamSettings"] = {"sockopt": {"interface": interface}}
            result.append(freedom)
            sockopt = {"dialerProxy": "warp-noise"}
    if sockopt:
        warp["streamSettings"] = {"sockopt": sockopt}
    return result
