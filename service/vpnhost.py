r"""Ядра VPN в службе (шаг 6 service/DESIGN.md): то, чему нужны права администратора, —
TUN sing-box + Xray (с kill switch и подменой DNS адаптеров), туннель WireGuard и OpenVPN.
Системный прокси (HKCU пользователя) и «только локальный прокси» прав не требуют — они
остаются в окне (vpn/backends.XrayBackend).

Окно присылает профиль (ссылку или текст конфигурации), настройки клиента (SETTINGS) и
готовые параметры маршрутизации (xray.options_from_settings окна). Служба работает от имени
системы, поэтому ничего исполняемого из присланного не берёт:
  * xray.exe и sing-box.exe — только свои (vpn/bin программы), не пути из настроек окна;
  * в .ovpn запрещены скрипты, плагины и пути к файлам (OVPN_FORBIDDEN, файлы — только
    встроенные блоки <ca>...</ca>), в .conf WireGuard — PreUp/PostUp/PreDown/PostDown;
  * geo-файлы профиля маршрутизации копируются в папку службы (*.dat, не больше ASSET_LIMIT);
  * параметры маршрутизации — только известные ключи OPTION_KEYS.
Журнал подключения и состояние уходят окну событиями «vpn» (служба — ServiceCore.emit_data).
"""
import os
import re
import shutil
import threading
from pathlib import Path

SETTINGS = {"vpn/ip_mode": str, "vpn/killswitch": bool, "vpn/direct_apps": str,
            "vpn/dns_server": str, "vpn/strict_route": bool}
OPTION_KEYS = {"route_ru", "block_ads", "block_quic", "block_udp", "rules_proxy",
               "rules_direct", "rules_block", "advanced", "ip_files", "adblock", "warp",
               "profile", "mux", "fragment", "cert_blocked", "mode", "ip_mode", "dns",
               "assets", "adblock_ext", "adblock_count"}
KINDS = ("vless", "wireguard", "openvpn")
ASSET_LIMIT = 256 << 20
MAX_CONFIG = 256 * 1024
OVPN_FORBIDDEN = {
    "up", "down", "route-up", "route-pre-down", "ipchange", "client-connect",
    "client-disconnect", "learn-address", "auth-user-pass-verify", "tls-verify", "plugin",
    "script-security", "management", "management-client-user", "log", "log-append", "writepid",
    "status", "cd", "config", "chroot", "daemon", "askpass", "auth-user-pass", "tmp-dir",
    "setenv", "setenv-safe", "pull-filter", "dhcp-option-up", "iproute", "service",
    "win-sys", "dev-node", "replay-persist", "echo", "x509-track"}
OVPN_FILES = {"ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "dh", "pkcs12",
              "crl-verify", "secret", "extra-certs", "http-proxy-user-pass"}
WG_FORBIDDEN = {"preup", "postup", "predown", "postdown"}


def window_options(log) -> dict:
    """Окно: параметры маршрутизации для службы (xray.options_from_settings). Список AdBlock
    при готовом файле .dat не передаётся (сотни тысяч доменов): Xray берёт его из файла."""
    from vpn import xray
    opts = xray.options_from_settings("singbox", log, xray.find_xray())
    opts["ip_files"] = sorted(opts.get("ip_files") or [])
    if opts.get("adblock_ext"):
        opts["adblock_count"] = len(opts.get("adblock") or [])
        opts["adblock"] = []
    return opts


def check_openvpn(text: str) -> None:
    inline = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        tag = re.fullmatch(r"<(/?)([a-z0-9-]+)>", line.lower())
        if tag:
            inline = None if tag.group(1) else tag.group(2)
            continue
        if inline:
            continue
        word = line.split()[0].lower().lstrip("-")
        if word in OVPN_FORBIDDEN:
            raise ValueError(f"OpenVPN: директива «{word}» в службе запрещена (скрипты, "
                             "файлы и управление недоступны конфигурации из окна)")
        if word in OVPN_FILES and len(line.split()) > 1 and line.split()[1] != "[inline]":
            raise ValueError(f"OpenVPN: «{word}» — только встроенным блоком <{word}>...</{word}>,"
                             " не путём к файлу")


def check_wireguard(text: str) -> None:
    for raw in text.splitlines():
        key = raw.split("=", 1)[0].strip().lower()
        if key in WG_FORBIDDEN:
            raise ValueError(f"WireGuard: «{raw.split('=', 1)[0].strip()}» (команды) в службе "
                             "запрещено")


def clean_settings(raw) -> dict:
    if not isinstance(raw, dict):
        raw = {}
    out = {}
    for key, kind in SETTINGS.items():
        value = raw.get(key)
        if value is None:
            continue
        if kind is bool:
            out[key] = bool(value)
        else:
            value = str(value)
            if len(value) > 64 * 1024 or "\0" in value:
                raise ValueError(f"настройка {key} слишком длинная")
            out[key] = value
    return out


def clean_options(raw) -> dict:
    if not isinstance(raw, dict):
        raise ValueError("параметры маршрутизации — словарём")
    opts = {k: v for k, v in raw.items() if k in OPTION_KEYS}
    opts["ip_files"] = set(opts.get("ip_files") or [])
    return opts


class VpnHost:
    """Одно подключение с правами. emit(kind, data)."""

    def __init__(self, emit, folder: Path, factory=None):
        self.emit = emit
        self.folder = Path(folder)
        self.factory = factory
        self.backend = None
        self.profile = None
        self._lock = threading.Lock()

    def _log(self, text: str) -> None:
        text = str(text)
        self.emit("vpn", {"log": text})
        # и в журнал службы: строки окна теряются, если его закрыли; ядра — только ошибки
        # (без «accepted» — куда ходит пользователь)
        from vpn.backends import core_problem
        if not text.startswith(("Xray: ", "sing-box: ")) or core_problem(text):
            from diag.log import get
            get("vpn").info("%s", text[:400])

    def _make(self, kind: str, mode: str):
        if self.factory is not None:
            return self.factory(kind, self._log, mode)
        from vpn import backends
        if kind == "vless":
            return backends.SingBoxBackend(self._log)
        return {"wireguard": backends.WireGuardBackend,
                "openvpn": backends.OpenVPNBackend}[kind](self._log)

    def _assets(self, folder: str) -> str:
        """geo-файлы профиля маршрутизации окна — копией в папку службы."""
        if not folder:
            return ""
        src = Path(folder)
        if not src.is_absolute():
            raise ValueError("папка geo-файлов — полным путём")
        dest = self.folder / "vpn-assets"
        shutil.rmtree(dest, ignore_errors=True)
        dest.mkdir(parents=True, exist_ok=True)
        total = 0
        for item in src.iterdir():
            if item.suffix.lower() != ".dat" or not item.is_file() or item.is_symlink():
                continue
            total += item.stat().st_size
            if total > ASSET_LIMIT:
                raise ValueError("geo-файлы профиля слишком большие")
            shutil.copyfile(item, dest / item.name)
        return str(dest)

    def connect(self, profile: dict, settings: dict, options: dict | None) -> dict:
        from vpn import backends, profiles
        kind, mode = str(profile.get("kind")), str(profile.get("mode") or "tun")
        if kind not in KINDS or (kind == "vless" and mode not in ("tun", "")):
            raise ValueError("в службе — только TUN (VLESS), WireGuard и OpenVPN")
        config = str(profile.get("config") or "")
        if not config or len(config) > MAX_CONFIG:
            raise ValueError("нет конфигурации профиля")
        if kind == "openvpn":
            check_openvpn(config)
        elif kind == "wireguard":
            check_wireguard(config)
        p = profiles.Profile(name=str(profile.get("name") or "VPN")[:100], kind=kind,
                             config=config, server=str(profile.get("server") or "")[:300],
                             mode=mode)
        with self._lock:
            if self.backend is not None and self.backend.state in (
                    backends.CONNECTED, backends.CONNECTING, backends.DISCONNECTING):
                raise ValueError("VPN уже подключён")
            backend = self._make(kind, mode)
            if not backend.available:
                raise ValueError(f"Не найдено: {backend.missing}")
            if kind == "vless":
                backend.settings = clean_settings(settings)
                if options is not None:
                    opts = clean_options(options)
                    opts["assets"] = self._assets(str(opts.get("assets") or ""))
                    backend.options = opts
            self.backend, self.profile = backend, p
        threading.Thread(target=self._run, args=(backend, p), daemon=True,
                         name="svc-vpn").start()
        return self.status()

    def _run(self, backend, p) -> None:
        try:
            backend.connect(p)
        except Exception as e:  # noqa: BLE001 — причину видит окно
            from diag.log import swallowed
            swallowed("служба: подключение VPN")
            backend.state, backend.error = "error", str(e)
        self.emit("vpn", {"state": self.status()})

    def disconnect(self) -> dict:
        with self._lock:
            backend = self.backend
        if backend is not None:
            backend.disconnect()
        self.emit("vpn", {"state": self.status()})
        return self.status()

    def release_block(self) -> bool:
        backend = self.backend
        return bool(backend is not None and hasattr(backend, "release_block")
                    and backend.release_block())

    def status(self) -> dict:
        b = self.backend
        if b is None:
            return {"state": "disconnected", "error": "", "since": 0.0, "blocked": False,
                    "adapter": "", "local_ports": {}, "profile": "", "pid": os.getpid()}
        return {"state": b.state, "error": b.error, "since": b.since,
                "blocked": bool(getattr(b, "blocked", False)), "adapter": b.adapter,
                "local_ports": dict(b.local_ports), "profile": self.profile.name if
                self.profile else "", "kind": self.profile.kind if self.profile else "",
                "pid": os.getpid()}

    def counters(self) -> tuple[int, int]:
        b = self.backend
        return b.counters() if b is not None else (0, 0)

    def stop(self) -> None:
        b = self.backend
        if b is not None and b.state != "disconnected":
            try:
                b.disconnect()
            except Exception:  # noqa: BLE001 — остановка службы не должна падать
                from diag.log import swallowed
                swallowed("служба: отключение VPN при остановке")
