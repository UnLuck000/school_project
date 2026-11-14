"""Способы подключения VPN (прототип).

• WireGuardBackend — через официальный клиент WireGuard для Windows: wireguard.exe
  /installtunnelservice <conf> создаёт службу туннеля и сетевой адаптер (нужны права
  администратора), /uninstalltunnelservice <имя> — отключение. Подключение пишется в журнал
  действий: отмена — отключение туннеля.
• OpenVPNBackend — openvpn.exe --config <ovpn> как дочерний процесс; вывод — в журнал окна,
  подключено после «Initialization Sequence Completed».
• SingBoxBackend — VLESS в режиме TUN: sing-box (vpn/singbox.py) + Xray, по умолчанию;
• XrayBackend — VLESS через Xray-core (vpn/xray.py): системный прокси или запасной TUN;
• DemoBackend — имитация без сервера, чтобы проверить окно.

Не реализовано (додумать): kill switch (правила брандмауэра на время подключения),
разделение туннеля по программам, свой протокол, проверка утечек DNS.
"""
import json
import os
import random
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

from recovery import journal
from vpn import procguard
import datadirs

TUNNEL_DIR = datadirs.CACHE / "vpn"
CREATE_NO_WINDOW = 0x08000000

DISCONNECTED, CONNECTING, CONNECTED, ERROR = "disconnected", "connecting", "connected", "error"
# ядра ещё завершаются (sing-box — до 8 с): новое подключение заняло бы их порты
DISCONNECTING = "disconnecting"


def _find(names: list[str], folders: list[str]) -> str:
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    for folder in folders:
        path = Path(os.path.expandvars(folder))
        for name in names:
            if (path / name).is_file():
                return str(path / name)
    return ""


def tunnel_name(name: str) -> str:
    """Имя туннеля WireGuard: буквы, цифры, «_=+.-», до 32 символов."""
    clean = re.sub(r"[^A-Za-z0-9_=+.-]", "_", name)[:32].strip("_")
    return clean or "sbit"


CORE_PROBLEMS = ("FATAL", "ERROR", "WARN", "failed", "Failed", "denied", "exists", "panic")


def core_problem(text: str) -> bool:
    """Строка ядра (Xray, sing-box) — ошибка или предупреждение, а не обычный ход работы.
    Обрывы отдельных соединений (i/o timeout до сайта) сюда тоже попадают — их сворачивает
    журнал окна."""
    return any(word in text for word in CORE_PROBLEMS) and " accepted " not in text


def xray_env(options: dict) -> dict | None:
    """Окружение Xray: у профиля маршрутизации свои файлы .dat — Xray ищет geo-файлы в
    папке options["assets"] (XRAY_LOCATION_ASSET), иначе — рядом с собой."""
    if not options.get("assets"):
        return None
    return {**os.environ, "XRAY_LOCATION_ASSET": options["assets"]}


def describe_options(options: dict, apps: list[str] | None = None) -> str:
    """«Маршрутизация: Default (российские сайты напрямую, ...)» — для журнала окна."""
    parts = [title for key, title in (("route_ru", "российские сайты напрямую"),
                                      ("block_ads", "реклама блокируется"),
                                      ("mux", "Mux"), ("fragment", "фрагментация"))
             if options.get(key)]
    if options.get("adblock") or options.get("adblock_count"):
        count = options.get("adblock_count") or len(options["adblock"])
        parts.append(f"AdBlock: {count} доменов")
    if options.get("warp"):
        parts.append("WARP")
    if options.get("advanced"):
        parts.append(f"дополнительных правил: {len(options['advanced'])}")
        if options.get("mode") == "singbox":
            blind = sum(1 for r in options["advanced"] if r.get("source") or r.get("source_port"))
            if blind:
                parts.append(f"у {blind} условие «источник» не сработает: в TUN источник "
                             "всегда 127.0.0.1")
    if options.get("assets"):
        parts.append("свои файлы .dat")
    if apps:
        parts.append(f"программ напрямую: {len(apps)}")
    return f"Маршрутизация: {options.get('profile') or 'Default'}" + (
        f" ({', '.join(parts)})" if parts else "")


def add_local_proxy(config: dict, log, strict: bool = False) -> dict[str, int]:
    """Локальные прокси для программ (SOCKS5 и/или HTTP), если включены и порты свободны.
    Занятый порт — запись в журнал, VPN подключается без него; strict (режим «Только
    локальный прокси») — ошибка. Добавлять ДО apply_options: правила действуют и на них."""
    from vpn import xray
    started = {}
    for kind, port in xray.local_ports().items():
        owner = xray.port_owner(port)
        title = "SOCKS5" if kind == "socks" else "HTTP"
        if owner:
            if strict:
                raise OSError(f"порт {title} {port} занят ({owner}) — закройте программу или "
                              "выберите другой порт")
            log(f"Локальный {title}-прокси не запущен: порт {port} занят ({owner})")
            continue
        xray.add_local_inbound(config, kind, port)
        started[kind] = port
    if strict and not started:
        raise OSError("в режиме «Только локальный прокси» включите SOCKS5- или HTTP-прокси "
                      "в настройках клиента")
    return started


class Backend:
    available = True
    missing = ""  # что установить, если недоступен

    def __init__(self, log):
        self.log = log  # log(text) из любого потока
        self.local_ports: dict[str, int] = {}  # локальные прокси для программ (Xray)
        self.blocked = False  # обрыв при kill switch: интернет перекрыт до решения
        self.state = DISCONNECTED
        self.since = 0.0
        self.adapter = ""
        self.error = ""

    def connect(self, profile) -> None:
        raise NotImplementedError

    def disconnect(self) -> None:
        raise NotImplementedError

    def counters(self) -> tuple[int, int]:
        """(получено, отправлено) байт через адаптер туннеля."""
        if not self.adapter:
            return 0, 0
        try:
            import psutil
            stats = psutil.net_io_counters(pernic=True).get(self.adapter)
        except Exception:
            return 0, 0
        return (stats.bytes_recv, stats.bytes_sent) if stats else (0, 0)

    def _set(self, state: str, error: str = "") -> None:
        self.state, self.error = state, error
        from diag import features
        if state == CONNECTED:
            features.end_if_active("vpn.connect", True, backend=type(self).__name__)
        elif state == ERROR:
            features.end_if_active("vpn.connect", False, error=error or "ошибка подключения")
        if state == CONNECTED:
            self.since = time.time()
            for kind, port in self.local_ports.items():
                self.log(f"Локальный {'SOCKS5' if kind == 'socks' else 'HTTP'}-прокси для "
                         f"программ: 127.0.0.1:{port}")


class WireGuardBackend(Backend):
    def __init__(self, log):
        super().__init__(log)
        self.exe = _find(["wireguard.exe"], [r"%ProgramFiles%\WireGuard"])
        self.available = bool(self.exe)
        self.missing = "WireGuard для Windows (wireguard.com/install)"
        self.name = ""

    def connect(self, profile) -> None:
        self._set(CONNECTING)
        self.name = tunnel_name(profile.name)
        TUNNEL_DIR.mkdir(parents=True, exist_ok=True)
        conf = (TUNNEL_DIR / f"{self.name}.conf").resolve()
        conf.write_text(profile.config, encoding="utf-8")
        self.log(f"WireGuard: устанавливаю туннель {self.name}...")
        result = subprocess.run([self.exe, "/installtunnelservice", str(conf)],
                                capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
        if result.returncode != 0:
            conf.unlink(missing_ok=True)
            text = (result.stderr or result.stdout).strip() or f"код {result.returncode}"
            self._set(ERROR, f"WireGuard: {text} (нужны права администратора)")
            self.log(self.error)
            return
        self.adapter = self.name
        journal.log_action(f"VPN: подключён туннель WireGuard {self.name}", "vpn_disconnect",
                           {"exe": self.exe, "name": self.name, "conf": str(conf)})
        self._set(CONNECTED)
        self.log(f"WireGuard: туннель {self.name} подключён")

    def disconnect(self) -> None:
        if not self.name:
            self._set(DISCONNECTED)
            return
        self.log(f"WireGuard: отключаю {self.name}...")
        _uninstall(self.exe, self.name, str((TUNNEL_DIR / f"{self.name}.conf").resolve()))
        self.adapter = ""
        self._set(DISCONNECTED)
        self.log("WireGuard: отключено")


def _uninstall(exe: str, name: str, conf: str) -> None:
    subprocess.run([exe, "/uninstalltunnelservice", name], capture_output=True,
                   creationflags=CREATE_NO_WINDOW)
    Path(conf).unlink(missing_ok=True)


@journal.undo_op("vpn_disconnect")
def _undo_connect(d: dict) -> str:
    _uninstall(d["exe"], d["name"], d["conf"])
    return f"Туннель WireGuard {d['name']} отключён"


class OpenVPNBackend(Backend):
    def __init__(self, log):
        super().__init__(log)
        self.exe = _find(["openvpn.exe"], [r"%ProgramFiles%\OpenVPN\bin",
                                           r"%ProgramFiles%\OpenVPN Connect"])
        self.available = bool(self.exe)
        self.missing = "OpenVPN Community (openvpn.net/community-downloads)"
        self.proc: subprocess.Popen | None = None
        self.conf: Path | None = None

    def connect(self, profile) -> None:
        self._set(CONNECTING)
        TUNNEL_DIR.mkdir(parents=True, exist_ok=True)
        self.conf = (TUNNEL_DIR / f"{tunnel_name(profile.name)}.ovpn").resolve()
        self.conf.write_text(profile.config, encoding="utf-8")
        self.proc = subprocess.Popen([self.exe, "--config", str(self.conf), "--verb", "3"],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                     encoding="utf-8", errors="replace",
                                     creationflags=CREATE_NO_WINDOW)
        procguard.bind(self.proc, self.log)
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        proc = self.proc
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            self.log("OpenVPN: " + line[-200:])
            if "Initialization Sequence Completed" in line:
                self._set(CONNECTED)
            match = re.search(r"TAP-WIN32 device \[(.+?)\] opened|"
                              r"(?:DCO|wintun) device \[(.+?)\] opened", line)
            if match:
                self.adapter = match.group(1) or match.group(2)
            if "AUTH_FAILED" in line:
                self._set(ERROR, "OpenVPN: неверный логин или пароль")
        if self.state != DISCONNECTED:
            self._set(ERROR if self.state != CONNECTED else DISCONNECTED,
                      self.error or "OpenVPN завершился")
        if self.conf:
            self.conf.unlink(missing_ok=True)

    def disconnect(self) -> None:
        proc, self.proc = self.proc, None
        self._set(DISCONNECTED)
        self.adapter = ""
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        self.log("OpenVPN: отключено")


class DemoBackend(Backend):
    """Имитация: подключение за 1,5 с, случайный трафик."""

    def __init__(self, log):
        super().__init__(log)
        self._rx = self._tx = 0

    def connect(self, profile) -> None:
        self._set(CONNECTING)
        self.log(f"Демо: подключаюсь к {profile.server}...")

        def done():
            time.sleep(1.5)
            if self.state == CONNECTING:
                self._rx = self._tx = 0
                self._set(CONNECTED)
                self.log("Демо: подключено (трафик не шифруется — это имитация)")

        threading.Thread(target=done, daemon=True).start()

    def disconnect(self) -> None:
        self._set(DISCONNECTED)
        self.log("Демо: отключено")

    def counters(self) -> tuple[int, int]:
        if self.state == CONNECTED:
            self._rx += random.randint(2_000, 400_000)
            self._tx += random.randint(500, 60_000)
        return self._rx, self._tx


class XrayBackend(Backend):
    def __init__(self, log):
        super().__init__(log)
        from vpn import xray
        self.x = xray
        self.exe = xray.find_xray()
        self.available = bool(self.exe)
        self.missing = ("Xray-core: xray.exe в vpn/bin, в PATH или путь в настройке "
                        "vpn/xray_path (github.com/XTLS/Xray-core/releases)")
        self.proc: subprocess.Popen | None = None
        self.mode = "proxy"
        self.old_proxy: dict | None = None
        self.server = ""
        self.config_path: Path | None = None
        self.env: dict | None = None

    def connect(self, profile) -> None:
        self._set(CONNECTING)
        x = self.x
        self.mode = {"tun-xray": "tun", "local": "local"}.get(profile.mode, "proxy")
        try:
            v = x.parse_vless(profile.config)
            interface = ""
            if self.mode == "tun":
                gateway, interface = x.default_route()
                if not gateway:
                    raise OSError("не найден маршрут по умолчанию")
                self.server = x.server_ip(v["address"])
                self.log(f"Xray TUN: шлюз {gateway} ({interface}), сервер {self.server}")
            if self.mode != "local":
                x.ensure_free(x.SOCKS_PORT, x.HTTP_PORT)
            if self.mode == "local":
                # только программы с прокси 127.0.0.1:порт: ни туннеля, ни системного прокси;
                # без порта у режима нет смысла — занят или выключен, подключения нет
                config = x.build_config(v, "proxy")
                config["inbounds"] = []
                self.local_ports = add_local_proxy(config, self.log, strict=True)
            else:
                config = x.build_config(v, self.mode, interface)
                self.local_ports = add_local_proxy(config, self.log)
            opts = x.options_from_settings(self.mode, self.log, self.exe)
            opts["interface"] = interface
            x.apply_options(config, v, opts, self.log)
            self.log(describe_options(opts))
            self.env = xray_env(opts)
            self.config_path = x.write_config(config, TUNNEL_DIR)
        except (OSError, ValueError) as e:
            self._set(ERROR, f"Xray: {e}")
            self.log(self.error)
            return
        title = {"tun": "TUN", "local": "только локальный прокси"}.get(self.mode,
                                                                         "системный прокси")
        self.log(f"Xray: запуск ({title})...")
        self.proc = subprocess.Popen([self.exe, "run", "-c", str(self.config_path)],
                                     cwd=str(Path(self.exe).parent), stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                                     errors="replace", creationflags=CREATE_NO_WINDOW,
                                     env=self.env)
        procguard.bind(self.proc, self.log)
        threading.Thread(target=self._read, daemon=True).start()
        if self.mode == "tun":
            error = x.setup_tun_routes(self.server, gateway)
            if error:
                self._fail(f"Xray TUN: маршруты не настроены: {error}")
                return
            self.adapter = x.TUN_NAME
        elif self.mode == "local":
            if not all(x.wait_port(port) for port in self.local_ports.values()):
                self._fail("Xray не открыл локальный прокси (смотрите журнал)")
                return
            self.log("Через VPN идут только программы с прокси " + ", ".join(
                f"127.0.0.1:{p}" for p in self.local_ports.values()) +
                ", остальной трафик — как без VPN (при обрыве у них просто нет связи — "
                "это и есть kill switch для этого режима)")
        else:
            if not x.wait_port(x.HTTP_PORT):
                self._fail("Xray не открыл локальный прокси (смотрите журнал)")
                return
            try:
                self.old_proxy = x.enable_system_proxy()
            except OSError as e:
                self._fail(f"Не удалось включить системный прокси: {e}")
                return
            self.log(f"Системный прокси: 127.0.0.1:{x.HTTP_PORT} (SOCKS5 — "
                     f"127.0.0.1:{x.SOCKS_PORT})")
        self._set(CONNECTED)
        self.log("Xray: подключено")

    def _read(self) -> None:
        proc = self.proc
        for line in proc.stdout:
            if line.strip():
                self.log("Xray: " + line.strip()[-200:])
        if self.state in (CONNECTED, CONNECTING) and proc is self.proc:
            # kill switch в режиме системного прокси: прокси Windows остаётся направленным на
            # остановившийся Xray — программы не уходят в интернет мимо VPN
            keep = self.mode == "proxy" and self.old_proxy is not None and \
                bool(self.x._cfg("vpn/killswitch", False))
            saved = self.old_proxy
            if keep:
                self.old_proxy = None
            self._cleanup()
            if keep:
                self.old_proxy = saved
                self.blocked = True
                self._set(ERROR, "Xray завершился. Kill switch: системный прокси оставлен, "
                                 "интернет перекрыт — «Снять блокировку» в окне VPN")
            else:
                self._set(ERROR, "Xray завершился")
            self.log(self.error)

    def release_block(self) -> bool:
        """Снять блокировку после обрыва: вернуть прежний системный прокси."""
        self.blocked = False
        if self.old_proxy is None:
            return False
        try:
            self.x.restore_system_proxy(self.old_proxy)
        finally:
            self.old_proxy = None
        return True

    def _fail(self, text: str) -> None:
        self._cleanup()
        self._set(ERROR, text)
        self.log(text)

    def _cleanup(self) -> None:
        if self.old_proxy is not None:
            try:
                self.x.restore_system_proxy(self.old_proxy)
                self.log("Системный прокси возвращён")
            except OSError as e:
                self.log(f"Системный прокси не возвращён: {e}")
            self.old_proxy = None
        proc, self.proc = self.proc, None
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        if self.mode == "tun":
            self.x.remove_tun_routes(self.server)
        if self.config_path is not None:
            self.config_path.unlink(missing_ok=True)  # в файле ключ подключения
            self.config_path = None
        self.adapter = ""

    def disconnect(self) -> None:
        self._set(DISCONNECTING)
        self._cleanup()
        self._set(DISCONNECTED)
        self.log("Xray: отключено")

    def counters(self) -> tuple[int, int]:
        if self.mode == "tun":
            return super().counters()
        try:  # системный прокси: весь трафик идёт через процесс Xray
            import psutil
            io = psutil.Process(self.proc.pid).io_counters()
            return io.read_bytes, io.write_bytes
        except Exception:
            return 0, 0


class SingBoxBackend(Backend):
    """TUN: sing-box забирает трафик системы и отдаёт его в SOCKS Xray, Xray ведёт VLESS.
    Адаптер, маршруты и DNS sing-box настраивает сам; соединения Xray — напрямую."""

    def __init__(self, log):
        super().__init__(log)
        from vpn import singbox, xray
        self.sb, self.x = singbox, xray
        self.exe = singbox.find_singbox()
        self.xray_exe = xray.find_xray()
        self.available = bool(self.exe and self.xray_exe)
        self.missing = ("sing-box и Xray-core: sing-box.exe и xray.exe в vpn/bin, в PATH или "
                        "пути в настройках vpn/singbox_path и vpn/xray_path")
        self.proc: subprocess.Popen | None = None       # sing-box
        self.xray_proc: subprocess.Popen | None = None
        self.paths: list[Path] = []
        self.killswitch = False   # блокировка брандмауэра включена этим подключением
        self.dns_changed = False  # DNS адаптеров подменён (vpn/dnsguard.py)
        self.blocked = False      # VPN оборвался, интернет перекрыт до решения пользователя
        # в службе (service/vpnhost.py): настройки клиента и параметры маршрутизации присылает
        # окно — у службы свои настройки пустые; None — брать из настроек этого процесса
        self.settings: dict | None = None
        self.options: dict | None = None

    def _get(self, key: str):
        if self.settings is not None:
            from ui.settings import DEFAULTS
            return self.settings.get(key, DEFAULTS.get(key))
        from ui import settings as cfg
        return cfg.get(key)

    def _write(self, config: dict, name: str) -> Path:
        TUNNEL_DIR.mkdir(parents=True, exist_ok=True)
        path = (TUNNEL_DIR / name).resolve()
        path.write_text(json.dumps(config, ensure_ascii=False, indent=1), encoding="utf-8")
        self.paths.append(path)
        return path

    def connect(self, profile) -> None:
        self._set(CONNECTING)
        x = self.x
        ip_mode = str(self._get("vpn/ip_mode") or "ipv4")
        kill = bool(self._get("vpn/killswitch"))
        try:
            opts = self.options if self.options is not None else \
                x.options_from_settings("singbox", self.log, self.xray_exe)
            v = x.parse_vless(profile.config)
            x.ensure_free(x.SOCKS_PORT)
            # адрес сервера — заранее, пока туннеля нет: потом системный DNS идёт через
            # туннель, а туннель — через ещё не подключённый Xray
            host = v["address"]
            v["address"] = x.server_address(host, ip_mode)
            from diag import anon
            anon.register_vpn_server(v["address"])  # разрешённый адрес сервера — не в журналы
            if v["sni"] == "" and v["security"] in ("tls", "reality"):
                v["sni"] = host
            # частные адреса и программы «напрямую» решает sing-box; у Xray — только правила
            # из настроек (российские сайты, реклама), без своих DNS-запросов (AsIs)
            xconfig = x.build_config(v, "proxy")
            xconfig["inbounds"] = [i for i in xconfig["inbounds"] if i["protocol"] == "socks"]
            xconfig["inbounds"][0].pop("sniffing", None)
            xconfig["routing"] = {"domainStrategy": "AsIs", "rules": []}
            self.local_ports = add_local_proxy(xconfig, self.log)
            x.apply_options(xconfig, v, opts, self.log)
            xpath = self._write(xconfig, "xray-tun.json")
            apps = [a for a in str(self._get("vpn/direct_apps") or "").splitlines()
                    if a.strip()]
            from vpn import windns
            win_dns = windns.manual_dns()  # до dnsguard.protect: он трогает только роутер
            if win_dns["v4"] or win_dns["v6"]:
                self.log(windns.describe(win_dns))
            def singbox_config(tun_address: str | None = None) -> Path:
                return self._write(self.sb.build_config(
                    x.SOCKS_PORT, self.xray_exe, ip_mode, apps, opts["block_quic"],
                    opts["block_udp"], str(self._get("vpn/dns_server") or "1.1.1.1"), win_dns,
                    strict_route=self._get("vpn/strict_route") is not False,
                    tun_address=tun_address), "sing-box.json")
            spath = singbox_config()
            self.log(describe_options(opts, apps))
        except (OSError, ValueError) as e:
            self._fail(f"VLESS: {e}")
            return
        from diag import features
        features.step("vpn.connect", "конфигурация")
        self.log("Xray: запуск (VLESS, локальный SOCKS для туннеля)...")
        self.xray_proc = subprocess.Popen(
            [self.xray_exe, "run", "-c", str(xpath)], cwd=str(Path(self.xray_exe).parent),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8",
            errors="replace", creationflags=CREATE_NO_WINDOW, env=xray_env(opts))
        procguard.bind(self.xray_proc, self.log)
        threading.Thread(target=self._read, args=(self.xray_proc, "Xray"), daemon=True).start()
        if not self._wait_port(x.SOCKS_PORT):
            self._fail(self.error or "Xray не открыл локальный SOCKS (смотрите журнал)")
            return
        features.step("vpn.connect", "xray")
        self._wait_old_adapter()
        tried: list[str] = []
        while True:
            address = self.sb.free_tun_address(exclude=tuple(tried))
            if tried:  # прежний адрес занят: конфигурация с другим
                spath = singbox_config(address)
            tried.append(address)
            self.log(f"sing-box: запуск TUN, адрес {address} (нужны права администратора)...")
            self.proc = subprocess.Popen(
                [self.exe, "run", "-c", str(spath)], cwd=str(Path(self.exe).parent),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                errors="replace", creationflags=CREATE_NO_WINDOW)
            procguard.bind(self.proc, self.log)
            reader = threading.Thread(target=self._read, args=(self.proc, "sing-box"),
                                      daemon=True)
            reader.start()
            if self._wait_adapter():
                break
            reader.join(timeout=2)  # ядро упало: дочитать его последнюю строку (причину)
            # «set ipv4 address: The object already exists»: адрес ещё держит адаптер
            # прежнего sing-box (Windows убирает его не сразу) или чужой клиент — другой адрес
            if "already exists" in self.error and len(tried) < len(self.sb.TUN_CANDIDATES) \
                    and self.state == CONNECTING:
                self.log(f"sing-box: адрес {address} занят — пробую другой")
                proc, self.proc = self.proc, None
                if proc is not None and proc.poll() is None:
                    proc.kill()
                self.error = ""
                continue
            if not self._aborted():
                self._fail(self.error or "sing-box не создал адаптер TUN (смотрите журнал)")
            return
        self.adapter = self.sb.TUN_NAME
        features.step("vpn.connect", "адаптер TUN")
        from vpn import dnsguard
        if self._aborted():
            return
        # Подмена DNS и kill switch друг от друга не зависят, а каждая — это запуски PowerShell
        # по 1–3 с (из 11,5 с подключения на них уходило 9): выполняются одновременно.
        ks_error: list[OSError] = []
        ks_thread = None
        if kill:
            from vpn import killswitch

            def enable_killswitch():
                try:
                    killswitch.enable(self.sb.TUN_NAME, [self.xray_exe, self.exe])
                    self.killswitch = True
                except OSError as e:
                    ks_error.append(e)

            ks_thread = threading.Thread(target=enable_killswitch, name="vpn-killswitch",
                                         daemon=True)
            ks_thread.start()
        dns_error = None
        try:
            changed = dnsguard.protect()
            self.dns_changed = bool(changed)
            if changed:
                self.log(f"DNS {', '.join(changed)} на время VPN — "
                         f"{', '.join(dnsguard.PUBLIC_DNS)} (через туннель, без утечки)")
        except OSError as e:
            dns_error = e
        if ks_thread is not None:
            ks_thread.join()  # до любого выхода: _fail снимает kill switch, если он включён
            if self.killswitch:
                features.step("vpn.connect", "kill switch")
                self.log("Kill switch: интернет только через туннель")
        if dns_error is not None:
            self._fail(f"DNS не защищён, VPN отключён: {dns_error}")
            return
        if ks_error:
            self._fail(f"Kill switch не включён, VPN отключён: {ks_error[0]}")
            return
        if self._aborted():
            return
        self._set(CONNECTED)
        self.log(f"Подключено: весь трафик через {self.sb.TUN_NAME} → Xray → сервер"
                 + ", " + x.IP_MODES.get(ip_mode, ip_mode))

    # ядро ещё живо — ждём дольше: на слабом ПК (Celeron, Windows 10) Xray и sing-box
    # запускаются дольше 8–10 с, и подключение срывалось «не открыл SOCKS» / «не создал
    # адаптер». Упавшее ядро обрывает ожидание сразу
    START_TIMEOUT = 30.0

    def _wait_port(self, port: int) -> bool:
        end = time.time() + self.START_TIMEOUT
        while time.time() < end:
            if self.x.wait_port(port, timeout=1.0):
                return True
            if self.xray_proc is None or self.xray_proc.poll() is not None or self.error:
                return False
        return False

    def _wait_old_adapter(self, timeout: float = 10.0) -> None:
        """Адаптер прежнего sing-box ещё есть (ядро завершено принудительно — Windows убирает
        его не сразу): подождать, пока исчезнет."""
        import psutil
        end = time.time() + timeout
        if self.sb.TUN_NAME not in psutil.net_if_stats():
            return
        self.log("sing-box: адаптер прежнего подключения ещё не убран — жду")
        while time.time() < end and self.sb.TUN_NAME in psutil.net_if_stats():
            time.sleep(0.5)

    def _wait_adapter(self, timeout: float | None = None) -> bool:
        """Адаптер TUN появился и sing-box после этого жив. Адаптер создаётся раньше, чем ему
        назначается адрес: ошибка («The object already exists») приходит следом, поэтому
        после появления — ещё секунда проверки."""
        import psutil
        end = time.time() + (timeout or self.START_TIMEOUT)
        while time.time() < end:
            if self.proc is None or self.proc.poll() is not None or self.error:
                return False
            if self.sb.TUN_NAME in psutil.net_if_stats():
                time.sleep(1.0)
                return self.proc is not None and self.proc.poll() is None and not self.error
            time.sleep(0.3)
        return False

    def _aborted(self) -> bool:
        """Подключение уже сорвалось: ядро упало (его поток вывода поставил ERROR) или
        пользователь нажал «Отключить». Тогда дальше DNS и kill switch не трогаем, а то, что
        это подключение успело поменять, возвращаем — раньше после падения sing-box подмена
        DNS и kill switch всё равно включались."""
        alive = all(p is not None and p.poll() is None for p in (self.proc, self.xray_proc))
        if self.state == CONNECTING and alive and not self.error:
            return False
        if self.killswitch or self.dns_changed or alive:
            self._cleanup()
        if self.state == CONNECTING:
            self._set(ERROR, self.error or "ядро VPN завершилось во время подключения")
            self.log(self.error)
        return True

    def _read(self, proc: subprocess.Popen, title: str) -> None:
        for line in proc.stdout:
            line = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()  # цвета в выводе
            if not line:
                continue
            self.log(f"{title}: " + line[-200:])
            if "FATAL" in line or "Failed to start" in line:
                self.error = f"{title}: " + line.split("FATAL", 1)[-1].strip()[-200:]
        if self.state == CONNECTING and "already exists" in self.error:
            return  # connect повторит запуск с другим адресом TUN
        if self.state in (CONNECTED, CONNECTING) and proc in (self.proc, self.xray_proc):
            dropped = self.killswitch
            self._cleanup(keep_block=dropped)  # обрыв: блокировка остаётся — в этом смысл
            self.blocked = dropped
            reason = self.error or f"{title} завершился"
            if dropped:
                reason += ". Интернет перекрыт kill switch — «Снять блокировку» в окне VPN"
            self._set(ERROR, reason)
            self.log(reason)

    def _fail(self, text: str) -> None:
        self._cleanup()
        self._set(ERROR, text)
        self.log(text)

    def release_block(self) -> bool:
        """Снять блокировку после обрыва (кнопка в окне VPN)."""
        from vpn import dnsguard, killswitch
        self.blocked = False
        if self.dns_changed:
            dnsguard.restore()
            self.dns_changed = False
        return killswitch.disable()

    def _cleanup(self, keep_block: bool = False) -> None:
        if self.killswitch and not keep_block:
            from vpn import killswitch
            killswitch.disable()
            self.log("Kill switch снят")
        self.killswitch = False
        if self.dns_changed and not keep_block:
            from vpn import dnsguard
            dnsguard.restore()
            self.log("DNS адаптеров возвращён")
            self.dns_changed = False
        for attr in ("proc", "xray_proc"):  # sing-box первым: он убирает адаптер и маршруты
            proc = getattr(self, attr)
            setattr(self, attr, None)
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.kill()
        for path in self.paths:
            path.unlink(missing_ok=True)  # в файлах ключ подключения
        self.paths = []
        self.adapter = ""

    def disconnect(self) -> None:
        self._set(DISCONNECTING)
        self._cleanup()
        self._set(DISCONNECTED)
        self.log("Отключено")


# окно без прав со службой (service/remote.py): TUN, WireGuard и OpenVPN подключает служба
REMOTE = None


def needs_service(kind: str, mode: str = "") -> bool:
    return kind in ("wireguard", "openvpn") or (kind == "vless" and mode in ("tun", ""))


def backend_for(kind: str, log, mode: str = "") -> Backend:
    if REMOTE is not None and needs_service(kind, mode):
        return REMOTE.backend(kind, log, mode)
    if kind == "vless":  # tun — sing-box + Xray; proxy, tun-xray, local — один Xray
        return SingBoxBackend(log) if mode in ("tun", "") else XrayBackend(log)
    return {"wireguard": WireGuardBackend, "openvpn": OpenVPNBackend}.get(kind, DemoBackend)(log)


def public_ip(timeout: int = 8) -> str:
    """Внешний IP-адрес (api.ipify.org): виден ли адрес сервера VPN."""
    import urllib.request
    req = urllib.request.Request("https://api.ipify.org",
                                 headers={"User-Agent": "StretchBIT/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("ascii", "replace").strip()
