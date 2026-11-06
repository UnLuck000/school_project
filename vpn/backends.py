"""Способы подключения VPN (прототип).

• WireGuardBackend — через официальный клиент WireGuard для Windows: wireguard.exe
  /installtunnelservice <conf> создаёт службу туннеля и сетевой адаптер (нужны права
  администратора), /uninstalltunnelservice <имя> — отключение. Подключение пишется в журнал
  действий: отмена — отключение туннеля.
• OpenVPNBackend — openvpn.exe --config <ovpn> как дочерний процесс; вывод — в журнал окна,
  подключено после «Initialization Sequence Completed».
• SingBoxBackend — VLESS в режиме TUN через sing-box (vpn/singbox.py), по умолчанию;
• XrayBackend — VLESS через Xray-core (vpn/xray.py): системный прокси или запасной TUN;
• DemoBackend — имитация без сервера, чтобы проверить окно.

Не реализовано (додумать): kill switch (правила брандмауэра на время подключения),
разделение туннеля по программам, свой протокол, проверка утечек DNS.
"""
import os
import random
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

from recovery import journal

TUNNEL_DIR = Path("cache") / "vpn"
CREATE_NO_WINDOW = 0x08000000

DISCONNECTED, CONNECTING, CONNECTED, ERROR = "disconnected", "connecting", "connected", "error"


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
    return clean or "myav"


class Backend:
    available = True
    missing = ""  # что установить, если недоступен

    def __init__(self, log):
        self.log = log  # log(text) из любого потока
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
        if state == CONNECTED:
            self.since = time.time()


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

    def connect(self, profile) -> None:
        self._set(CONNECTING)
        x = self.x
        self.mode = "tun" if profile.mode == "tun-xray" else "proxy"
        try:
            v = x.parse_vless(profile.config)
            interface = ""
            if self.mode == "tun":
                gateway, interface = x.default_route()
                if not gateway:
                    raise OSError("не найден маршрут по умолчанию")
                self.server = x.server_ip(v["address"])
                self.log(f"Xray TUN: шлюз {gateway} ({interface}), сервер {self.server}")
            self.config_path = x.write_config(x.build_config(v, self.mode, interface),
                                              TUNNEL_DIR)
        except (OSError, ValueError) as e:
            self._set(ERROR, f"Xray: {e}")
            self.log(self.error)
            return
        self.log(f"Xray: запуск ({'TUN' if self.mode == 'tun' else 'системный прокси'})...")
        self.proc = subprocess.Popen([self.exe, "run", "-c", str(self.config_path)],
                                     cwd=str(Path(self.exe).parent), stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                                     errors="replace", creationflags=CREATE_NO_WINDOW)
        threading.Thread(target=self._read, daemon=True).start()
        if self.mode == "tun":
            error = x.setup_tun_routes(self.server, gateway)
            if error:
                self._fail(f"Xray TUN: маршруты не настроены: {error}")
                return
            self.adapter = x.TUN_NAME
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
            self._cleanup()
            self._set(ERROR, "Xray завершился")

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
        self._set(DISCONNECTED)
        self._cleanup()
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
    """TUN через sing-box: адаптер, маршруты и DNS sing-box настраивает сам."""

    def __init__(self, log):
        super().__init__(log)
        from vpn import singbox
        self.sb = singbox
        self.exe = singbox.find_singbox()
        self.available = bool(self.exe)
        self.missing = ("sing-box: sing-box.exe в vpn/bin, в PATH или путь в настройке "
                        "vpn/singbox_path (github.com/SagerNet/sing-box/releases)")
        self.proc: subprocess.Popen | None = None
        self.config_path: Path | None = None

    def connect(self, profile) -> None:
        self._set(CONNECTING)
        from vpn import xray
        try:
            config = self.sb.build_config(xray.parse_vless(profile.config))
            self.config_path = xray.write_config(config, TUNNEL_DIR)
        except (OSError, ValueError) as e:
            self._set(ERROR, f"sing-box: {e}")
            self.log(self.error)
            return
        self.log("sing-box: запуск TUN (нужны права администратора)...")
        self.proc = subprocess.Popen([self.exe, "run", "-c", str(self.config_path)],
                                     cwd=str(Path(self.exe).parent), stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                                     errors="replace", creationflags=CREATE_NO_WINDOW)
        threading.Thread(target=self._read, daemon=True).start()
        if not self._wait_adapter():
            self._fail(self.error or "sing-box не создал адаптер TUN (смотрите журнал)")
            return
        self.adapter = self.sb.TUN_NAME
        self._set(CONNECTED)
        self.log(f"sing-box: подключено, весь трафик через {self.sb.TUN_NAME}")

    def _wait_adapter(self, timeout: float = 10.0) -> bool:
        import psutil
        end = time.time() + timeout
        while time.time() < end:
            if self.proc is None or self.proc.poll() is not None:
                return False
            if self.sb.TUN_NAME in psutil.net_if_stats():
                return True
            time.sleep(0.3)
        return False

    def _read(self) -> None:
        proc = self.proc
        for line in proc.stdout:
            line = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()  # цвета в выводе
            if not line:
                continue
            self.log("sing-box: " + line[-200:])
            if "FATAL" in line:
                self.error = "sing-box: " + line.split("FATAL", 1)[-1].strip()[-200:]
        if self.state in (CONNECTED, CONNECTING) and proc is self.proc:
            self._cleanup()
            self._set(ERROR, self.error or "sing-box завершился")

    def _fail(self, text: str) -> None:
        self._cleanup()
        self._set(ERROR, text)
        self.log(text)

    def _cleanup(self) -> None:
        proc, self.proc = self.proc, None
        if proc and proc.poll() is None:
            proc.terminate()  # sing-box сам убирает адаптер и маршруты
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
        if self.config_path is not None:
            self.config_path.unlink(missing_ok=True)  # в файле ключ подключения
            self.config_path = None
        self.adapter = ""

    def disconnect(self) -> None:
        self._set(DISCONNECTED)
        self._cleanup()
        self.log("sing-box: отключено")


def backend_for(kind: str, log, mode: str = "") -> Backend:
    if kind == "vless":
        return SingBoxBackend(log) if mode in ("tun", "") else XrayBackend(log)
    return {"wireguard": WireGuardBackend, "openvpn": OpenVPNBackend}.get(kind, DemoBackend)(log)


def public_ip(timeout: int = 8) -> str:
    """Внешний IP-адрес (api.ipify.org): виден ли адрес сервера VPN."""
    import urllib.request
    req = urllib.request.Request("https://api.ipify.org",
                                 headers={"User-Agent": "study-av/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("ascii", "replace").strip()
