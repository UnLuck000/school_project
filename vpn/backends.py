"""Способы подключения VPN (прототип).

• WireGuardBackend — через официальный клиент WireGuard для Windows: wireguard.exe
  /installtunnelservice <conf> создаёт службу туннеля и сетевой адаптер (нужны права
  администратора), /uninstalltunnelservice <имя> — отключение. Подключение пишется в журнал
  действий: отмена — отключение туннеля.
• OpenVPNBackend — openvpn.exe --config <ovpn> как дочерний процесс; вывод — в журнал окна,
  подключено после «Initialization Sequence Completed».
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


def backend_for(kind: str, log) -> Backend:
    return {"wireguard": WireGuardBackend, "openvpn": OpenVPNBackend}.get(kind, DemoBackend)(log)


def public_ip(timeout: int = 8) -> str:
    """Внешний IP-адрес (api.ipify.org): виден ли адрес сервера VPN."""
    import urllib.request
    req = urllib.request.Request("https://api.ipify.org",
                                 headers={"User-Agent": "study-av/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("ascii", "replace").strip()
