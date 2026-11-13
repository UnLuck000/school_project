"""Интерфейс со службой: карантин, журнал защиты, белый список, брандмауэр, журнал действий
службы, датчики сети и VPN с правами ведёт служба.

install(client) подменяет функции quarantine / recovery.threatlog / scanner.whitelist /
networkmonitor.firewall / recovery.journal (их set_remote), датчики DNS и TLS сетевого
монитора (netmon.SENSORS) и ядра VPN с правами (backends.REMOTE): весь прежний код окна
работает как раньше, но через канал. Файлы пользователя служба не открывает по пути: окно само
открывает файл со своими правами и передаёт дескриптор (service/DESIGN.md).

События службы приходят в поток EventPump: dispatch() отдаёт датчикам и VPN их события сразу
(без главного потока), остальное — окну сигналом.
"""
import os
import threading
import time
from pathlib import Path

from service import winapi
from service.client import ServiceClient, ServiceError

WHITELIST_SECONDS = 2.0
STREAM_KINDS = ("dns", "tls", "vpn", "net_status")  # события датчиков и VPN — не окну


class Remote:
    def __init__(self, client: ServiceClient):
        self.client = client
        self._white: tuple[float, dict] | None = None
        self._listeners: dict[str, list] = {}
        self._llock = threading.Lock()

    # ---------- события ----------
    def listen(self, kind: str, callback) -> None:
        with self._llock:
            self._listeners.setdefault(kind, []).append(callback)

    def unlisten(self, kind: str, callback) -> None:
        with self._llock:
            items = self._listeners.get(kind, [])
            if callback in items:
                items.remove(callback)

    def dispatch(self, event: dict) -> bool:
        """True — событие для датчиков сети или VPN (окну сигналом его не отдавать)."""
        kind = event.get("kind", "")
        if kind not in STREAM_KINDS:
            return False
        if event.get("replay"):
            return True  # прежние события датчиков и VPN не повторяются
        with self._llock:
            callbacks = list(self._listeners.get(kind, []))
        for callback in callbacks:
            try:
                callback(event.get("data") if kind != "net_status" else
                         (event.get("data") or event.get("text", "")))
            except Exception:  # noqa: BLE001 — ошибка слушателя не останавливает опрос
                from diag.log import swallowed
                swallowed("служба: слушатель события")
        return True

    # ---------- карантин ----------
    def quarantine_file(self, path, reason: str) -> str:
        path = os.path.abspath(str(path))
        h = winapi.open_file(path, winapi.GENERIC_READ | winapi.DELETE,
                             winapi.FILE_SHARE_READ | winapi.FILE_SHARE_DELETE,
                             winapi.OPEN_EXISTING)
        try:
            return self.client.call("quarantine.add", timeout=120.0, handle=int(h),
                                    reason=reason)["id"]
        finally:
            winapi.close(h)

    def list_quarantine(self, include_history: bool = False) -> list[dict]:
        try:
            return self.client.call("quarantine.list", history=include_history)
        except ServiceError:
            from diag.log import swallowed
            swallowed("служба: список карантина")
            return []

    def restore_file(self, item_id: str, overwrite: bool = False,
                     whitelist: bool = True) -> Path:
        meta = next((m for m in self.list_quarantine(True) if m["id"] == item_id), None)
        if meta is None:
            raise ValueError("Такого файла в карантине нет")
        if meta.get("status") != "quarantined":
            raise ValueError("Этот элемент уже восстановлен или удалён")
        dest = Path(meta["original_path"])
        existed = dest.exists()
        if existed and not overwrite:
            raise FileExistsError(f"По пути {dest} уже есть файл")
        dest.parent.mkdir(parents=True, exist_ok=True)
        h = winapi.open_file(str(dest), winapi.GENERIC_WRITE, 0,
                             winapi.CREATE_ALWAYS if overwrite else winapi.CREATE_NEW)
        try:
            result = self.client.call("quarantine.restore", timeout=120.0, id=item_id,
                                      handle=int(h), whitelist=whitelist)
        except BaseException:
            winapi.close(h)
            h = None
            if not existed:
                dest.unlink(missing_ok=True)  # пустой файл, который создали сами
            raise
        finally:
            if h is not None:
                winapi.close(h)
        self._white = None
        from scanner import whitelist as wl
        wl.forget_trusted()
        return Path(result["path"])

    def delete_file(self, item_id: str) -> bool:
        return bool(self.client.call("quarantine.delete", id=item_id))

    # ---------- журнал защиты ----------
    def add(self, path, level, text, source="", story="", pid=0) -> str:
        return self.client.call("threats.add", path=str(path or ""), level=level, text=text,
                                source=source, story=story, pid=int(pid or 0))

    def set_status(self, record_id, status, qid="") -> None:
        self.client.call("threats.set_status", id=record_id, status=status, qid=qid)

    def merged(self, include_done: bool = False) -> list[dict]:
        try:
            return self.client.call("threats.list", include_done=include_done)
        except ServiceError:
            from diag.log import swallowed
            swallowed("служба: журнал защиты")
            return []

    def get(self, record_id):
        return self.client.call("threats.get", id=record_id)

    def mark_path(self, path, status, qid="") -> None:
        self.client.call("threats.mark_path", path=str(path), status=status, qid=qid)

    def dismiss(self, record_id) -> None:
        self.client.call("threats.dismiss", id=record_id)

    # ---------- белый список ----------
    def load_whitelist(self) -> dict:
        now = time.monotonic()
        if self._white is None or now - self._white[0] > WHITELIST_SECONDS:
            try:
                self._white = (now, self.client.call("whitelist.list") or {})
            except ServiceError:
                from diag.log import swallowed
                swallowed("служба: белый список")
                return dict(self._white[1]) if self._white else {}
        return dict(self._white[1])

    def add_to_whitelist(self, sha256: str, path: str) -> bool:
        self._white = None
        return bool(self.client.call("whitelist.add", sha256=sha256, path=path))

    def remove_from_whitelist(self, sha256: str) -> bool:
        self._white = None
        return bool(self.client.call("whitelist.remove", sha256=sha256))

    # ---------- брандмауэр ----------
    def block_ip(self, ip: str) -> list[str]:
        return self.client.call("firewall.block_ip", timeout=60.0, ip=ip)

    def block_program(self, exe: str) -> list[str]:
        return self.client.call("firewall.block_program", timeout=60.0, exe=exe)

    def unblock(self, rule_names: list[str], target: str) -> None:
        self.client.call("firewall.unblock", timeout=60.0, names=list(rule_names),
                         target=target)

    # ---------- журнал действий службы ----------
    def journal_list(self) -> list[dict]:
        try:
            return self.client.call("journal.list") or []
        except ServiceError:
            from diag.log import swallowed
            swallowed("служба: журнал действий")
            return []

    def journal_undo(self, record_id: str) -> str:
        return self.client.call("journal.undo", timeout=120.0, id=record_id)

    def journal_cleanup(self) -> int:
        try:
            return int(self.client.call("journal.cleanup", timeout=60.0) or 0)
        except ServiceError:
            return 0


# ---------- датчики сетевого монитора ----------
class RemoteSensor:
    """Вместо DnsWatcher / TlsWatcher окна: события того же вида приходят от службы (у неё
    права на ETW и WinDivert)."""

    def __init__(self, remote: Remote, kind: str, on_item, on_status=None):
        self.remote, self.kind = remote, kind
        self.on_item = on_item
        self.on_status = on_status or (lambda text: None)
        self.mode = "service"
        self.running = False

    def convert(self, data):
        if self.kind == "dns":
            from networkmonitor.dns_etw import DnsQuery
            data = dict(data)
            data["results"] = tuple(data.get("results") or ())
            return DnsQuery(**data)
        from networkmonitor.tls import ClientHello, TlsEvent
        data = dict(data)
        data["hello"] = ClientHello(**data["hello"])
        return TlsEvent(**data)

    def _on(self, data) -> None:
        self.on_item(self.convert(data))

    def start(self) -> None:
        self.remote.listen(self.kind, self._on)
        if self.kind == "dns":
            self.remote.listen("net_status", self.on_status)
        self.running = True
        try:
            self.remote.client.call("net.sensors", on=True)
            self.on_status(("DNS" if self.kind == "dns" else "TLS") +
                           ": события от службы защиты (с правами системы)")
        except (ServiceError, PermissionError) as e:
            self.on_status(f"Служба не включила датчик {self.kind.upper()}: {e}")

    def stop(self) -> None:
        self.remote.unlisten(self.kind, self._on)
        if self.kind == "dns":
            self.remote.unlisten("net_status", self.on_status)
        if self.running:
            self.running = False
            try:
                self.remote.client.call("net.sensors", on=False)
            except (ServiceError, PermissionError):
                from diag.log import swallowed
                swallowed("служба: датчики сети")


class RemoteSensors:
    def __init__(self, remote: Remote):
        self.remote = remote

    def dns(self, on_query, on_status=None) -> RemoteSensor:
        return RemoteSensor(self.remote, "dns", on_query, on_status)

    def tls(self, on_hello, on_status=None, _dll_dir: str = "") -> RemoteSensor:
        return RemoteSensor(self.remote, "tls", on_hello, on_status)


# ---------- VPN с правами ----------
class RemoteBackend:
    """vpn.backends.Backend для окна без прав: TUN, WireGuard и OpenVPN подключает служба,
    состояние и журнал — событиями «vpn». Ждать подключения не нужно: окно, как и раньше,
    смотрит на state по таймеру."""
    available = True
    missing = ""
    remote = True

    def __init__(self, remote: Remote, kind: str, log, mode: str = ""):
        self.remote, self.kind, self.mode = remote, kind, mode
        self.log = log
        self.local_ports: dict[str, int] = {}
        self.blocked = False
        self.state = "disconnected"
        self.since = 0.0
        self.adapter = ""
        self.error = ""
        self._listening = False

    def _listen(self) -> None:
        # слушает только подключение, которое ведёт (окно создаёт и пробные объекты)
        if not self._listening:
            self._listening = True
            self.remote.listen("vpn", self._on_event)

    def _apply(self, status: dict) -> None:
        self.state = status.get("state", self.state)
        self.error = status.get("error", "")
        self.since = float(status.get("since") or 0.0)
        self.blocked = bool(status.get("blocked"))
        self.adapter = status.get("adapter", "")
        self.local_ports = dict(status.get("local_ports") or {})

    def _on_event(self, data) -> None:
        if not isinstance(data, dict):
            return
        if "log" in data:
            self.log(data["log"])
        if "state" in data:
            self._apply(data["state"])

    def adopt(self) -> dict | None:
        """Служба уже держит подключение (окно перезапущено): показать его. Состояние
        службы (profile, kind) или None."""
        try:
            status = self.remote.client.call("vpn.status")
        except ServiceError:
            return None
        if status.get("state") in ("disconnected", "", None):
            return None
        self.kind = status.get("kind") or self.kind
        self._apply(status)
        self._listen()
        return status

    def connect(self, profile) -> None:
        from service import vpnhost
        from ui import settings as cfg
        self._listen()
        self.state, self.error = "connecting", ""
        settings = {key: cfg.get(key) for key in vpnhost.SETTINGS}
        try:
            options = vpnhost.window_options(self.log) if self.kind == "vless" else None
            status = self.remote.client.call(
                "vpn.connect", timeout=60.0,
                profile={"name": profile.name, "kind": profile.kind, "mode": profile.mode,
                         "config": profile.config, "server": profile.server},
                settings=settings, options=options)
        except (OSError, ValueError) as e:
            self.state, self.error = "error", f"Служба: {e}"
            self.log(self.error)
            return
        self._apply(status)

    def disconnect(self) -> None:
        self.state = "disconnecting"
        try:
            self._apply(self.remote.client.call("vpn.disconnect", timeout=60.0))
        except ServiceError as e:
            self.state, self.error = "error", f"Служба не отключила VPN: {e}"
            self.log(self.error)

    def counters(self) -> tuple[int, int]:
        try:
            rx, tx = self.remote.client.call("vpn.counters", timeout=5.0)
            return int(rx), int(tx)
        except (ServiceError, ValueError, TypeError):
            return 0, 0

    def release_block(self) -> bool:
        try:
            done = bool(self.remote.client.call("vpn.release_block", timeout=60.0))
        except ServiceError:
            return False
        if done:
            self.blocked = False
        return done


class RemoteVpn:
    def __init__(self, remote: Remote):
        self.remote = remote

    def backend(self, kind: str, log, mode: str = "") -> RemoteBackend:
        return RemoteBackend(self.remote, kind, log, mode)


# ---------- защита от стилеров: решение по тревоге ----------
class RemoteStealer:
    remote = True

    def __init__(self, client: ServiceClient):
        self.client = client

    def decide(self, alarm: str, action: str) -> str:
        return self.client.call("stealer.decide", alarm=alarm, action=action)

    def reload_trust(self) -> None:
        pass  # разрешение записала служба


REMOTE: Remote | None = None


def install(client: ServiceClient) -> Remote:
    global REMOTE
    import quarantine
    from networkmonitor import firewall, netmon
    from recovery import journal, threatlog
    from scanner import whitelist
    from vpn import backends
    remote = Remote(client)
    quarantine.set_remote(remote)
    threatlog.set_remote(remote)
    whitelist.set_remote(remote)
    firewall.set_remote(remote)
    journal.set_remote(remote)
    netmon.SENSORS = RemoteSensors(remote)
    backends.REMOTE = RemoteVpn(remote)
    REMOTE = remote
    return remote


def uninstall() -> None:
    global REMOTE
    import quarantine
    from networkmonitor import firewall, netmon
    from recovery import journal, threatlog
    from scanner import whitelist
    from vpn import backends
    quarantine.set_remote(None)
    threatlog.set_remote(None)
    whitelist.set_remote(None)
    firewall.set_remote(None)
    journal.set_remote(None)
    netmon.SENSORS = None
    backends.REMOTE = None
    REMOTE = None
