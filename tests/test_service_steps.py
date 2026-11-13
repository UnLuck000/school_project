"""Служба, шаги 2–7 (service/DESIGN.md): защиты с правами в службе (guards), брандмауэр,
журнал действий службы, датчики сети, ядра VPN (vpnhost) и процесс с правами (elevate).
Настоящие ETW, AMSI, WinDivert и ядра VPN не запускаются — подставные объекты."""
import json
import time

import pytest

from service.pipeserver import Client


def user(sid="S-1-5-21-1", elevated=False, pid=0):
    return Client(pid, "", sid=sid, elevated=elevated)


class FakeMonitor:
    def __init__(self, folders, on_event):
        self.on_event = on_event

    def start(self):
        self.on_event("status", "Защита включена (тест)")

    def stop(self):
        pass

    def reload_bases(self):
        pass


class FakeGuard:
    made: dict = {}

    def __init__(self, *callbacks, name="", **_kw):
        self.callbacks = callbacks
        self.name = name
        self.stopped = False
        self.error = ""
        self.trust_reloaded = 0

    def start(self):
        # AmsiServer.start → True, если запущен; ScriptBlockWatch.start → пусто, если запущен
        return True if self.name == "amsi" else ""

    def stop(self):
        self.stopped = True

    def reload_trust(self):
        self.trust_reloaded += 1


def factory(name):
    def make(*callbacks):
        guard = FakeGuard(*callbacks, name=name)
        FakeGuard.made[name] = guard
        return guard
    return make


@pytest.fixture
def svc(tmp_path, monkeypatch):
    import quarantine
    from recovery import journal, threatlog
    from scanner import whitelist
    monkeypatch.setattr(quarantine, "QUARANTINE_DIR", tmp_path / "quarantine")
    monkeypatch.setattr(threatlog, "THREATS_FILE", tmp_path / "journal" / "threats.json")
    monkeypatch.setattr(whitelist, "WHITELIST_FILE", tmp_path / "whitelist.json")
    monkeypatch.setattr(journal, "JOURNAL_DIR", tmp_path / "journal")
    monkeypatch.setattr(journal, "JOURNAL_FILE", tmp_path / "journal" / "actions.jsonl")
    from service.core import ServiceCore
    FakeGuard.made = {}
    names = ("launch", "stealer", "pslog", "dns", "tls")
    core = ServiceCore(tmp_path / "svc", monitor_factory=FakeMonitor,
                       guard_factories={n: factory(n) for n in names} | {"amsi": factory("amsi")})
    yield core
    core.stop()
    from service import remote
    remote.uninstall()


def events(core, kind):
    return [e for e in core.op_events(user(), {"since": 0})["events"] if e["kind"] == kind]


def test_guards_follow_protection_and_settings(svc):
    svc.handle(user(), "protection.set", {"on": True})
    state = svc.handle(user(), "guards.state", {})
    assert set(state["running"]) == {"launch", "stealer", "pslog"}   # AMSI — по галочке
    svc.handle(user(), "guards.set", {"amsi": True})
    assert "amsi" in svc.guards.running
    svc.handle(user(), "guards.set", {"launch": False})       # без запрета — можно
    assert "launch" not in svc.guards.running and FakeGuard.made["launch"].stopped
    assert svc.config["guards"]["launch"] is False
    from service.core import ServiceCore
    again = ServiceCore(svc.folder, monitor_factory=FakeMonitor)  # настройка сохранена
    assert again.config["guards"]["launch"] is False
    svc.handle(user(), "protection.set", {"on": False})
    assert not svc.guards.running                             # защиты — вместе с защитой файлов


def test_lock_refuses_turning_guards_off(svc):
    from service.core import Refused
    svc.handle(user(elevated=True), "config.set", {"lock_protection": True})
    svc.handle(user(), "protection.set", {"on": True})
    with pytest.raises(Refused):
        svc.handle(user(), "guards.set", {"stealer": False})
    with pytest.raises(Refused):
        svc.handle(user(), "net.sensors", {"on": False})
    svc.handle(user(elevated=True), "guards.set", {"stealer": False})
    assert "stealer" not in svc.guards.running


def test_launch_threat_logged_by_service(svc):
    svc.handle(user(), "protection.set", {"on": True})
    on_event = FakeGuard.made["launch"].callbacks[0]
    on_event("blocked", {"name": "evil.exe", "exe": r"C:\Users\x\evil.exe", "text": "хэш",
                         "pid": 0, "killed": True})
    from recovery import threatlog
    assert threatlog.merged()[0]["path"] == r"C:\Users\x\evil.exe"
    ev = events(svc, "guard")[-1]["data"]
    assert ev["guard"] == "launch" and ev["kind"] == "blocked" and ev["info"]["logged"]


def test_stealer_alarm_decisions(svc, monkeypatch):
    from toolbox import decoys, stealerguard
    resumed, trusted = [], []
    monkeypatch.setattr(decoys, "resume", lambda pid: resumed.append(pid) or True)
    monkeypatch.setattr(stealerguard, "trust", lambda exe: trusted.append(exe))
    monkeypatch.setattr("service.guards.ALARM_TIMEOUT", 0.2)
    svc.handle(user(), "protection.set", {"on": True})
    on_alarm = FakeGuard.made["stealer"].callbacks[0]
    on_alarm({"pid": 42, "name": "x.exe", "exe": r"C:\x.exe", "path": "Login Data",
              "kind": "пароли", "owner": "Chrome", "suspended": True})
    alarm = events(svc, "guard")[-1]["data"]["info"]["alarm"]
    assert svc.handle(user(), "guards.state", {})["alarms"][0]["alarm"] == alarm
    assert "разрешён" in svc.handle(user(), "stealer.decide", {"alarm": alarm,
                                                                "action": "allow"})
    assert resumed == [42] and trusted == [r"C:\x.exe"]
    assert FakeGuard.made["stealer"].trust_reloaded == 1
    with pytest.raises(ValueError):                       # решена — второй раз нельзя
        svc.handle(user(), "stealer.decide", {"alarm": alarm, "action": "once"})
    on_alarm({"pid": 43, "name": "y.exe", "exe": r"C:\y.exe", "path": "Cookies",
              "kind": "cookies", "owner": "Edge", "suspended": True})
    time.sleep(0.6)                                       # никто не ответил — отпущен
    assert resumed[-1] == 43 and not svc.guards.alarms
    assert events(svc, "guard")[-1]["data"]["kind"] == "expired"
    from recovery import threatlog
    assert any(r["level"] == "suspicious" for r in threatlog.merged())


def test_alarm_without_window_opens_it(svc, monkeypatch):
    """Окна нет — служба запускает его в сеансе пользователя, чей процесс остановлен."""
    from service import winapi
    monkeypatch.setattr(winapi, "session_of", lambda pid: 3 if pid == 42 else 0)
    monkeypatch.setattr(winapi, "active_session", lambda: 7)
    launched = []
    svc.window_launcher = lambda session: launched.append(session) or 555
    svc.handle(user(), "protection.set", {"on": True})
    on_alarm = FakeGuard.made["stealer"].callbacks[0]
    info = {"pid": 42, "name": "x.exe", "exe": "x.exe", "path": "Login Data",
            "kind": "пароли", "owner": "Chrome", "suspended": False}
    on_alarm(dict(info))
    assert launched == [3]
    on_alarm(dict(info))                                  # не чаще раза в минуту на сеанс
    assert launched == [3]
    on_alarm(dict(info, pid=900))                         # процесс службы: сеанс на экране
    assert launched == [3, 7]
    svc._woken.clear()
    client = user()
    client.session = 3
    svc.op_events(client, {"since": 0})                   # окно в сеансе 3 открыто
    on_alarm(dict(info))
    assert launched == [3, 7]
    svc.window_launcher = lambda session: (_ for _ in ()).throw(OSError("нет сеанса"))
    svc._listeners.clear()
    on_alarm(dict(info))                                  # сбой запуска тревоге не мешает
    assert len(svc.guards.alarms) == 5


def test_stealer_allow_is_weakening(svc):
    from service.core import Refused
    svc.handle(user(elevated=True), "config.set", {"lock_protection": True})
    with pytest.raises(Refused):
        svc.handle(user(), "stealer.decide", {"alarm": "x", "action": "allow"})


def test_firewall_ops_validate(svc, monkeypatch):
    from networkmonitor import firewall
    calls = []
    monkeypatch.setattr(firewall, "block_program", lambda exe: calls.append(exe) or ["sbit-1"])
    monkeypatch.setattr(firewall, "unblock", lambda names, target: calls.append(names))
    with pytest.raises(ValueError):
        svc.handle(user(), "firewall.block_program", {"exe": "evil.exe"})
    assert svc.handle(user(), "firewall.block_program", {"exe": r"C:\x\a.exe"}) == ["sbit-1"]
    with pytest.raises(ValueError, match="правила программы"):
        svc.handle(user(), "firewall.unblock", {"names": ["CoreNet-DHCP-In"], "target": "x"})
    svc.handle(user(), "firewall.unblock", {"names": ["SBIT-abc123"], "target": "1.2.3.4"})
    assert calls[-1] == ["SBIT-abc123"]
    from service.core import Refused
    svc.handle(user(elevated=True), "config.set", {"lock_protection": True})
    with pytest.raises(Refused):                          # снять блокировку — ослабление
        svc.handle(user(), "firewall.unblock", {"names": ["SBIT-abc123"], "target": "x"})


def test_service_journal_merged_and_undone_through_service(svc, tmp_path, monkeypatch):
    from recovery import journal
    done = []
    journal.UNDO_HANDLERS["svc_test"] = lambda d: done.append(d) or "откат службы"
    try:
        sid = journal.log_action("служба: тест", "svc_test", {"v": 1})   # журнал службы

        service_file, service_dir = journal.JOURNAL_FILE, journal.JOURNAL_DIR

        class FakeRemote:
            """Служба — другой процесс: её журнал читается без подмены (_remote = None)."""

            def _as_service(self, op, args):
                saved = (journal.JOURNAL_FILE, journal.JOURNAL_DIR, journal._remote)
                journal.JOURNAL_FILE, journal.JOURNAL_DIR = service_file, service_dir
                journal._remote = None
                try:
                    return svc.handle(user(), op, args)
                finally:
                    journal.JOURNAL_FILE, journal.JOURNAL_DIR, journal._remote = saved

            def journal_list(self):
                return self._as_service("journal.list", {})

            def journal_undo(self, rid):
                return self._as_service("journal.undo", {"id": rid})

            def journal_cleanup(self):
                return 0
        # окно: свой журнал в другой папке, журнал службы — через канал
        monkeypatch.setattr(journal, "JOURNAL_FILE", tmp_path / "window" / "actions.jsonl")
        monkeypatch.setattr(journal, "JOURNAL_DIR", tmp_path / "window")
        journal.log_action("окно: тест", "svc_test", {"v": 2})
        journal.set_remote(FakeRemote())
        records = journal.read_all()
        assert {r["title"] for r in records} == {"служба: тест", "окно: тест"}
        assert [r for r in records if r["id"] == sid][0]["where"] == "service"
        # отмена записи службы уходит службе (она пишет в свой журнал)
        assert journal.undo(sid) == "откат службы" and done == [{"v": 1}]
        assert [r for r in journal.read_all() if r["id"] == sid][0]["undone"]
    finally:
        journal.set_remote(None)
        journal.UNDO_HANDLERS.pop("svc_test", None)


def test_net_sensors_and_remote_dispatch(svc):
    from service import remote
    from service.guards import jsonable
    svc.handle(user(), "net.sensors", {"on": True})
    assert {"dns", "tls"} <= set(svc.guards.running)
    from networkmonitor.dns_etw import DnsQuery
    from networkmonitor.tls import ClientHello, TlsEvent
    on_query = FakeGuard.made["dns"].callbacks[0]
    on_query(DnsQuery(1.0, 7, "evil.example", ("1.2.3.4",)))
    on_hello = FakeGuard.made["tls"].callbacks[0]
    on_hello(TlsEvent(2.0, 7, "a.exe", r"C:\a.exe", "1.2.3.4:443",
                      ClientHello("evil.example", "abc", "771,...")))

    class FakeClient:
        def call(self, op, **kw):
            return svc.handle(user(), op, kw)
    r = remote.Remote(FakeClient())
    sensors = remote.RemoteSensors(r)
    got = []
    dns = sensors.dns(got.append)
    tls = sensors.tls(got.append)
    dns.start()
    tls.start()
    for ev in svc.op_events(user(), {"since": 0})["events"]:
        if ev["kind"] in ("dns", "tls"):
            assert r.dispatch(ev)
    assert got[0] == DnsQuery(1.0, 7, "evil.example", ("1.2.3.4",))
    assert got[1].hello.sni == "evil.example" and got[1].pid == 7
    assert not r.dispatch({"kind": "threat", "text": "x"})   # прочее — окну
    assert jsonable({"s": {"b", "a"}}) == {"s": ["a", "b"]}
    dns.stop()
    tls.stop()
    assert "dns" not in svc.guards.running


def test_netmon_uses_service_sensors(monkeypatch, tmp_path):
    from networkmonitor import netmon
    made = []

    class Sensors:
        def dns(self, on_query, on_status=None):
            made.append("dns")
            return object()

        def tls(self, on_hello, on_status=None, dll=""):
            made.append("tls")
            return object()
    monkeypatch.setattr(netmon, "SENSORS", Sensors())
    netmon.NetworkMonitor(tmp_path, tmp_path, tmp_path, lambda *a: None)
    assert made == ["dns", "tls"]


# ---------- VPN ----------
def test_openvpn_and_wireguard_configs_checked():
    from service import vpnhost
    good = "client\nremote vpn.example 1194\n<ca>\n-----BEGIN-----\nup evil\n</ca>\n"
    vpnhost.check_openvpn(good)                        # «up» внутри встроенного блока — данные
    for bad in ("client\nup C:\\evil.cmd\n", "script-security 2\n", "plugin x.dll\n",
                "log C:\\Windows\\x.txt\n", "ca C:\\Users\\x\\ca.crt\n", "--management 0 1\n"):
        with pytest.raises(ValueError):
            vpnhost.check_openvpn(bad)
    vpnhost.check_wireguard("[Interface]\nPrivateKey = x\n[Peer]\nEndpoint = a:1\n")
    with pytest.raises(ValueError, match="PostUp"):
        vpnhost.check_wireguard("[Interface]\nPostUp = calc.exe\n")
    s = vpnhost.clean_settings({"vpn/killswitch": 1, "vpn/xray_path": r"C:\evil.exe"})
    assert s == {"vpn/killswitch": True}               # пути к ядрам из окна не берутся
    o = vpnhost.clean_options({"route_ru": True, "ip_files": ["a.dat"], "log": "x"})
    assert "log" not in o and o["ip_files"] == {"a.dat"}


class FakeBackend:
    available, missing = True, ""

    def __init__(self, log):
        self.log = log
        self.state, self.error, self.since = "disconnected", "", 0.0
        self.adapter, self.local_ports, self.blocked = "", {}, False
        self.settings = self.options = None
        self.profile = None

    def connect(self, profile):
        self.profile = profile
        self.log("подключаюсь")
        self.state, self.adapter, self.since = "connected", "sbit-tun", 1.0

    def disconnect(self):
        self.state, self.adapter = "disconnected", ""

    def counters(self):
        return 10, 20


def test_vpn_host_connect_and_status(svc, tmp_path):
    made = []

    def make(kind, log, mode):
        made.append(FakeBackend(log))
        return made[-1]
    svc.vpn.factory = make
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "geosite.dat").write_bytes(b"\x0a\x00")
    (assets / "notes.txt").write_text("x", encoding="utf-8")
    with pytest.raises(ValueError, match="TUN"):
        svc.handle(user(), "vpn.connect", {"profile": {"kind": "vless", "mode": "proxy",
                                                      "config": "vless://x"}})
    with pytest.raises(ValueError, match="OpenVPN"):
        svc.handle(user(), "vpn.connect", {"profile": {"kind": "openvpn",
                                                      "config": "up evil.cmd\n"}})
    svc.handle(user(), "vpn.connect", {
        "profile": {"name": "NL", "kind": "vless", "mode": "tun", "config": "vless://x"},
        "settings": {"vpn/killswitch": True}, "options": {"assets": str(assets),
                                                          "route_ru": True}})
    deadline = time.monotonic() + 3
    while svc.handle(user(), "vpn.status", {})["state"] != "connected" and \
            time.monotonic() < deadline:
        time.sleep(0.02)
    status = svc.handle(user(), "vpn.status", {})
    assert status["state"] == "connected" and status["profile"] == "NL"
    backend = made[-1]
    assert backend.settings == {"vpn/killswitch": True}
    copied = backend.options["assets"]
    assert copied.startswith(str(svc.folder)) and (svc.folder / "vpn-assets" / "geosite.dat").exists()
    assert not (svc.folder / "vpn-assets" / "notes.txt").exists()
    with pytest.raises(ValueError, match="уже"):
        svc.handle(user(), "vpn.connect", {"profile": {"kind": "wireguard",
                                                      "config": "[Interface]\n"}})
    assert svc.handle(user(), "vpn.counters", {}) == [10, 20]
    logs = [e["data"]["log"] for e in events(svc, "vpn") if "log" in e["data"]]
    assert "подключаюсь" in logs
    assert svc.handle(user(), "vpn.disconnect", {})["state"] == "disconnected"


def test_window_backend_routes_to_service(monkeypatch):
    from service import remote
    from vpn import backends
    calls = []

    class FakeClient:
        def call(self, op, timeout=None, **kw):
            calls.append((op, kw))
            if op == "vpn.connect":
                return {"state": "connecting", "since": 0.0}
            if op == "vpn.status":
                return {"state": "connected", "profile": "NL", "kind": "vless", "since": 5.0,
                        "adapter": "sbit-tun", "local_ports": {"socks": 2082}}
            return {"state": "disconnected"}
    r = remote.Remote(FakeClient())
    monkeypatch.setattr(backends, "REMOTE", remote.RemoteVpn(r))
    try:
        assert isinstance(backends.backend_for("wireguard", print), remote.RemoteBackend)
        assert isinstance(backends.backend_for("vless", print, "tun"), remote.RemoteBackend)
        assert not isinstance(backends.backend_for("vless", print, "proxy"),
                              remote.RemoteBackend)        # системный прокси — HKCU, в окне
        lines = []
        b = backends.backend_for("openvpn", lines.append)
        from vpn import profiles
        b.connect(profiles.Profile(name="Office", kind="openvpn", config="client\n"))
        op, kw = calls[-1]
        assert op == "vpn.connect" and kw["profile"]["config"] == "client\n"
        assert kw["options"] is None and "vpn/killswitch" in kw["settings"]
        r.dispatch({"kind": "vpn", "data": {"log": "OpenVPN: готово",
                                            "state": {"state": "connected", "since": 3.0}}})
        assert b.state == "connected" and lines == ["OpenVPN: готово"]
        adopted = backends.backend_for("vless", print, "tun")
        assert adopted.adopt()["profile"] == "NL" and adopted.local_ports == {"socks": 2082}
    finally:
        r = None


# ---------- процесс с правами ----------
def test_elevate_helpers(monkeypatch):
    from service import elevate, remote
    assert elevate.needs_admin(PermissionError("x"))
    assert elevate.needs_admin(OSError("Access is denied."))
    assert not elevate.needs_admin(ValueError("Запись журнала не найдена"))
    exe, params = elevate.command(["--undo", "a b"])
    assert params.endswith('--undo "a b"') and "gui.py" in params
    monkeypatch.setattr(remote, "REMOTE", None)
    assert not elevate.wanted("recovery")                 # без службы — как раньше
    monkeypatch.setattr(remote, "REMOTE", object())
    monkeypatch.setattr("trustseal.is_admin", lambda: False)
    assert elevate.wanted("autoruns") and not elevate.wanted("vpn")


def test_protocol_lists_new_ops_with_handlers():
    from service import protocol
    from service.core import ServiceCore
    for op in protocol.OPS:
        assert hasattr(ServiceCore, "op_" + op.replace(".", "_")), op
    assert protocol.OPS["journal.undo"] == protocol.WEAKEN
    assert protocol.OPS["firewall.unblock"] == protocol.WEAKEN
    json.dumps(protocol.OPS)


def test_amsi_reregisters_after_move(tmp_path, monkeypatch):
    """Установка переехала: старый путь в списке серверов, нового нет — регистрация заново."""
    import sys

    import trustseal
    from scanner import amsi
    folder = tmp_path / "seal" / "amsi"
    folder.mkdir(parents=True)
    src = tmp_path / "sbit_amsi64.dll"
    src.write_bytes(b"MZ provider")
    dll = folder / "sbit_amsi64-x.dll"
    dll.write_bytes(b"MZ provider")
    new_exe = tmp_path / "new" / "StretchBIT.exe"
    new_exe.parent.mkdir()
    new_exe.write_bytes(b"MZ")
    monkeypatch.setattr(trustseal, "protected_dir", lambda: tmp_path / "seal")
    monkeypatch.setattr(amsi, "registered", lambda: {64: str(dll)})
    monkeypatch.setattr(amsi, "dll_sources", lambda bin_dir=None: {64: src})
    monkeypatch.setattr(amsi, "server_paths", lambda: [str(new_exe).lower()])
    servers = [r"c:\program files (x86)\stretchbit-test\stretchbit.exe"]
    monkeypatch.setattr(amsi, "registered_servers", lambda: list(servers))
    assert not amsi.registration_ok()              # новой программы в списке нет
    servers[:] = [str(new_exe).lower()]
    assert amsi.registration_ok()
    servers.append(r"c:\gone\stretchbit.exe")      # несуществующий путь — убрать
    assert not amsi.registration_ok()
    servers.pop()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    import winacl                                  # собранная: папка пользователя — небезопасно
    monkeypatch.setattr(winacl, "admin_only", lambda p: (False, "пользователь"))
    assert not amsi.server_allowed(str(new_exe)) and not amsi.registration_ok()
