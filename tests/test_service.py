"""Служба Windows и канал (service/): без установки службы — ядро и сервер канала в этом же
процессе, защита файлов — подставной монитор."""
import sys
import threading
import uuid
from pathlib import Path

import pytest

from service import protocol
from service.pipeserver import Client

ROOT = Path(__file__).resolve().parent.parent
windows = pytest.mark.skipif(sys.platform != "win32", reason="только Windows")


class FakeMonitor:
    instances: list = []

    def __init__(self, folders, on_event):
        self.folders, self.on_event = list(folders), on_event
        self.started = self.stopped = False
        self.reloaded = 0
        FakeMonitor.instances.append(self)

    def start(self):
        self.started = True
        self.on_event("status", "Защита включена. Папок пользователя: 1, системных: 0")

    def stop(self):
        self.stopped = True
        self.on_event("stopped", "Защита выключена")

    def reload_bases(self):
        self.reloaded += 1


@pytest.fixture
def stores(tmp_path, monkeypatch):
    """Карантин, журнал защиты и белый список — во временных папках."""
    import quarantine
    from recovery import threatlog
    from scanner import whitelist
    monkeypatch.setattr(quarantine, "QUARANTINE_DIR", tmp_path / "quarantine")
    monkeypatch.setattr(quarantine, "SIGNATURES_FILE", tmp_path / "sig" / "hashes.txt")
    monkeypatch.setattr(threatlog, "THREATS_FILE", tmp_path / "journal" / "threats.json")
    monkeypatch.setattr(whitelist, "WHITELIST_FILE", tmp_path / "whitelist.json")
    whitelist.forget_trusted()
    yield tmp_path
    from service import remote
    remote.uninstall()


@pytest.fixture
def core(tmp_path, stores):
    from service.core import ServiceCore
    FakeMonitor.instances = []
    c = ServiceCore(tmp_path / "svc", monitor_factory=FakeMonitor)
    yield c
    c.stop()


def user(sid="S-1-5-21-1", elevated=False, pid=0):
    return Client(pid, "", sid=sid, elevated=elevated)


def test_ops_have_handlers_and_rights(core):
    for op, level in protocol.OPS.items():
        assert level in (protocol.READ, protocol.CONTROL, protocol.WEAKEN, protocol.ADMIN)
        assert hasattr(core, "op_" + op.replace(".", "_")), op
    # ослабляющие защиту операции не доступны просто так
    assert protocol.OPS["quarantine.restore"] == protocol.WEAKEN
    assert protocol.OPS["whitelist.add"] == protocol.WEAKEN
    assert protocol.OPS["config.set"] == protocol.ADMIN


def test_names_by_edition():
    assert protocol.service_name().startswith("StretchBITService")
    assert protocol.pipe_name().startswith(r"\\.\pipe\sbit-service")


def test_protection_on_off_and_config_persist(core, tmp_path):
    folder = str(tmp_path)
    status = core.handle(user(), "protection.set", {"on": True, "folders": [folder]})
    assert status["running"] and status["folders"] == [folder]
    assert FakeMonitor.instances[-1].folders == [folder]
    # тот же набор папок — защита не перезапускается
    core.handle(user(), "protection.set", {"on": True, "folders": [folder]})
    assert len(FakeMonitor.instances) == 1
    # папки другого пользователя добавляются к общему списку
    other = str(tmp_path / "other")
    core.handle(user("S-1-5-21-2"), "protection.set", {"on": True, "folders": [other]})
    assert set(FakeMonitor.instances[-1].folders) == {folder, other}
    off = core.handle(user(), "protection.set", {"on": False})
    assert not off["running"] and FakeMonitor.instances[-1].stopped
    from service.core import ServiceCore
    again = ServiceCore(core.folder, monitor_factory=FakeMonitor)
    assert again.config["enabled"] is False
    assert again.config["folders"]["S-1-5-21-2"] == [other]


def test_enabled_protection_starts_with_service(core, tmp_path):
    core.handle(user(), "protection.set", {"on": True, "folders": [str(tmp_path)]})
    core.stop()
    from service.core import ServiceCore
    again = ServiceCore(core.folder, monitor_factory=FakeMonitor)
    again.start(pipe=False)
    try:
        assert again.op_status(user(), {})["running"]
    finally:
        again.stop()


def test_lock_refuses_weakening_without_admin(core, tmp_path):
    from service.core import NeedAdmin, Refused
    with pytest.raises(NeedAdmin):
        core.handle(user(), "config.set", {"lock_protection": True})
    core.handle(user(elevated=True), "config.set", {"lock_protection": True})
    core.handle(user(), "protection.set", {"on": True, "folders": [str(tmp_path), "C:\\x"]})
    with pytest.raises(Refused):
        core.handle(user(), "protection.set", {"on": False})
    with pytest.raises(Refused):  # убрать свою папку — тоже ослабление
        core.handle(user(), "protection.set", {"on": True, "folders": [str(tmp_path)]})
    with pytest.raises(Refused):
        core.handle(user(), "whitelist.add", {"sha256": "a" * 64, "path": "x"})
    assert not core.handle(user(elevated=True), "protection.set", {"on": False})["running"]


def test_bad_arguments_refused(core):
    with pytest.raises(ValueError):
        core.handle(user(), "protection.set", {"on": True, "folders": ["relative\\path"]})
    with pytest.raises(ValueError):
        core.handle(user(), "protection.set", {"on": True, "folders": ["C:\\a"] * 40 + ["C:\\b"]})
    with pytest.raises(ValueError):
        core.handle(user(), "no.such.op", {})
    with pytest.raises(ValueError):
        core.handle(user(), "threats.add", {"level": "bad", "text": "x"})


def test_events_since_replay_and_wait(core, tmp_path):
    core.emit("scanned", "OK: a")
    core.emit("scanned", "OK: b")
    last = core.handle(user(), "events", {"since": -1})
    assert [e["text"] for e in last["events"]] == ["OK: b"]
    seq = last["seq"]
    threading.Timer(0.2, lambda: core.emit("threat", "c\tx\ty")).start()
    got = core.handle(user(), "events", {"since": seq, "wait": 3})
    assert [e["kind"] for e in got["events"]] == ["threat"]
    # другой номер запуска службы — всё сначала
    assert len(core.handle(user(), "events", {"since": 999, "boot": "old"})["events"]) == 3


def test_monitor_threat_goes_to_threatlog(core, tmp_path):
    core.handle(user(), "protection.set", {"on": True, "folders": [str(tmp_path)]})
    monitor = FakeMonitor.instances[-1]
    monitor.on_event("threat", f"{tmp_path / 'bad.exe'}\thash match (x)\tобнаружен")
    found = core.handle(user(), "threats.list", {})
    assert found and found[0]["source"] == "Защита файлов"


def test_quarantine_stream_roundtrip(stores):
    import io
    import quarantine
    data = b"MZ" + b"\x01" * 5000
    deleted = []
    qid = quarantine.quarantine_stream(io.BytesIO(data), "C:\\x\\a.exe", "тест",
                                       delete=lambda: deleted.append(1))
    assert deleted == [1]
    stored = (quarantine.QUARANTINE_DIR / f"{qid}.quar").read_bytes()
    assert stored != data and len(stored) == len(data)  # не рабочая программа
    out = io.BytesIO()
    dest = quarantine.restore_stream(qid, out, "C:\\y\\a.exe")
    assert out.getvalue() == data and dest == "C:\\y\\a.exe"
    import hashlib

    from scanner.whitelist import load_whitelist
    assert hashlib.sha256(data).hexdigest() in load_whitelist()


def test_quarantine_stream_undone_when_delete_fails(stores):
    import io
    import quarantine

    def fail():
        raise PermissionError(13, "нет")
    with pytest.raises(PermissionError):
        quarantine.quarantine_stream(io.BytesIO(b"abc"), "C:\\a", "x", delete=fail)
    assert not list(quarantine.QUARANTINE_DIR.glob("*"))


# ---------- канал: сервер и клиент в этом процессе ----------
@pytest.fixture
def pipe(core):
    from service import client as svc_client
    name = rf"\\.\pipe\sbit-test-{uuid.uuid4().hex[:8]}"
    core.start_pipe(name)
    c = svc_client.ServiceClient(name, verify_server=svc_client.dev_server_check())
    yield core, c, name
    c.close()


@windows
def test_pipe_roundtrip_identity_and_errors(pipe, tmp_path):
    core, c, _name = pipe
    hello = c.call("hello")
    assert hello["protocol"] == protocol.PROTOCOL and hello["sid"].startswith("S-1-")
    status = c.call("protection.set", on=True, folders=[str(tmp_path)])
    assert status["running"] and status["folders"] == [str(tmp_path)]
    with pytest.raises(ValueError):
        c.call("protection.set", on=True, folders=["relative"])
    from service.client import NeedAdminRemote
    if not hello["elevated"]:
        with pytest.raises(NeedAdminRemote):
            c.call("config.set", lock_protection=True)


@pytest.fixture
def child(tmp_path):
    """Ядро службы в отдельном процессе; окно (этот процесс) — через remote.install."""
    import os
    import subprocess

    from service import client as svc_client, remote
    name = rf"\\.\pipe\sbit-test-{uuid.uuid4().hex[:8]}"
    env ={**os.environ, "PYTHONPATH": str(ROOT), "STRETCHBIT_SEAL_DIR": str(tmp_path / "seal")}
    proc = subprocess.Popen([sys.executable, str(ROOT / "tests" / "service_child.py"), name,
                             str(tmp_path / "data")], cwd=tmp_path, env=env,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        assert proc.stdout.readline().strip() == b"ready"
        c = svc_client.ServiceClient(name, verify_server=svc_client.dev_server_check())
        remote.install(c)
        yield c, tmp_path
        c.close()
    finally:
        remote.uninstall()
        proc.stdin.close()
        proc.wait(timeout=15)


@windows
def test_pipe_quarantine_by_handle(child):
    _c, tmp_path = child
    import quarantine
    from recovery import threatlog
    victim = tmp_path / "files" / "bad.exe"
    victim.parent.mkdir()
    victim.write_bytes(b"MZ" + bytes([0x90]) * 3000)
    rid = threatlog.add(str(victim), "threat", "hash match (тест)", "Защита файлов")
    qid = quarantine.quarantine_file(victim, "тест")
    assert not victim.exists()  # удалён через дескриптор окна
    assert (tmp_path / "quarantine_data" / f"{qid}.quar").is_file()  # карантин службы
    items = quarantine.list_quarantine()
    assert [m["id"] for m in items] == [qid]
    assert items[0]["original_path"].lower() == str(victim).lower()
    threatlog.set_status(rid, threatlog.QUARANTINED, qid)
    assert threatlog.get(rid)["status"] == threatlog.QUARANTINED
    dest = quarantine.restore_file(qid)
    assert victim.read_bytes().startswith(b"MZ") and dest.name == "bad.exe"
    from scanner.whitelist import load_whitelist, trusted_hashes
    assert items[0]["sha256"] in load_whitelist()
    assert items[0]["sha256"] in trusted_hashes()
    with pytest.raises(ValueError):
        quarantine.restore_file(qid)


@windows
def test_pipe_busy_file_and_existing_destination(child):
    _c, tmp_path = child
    import quarantine
    busy = tmp_path / "busy.exe"
    busy.write_bytes(b"MZ")
    # открыт без FILE_SHARE_DELETE — «занят»
    with open(busy, "rb"), pytest.raises(PermissionError):
        quarantine.quarantine_file(busy, "тест")
    assert busy.exists()
    qid = quarantine.quarantine_file(busy, "тест")
    busy.write_bytes(b"new")
    with pytest.raises(FileExistsError):
        quarantine.restore_file(qid)
    assert busy.read_bytes() == b"new"
    assert quarantine.delete_file(qid) is True  # хэш — в свою базу службы
    assert (tmp_path / "signatures" / "hashes.txt").is_file()


@windows
def test_client_refuses_foreign_server(core):
    from service import client as svc_client
    name = rf"\\.\pipe\sbit-test-{uuid.uuid4().hex[:8]}"
    core.start_pipe(name)
    c = svc_client.ServiceClient(name, verify_server=lambda pid: False)
    with pytest.raises(svc_client.ServiceUnavailable):
        c.call("hello")


@windows
def test_server_refuses_foreign_client(core):
    from service import client as svc_client, pipeserver
    name = rf"\\.\pipe\sbit-test-{uuid.uuid4().hex[:8]}"
    core.start_pipe(name, allowed=pipeserver.same_program(r"C:\nope\other.exe"))
    c = svc_client.ServiceClient(name, verify_server=svc_client.dev_server_check(),
                                 timeout=2.0)
    with pytest.raises(svc_client.ServiceUnavailable):
        c.call("hello")
    assert core.server.rejected >= 1


@windows
def test_event_pump_delivers(pipe):
    from service.client import EventPump, ServiceClient, dev_server_check
    core, _c, name = pipe
    got, links = [], []
    done = threading.Event()

    def on_event(e):
        got.append(e)
        if e["kind"] == "threat":
            done.set()
    pump = EventPump(ServiceClient(name, verify_server=dev_server_check()), on_event,
                     links.append)
    pump.start()
    try:
        threading.Timer(0.3, lambda: core.emit("threat", "x\ty\tz")).start()
        assert done.wait(5)
        assert links == [True]
    finally:
        pump.stop()


def test_scm_query_unknown_service():
    from service import scm
    assert scm.query("SBIT-no-such-service-" + uuid.uuid4().hex[:6]) is None
    assert scm.command_line(r"C:\P F\StretchBIT.exe") == '"C:\\P F\\StretchBIT.exe" --service'


def test_connect_without_service_from_sources(monkeypatch):
    from service import client as svc_client
    monkeypatch.delenv(protocol.DEV_ENV, raising=False)
    assert svc_client.connect() is None  # из исходников без ядра в консоли — как раньше


def test_service_folders_include_profiles(monkeypatch, tmp_path):
    from service import core as svc_core
    profile = tmp_path / "User"
    (profile / "AppData" / "Roaming").mkdir(parents=True)
    monkeypatch.setattr(svc_core, "user_profiles", lambda: [profile])
    folders = {str(f): (r, a) for f, r, a in svc_core.service_system_folders()}
    assert folders[str(profile / "AppData" / "Roaming")] == (True, False)
    startup = profile / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / \
        "Programs" / "Startup"
    assert folders[str(startup)] == (True, True)


def test_installer_and_uninstall_know_service():
    text = (ROOT / "installer.iss").read_text(encoding="utf-8")
    assert "--service-install" in text and "net.exe" in text
    import uninstall
    names = [title for title, _ in uninstall.steps(ROOT, test=True, wipe=False)]
    assert names[0] == "Закрыть запущенную программу"
    assert "Удалить службу защиты" in names


def test_fake_monitor_core_does_not_update_bases(core):
    """Ядро с подставным монитором (тесты) не запускает автообновление баз."""
    assert core.auto_update is False
    core.start(pipe=False)
    assert getattr(core, "_db_thread", None) is None


def test_service_updates_bases_once_a_day(core, monkeypatch):
    import updater
    calls = []
    monkeypatch.setattr(updater, "can_update", lambda: True)
    monkeypatch.setattr(updater, "bases_missing", lambda: False)
    def update_all(fraction=None):
        for value in (0.0, 0.004, 0.3, 0.6, 1.0):
            fraction(value)
            calls.append(core.op_status(user(), {})["db_progress"])
        return True
    monkeypatch.setattr(updater, "update_all", update_all)
    core.handle(user(), "protection.set", {"on": True})
    assert core.update_bases_if_due(now=10 * 86400.0) is True
    assert calls == [0.0, 0.0, 0.3, 0.6, 1.0] and FakeMonitor.instances[-1].reloaded == 1
    status = core.op_status(user(), {})
    assert status["db_last_update"] == 10 * 86400.0 and status["db_progress"] is None
    events = core.op_events(user(), {"since": 0})["events"]
    assert events[-1]["kind"] == "db" and events[-1]["text"] == "ok"
    # ход обновления — одним событием (последним), начало — «db start»
    progress = [e for e in events if e["kind"] == "db_progress"]
    assert len(progress) == 1 and progress[0]["data"]["value"] == 1.0
    assert [e["text"] for e in events if e["kind"] == "db"] == ["start", "ok"]
    assert core.update_bases_if_due(now=10 * 86400.0 + 3600) is None   # ещё не сутки
    from service.core import ServiceCore
    again = ServiceCore(core.folder, monitor_factory=FakeMonitor)        # время сохранено
    assert again.config["db_last_update"] == 10 * 86400.0
    monkeypatch.setattr(updater, "update_all", lambda fraction=None: False)
    assert core.update_bases_if_due(now=12 * 86400.0) is False
    assert core.op_events(user(), {"since": 0})["events"][-1]["text"] == "fail"



def test_service_updates_missing_bases_and_logs_reasons(core, monkeypatch, caplog):
    """Баз на диске нет (переустановка, перенос папки) — обновить, хоть сутки и не прошли;
    причины сбоя каждого источника — в журнале службы, а не только в service-stdout.log."""
    import logging

    import updater
    monkeypatch.setattr(updater, "can_update", lambda: True)
    core.config["db_last_update"] = 10 * 86400.0
    monkeypatch.setattr(updater, "bases_missing", lambda: False)
    assert core.update_bases_if_due(now=10 * 86400.0 + 60) is None
    monkeypatch.setattr(updater, "bases_missing", lambda: True)

    def failing(fraction=None):
        print("MalwareBazaar: ошибка URLError: CERTIFICATE_VERIFY_FAILED")
        return False
    monkeypatch.setattr(updater, "update_all", failing)
    monkeypatch.setattr(core.log, "propagate", True)
    monkeypatch.setattr(core.log.parent, "propagate", True)
    with caplog.at_level(logging.INFO, logger="sbit"):
        assert core.update_bases_if_due(now=10 * 86400.0 + 120) is False
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "баз на диске нет" in text and "CERTIFICATE_VERIFY_FAILED" in text
