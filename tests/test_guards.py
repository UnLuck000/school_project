"""Контроль запуска, защита от стилеров, драйверы, расписание, быстрая проверка, расширения, VPN."""
import hashlib
import json
import os
import struct
import threading
import time
from datetime import datetime
from pathlib import Path

import pytest

from scanner import drivers, fullscan, launchguard, schedule
from toolbox import extensions, stealerguard
from vpn import profiles


# ---------- контроль запуска ----------
def _process_start_v3(pid: int, ppid: int, image: str) -> bytes:
    """Событие Kernel-Process 1 в раскладке Windows 10/11 (как в живом ETW)."""
    sid = bytes.fromhex("010100000000001000300000")  # S-1-16-12288
    return (struct.pack("<IQQIQIIII", pid, 0xC8F8, 0x01DD6DEF8338C727, ppid, 0xC8F7,
                        1, 0, 2, 1) + sid + image.encode("utf-16-le") + b"\0\0")


def test_parse_process_start_new_and_old_layouts():
    image = r"\Device\HarddiskVolume3\Windows\System32\cmd.exe"
    assert launchguard.parse_process_start(_process_start_v3(2436, 20668, image)) == \
        (2436, 20668, image)
    old = struct.pack("<IQIII", 100, 0x01DD6DEF8338C727, 50, 1, 0) + \
        image.encode("utf-16-le") + b"\0\0"
    assert launchguard.parse_process_start(old) == (100, 50, image)


def test_script_rules(tmp_path):
    script = tmp_path / "run.ps1"
    script.write_text("Write-Host 1")
    assert launchguard.script_args(["powershell.exe", "-File", str(script)]) == [str(script)]
    assert launchguard.encoded_command(["powershell.exe", "-NoProfile", "-enc",
                                        "VwByAGkAdABlAC0ASABvAHMAdAAgAGgAaQA="])
    assert not launchguard.encoded_command(["powershell.exe", "-File", str(script)])
    assert launchguard.chain_reason("WINWORD.EXE", "powershell.exe")
    assert launchguard.chain_reason("explorer.exe", "powershell.exe") is None


def test_threat_is_reported_but_not_killed(monkeypatch, tmp_path):
    """Экстренное завершение закомментировано: угроза — только уведомление, процесс
    возобновляется."""
    exe = tmp_path / "evil.exe"
    exe.write_bytes(b"MZ" + b"\0" * 100)
    events, resumed = [], []
    guard = launchguard.LaunchGuard(lambda k, i: events.append((k, i)))
    monkeypatch.setattr(guard, "_own", lambda pid, ppid: False)
    monkeypatch.setattr(guard, "_cached", lambda exe: False)
    monkeypatch.setattr(guard, "_verdict", lambda paths: {p: "YARA: Evil_Test" for p in paths})
    monkeypatch.setattr(launchguard, "_suspend", lambda pid: True)
    monkeypatch.setattr(launchguard, "_resume", lambda pid: resumed.append(pid))
    killed = []
    monkeypatch.setattr(launchguard, "_kill_tree", lambda pid: killed.append(pid) or True)
    guard._check_new(1234, 1, str(exe), [])
    assert events[0][0] == "blocked" and events[0][1]["killed"] is False
    assert killed == [] and resumed == [1234]


# ---------- стилеры ----------
def test_secret_kinds_and_owners():
    chrome = r"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Login Data"
    assert stealerguard.secret_kind(chrome) == "пароли"
    assert stealerguard.secret_kind(r"C:\x\Telegram Desktop\tdata\key_datas") == "сеанс Telegram"
    assert stealerguard.secret_kind(r"C:\x\notes.txt") is None
    assert "chrome.exe" in stealerguard.owner_of(chrome)[1]


def test_stealer_policy(monkeypatch):
    guard = stealerguard.StealerGuard(lambda info: None)
    guard._trusted = set()
    monkeypatch.setattr(stealerguard, "_signed", lambda exe: True)
    path = r"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Login Data"
    assert guard.allowed(10, r"C:\Program Files\Google\Chrome\chrome.exe", path)
    assert guard.allowed(10, r"C:\Program Files\Backup\backup.exe", path)  # подписан
    assert not guard.allowed(10, r"C:\Python\python.exe", path)  # подписан, но интерпретатор
    monkeypatch.setattr(stealerguard, "_signed", lambda exe: False)
    assert not guard.allowed(10, r"C:\Users\u\AppData\Local\Temp\x.exe", path)


def test_stealer_alarm_once_per_process(monkeypatch):
    alarms = []
    guard = stealerguard.StealerGuard(alarms.append)
    monkeypatch.setattr(guard, "allowed", lambda pid, exe, path: False)
    import toolbox.decoys
    monkeypatch.setattr(toolbox.decoys, "suspend", lambda pid: True)
    from processmanager import ntsnap
    monkeypatch.setattr(ntsnap, "identity", lambda pid: (r"C:\Temp\steal.exe", ""))
    for name in ("Login Data", "Cookies"):
        guard.check_access(777, rf"C:\x\Google\Chrome\User Data\Default\{name}", "пароли")
    assert len(alarms) == 1 and alarms[0]["suspended"] and alarms[0]["owner"] == "Google Chrome"


# ---------- драйверы ----------
def _pe(cert: bytes = b"", checksum: int = 0) -> bytes:
    data = bytearray(0x200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    opt = 0x80 + 24
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<I", data, opt + 64, checksum)
    if cert:
        struct.pack_into("<II", data, opt + 112 + 32, len(data), len(cert))
    return bytes(data) + cert


def test_authentihash_ignores_checksum_and_certificate():
    plain = drivers.authentihash(_pe())
    assert plain and drivers.authentihash(_pe(checksum=12345)) == plain
    assert drivers.authentihash(_pe(cert=b"C" * 64)) == drivers.authentihash(_pe(cert=b"D" * 64))
    assert drivers.authentihash(b"not a pe") == ""


def test_driver_db_matching(tmp_path):
    good = tmp_path / "ok.sys"
    good.write_bytes(_pe())
    bad = tmp_path / "evil.sys"
    bad.write_bytes(_pe(checksum=7) + b"payload")
    sha = hashlib.sha256(bad.read_bytes()).hexdigest()
    db_file = tmp_path / "db.tsv"
    db_file.write_text(drivers.convert_loldrivers([
        {"Category": "vulnerable driver", "Tags": ["evil.sys"],
         "Commands": {"Description": "чтение памяти ядра"},
         "KnownVulnerableSamples": [{"SHA256": sha, "Authentihash": {"SHA256": ""}}]},
        {"Category": "malicious", "Tags": ["named.sys"], "Commands": {},
         "KnownVulnerableSamples": [{"SHA256": "0" * 64}]}]), encoding="utf-8")
    db = drivers.load_db(db_file)
    assert drivers.check(drivers.Driver(str(bad)), db).match == drivers.MATCH_HASH
    assert drivers.check(drivers.Driver(str(good)), db).entry is None
    named = tmp_path / "named.sys"
    named.write_bytes(_pe())
    assert drivers.check(drivers.Driver(str(named)), db).level == "warning"  # только имя


def test_resolve_driver_path():
    root = os.environ.get("SystemRoot", r"C:\Windows")
    assert drivers.resolve_path(r"\SystemRoot\System32\drivers\x.sys").lower() == \
        os.path.join(root, "System32", "drivers", "x.sys").lower()
    assert drivers.resolve_path(r"\??\C:\Tools\y.sys") == r"C:\Tools\y.sys"
    assert drivers.resolve_path("System32\\drivers\\z.sys").lower().endswith(
        r"system32\drivers\z.sys")


# ---------- расписание ----------
def _ts(*args) -> float:
    return datetime(*args).timestamp()


def test_schedule_next_run():
    now = _ts(2026, 1, 10, 9, 0)
    assert schedule.next_run(0, "1w", "12:00", now) == _ts(2026, 1, 10, 12, 0)
    assert schedule.next_run(0, "1w", "08:00", now) == _ts(2026, 1, 11, 8, 0)
    assert schedule.next_run(_ts(2026, 1, 3, 12, 5), "1w", "12:00", now) == \
        _ts(2026, 1, 10, 12, 0)
    later = _ts(2026, 2, 1, 9, 0)
    assert schedule.next_run(_ts(2026, 1, 31, 3, 0), "1m", "03:00", later) == \
        _ts(2026, 2, 28, 3, 0)  # 31 января + месяц = последний день февраля
    assert schedule.next_run(_ts(2025, 11, 30, 3, 0), "3m", "24:00", later) == \
        _ts(2026, 2, 28, 0, 0)
    # пропущенная (компьютер был выключен) — в прошлом: начнётся после предупреждения
    assert schedule.next_run(_ts(2025, 12, 1, 12, 0), "2w", "12:00", now) < now
    postponed = now + 3600
    assert schedule.next_run(_ts(2025, 12, 1, 12, 0), "2w", "12:00", now, postponed) == postponed


# ---------- быстрая проверка ----------
def test_quick_scan_filter(tmp_path, monkeypatch):
    windows = tmp_path / "Windows"
    other = tmp_path / "Games2"
    windows.mkdir()
    other.mkdir()
    (windows / "notes.txt").write_text("x")             # Windows: проверяется всё
    (other / "tool.exe").write_bytes(b"MZ")              # .exe до 16 МБ
    (other / "hidden.png").write_bytes(b"MZ" + b"\0" * 10)  # программа под видом картинки
    (other / "data.png").write_bytes(b"\x89PNG")         # настоящая картинка
    (other / "photo.jpg").write_bytes(b"MZ")             # .jpg на MZ не открывается
    (other / "lib.bin").write_bytes(b"MZ")               # .bin — тоже
    (other / "mod.pyd").write_bytes(b"\0")               # библиотека: без открытия
    big = other / "big.exe"
    with open(big, "wb") as f:
        f.truncate(fullscan.QUICK_LIMIT)
    monkeypatch.setattr(fullscan, "full_roots", lambda: [str(windows)])
    stats, cancel = fullscan.Stats(), threading.Event()
    found = []
    for root, quick in fullscan.quick_plan([str(tmp_path)]):
        found += list(fullscan.walk(root, stats, cancel, quick,
                                    {str(windows)} if quick else None))
    names = sorted(os.path.basename(p) for p in found)
    assert names == ["hidden.png", "mod.pyd", "notes.txt", "tool.exe"]


# ---------- расширения ----------
def test_extension_risk_and_chromium_profile(tmp_path, monkeypatch):
    local = tmp_path / "Local"
    profile = local / "Google" / "Chrome" / "User Data" / "Default"
    folder = profile / "Extensions" / "abcdefghijklmnopabcdefghijklmnop" / "1.0_0"
    folder.mkdir(parents=True)
    (folder / "manifest.json").write_text(json.dumps({
        "name": "__MSG_name__", "version": "1.0", "default_locale": "en",
        "permissions": ["nativeMessaging", "proxy"], "host_permissions": ["<all_urls>"]}))
    (folder / "_locales" / "en").mkdir(parents=True)
    (folder / "_locales" / "en" / "messages.json").write_text(
        json.dumps({"name": {"message": "Adult Ads Helper"}}))
    (profile / "Preferences").write_text(json.dumps({
        "extensions": {"settings": {"abcdefghijklmnopabcdefghijklmnop": {
            "location": 3, "from_webstore": False,
            "path": "abcdefghijklmnopabcdefghijklmnop\\1.0_0"}}},
        "profile": {"content_settings": {"exceptions": {"notifications": {
            "https://spam.example:443,*": {"setting": 1}}}}}}))
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming"))
    items = extensions.chromium_extensions()
    assert len(items) == 1
    ext = items[0]
    assert ext.name == "Adult Ads Helper" and ext.forced and ext.all_sites
    assert ext.risk[0] == "danger"
    sites = extensions.notification_sites()
    assert [(s.site, s.allowed) for s in sites] == [("https://spam.example:443", True)]


def test_remove_extension_and_undo(tmp_path, monkeypatch):
    from recovery import journal
    monkeypatch.setattr(extensions, "BACKUP_DIR", tmp_path / "backup")
    monkeypatch.setattr(extensions, "browser_running", lambda exe: False)
    logged = []
    monkeypatch.setattr(journal, "log_action", lambda t, op, d: logged.append((op, d)))
    profile = tmp_path / "Default"
    ext_dir = profile / "Extensions" / "idid" / "1.0_0"
    ext_dir.mkdir(parents=True)
    (ext_dir / "manifest.json").write_text("{}")
    prefs = {"extensions": {"settings": {"idid": {"location": 1}, "other": {}}}}
    (profile / "Preferences").write_text(json.dumps(prefs))
    ext = extensions.Extension("Chrome", "Default", "idid", name="X", path=str(ext_dir),
                               prefs=str(profile), exe="chrome.exe")
    message = extensions.remove_extension(ext)
    assert "Удалено" in message and not (profile / "Extensions" / "idid").exists()
    left = json.loads((profile / "Preferences").read_text())
    assert "idid" not in left["extensions"]["settings"] and "other" in left["extensions"]["settings"]
    op, data = logged[0]
    assert op == "ext_restore"
    extensions._undo_remove(data)
    assert (ext_dir / "manifest.json").exists()
    assert "idid" in json.loads((profile / "Preferences").read_text())["extensions"]["settings"]


# ---------- VPN ----------
WG = """[Interface]
PrivateKey = aGVsbG8=
Address = 10.0.0.2/32
[Peer]
PublicKey = d29ybGQ=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
"""


def test_vpn_profiles_parse_and_encrypted_store(tmp_path):
    wg = profiles.from_text("Дом", WG)
    assert (wg.kind, wg.server) == ("wireguard", "vpn.example.com:51820")
    ovpn = profiles.from_text("Работа", "client\nremote 1.2.3.4 1194\nproto udp\n", "w.ovpn")
    assert (ovpn.kind, ovpn.server) == ("openvpn", "1.2.3.4:1194")
    with pytest.raises(ValueError):
        profiles.from_text("x", "hello")
    store = tmp_path / "p.dat"
    profiles.save([wg, ovpn], store)
    assert b"PrivateKey" not in store.read_bytes()  # ключи не лежат открытым текстом
    assert [p.name for p in profiles.load(store)] == ["Дом", "Работа"]


def test_vpn_demo_backend():
    from vpn import backends
    log = []
    backend = backends.backend_for("demo", log.append)
    backend.connect(profiles.demo_profile())
    deadline = time.time() + 5
    while backend.state != backends.CONNECTED and time.time() < deadline:
        time.sleep(0.1)
    assert backend.state == backends.CONNECTED
    assert backend.counters()[0] > 0
    backend.disconnect()
    assert backend.state == backends.DISCONNECTED
    assert backends.tunnel_name("Мой VPN #1") == "VPN__1"
