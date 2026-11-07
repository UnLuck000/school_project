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


# ---------- правки после проверки ----------
def test_encoded_command_parent_rules():
    assert launchguard.decode_command(["powershell.exe", "-enc",
                                       "VwByAGkAdABlAC0ASABvAHMAdAAgAGgAaQA="]) == "Write-Host hi"
    assert not launchguard.encoded_suspicious("claude.exe", True)   # подписан: тихо
    assert launchguard.encoded_suspicious("winword.exe", True)      # документ
    assert launchguard.encoded_suspicious("python.exe", True)       # интерпретатор
    assert launchguard.encoded_suspicious("dropper.exe", False)     # без подписи
    assert launchguard.encoded_suspicious("", None)                 # родитель уже вышел


def test_vless_profile_and_xray_config():
    from vpn import xray
    uri = ("vless://11111111-2222-3333-4444-555555555555@vpn.example.com:8443?type=ws"
           "&security=tls&path=%2Fws&host=cdn.example.com&sni=cdn.example.com"
           "&flow=xtls-rprx-vision#%D0%94%D0%BE%D0%BC")
    p = profiles.from_text("Профиль", uri)
    assert (p.kind, p.server, p.name, p.mode) == ("vless", "vpn.example.com:8443", "Дом", "tun")
    config = xray.build_config(xray.parse_vless(uri), "proxy")
    out = config["outbounds"][0]
    assert out["settings"]["vnext"][0]["users"][0]["flow"] == "xtls-rprx-vision"
    assert out["streamSettings"]["wsSettings"]["headers"] == {"Host": "cdn.example.com"}
    assert {i["port"] for i in config["inbounds"]} == {xray.SOCKS_PORT, xray.HTTP_PORT}
    # Xray не решает маршрут по своему DNS (иначе часть соединений уходила напрямую)
    assert config["routing"]["domainStrategy"] == "AsIs"
    tun = xray.build_config(xray.parse_vless(uri), "tun", "Ethernet")
    assert tun["inbounds"][0]["protocol"] == "tun"
    assert tun["outbounds"][0]["streamSettings"]["sockopt"] == {"interface": "Ethernet"}
    with pytest.raises(ValueError):
        xray.parse_vless("vmess://abc")


def test_system_proxy_restore_on_test_key():
    import winreg
    from vpn import xray
    key = r"Software\StudyAVTest\InternetSettings"
    try:
        xray.write_proxy({"ProxyEnable": 0, "ProxyServer": "old:1", "ProxyOverride": None}, key)
        old = xray.read_proxy(key)
        xray.write_proxy({"ProxyEnable": 1, "ProxyServer": "127.0.0.1:10809",
                          "ProxyOverride": xray.BYPASS}, key)
        assert xray.read_proxy(key)["ProxyEnable"] == 1
        xray.write_proxy(old, key)
        assert xray.read_proxy(key) == old
    finally:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key)


def test_drive_properties():
    from analyzer import fileops
    root = os.environ.get("SystemDrive", "C:") + "\\"
    rows = dict(fileops.folder_properties(root))
    assert {"Имя диска", "Тип диска", "Файловая система", "Ёмкость", "Занято",
            "Свободно"} <= set(rows)
    assert fileops.is_drive_root(root) and not fileops.is_drive_root(os.path.join(root, "x"))


def test_driver_exclusions_in_release_file(tmp_path, monkeypatch):
    from scanner import exclusions
    monkeypatch.setattr(exclusions, "EXCLUSIONS_FILE", tmp_path / "exclusions.json")
    monkeypatch.setattr(exclusions, "RELEASE_FILE", tmp_path / "release_exclusions.json")
    exclusions.add("drivers", "ab" * 32, "x.sys")
    exclusions.add("checks", "k", "hosts")
    assert "drivers" in json.loads((tmp_path / "release_exclusions.json").read_text())
    assert "drivers" not in json.loads((tmp_path / "exclusions.json").read_text())
    assert set(exclusions.load()) == {"drivers", "checks"}
    d = drivers.Driver("x.sys", sha256="ab" * 32,
                       entry=drivers.DbEntry("vulnerable driver", "x.sys", ""),
                       match=drivers.MATCH_HASH, excluded=True)
    assert d.level == "clean" and "исключениях" in d.verdict()
    assert exclusions.remove("drivers", "ab" * 32)


def test_removed_extension_is_not_installed(tmp_path, monkeypatch):
    local = tmp_path / "Local"
    profile = local / "Google" / "Chrome" / "User Data" / "Default"
    profile.mkdir(parents=True)
    (profile / "Secure Preferences").write_text(json.dumps({"extensions": {"settings": {
        "gonegonegonegonegonegonegonegone": {"location": 6, "from_webstore": True,
                                             "path": "gonegone\1.0_0",
                                             "disable_reasons": [1]}}}}))
    (profile / "Preferences").write_text("{}")
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming"))
    items = extensions.chromium_extensions()
    assert items and items[0].removed and items[0].risk[0] == "removed"


def test_singbox_config_and_modes():
    from vpn import backends, singbox, xray
    reality = ("vless://11111111-2222-3333-4444-555555555555@vpn.example.com:443?type=tcp"
               "&security=reality&pbk=key&sid=ab&sni=www.microsoft.com&flow=xtls-rprx-vision#r")
    config = singbox.build_config(xray.SOCKS_PORT, r"C:\x\xray.exe")
    tun = config["inbounds"][0]
    assert tun["type"] == "tun" and tun["auto_route"] and tun["strict_route"]
    assert config["outbounds"][0] == {"type": "socks", "tag": "proxy", "server": "127.0.0.1",
                                      "server_port": xray.SOCKS_PORT, "version": "5"}
    # мимо туннеля — только наш xray.exe по полному пути, не любой файл с таким именем
    assert {"process_path": [r"C:\x\xray.exe"], "outbound": "direct"} in config["route"]["rules"]
    # IPv6: выключен — заходит в туннель и отклоняется; включён — идёт через сервер
    assert {"ip_version": 6, "action": "reject"} in config["route"]["rules"]
    assert config["dns"]["strategy"] == "ipv4_only"
    with6 = singbox.build_config(xray.SOCKS_PORT, r"C:\x\xray.exe", ipv6=True)
    assert {"ip_version": 6, "action": "reject"} not in with6["route"]["rules"]
    assert any(":" in a for a in with6["inbounds"][0]["address"])
    assert config["route"]["auto_detect_interface"] and config["route"]["find_process"]
    assert profiles.from_text("x", reality).mode == "tun"  # по умолчанию — TUN
    assert isinstance(backends.backend_for("vless", print, "tun"), backends.SingBoxBackend)
    assert isinstance(backends.backend_for("vless", print, "tun-xray"), backends.XrayBackend)
    assert isinstance(backends.backend_for("vless", print, "proxy"), backends.XrayBackend)
    assert isinstance(backends.backend_for("vless", print, "local"), backends.XrayBackend)
    assert "local" in profiles.MODES


def test_release_trusted_files():
    """Заранее известные безвредные файлы релиза: winws.exe и WinDivert (zapret), MsIo64.sys."""
    from scanner import exclusions
    from scanner.whitelist import trusted_hashes
    data = json.loads(exclusions.RELEASE_FILE.read_text(encoding="utf-8"))
    names = {e["title"] for e in data["programs"].values()}
    assert {"winws.exe", "WinDivert64.sys", "WinDivert.dll", "MsIo64.sys"} <= names
    assert {e["title"] for e in data["drivers"].values()} == {"WinDivert64.sys", "MsIo64.sys"}
    assert set(data["programs"]) <= trusted_hashes()


def test_vpn_guards_restore(monkeypatch):
    """Kill switch и подмена DNS: копия прежних значений, возврат и запись в журнал."""
    from vpn import dnsguard, killswitch
    store = {}
    from ui import settings as cfg
    monkeypatch.setattr(cfg, "set_", lambda k, v: store.__setitem__(k, v))
    monkeypatch.setattr(cfg, "get", lambda k: store.get(k, ""))
    calls, logged = [], []
    monkeypatch.setattr(killswitch, "_powershell", lambda script, env=None: (
        calls.append((script, env)),
        type("R", (), {"returncode": 0, "stdout": "Public|True|NotConfigured\n", "stderr": ""})())[1])
    monkeypatch.setattr(killswitch.journal, "log_action", lambda *a: logged.append(a[1]))
    killswitch.enable("myav-tun", [r"C:\x\xray.exe", r"C:\x\sing-box.exe"])
    assert killswitch.active() and logged == ["vpn_killswitch_off"]
    script, env = calls[-1]
    assert "DefaultOutboundAction Block" in script and env["KS_TUN"] == "myav-tun"
    assert r"C:\x\xray.exe" in env["KS_PROGRAMS"] and "192.168.0.0/16" in env["KS_LAN"]
    assert killswitch.disable() and not killswitch.active()
    assert '"Public": "NotConfigured"' in calls[-1][1]["KS_OLD"]
    # DNS: адаптер с DHCP возвращается к DHCP
    monkeypatch.setattr(dnsguard, "_powershell", lambda script, env=None: (
        calls.append((script, env)),
        type("R", (), {"returncode": 0, "stdout": "6|Wi-Fi|10.0.0.1|True\n", "stderr": ""})())[1])
    monkeypatch.setattr(dnsguard.journal, "log_action", lambda *a: logged.append(a[1]))
    assert dnsguard.protect() == ["Wi-Fi"] and logged[-1] == "vpn_dns_restore"
    assert any(env and env.get("DNS") == "1.1.1.1,1.0.0.1" for _, env in calls)
    assert dnsguard.restore()
    assert any("ResetServerAddresses" in s for s, _ in calls)


def test_vpn_routing_mux_fragment():
    from vpn import singbox, xray
    plain = xray.parse_vless("vless://11111111-2222-3333-4444-555555555555@vpn.example.com:443"
                             "?type=tcp&security=reality&pbk=key&sid=ab#x")
    vision = dict(plain, flow="xtls-rprx-vision")
    opts = {"route_ru": True, "block_ads": True, "mux": True, "fragment": True}
    said = []
    c = xray.build_config(plain, "proxy", options=opts, log=said.append)
    rules = c["routing"]["rules"]
    assert rules[0] == {"type": "field", "domain": xray.ADS, "outboundTag": "block"}
    assert {"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct"} in rules
    assert any("geosite:category-ru" in r.get("domain", []) for r in rules)
    assert c["routing"]["domainStrategy"] == "AsIs"  # без своих DNS-запросов
    assert all(i["sniffing"]["routeOnly"] for i in c["inbounds"])
    proxy = c["outbounds"][0]
    assert proxy["mux"]["enabled"] and proxy["streamSettings"]["sockopt"]["dialerProxy"] == \
        "fragment"
    assert any(o["tag"] == "fragment" and o["settings"]["fragment"] for o in c["outbounds"])
    # Vision и Mux несовместимы: Mux не включается
    cv = xray.build_config(vision, "proxy", options={"mux": True}, log=said.append)
    assert "mux" not in cv["outbounds"][0] and any("Mux" in t for t in said)
    # без опций — правил маршрутизации, кроме частных адресов, нет
    assert len(xray.build_config(plain, "proxy")["routing"]["rules"]) == 1
    # программы напрямую — в sing-box по полному пути
    sb = singbox.build_config(10808, r"C:\x\xray.exe", direct_apps=[r"C:\Games\game.exe"])
    assert {"process_path": [r"C:\Games\game.exe"], "outbound": "direct"} in sb["route"]["rules"]


def test_vpn_local_proxy(monkeypatch):
    """Локальный прокси для программ: SOCKS5 и HTTP на одном порту, только 127.0.0.1;
    занятый порт — VPN без него, с записью в журнал."""
    import socket
    from vpn import backends, xray
    from ui import settings as cfg
    values = {"vpn/local_proxy": True, "vpn/local_port": 0}
    monkeypatch.setattr(cfg, "get", lambda k: values.get(k, False))
    busy = socket.socket()
    busy.bind(("127.0.0.1", 0))
    busy.listen(1)
    free = socket.socket()
    free.bind(("127.0.0.1", 0))
    free_port = free.getsockname()[1]
    free.close()
    try:
        values["vpn/local_port"] = busy.getsockname()[1]
        if values["vpn/local_port"] < 1024:
            return
        config, said = {"inbounds": []}, []
        assert backends.add_local_proxy(config, said.append) is None
        assert config["inbounds"] == [] and "занят" in said[0]
        values["vpn/local_port"] = free_port
        assert backends.add_local_proxy(config, said.append) == free_port
        inbound = config["inbounds"][0]
        assert (inbound["protocol"], inbound["listen"]) == ("mixed", "127.0.0.1")
        values["vpn/local_proxy"] = False
        assert xray.local_port() is None
        values.update({"vpn/local_proxy": True, "vpn/local_port": xray.SOCKS_PORT})
        assert xray.local_port() is None  # свой внутренний порт не отдаём
    finally:
        busy.close()
