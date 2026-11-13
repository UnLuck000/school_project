"""Новое 13.11.2026: подписки VPN, проверка серверов и утечек, изменения профиля по ссылке,
AdBlock файлом .dat, журнал PowerShell 4104, репутация VirusTotal, проверка обновления."""
import base64
import hashlib
import json
import struct

import pytest

LINK1 = ("vless://11111111-2222-3333-4444-555555555555@nl.example.com:443"
         "?type=tcp&security=reality&pbk=key&sid=ab#Нидерланды")
LINK2 = ("vless://66666666-2222-3333-4444-555555555555@de.example.com:8443"
         "?type=tcp&security=tls#Германия")


def test_subscription_parse_and_merge():
    from vpn import profiles, subscriptions
    data = base64.b64encode(f"{LINK1}\n{LINK2}\nvmess://abc\ntrojan://x@y:1\n".encode())
    links, skipped = subscriptions.parse_links(data)
    assert links == [LINK1, LINK2] and skipped == 2
    assert subscriptions.parse_links(f"{LINK1}\n".encode()) == ([LINK1], 0)  # не base64
    with pytest.raises(ValueError):
        subscriptions.parse_links(b"!!!not base64!!!")
    assert subscriptions.parse_info("upload=1; download=2; total=3; expire=4") == {
        "upload": 1, "download": 2, "total": 3, "expire": 4}
    with pytest.raises(ValueError, match="https"):
        subscriptions.new("x", "http://example.com/sub")
    sub = subscriptions.new("", "https://provider.example/sub/token")
    assert sub.name == "provider.example"
    mine = profiles.Profile(name="Нидерланды", kind="demo", server="x")
    current, count = subscriptions.merge([mine], sub, [LINK1, LINK2])
    assert count == 2 and [p.name for p in current] == ["Нидерланды", "Нидерланды (1)", "Германия"]
    current[1].mode, current[1].auto_connect = "proxy", True
    updated, _ = subscriptions.merge(current, sub, [LINK1])   # Германия ушла из подписки
    assert [p.name for p in updated] == ["Нидерланды", "Нидерланды (1)"]
    assert updated[1].mode == "proxy" and updated[1].auto_connect     # настройки сервера те же
    sub.updated = 100.0
    assert subscriptions.due([sub], now=100.0 + 23 * 3600) == []
    assert subscriptions.due([sub], now=100.0 + 24 * 3600) == [sub]


def test_ping_and_server_address():
    import socket

    from vpn import leaks
    assert leaks.server_address("vpn.example.com:443") == ("vpn.example.com", 443)
    assert leaks.server_address("[2001:db8::1]:8443") == ("2001:db8::1", 8443)
    assert leaks.server_address("nonsense") is None
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    port = listener.getsockname()[1]
    try:
        alive, dead = leaks.ping_all([f"127.0.0.1:{port}", "nonsense"])
        assert alive is not None and alive >= 0 and dead is None
    finally:
        listener.close()


def test_leak_checks_with_fake_service():
    from vpn import leaks
    rows = [{"ip": "203.0.113.5", "country_name": "Netherlands", "asn": "VPN Host", "type": "ip"},
            {"ip": "1.1.1.1", "country_name": "Netherlands", "asn": "Cloudflare", "type": "dns"}]

    def get(url, timeout=10):
        if url.endswith("/id"):
            return b"123456"
        if "dnsleak" in url:
            return json.dumps(rows).encode()
        raise OSError("нет")

    asked = []
    ok = leaks.dns_check(get, lambda name, port: asked.append(name))
    assert ok.level == leaks.OK and len(asked) == 10 and all(".123456.bash.ws" in a for a in asked)
    rows.append({"ip": "95.0.0.1", "country_name": "Russia", "asn": "Провайдер", "type": "dns"})
    bad = leaks.dns_check(get, lambda name, port: None)
    assert bad.level == leaks.BAD and "Russia" in bad.detail
    assert leaks.ipv6_check("ipv4", lambda url, timeout=8: b"2001:db8::5").level == leaks.BAD
    assert leaks.ipv6_check("ipv4", get).level == leaks.OK                # IPv6 закрыт
    assert "DNS" in leaks.report([ok])


def test_profile_link_changes_are_reported(tmp_path, monkeypatch):
    from vpn import routing
    monkeypatch.setattr(routing, "ROUTING_DIR", tmp_path / "routing")
    remote = routing.from_dict({"name": "Чужой", "route_ru": True}, "x")
    blob = lambda: json.dumps({"format": routing.FORMAT,  # noqa: E731
                               "profile": routing.to_dict(remote)}).encode()
    p, _ = routing.import_url("https://example.com/p.json", 1, None, [], data=blob())
    routing.pop_changes()
    remote.route_ru = False
    remote.rules_direct = ["bank.example", "mail.example"]
    text = routing.update_source(p, "", data=blob())
    changes = routing.pop_changes()[p.id]
    assert "Российские сайты напрямую: выкл." in changes
    assert any("Обход: добавлено bank.example" in c for c in changes) and "Обход" in text
    with pytest.raises(ValueError, match="https"):
        routing.fetch("http://example.com/list.dat")


def test_adblock_geosite_file(tmp_path, monkeypatch):
    from vpn import routing, xray
    data = routing.build_geosite({"adblock": ["ads.example", "track.example"]})
    path = tmp_path / "a.dat"
    path.write_bytes(data)
    assert routing.dat_info(path) == ("geosite", ["ADBLOCK"])
    monkeypatch.setattr(routing, "ASSETS_DIR", tmp_path / "assets")
    p = routing.RoutingProfile(id="default", name="Default")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    folder = routing.assets_dir(p, bin_dir, ["ads.example"])
    assert (tmp_path / "assets" / "default" / routing.ADBLOCK_DAT).is_file() and folder
    assert routing.assets_dir(p, bin_dir, []) == ""
    v = xray.parse_vless("vless://11111111-2222-3333-4444-555555555555@vpn.example.com:443"
                          "?type=tcp&security=reality&pbk=key&sid=ab#x")
    rules = xray.build_config(v, "proxy", options={"adblock": ["x.example"],
                                                  "adblock_ext": routing.ADBLOCK_DAT})["routing"]["rules"]
    assert {"type": "field", "domain": [f"ext:{routing.ADBLOCK_DAT}:adblock"],
            "outboundTag": "block"} in rules
    assert not any("domain:x.example" in r.get("domain", []) for r in rules)


def _event_4104(number, total, text, block_id="{id}", path=r"C:\x\a.ps1") -> bytes:
    w = lambda s: s.encode("utf-16-le") + b"\0\0"  # noqa: E731
    return struct.pack("<ii", number, total) + w(text) + w(block_id) + w(path)


def test_pslog_assembles_and_checks(monkeypatch):
    from scanner import amsi, pslog
    assert pslog.parse_4104(_event_4104(1, 1, "Get-Date")) == (1, 1, "Get-Date", "{id}",
                                                               r"C:\x\a.ps1")
    asm = pslog.Assembler()
    assert asm.add(7, 1, 2, "Write-", "{b}", "") is None
    assert asm.add(7, 2, 2, "Host hi", "{b}", r"C:\s.ps1") == ("Write-Host hi", r"C:\s.ps1")
    events, killed = [], []
    watch = pslog.ScriptBlockWatch(events.append, skip_own=False)
    watch._bases = (None, None)
    import psutil

    class Fake:
        def __init__(self, pid):
            self.pid = pid

        def kill(self):
            killed.append(self.pid)

    monkeypatch.setattr(psutil, "Process", Fake)
    assert watch.check(10, "Get-ChildItem C:\\", "") is None
    info = watch.check(11, "$x = '" + amsi.BYPASS_PARTS[0] + "'", "")
    assert info["level"] == "threat" and info["killed"] and killed == [11]


def test_reputation_parse_and_levels():
    from scanner import reputation
    doc = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 12, "suspicious": 1, "undetected": 50,
                                "harmless": 0},
        "popular_threat_classification": {"suggested_threat_label": "trojan.agent"}}}}
    rep = reputation.parse("a" * 64, doc)
    assert (rep.malicious, rep.total, rep.level) == (12, 63, "threat")
    assert "12 из 63" in rep.text() and "trojan.agent" in rep.text()
    assert reputation.Reputation("b" * 64).level == "unknown"
    assert reputation.Reputation("c" * 64, found=True, total=70).level == "clean"


def test_update_check_helpers(tmp_path, monkeypatch):
    import updatecheck
    assert updatecheck.newer("1.0.1", "1.0.0") and not updatecheck.newer("1.0.0", "1.0.0")
    assert updatecheck.newer("v1.10.0".lstrip("v"), "1.9.9")
    assert updatecheck.repo().count("/") == 1
    installer = tmp_path / "setup.exe"
    installer.write_bytes(b"MZ installer")
    digest = hashlib.sha256(installer.read_bytes()).hexdigest()
    sums = updatecheck.parse_sums(f"{digest}  StretchBIT-1.0.1-setup.exe\nbad line\n")
    assert sums == {"StretchBIT-1.0.1-setup.exe": digest}

    class Sig:
        def __init__(self, status, publisher=None):
            self.status, self.publisher = status, publisher

    signed = {str(installer): Sig("unsigned")}
    monkeypatch.setattr(updatecheck, "_signature", lambda p: signed.get(str(p), Sig("unsigned")))
    updatecheck.verify(installer, digest, current_exe="")          # обе без подписи — можно
    with pytest.raises(ValueError, match="SHA-256"):
        updatecheck.verify(installer, "0" * 64, current_exe="")
    me = tmp_path / "StretchBIT.exe"
    signed[str(me)] = Sig("valid", "Автор")
    with pytest.raises(ValueError, match="подписана"):            # своя подписана, установщик нет
        updatecheck.verify(installer, digest, current_exe=str(me))
    signed[str(installer)] = Sig("valid", "Другой")
    with pytest.raises(ValueError, match="издатель"):
        updatecheck.verify(installer, digest, current_exe=str(me))
    signed[str(installer)] = Sig("valid", "Автор")
    updatecheck.verify(installer, digest, current_exe=str(me))
