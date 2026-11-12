"""Сетевая часть: домены и DGA, DNS через ETW (разбор событий), TLS ClientHello и JA3,
маячки, брандмауэр, базы доменов; проверка отзыва сертификатов."""
import socket
import ssl
import struct
import threading
import time
from pathlib import Path

import pytest

from networkmonitor import beacon, dns_etw, domains, firewall, tls


def test_domain_lookup_and_dga(tmp_path):
    (tmp_path / "feed.txt").write_text("# комментарий\nevil.com\nbad.example.org\n")
    data = domains.load_domains(tmp_path)
    assert domains.lookup(data, "cdn.evil.com.") == ("evil.com", "feed")
    assert domains.lookup(data, "example.org") is None
    assert domains.looks_generated("kzpq3v9xh2m4tr7w.info")
    assert domains.looks_generated("ndfjkqwmvzpxrtl.top")
    for name in ("google.com", "www.youtube.com", "stackoverflow.com", "mail.yandex.ru",
                 "rr3---sn-4g5e6nzz.googlevideo.com", "internationalbusiness.org"):
        assert not domains.looks_generated(name), name


def test_ja3_list(tmp_path):
    (tmp_path / "sslbl.txt").write_text("# x\n03e186a7f83285e93341de478334006e\tTofsee\n")
    assert domains.load_ja3(tmp_path) == {"03e186a7f83285e93341de478334006e": "Tofsee (sslbl)"}


def test_dns_event_parsing():
    name = "Example.COM".encode("utf-16-le") + b"\0\0"
    start = dns_etw.parse_event(3006, 42, name + struct.pack("<IQ", 1, 0))
    assert start.name == "example.com" and start.pid == 42 and not start.final
    results = "type: 5 cdn.example.com;::ffff:93.184.216.34;2606:2800::1;".encode("utf-16-le")
    done = dns_etw.parse_event(3008, 42, name + struct.pack("<IQI", 1, 0, 0) + results + b"\0\0")
    assert done.final and done.results == ("93.184.216.34", "2606:2800::1")
    assert dns_etw.parse_event(1234, 1, name) is None


def test_etw_structure_sizes():
    import ctypes
    assert ctypes.sizeof(dns_etw.EVENT_TRACE_PROPERTIES) == 120
    assert ctypes.sizeof(dns_etw.EVENT_TRACE_LOGFILEW) == 448
    assert ctypes.sizeof(dns_etw.EVENT_HEADER) == 80
    assert dns_etw.EVENT_RECORD.UserData.offset == 96


def _real_client_hello(server_name: str) -> bytes:
    """Настоящий ClientHello от модуля ssl: локальный сервер читает первые байты."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    box = []

    def accept():
        conn, _ = srv.accept()
        box.append(conn.recv(65535))
        conn.close()

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    client = socket.create_connection(srv.getsockname())
    try:
        ssl.create_default_context().wrap_socket(client, server_hostname=server_name)
    except (ssl.SSLError, OSError):
        pass
    thread.join(5)
    srv.close()
    return box[0]


def test_client_hello_sni_and_ja3():
    hello = tls.parse_client_hello(_real_client_hello("example.org"))
    assert hello.sni == "example.org"
    assert len(hello.ja3) == 32
    version, ciphers, extensions, *_ = hello.ja3_text.split(",")
    assert version == "771" and ciphers and "0" in extensions.split("-")
    assert tls.parse_client_hello(b"\x17\x03\x03\x00\x10" + b"\0" * 16) is None  # не Handshake


def test_ja3_skips_grease():
    # минимальный ClientHello: версия 0x0303, шифры GREASE 0x0a0a и 0x1301, без расширений
    body = struct.pack(">H", 0x0303) + b"\0" * 32 + b"\0" + struct.pack(">H4H", 4, 0x0A0A,
                                                                          0x1301, 0, 0)[:6]
    body += b"\x01\x00" + struct.pack(">H", 0)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake
    hello = tls.parse_client_hello(record)
    assert hello.ja3_text == "771,4865,,,"


def test_tcp_payload_ipv4():
    ip = bytes([0x45, 0, 0, 0, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 93, 184, 216, 34])
    tcp = struct.pack(">HHIIBBHHH", 50000, 443, 0, 0, 5 << 4, 0x18, 0, 0, 0)
    assert tls.tcp_payload(ip + tcp + b"\x16data") == ("93.184.216.34", 50000, 443, b"\x16data")


def test_beacon_detector():
    det = beacon.BeaconDetector()
    found = None
    for i in range(8):  # каждые 60 с ± 1 с
        found = det.feed("bot.exe", r"C:\Temp\bot.exe", "evil.com", 1000 + i * 60 + (i % 2), "tcp")
        if found:
            break
    assert found and found.count == 6 and 55 < found.period < 65
    noisy = beacon.BeaconDetector()
    for t in (0, 5, 70, 80, 300, 310, 900, 905):
        assert noisy.feed("app.exe", "", "site.com", t, "tcp") is None


def test_firewall_refuses_local_addresses():
    with pytest.raises(ValueError):
        firewall.block_ip("192.168.1.10")
    with pytest.raises(ValueError):
        firewall.block_ip("127.0.0.1")


# noinspection HttpUrlsUsage
def test_updater_host_parsing():
    import updater
    assert updater._host("http://Evil.com:8080/path?x=1") == "evil.com"
    assert updater._host("evil.com:443") == "evil.com"
    assert updater._host("http://1.2.3.4/x") is None
    assert updater._host("not a domain") is None


def test_revocation(monkeypatch):
    from scanner import signature
    target = Path(__file__)
    valid = signature.SignatureInfo(signature.VALID, "Издатель", "embedded")
    monkeypatch.setattr(signature, "_revocation_code", lambda p, source: signature.CERT_E_REVOKED)
    signature._rev_cache.clear()
    revoked = signature.check_revocation(target, valid)
    assert revoked.status == signature.REVOKED and "отозван" in signature.describe(revoked)
    monkeypatch.setattr(signature, "_revocation_code", lambda p, source: 0x80092013)  # offline
    signature._rev_cache.clear()
    unknown = signature.check_revocation(target, valid)
    assert unknown.status == signature.VALID and unknown.revocation == signature.REV_UNKNOWN

    def slow_server(_path, _source):
        time.sleep(2)
        return 0

    monkeypatch.setattr(signature, "_revocation_code", slow_server)
    signature._rev_cache.clear()
    slow = signature.check_revocation(target, valid, timeout=0.2)  # сервер не ответил
    assert slow.revocation == signature.REV_UNKNOWN
    unsigned = signature.SignatureInfo(signature.UNSIGNED)
    assert signature.check_revocation(target, unsigned) is unsigned


def test_engine_revoked_signature_keeps_detection(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from scanner import engine
    from scanner.signature import REVOKED, SignatureInfo
    target = tmp_path / "x.exe"
    target.write_bytes(b"MZ")
    monkeypatch.setattr(engine, "match_details",
                        lambda rules, p, data=None: [SimpleNamespace(rule="R", namespace="1_x", meta={})])
    monkeypatch.setattr(engine, "inspect_signature", lambda p: SignatureInfo("valid", "X"))
    monkeypatch.setattr(engine, "check_revocation",
                        lambda p, sig: SignatureInfo(REVOKED, "X", revocation="revoked"))
    assert engine.analyze(target, object(), heuristics=False, revocation=True) == \
        "YARA: R [сертификат отозван]"
    assert engine.analyze(target, object(), heuristics=False, revocation=False) is None


def test_pool_modes():
    from scanner import pool
    assert [pool.mode_size(m) for m in ("slow", "balanced", "fast", "?")] == [2, 4, 6, 4]
    scan = pool.ScanPool(6)
    scan.resize(2)
    assert scan.size == 2


def test_shared_services_and_quiet_alerts(tmp_path, monkeypatch):
    import os
    from networkmonitor.netmon import NetworkMonitor
    data = {"github.com": "urlhaus", "discord.com": "urlhaus", "evil-c2.top": "threatfox"}
    assert domains.lookup(data, "codeload.github.com") is None
    assert domains.lookup(data, "discord.com") is None
    assert domains.lookup(data, "cdn.evil-c2.top") == ("evil-c2.top", "threatfox")
    mon = NetworkMonitor(tmp_path, tmp_path, tmp_path, lambda *a: None,
                         watch_dns=False, watch_tls=False)
    monkeypatch.setattr(mon, "_verdict", lambda exe: "")
    monkeypatch.setattr(mon, "_signature", lambda exe: ("Действительна (Discord Inc.)", True))
    assert "сама программа" in mon.quiet_reason(os.getpid(), "pythonw.exe", "x")
    assert "подписана" in mon.quiet_reason(1234, "Discord.exe", r"C:\Discord.exe")
    assert mon.quiet_reason(1234, "powershell.exe", r"C:\powershell.exe") == ""  # LOLBin
    monkeypatch.setattr(mon, "_signature", lambda exe: ("Нет подписи", False))
    assert mon.quiet_reason(1234, "bot.exe", r"C:\Temp\bot.exe") == ""


def test_socket_event_layout():
    """WINDIVERT_ADDRESS уровня SOCKET: PID и порты по смещениям windivert.h 2.x."""
    import struct
    addr = bytearray(80)
    struct.pack_into("<I", addr, 32, 4321)
    struct.pack_into("<HH", addr, 68, 55123, 443)
    assert tls.socket_event(bytes(addr)) == (4321, 55123, 443)
    assert tls.socket_event(b"\0" * 10) is None


def test_socket_map_names_process_at_connect():
    import os
    m = tls.SocketMap()
    m.add(50001, os.getpid())
    pid, name, _ = m.get(50001)
    assert pid == os.getpid() and name.lower().startswith("python")
    assert m.get(50002) is None


def test_domain_level_apex_and_shared():
    from networkmonitor import domains
    feed = {"baidu.com": "threatfox", "evil.com": "threatfox", "x.bad.net": "urlhaus"}
    assert domains.lookup(feed, "hm.baidu.com") is None            # крупный сайт — не судим
    assert domains.lookup_level(feed, "evil.com")[2] == "critical"   # точное имя
    assert domains.lookup_level(feed, "a.evil.com")[2] == "warning"  # только родитель 2-го уровня
    assert domains.lookup_level(feed, "a.x.bad.net")[2] == "critical"
