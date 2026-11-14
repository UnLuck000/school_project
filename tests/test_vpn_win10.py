"""VPN по журналам Windows 10 (14.11.2026): повторы журнала, «The object already exists»,
долгий запуск ядер, сертификат с недокачанным корнем, zapret."""
import ssl
import threading

import pytest

from vpn import backends, checks, netdiag, singbox


# ---------- журнал не повторяется ----------
class FakeRemote:
    def __init__(self):
        self._llock = threading.Lock()
        self.listeners = []

    def listen(self, kind, callback):
        self.listeners.append(callback)

    def unlisten(self, kind, callback):
        self.listeners.remove(callback)


def test_one_vpn_listener_per_window():
    from service.remote import RemoteBackend
    remote, lines = FakeRemote(), []
    for _ in range(5):                                    # пять подключений подряд
        RemoteBackend(remote, "vless", lines.append, "tun")._listen()
    assert len(remote.listeners) == 1
    for callback in remote.listeners:
        callback({"log": "Подключено"})
    assert lines == ["Подключено"]


def test_core_problems_are_logged_in_release():
    assert backends.core_problem("sing-box: FATAL[0000] start service: The object already exists.")
    assert backends.core_problem("Xray: 2026/11/14 [Warning] failed to dial")
    assert not backends.core_problem("sing-box: INFO[0000] sing-box started (0.31s)")
    assert not backends.core_problem("Xray: from 1.2.3.4 accepted tcp:x.com:443 [proxy] ERROR")


# ---------- адрес TUN ----------
def test_tun_address_skips_stale_own_adapter_and_failed():
    # адрес держит адаптер прежнего sing-box (тоже sbit-tun) — берём другой
    assert singbox.free_tun_address(["172.19.0.1"]) == "172.23.231.1/30"
    assert singbox.free_tun_address([], exclude=("172.19.0.1/30",)) == "172.23.231.1/30"
    every = singbox.TUN_CANDIDATES
    assert singbox.free_tun_address([], exclude=every[:-1]) == every[-1]
    assert singbox.tun_address6(every[0]) != singbox.tun_address6(every[1])
    config = singbox.build_config(10808, r"C:\x\xray.exe", tun_address=every[2])
    tun = next(i for i in config["inbounds"] if i["type"] == "tun")
    assert tun["address"] == [every[2], singbox.TUN6_CANDIDATES[2]]


class FakeProc:
    """Ядро: печатает строки и, пока живо, держит вывод открытым (как настоящее)."""

    def __init__(self, lines, alive=True):
        self._alive = alive
        self._done = threading.Event()
        if not alive:
            self._done.set()
        self.stdout = self._lines(lines)

    def _lines(self, lines):
        yield from lines
        self._done.wait(5)

    def poll(self):
        return None if self._alive else 1

    def kill(self):
        self._alive = False
        self._done.set()

    terminate = kill

    def wait(self, timeout=None):
        return 1


def _tun_backend(tmp_path, monkeypatch):
    """SingBoxBackend с подставными ядрами: sing-box и Xray запускаются и живут."""
    monkeypatch.setattr(backends, "TUNNEL_DIR", tmp_path)
    b = backends.SingBoxBackend(lambda text: None)
    b.exe, b.xray_exe, b.available = r"C:\sb\sing-box.exe", r"C:\x\xray.exe", True
    b.options = {"block_quic": True, "block_udp": False}
    b.settings = {"vpn/killswitch": True}
    from vpn import procguard, windns, xray
    monkeypatch.setattr(xray, "parse_vless", lambda cfg: {
        "address": "1.2.3.4", "sni": "x", "security": "reality"})
    monkeypatch.setattr(xray, "ensure_free", lambda port: None)
    monkeypatch.setattr(xray, "server_address", lambda host, mode: host)
    monkeypatch.setattr(xray, "build_config", lambda v, mode: {
        "inbounds": [{"protocol": "socks", "port": 10808}], "outbounds": []})
    monkeypatch.setattr(xray, "apply_options", lambda *a: None)
    monkeypatch.setattr(xray, "wait_port", lambda port, timeout=8.0: True)
    monkeypatch.setattr(backends, "add_local_proxy", lambda cfg, log: {})
    monkeypatch.setattr(windns, "manual_dns", lambda: {"v4": [], "v6": []})
    monkeypatch.setattr(procguard, "bind", lambda proc, log: None)
    monkeypatch.setattr(backends.subprocess, "Popen", lambda args, **_kw: FakeProc([]))
    monkeypatch.setattr(b, "_wait_old_adapter", lambda: None)
    monkeypatch.setattr(b, "_wait_adapter", lambda timeout=None: True)
    return b


def test_disconnect_during_dns_and_killswitch_is_not_error(tmp_path, monkeypatch):
    """«Отключить», пока шли подмена DNS и kill switch (Windows 10, 18:58): раньше kill
    switch падал на убранном адаптере (HRESULT 0x80070057) и окно показывало ошибку."""
    b = _tun_backend(tmp_path, monkeypatch)
    from vpn import dnsguard, killswitch
    restored = []

    def protect():
        b.disconnect()                       # пользователь нажал «Отключить»
        return ["Беспроводная сеть"]
    monkeypatch.setattr(dnsguard, "protect", protect)
    monkeypatch.setattr(dnsguard, "restore", lambda: restored.append("dns"))
    monkeypatch.setattr(killswitch, "enable", lambda *a: None)
    monkeypatch.setattr(killswitch, "disable", lambda: restored.append("ks") or True)

    class P:
        config, server, name = "vless://x", "1.2.3.4:443", "p"
    b.connect(P())
    assert b.state == backends.DISCONNECTED, b.error
    assert not b.dns_changed and not b.killswitch and "dns" in restored


def test_singbox_retries_with_other_address(tmp_path, monkeypatch):
    """Первый sing-box падает с «already exists» — второй запуск с другим адресом."""
    monkeypatch.setattr(backends, "TUNNEL_DIR", tmp_path)
    b = backends.SingBoxBackend(lambda text: None)
    b.exe, b.xray_exe, b.available = r"C:\sb\sing-box.exe", r"C:\x\xray.exe", True
    b.options, b.settings = {"block_quic": True, "block_udp": False}, {"vpn/killswitch": False}
    from vpn import dnsguard, procguard, windns, xray
    monkeypatch.setattr(xray, "parse_vless", lambda cfg: {
        "address": "1.2.3.4", "sni": "x", "security": "reality"})
    monkeypatch.setattr(xray, "ensure_free", lambda port: None)
    monkeypatch.setattr(xray, "server_address", lambda host, mode: host)
    monkeypatch.setattr(xray, "build_config", lambda v, mode: {
        "inbounds": [{"protocol": "socks", "port": 10808}], "outbounds": []})
    monkeypatch.setattr(xray, "apply_options", lambda *a: None)
    monkeypatch.setattr(xray, "wait_port", lambda port, timeout=8.0: True)
    monkeypatch.setattr(backends, "add_local_proxy", lambda cfg, log: {})
    monkeypatch.setattr(windns, "manual_dns", lambda: {"v4": [], "v6": []})
    monkeypatch.setattr(dnsguard, "protect", lambda: [])
    monkeypatch.setattr(procguard, "bind", lambda proc, log: None)
    monkeypatch.setattr(singbox, "free_tun_address",
                        lambda used=None, exclude=(): next(
                            c for c in singbox.TUN_CANDIDATES if c not in exclude))
    started = []

    def popen(args, **_kw):
        if "xray" in args[0]:
            return FakeProc([])
        from pathlib import Path
        started.append(Path(args[-1]).read_text(encoding="utf-8"))
        if len(started) == 1:
            return FakeProc(["FATAL[0000] start service: set ipv4 address: "
                             "The object already exists."], alive=False)
        return FakeProc([])
    monkeypatch.setattr(backends.subprocess, "Popen", popen)
    monkeypatch.setattr(b, "_wait_old_adapter", lambda: None)
    attempts = []

    def wait_adapter(timeout=None):
        attempts.append(1)
        if len(attempts) == 1:
            b.error = "sing-box: start service: The object already exists."
            return False
        return True
    monkeypatch.setattr(b, "_wait_adapter", wait_adapter)

    class P:
        config, server, name = "vless://x", "1.2.3.4:443", "p"
    b.connect(P())
    assert b.state == backends.CONNECTED, b.error
    assert len(started) == 2
    assert singbox.TUN_CANDIDATES[0] in started[0] and singbox.TUN_CANDIDATES[1] in started[1]
    b.disconnect()


# ---------- сертификат ----------
def test_cert_trusted_by_windows_is_not_substituted(monkeypatch):
    """Python не нашёл корень (код 20), а Windows цепочку строит — не подмена."""
    calls = []

    class Sock:
        def close(self):
            pass

    def wrap(self, sock, server_hostname=None):
        calls.append(server_hostname)
        e = ssl.SSLCertVerificationError("certificate verify failed")
        e.verify_code, e.verify_message = 20, "unable to get local issuer certificate"
        raise e
    monkeypatch.setattr(checks, "open_tcp", lambda *a, **k: Sock())
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap)
    monkeypatch.setattr(checks, "_peek_issuer", lambda *a: "GoDaddy.com, Inc.")
    monkeypatch.setattr(checks, "windows_trusts", lambda *a: True)
    result = checks.probe("telegram.org", ("direct",))
    assert result.cert == "ok" and len(calls) == 2           # повтор после докачки корня
    monkeypatch.setattr(checks, "windows_trusts", lambda *a: False)
    assert checks.probe("telegram.org", ("direct",)).cert == "substituted"


def test_root_sent_by_server_code_19(monkeypatch):
    """«self-signed certificate in certificate chain» (код 19) — тот же случай: корень
    прислал сервер, в хранилище Python его нет (telegram.org, Windows 10, 19:00)."""
    class Sock:
        def close(self):
            pass

    def wrap(self, sock, server_hostname=None):
        e = ssl.SSLCertVerificationError("self-signed certificate in certificate chain")
        e.verify_code, e.verify_message = 19, "self-signed certificate in certificate chain"
        raise e
    monkeypatch.setattr(checks, "open_tcp", lambda *a, **k: Sock())
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap)
    monkeypatch.setattr(checks, "_peek_issuer", lambda *a: "GoDaddy.com, Inc.")
    monkeypatch.setattr(checks, "windows_trusts", lambda *a: True)
    assert checks.probe("telegram.org", ("direct",)).cert == "ok"


def test_name_is_checked_when_windows_trusts_chain():
    """При ошибке цепочки OpenSSL имя не проверяет, Windows — тоже: проверяем сами."""
    cert = {"subjectAltName": (("DNS", "telegram.org"), ("DNS", "*.telegram.org"))}
    assert checks.name_matches(cert, "telegram.org")
    assert checks.name_matches(cert, "core.telegram.org")
    assert not checks.name_matches(cert, "a.b.telegram.org")
    assert not checks.name_matches(cert, "evil.org")
    assert not checks.name_matches({"subjectAltName": (("DNS", "evil.org"),)}, "telegram.org")


def test_wrong_name_is_substituted_even_if_windows_trusts(monkeypatch):
    class Sock:
        def close(self):
            pass

    def wrap(self, sock, server_hostname=None):
        e = ssl.SSLCertVerificationError("hostname mismatch")
        e.verify_code, e.verify_message = 62, "Hostname mismatch"
        raise e
    monkeypatch.setattr(checks, "open_tcp", lambda *a, **k: Sock())
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap)
    monkeypatch.setattr(checks, "_peek_issuer", lambda *a: "Evil CA")
    monkeypatch.setattr(checks, "windows_trusts", lambda *a: pytest.fail("не спрашивать"))
    assert checks.probe("telegram.org", ("direct",)).cert == "substituted"


# ---------- zapret ----------
def test_zapret_is_reported_before_tun(monkeypatch):
    from processmanager import ntsnap

    class P:
        def __init__(self, name, pid):
            self.name, self.pid = name, pid
    monkeypatch.setattr(ntsnap, "list_processes", lambda: [P("winws.exe", 10)])
    import psutil
    monkeypatch.setattr(psutil, "net_if_stats", lambda: {})
    found = netdiag.foreign_tunnels()
    assert found and "zapret" in found[0]
