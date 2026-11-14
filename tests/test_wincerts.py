"""wincerts.py: на «чистой» Windows недостающий корень докачивает Windows, затем повтор."""
import http.client
import ssl

import pytest

import wincerts


@pytest.fixture
def fresh(monkeypatch):
    monkeypatch.setattr(wincerts, "_tried", set())
    monkeypatch.setattr(wincerts, "_installed", False)
    monkeypatch.setattr(http.client.HTTPSConnection, "connect",
                        http.client.HTTPSConnection.connect)


def _error(code=20):
    e = ssl.SSLCertVerificationError("certificate verify failed")
    e.verify_code = code
    return e


def test_retry_after_windows_fetched_root(fresh, monkeypatch):
    calls, reloaded, asked = [], [], []

    def original(self):
        calls.append(1)
        if len(calls) == 1:
            raise _error()
    monkeypatch.setattr(http.client.HTTPSConnection, "connect", original)
    monkeypatch.setattr(wincerts, "server_certificate", lambda h, p, t: b"der")
    monkeypatch.setattr(wincerts, "build_chain", lambda der: asked.append(der) or 0)
    wincerts.install()
    conn = http.client.HTTPSConnection("example.org")
    monkeypatch.setattr(conn._context, "load_default_certs", lambda: reloaded.append(1))
    conn.connect()
    assert calls == [1, 1] and reloaded == [1] and asked == [b"der"]


def test_no_retry_when_windows_does_not_trust(fresh, monkeypatch):
    calls = []

    def original(self):
        calls.append(1)
        raise _error()
    monkeypatch.setattr(http.client.HTTPSConnection, "connect", original)
    monkeypatch.setattr(wincerts, "server_certificate", lambda h, p, t: b"der")
    monkeypatch.setattr(wincerts, "build_chain", lambda der: 0x20)  # не доверяет
    wincerts.install()
    with pytest.raises(ssl.SSLCertVerificationError):
        http.client.HTTPSConnection("evil.example").connect()
    assert calls == [1]


def test_other_errors_and_second_try_pass_through(fresh, monkeypatch):
    calls = []

    def original(self):
        calls.append(1)
        raise _error(code=62)                        # не тот сертификат для имени
    monkeypatch.setattr(http.client.HTTPSConnection, "connect", original)
    monkeypatch.setattr(wincerts, "server_certificate",
                        lambda h, p, t: pytest.fail("сертификат не нужен"))
    wincerts.install()
    with pytest.raises(ssl.SSLCertVerificationError):
        http.client.HTTPSConnection("example.org").connect()
    monkeypatch.setattr(wincerts, "server_certificate", lambda h, p, t: b"der")
    monkeypatch.setattr(wincerts, "build_chain", lambda der: 0)
    assert wincerts.fetch_root("a.example") and not wincerts.fetch_root("a.example")  # раз


def test_windows_builds_chain_for_real_certificate():
    """Сертификат с диска Windows (без сети): вызов CryptoAPI работает."""
    import os
    import sys
    if sys.platform != "win32":
        pytest.skip("только Windows")
    pem = ssl.DER_cert_to_PEM_cert(ssl.enum_certificates("ROOT")[0][0])
    assert wincerts.build_chain(ssl.PEM_cert_to_DER_cert(pem)) is not None
    assert wincerts.build_chain(b"not a certificate") is None
    assert os.name == "nt"
