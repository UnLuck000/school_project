"""Диагностика: обезличивание, исправность функций и эталон, журнал внешних команд."""
import json
import logging
import subprocess
import sys

import pytest

from diag import anon, edition, features, specs


@pytest.fixture(autouse=True)
def clean_anon():
    anon.reset()
    yield
    anon.reset()


def test_scrub_vpn_and_addresses():
    anon.register_vpn_profile("Ivan_Network-Vova", "178.208.75.193:443")
    anon.register_vpn_profile("KZ-KVN-vova", "frends.d7s.ru:443")
    anon.register_vpn_server("176.12.77.151")
    anon.register_own_ip("85.140.1.2")
    text = ("Подключение: Ivan_Network-Vova (vless); сервер 178.208.75.193:443, "
            "KZ-KVN-vova → frends.d7s.ru:443 (176.12.77.151); внешний 85.140.1.2; "
            "роутер 192.168.1.1, fe80::1c2b:3a4d:5e6f:7081, MAC 3C:7C:3F:12:AB:CD; "
            "сайт 77.88.55.88:443 grok.com; локально 127.0.0.1:2082; время 17:04:32")
    out = anon.scrub(text)
    for secret in ("Ivan_Network", "KZ-KVN", "178.208.75.193", "frends.d7s.ru",
                   "176.12.77.151", "85.140.1.2", "192.168.1.1", "fe80::", "3C:7C"):
        assert secret.lower() not in out.lower(), secret
    assert "%PROFILE1%" in out and "%PROFILE2%" in out
    assert "%VPNSERVER1%:443" in out and "%VPNSERVER2%:443" in out and "%VPNSERVER3%" in out
    assert "%MYIP%" in out and "%LANIP%" in out and "%MAC%" in out
    # адреса сайтов, loopback и время остаются
    assert "77.88.55.88:443 grok.com" in out and "127.0.0.1:2082" in out and "17:04:32" in out


def test_scrub_user_paths(monkeypatch):
    monkeypatch.setenv("USERPROFILE", r"C:\Users\Ivan")
    monkeypatch.setenv("USERNAME", "Ivan")
    monkeypatch.setenv("COMPUTERNAME", "IVAN-PC")
    out = anon.scrub(r"C:\Users\Ivan\Desktop\Договор.docx на IVAN-PC")
    assert out == r"%USERPROFILE%\Desktop\Договор.docx на %COMPUTERNAME%"


@pytest.fixture
def feats(tmp_path, monkeypatch):
    monkeypatch.setattr(features, "BASELINE_FILE", tmp_path / "baseline.json")
    monkeypatch.setattr(features, "RUNS_FILE", tmp_path / "runs.json")
    monkeypatch.setattr(features, "_runs", None)
    monkeypatch.setattr(features, "_baseline", None)
    monkeypatch.setattr(features, "_active", [])
    monkeypatch.setattr(specs, "cached", lambda: {})
    return tmp_path


def _records(caplog):
    return [(r.levelname, r.getMessage()) for r in caplog.records]


def test_feature_baseline_and_deviation(feats, caplog):
    logger = logging.getLogger("sbit")
    logger.propagate = True
    try:
        caplog.set_level(logging.DEBUG, logger="sbit")
        run = features.begin("vpn.connect")
        run.step("xray")
        run.step("адаптер TUN")
        run.finish(True)
        entry = features.mark_ok("vpn.connect")
        assert entry["steps"] == ["xray", "адаптер TUN"] and entry["had_run"]
        assert json.loads((feats / "baseline.json").read_text(encoding="utf-8"))["vpn.connect"]

        caplog.clear()
        run = features.begin("vpn.connect")
        run.step("xray")  # адаптер не появился
        run.finish(True)
        assert any(level == "ERROR" and "ОТКЛОНЕНИЕ" in text and "адаптер TUN" in text
                   for level, text in _records(caplog))

        caplog.clear()
        features.begin("vpn.connect")
        features.on_error_dialog("VPN", "порт занят")
        features.end_if_active("vpn.connect", True)
        assert features.runs()["vpn.connect"]["ok"] is False
        assert any("ОТКЛОНЕНИЕ" in text and "порт занят" in text
                   for _, text in _records(caplog))
    finally:
        logger.propagate = False


def test_wrap_method_drops_extra_qt_args(feats):
    class Window:
        def remove(self):
            return "removed"

        def toggle(self, force=False):
            return force

    features.wrap_method(Window, "remove", "journal.whitelist")
    features.wrap_method(Window, "toggle", "protect.realtime")
    w = Window()
    assert w.remove(False) == "removed"  # clicked(bool) передал бы checked
    assert w.toggle(True) is True
    assert features.runs()["journal.whitelist"]["ok"] is True


def test_wrap_method_records_exception(feats):
    class Window:
        def broken(self):
            raise OSError("нет доступа")

    features.wrap_method(Window, "broken", "journal.quarantine")
    with pytest.raises(OSError):
        Window().broken()
    last = features.runs()["journal.quarantine"]
    assert last["ok"] is False and "нет доступа" in last["errors"][0]


def test_edition_from_sources_is_test():
    assert getattr(sys, "frozen", False) is False
    assert edition.is_test()


def test_proc_logs_commands(caplog):
    from diag import proc
    proc.install()
    logger = logging.getLogger("sbit")
    logger.propagate = True
    try:
        caplog.set_level(logging.DEBUG, logger="sbit")
        subprocess.run([sys.executable, "-c", "import sys; sys.exit(3)"], capture_output=True)
        assert any(level == "WARNING" and "Код 3" in text for level, text in _records(caplog))
    finally:
        logger.propagate = False


def test_specs_describe_sample():
    data = {"os": {"caption": "Windows 11 Pro", "build": "26300", "ubr": 1, "arch": "64-bit"},
            "computer": {"manufacturer": "MSI", "model": "GF76", "ram_bytes": 34 * 2 ** 30},
            "cpu": {"Name": "i5-12450H", "NumberOfCores": 8, "NumberOfLogicalProcessors": 12},
            "gpu": [{"Name": "RTX 3050"}], "disks": [{"FriendlyName": "Samsung", "MediaType": "SSD",
                                                      "Size": 512 * 10 ** 9}],
            "network": [{"InterfaceDescription": "Intel Wi-Fi", "Status": "Up"}]}
    text = "\n".join(specs.describe(data))
    assert "i5-12450H" in text and "RTX 3050" in text and "SSD" in text and "Intel Wi-Fi" in text
    assert "MAC" not in text


def test_last_profile_server_hidden_without_profile(monkeypatch):
    """Профилей нет, а в настройке vpn/last_profile остался сервер — в журнал он не попадает."""
    from diag import anon
    from ui import settings as cfg
    from vpn import profiles
    monkeypatch.setattr(profiles, "load", lambda *a: [])
    monkeypatch.setattr(cfg, "get", lambda k: "Old-Profile|203.0.113.77:443"
                        if k == "vpn/last_profile" else "")
    anon.register_vpn_profiles()
    text = anon.scrub("vpn/last_profile = Old-Profile|203.0.113.77:443")
    assert "203.0.113.77" not in text and "Old-Profile" not in text


def test_closed_by_installer_is_not_a_crash(tmp_path, monkeypatch, caplog):
    """Установщик закрывает программу принудительно: это не «завершился аварийно»."""
    import json
    import logging
    import time

    import selfguard
    from diag import crash
    monkeypatch.setattr(crash, "SESSION", tmp_path / "session.json")
    monkeypatch.setattr(crash, "CRASH_LOG", tmp_path / "crash.log")
    monkeypatch.setattr(selfguard, "NO_RESTART", tmp_path / "no_restart")
    monkeypatch.setattr(crash, "_pid_alive", lambda pid: False)
    monkeypatch.setattr(crash.log, "propagate", True)
    monkeypatch.setattr(crash.log.parent, "propagate", True)
    crash.SESSION.write_text(json.dumps({"pid": 4242, "started": time.time() - 60}),
                             encoding="utf-8")
    with caplog.at_level(logging.INFO, logger="sbit"):
        crash._check_previous_session()            # метки нет — это сбой
        assert any("аварийно" in r.getMessage() for r in caplog.records)
        caplog.clear()
        selfguard.NO_RESTART.write_text("setup", encoding="ascii")
        crash._check_previous_session()            # метка новее сеанса — закрыл установщик
        assert not any("аварийно" in r.getMessage() for r in caplog.records)
        assert any("установщиком" in r.getMessage() for r in caplog.records)
