"""Закрытые уязвимости (проверка кода 13.11.2026): права файлов, переменные окружения в
собранной программе, чужая папка в ProgramData, защищённые настройки, подпись журнала
действий, занятое имя единственного экземпляра, ссылки-папки, папки данных без прав."""
import json
import os
import sys
from pathlib import Path

import pytest

import trustseal
import userdata

WINDOWS = sys.platform == "win32"


@pytest.mark.skipif(not WINDOWS, reason="Windows")
def test_admin_only_writable():
    import winacl
    system = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "kernel32.dll"
    assert winacl.admin_only(system) == (True, "")
    ok, reason = winacl.admin_only(Path(__file__))      # папка проекта — пользователя
    assert not ok and reason


@pytest.mark.skipif(not WINDOWS, reason="Windows")
def test_windivert_from_user_folder_is_not_loaded(tmp_path, monkeypatch):
    from networkmonitor import tls
    folder = tmp_path / "zapret" / "bin"
    folder.mkdir(parents=True)
    (folder / "WinDivert.dll").write_bytes(b"MZ")
    (folder / "WinDivert64.sys").write_bytes(b"MZ")
    monkeypatch.setattr(tls, "windivert_candidates", lambda: [folder / "WinDivert.dll"])
    assert tls.find_windivert() is None
    assert tls.find_windivert.unsafe and tls.find_windivert.unsafe[0][0] == folder / "WinDivert.dll"


def test_windivert_only_from_program_folder():
    """По чужим папкам (zapret, выбранная пользователем, копия в ProgramData) WinDivert
    больше не ищется: только своя копия в папке программы (14.11.2026)."""
    from networkmonitor import tls
    assert tls.windivert_candidates() == [tls.PROJECT_DIR / "native" / "windivert" /
                                          "WinDivert.dll"]
    assert not hasattr(tls, "trust_windivert")
    from ui import settings
    assert "net/windivert_dir" not in settings.SECURE_KEYS


def test_build_includes_windivert_by_default(monkeypatch, tmp_path):
    import sys

    import build_release
    monkeypatch.setattr(build_release, "WINDIVERT_SRC", tmp_path)
    monkeypatch.setattr(sys, "argv", ["build_release.py", "--installer"])
    with pytest.raises(SystemExit):            # файлов нет — сборка останавливается
        build_release.check_windivert()
    monkeypatch.setattr(sys, "argv", ["build_release.py", "--no-windivert"])
    build_release.check_windivert()
    for name in build_release.WINDIVERT_FILES:
        (tmp_path / name).write_bytes(b"MZ")
    monkeypatch.setattr(sys, "argv", ["build_release.py"])
    build_release.check_windivert()
    app = tmp_path / "app"
    build_release.copy_windivert(app)
    assert all((app / "native" / "windivert" / n).is_file() for n in build_release.WINDIVERT_FILES)


def test_env_overrides_ignored_in_frozen_build(monkeypatch, tmp_path):
    monkeypatch.setenv(trustseal.ENV_OFF, "off")
    monkeypatch.setenv(trustseal.ENV_DIR, str(tmp_path))
    assert not trustseal.enabled() and trustseal.protected_dir() == tmp_path
    from diag import edition
    monkeypatch.setattr(edition, "_edition", edition.TEST)  # без чтения sys._MEIPASS
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert trustseal.enabled()                                # выключить защиту нельзя
    assert trustseal.protected_dir() != tmp_path              # и подменить папку тоже


def test_untrusted_root_is_not_read(tmp_path, monkeypatch):
    """Корень, который не закрыт (его мог создать кто угодно), не читается: копии, ключ
    кэша и правила YARA в нём не действуют."""
    root = tmp_path / "planted"
    (root / "trusted").mkdir(parents=True)
    (root / "cache.key").write_bytes(b"k" * 32)
    victim = tmp_path / "whitelist.json"
    victim.write_text('{"real": 1}', encoding="utf-8")
    (root / "trusted" / trustseal._mirror(victim).name).write_text('{"planted": 1}',
                                                                   encoding="utf-8")
    monkeypatch.setattr(trustseal, "_env_dir", lambda: "")
    monkeypatch.setattr(trustseal, "protected_dir", lambda: root)
    monkeypatch.setattr(trustseal, "_root_secured", lambda path: False)
    monkeypatch.setattr(trustseal, "is_admin", lambda: False)
    trustseal.reset_state()
    try:
        assert not trustseal.root_trusted()
        assert trustseal.read(victim) == b'{"real": 1}'      # копия злоумышленника не взята
        assert trustseal.mac_key() == b""                     # и его ключ тоже
        from scanner import yara_engine
        monkeypatch.setattr(yara_engine, "CACHE_DIR", None)
        assert yara_engine._cache_dir() is None
    finally:
        trustseal.reset_state()


def test_remove_foreign_clears_planted_files(tmp_path):
    root = tmp_path / "root"
    (root / "amsi").mkdir(parents=True)
    (root / "amsi" / "sbit_amsi64-000000000000.dll").write_bytes(b"MZ planted")
    (root / "cache.key").write_bytes(b"k")
    trustseal._remove_foreign(root)
    assert list(root.iterdir()) == []


def test_secure_settings_survive_ini_tampering(monkeypatch):
    from ui import settings as cfg
    cfg.set_("protect/launch", False)
    cfg.set_("vpn/xray_path", r"C:\Program Files\Xray\xray.exe")
    assert cfg.get("protect/launch") is False
    ini = cfg.store()
    ini.setValue("protect/launch", True)                  # правка settings.ini — не действует
    ini.setValue("vpn/xray_path", r"C:\Users\x\evil.exe")
    ini.sync()
    assert cfg.get("protect/launch") is False
    assert cfg.get("vpn/xray_path") == r"C:\Program Files\Xray\xray.exe"
    path = userdata.SECURE_SETTINGS_FILE
    data = json.loads(path.read_text(encoding="utf-8"))
    data["vpn/xray_path"] = r"C:\Users\x\evil.exe"
    path.write_text(json.dumps(data), encoding="utf-8")   # правка самого файла — тоже
    trustseal.reset_state()
    assert cfg.get("vpn/xray_path") == r"C:\Program Files\Xray\xray.exe"
    assert str(path) in trustseal.pending()
    trustseal.reject(path)
    cfg.set_("protect/launch", True)
    cfg.set_("vpn/xray_path", "")
    assert cfg.secure("lock/vpn") and cfg.secure("scan/mode") and not cfg.secure("general/theme")


def test_journal_signature(monkeypatch, tmp_path):
    from recovery import journal
    monkeypatch.setattr(journal, "JOURNAL_DIR", tmp_path)
    monkeypatch.setattr(journal, "JOURNAL_FILE", tmp_path / "actions.jsonl")
    calls = []
    journal.UNDO_HANDLERS["test_op"] = lambda d: calls.append(d) or "ok"
    try:
        good = journal.log_action("тест", "test_op", {"value": 1})
        assert journal.undo(good) == "ok" and calls == [{"value": 1}]
        # подделка: чужая программа поменяла данные подписанной записи
        forged = journal.log_action("тест", "test_op", {"value": 2})
        records = journal.read_all()
        for r in records:
            if r["id"] == forged:
                r["data"]["value"] = 666
        journal._write(records)
        with pytest.raises(ValueError, match="подпись"):
            journal.undo(forged)
        # запись без подписи (дописана руками): только после подтверждения
        unsigned = {"id": "u1", "time": "", "title": "чужое", "op": "test_op",
                    "data": {"value": 3}, "undone": False, "undone_at": ""}
        with journal.JOURNAL_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(unsigned) + "\n")
        with pytest.raises(journal.UnsignedRecord, match="test_op"):
            journal.undo("u1")
        assert journal.undo("u1", unsigned_ok=True) == "ok"
        assert calls[-1] == {"value": 3}
    finally:
        journal.UNDO_HANDLERS.pop("test_op", None)


@pytest.mark.skipif(not WINDOWS, reason="Windows")
def test_single_instance_detects_foreign_server(qapp=None):
    from PySide6.QtCore import QCoreApplication
    from PySide6.QtNetwork import QLocalServer, QLocalSocket

    from ui import single_instance
    app = QCoreApplication.instance() or QCoreApplication([])
    name = f"sbit-test-{os.getpid()}"
    server = QLocalServer()
    assert server.listen(name)
    try:
        socket = QLocalSocket()
        socket.connectToServer(name)
        assert socket.waitForConnected(1000)
        pid, exe = single_instance.server_process(socket)
        assert pid == os.getpid()
        assert os.path.normcase(exe) == os.path.normcase(os.path.abspath(sys.executable))
        socket.abort()
        guard = single_instance.SingleInstance(name)
        assert guard.already_running(notify=False)          # сервер — мы сами
        assert guard.squatted is None
    finally:
        server.close()
    del app


@pytest.mark.skipif(not WINDOWS, reason="Windows")
def test_remove_links_keeps_targets(tmp_path):
    import subprocess
    root = tmp_path / "config"
    (root / "journal").mkdir(parents=True)
    target = tmp_path / "victim"
    target.mkdir()
    (target / "important.txt").write_text("x", encoding="utf-8")
    link = root / "journal" / "ext_backup"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True)
    if not link.exists():
        pytest.skip("не удалось создать ссылку-папку")
    (root / "settings.ini").write_text("", encoding="utf-8")
    removed = userdata.remove_links(root)
    assert removed == [str(link)]
    assert not link.exists() and (target / "important.txt").exists()
    assert (root / "settings.ini").exists()


def test_data_dirs_without_admin(monkeypatch):
    import datadirs
    from diag import edition
    monkeypatch.setattr(edition, "_edition", edition.RELEASE)  # без чтения sys._MEIPASS
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(datadirs, "_admin", lambda: False)
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\x\AppData\Local")
    assert datadirs.root() == Path(r"C:\Users\x\AppData\Local") / "StretchBIT"
    monkeypatch.setattr(datadirs, "_admin", lambda: True)
    assert datadirs.root() == Path(userdata.APP_DIR)
