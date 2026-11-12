"""Папка конфигурации пользователя (userdata.py): перенос из папки программы и реестра."""
import json
import sys

import pytest

import userdata


def test_config_dir_from_env_in_tests():
    """conftest подменяет папку: тесты не пишут в настоящий %APPDATA%."""
    assert "sbit-config-" in str(userdata.CONFIG_DIR)
    from recovery import journal
    from scanner import exclusions, overrides, whitelist
    from vpn import profiles
    for path in (journal.JOURNAL_DIR, whitelist.WHITELIST_FILE, exclusions.EXCLUSIONS_FILE,
                 overrides.OVERRIDES_FILE, profiles.PROFILES_FILE):
        assert userdata.CONFIG_DIR in path.parents
    # файлы релиза остаются в signatures/ программы (release_overrides подменяет conftest)
    assert exclusions.RELEASE_FILE.parent.name == "signatures"


def test_migrate_moves_and_fixes_journal_paths(tmp_path, monkeypatch):
    app, config = tmp_path / "app", tmp_path / "config"
    old_journal = app / "journal"
    (old_journal / "ext_backup" / "abc").mkdir(parents=True)
    backup = str(old_journal / "ext_backup" / "abc")
    (old_journal / "actions.jsonl").write_text(
        json.dumps({"op": "ext_remove", "data": {"backup": backup}}) + "\n", encoding="utf-8")
    (app / "signatures").mkdir()
    (app / "signatures" / "whitelist.json").write_text("{}", encoding="utf-8")
    config.mkdir()
    (config / "exclusions.json").write_text('{"new": 1}', encoding="utf-8")   # уже есть
    (app / "signatures" / "exclusions.json").write_text('{"old": 1}', encoding="utf-8")
    monkeypatch.setattr(userdata, "CONFIG_DIR", config)
    monkeypatch.setattr(userdata, "SETTINGS_FILE", config / "settings.ini")
    monkeypatch.setattr(userdata, "JOURNAL_DIR", config / "journal")
    monkeypatch.setattr(userdata, "_migrate_registry", lambda: False)  # реестр — отдельный тест
    monkeypatch.setattr(userdata, "MOVES", (
        (old_journal, config / "journal"),
        (app / "signatures" / "whitelist.json", config / "whitelist.json"),
        (app / "signatures" / "exclusions.json", config / "exclusions.json"),
        (app / "vpn_profiles", config / "vpn_profiles"),                       # нет — пропуск
    ))
    done = userdata.migrate(force=True)
    assert len(done) == 2
    assert not old_journal.exists() and (config / "whitelist.json").is_file()
    record = json.loads((config / "journal" / "actions.jsonl").read_text(encoding="utf-8"))
    assert record["data"]["backup"] == str(config / "journal" / "ext_backup" / "abc")
    # существующее не перезаписано, старый файл остался на месте
    assert json.loads((config / "exclusions.json").read_text()) == {"new": 1}
    assert (app / "signatures" / "exclusions.json").exists()
    assert userdata.migrate(force=True) == []   # второй раз — нечего переносить


@pytest.mark.skipif(sys.platform != "win32", reason="реестр Windows")
def test_migrate_registry_to_ini(tmp_path, monkeypatch):
    import winreg

    from PySide6.QtCore import QSettings
    old = ("SBITTestMigrate", "myav")   # своя ветка: SBITTest удаляют другие тесты
    reg = QSettings(*old)
    reg.setValue("general/theme", "dark")
    reg.setValue("vpn/socks_port", 2090)
    reg.sync()
    del reg                                   # открытый ключ мешал бы удалению
    try:
        ini = tmp_path / "settings.ini"
        monkeypatch.setattr(userdata, "OLD_REGISTRY", old)
        monkeypatch.setattr(userdata, "SETTINGS_FILE", ini)
        assert userdata._migrate_registry()
        new = QSettings(str(ini), QSettings.Format.IniFormat)
        assert new.value("general/theme") == "dark"
        assert int(new.value("vpn/socks_port")) == 2090
        assert not userdata._migrate_registry()   # ini уже есть
        del new
    finally:
        import gc

        import uninstall
        gc.collect()
        uninstall._delete_tree(winreg.HKEY_CURRENT_USER, r"Software\SBITTestMigrate")


def test_settings_go_to_ini():
    from ui import settings as cfg
    cfg.set_("general/theme", "dark")
    try:
        from pathlib import Path
        assert Path(cfg.store().fileName()) == userdata.SETTINGS_FILE
        assert cfg.get("general/theme") == "dark"
    finally:
        cfg.store().remove("general/theme")


def test_migrate_skipped_with_overridden_dir(tmp_path, monkeypatch):
    """Тесты (STRETCHBIT_CONFIG_DIR) не трогают настоящие данные в папке проекта."""
    old = tmp_path / "vpn_profiles"
    old.mkdir()
    monkeypatch.setattr(userdata, "MOVES", ((old, tmp_path / "config" / "vpn_profiles"),))
    assert userdata.migrate() == []
    assert old.is_dir()
