"""Папка программы и данные, от которых зависят проверки (с 1.0.0 после сборки релиза):
базы и карантин пишет только программа с правами администратора, скомпилированные правила
YARA — в защищённой папке, установка — в Program Files с переездом из C:\\Utils."""
from pathlib import Path

import pytest

import trustseal
from scanner import yara_engine as ye

ROOT = Path(__file__).resolve().parent.parent
RULE = 'rule Marker_Rule { strings: $a = "SbitAclMarker" condition: $a }\n'


@pytest.fixture
def rules_dir(tmp_path, monkeypatch):
    folder = tmp_path / "rules"
    folder.mkdir()
    (folder / "a.yar").write_text(RULE, encoding="utf-8")
    monkeypatch.setattr(ye, "CACHE_DIR", None)            # настоящее место — защищённая папка
    monkeypatch.setattr(ye, "OLD_CACHE_DIR", tmp_path / "old_cache")
    monkeypatch.setattr(ye, "LOG_FILE", tmp_path / "yara.log")
    return folder


def test_compiled_rules_go_to_protected_folder(rules_dir, tmp_path):
    old = tmp_path / "old_cache"
    old.mkdir()
    (old / "yara_stale.bin").write_bytes(b"x")              # прежнее открытое место
    rules, _ = ye.load_rules(rules_dir, purpose=f"file-{tmp_path.name}")
    assert rules is not None and rules.match(data=b"..SbitAclMarker..")
    saved = list((trustseal.protected_dir() / "yara").glob("yara_*.bin"))
    assert saved, "правила не сохранены в защищённой папке"
    assert not list(old.glob("yara_*"))                     # старый кэш убран


def test_without_admin_rules_are_not_saved(rules_dir, tmp_path, monkeypatch):
    monkeypatch.setattr(trustseal, "can_write", lambda: False)
    purpose = f"noadmin-{tmp_path.name}"
    before = set((trustseal.protected_dir() / "yara").glob("*")) \
        if (trustseal.protected_dir() / "yara").exists() else set()
    rules, _ = ye.load_rules(rules_dir, purpose=purpose)
    assert rules is not None and rules.match(data=b"SbitAclMarker")  # в памяти работает
    after = set((trustseal.protected_dir() / "yara").glob("*")) \
        if (trustseal.protected_dir() / "yara").exists() else set()
    assert after == before


def test_quarantine_needs_admin(tmp_path, monkeypatch):
    import quarantine
    monkeypatch.setattr(quarantine, "QUARANTINE_DIR", tmp_path / "q")
    real = Path.write_bytes

    def deny(self, data):
        if self.name.startswith(".probe-"):
            raise PermissionError(13, "Отказано в доступе")
        return real(self, data)

    monkeypatch.setattr(Path, "write_bytes", deny)
    victim = tmp_path / "x.exe"
    victim.write_text("x", encoding="utf-8")
    with pytest.raises(quarantine.NeedAdmin, match="права администратора"):
        quarantine.quarantine_file(victim, "тест")
    assert victim.exists()                                  # файл не тронут
    assert issubclass(quarantine.NeedAdmin, PermissionError)


def test_updates_need_writable_bases(tmp_path, monkeypatch):
    import updater
    monkeypatch.setattr(updater, "SIG_DIR", tmp_path / "sig")
    assert updater.can_update()
    real = Path.write_bytes
    monkeypatch.setattr(Path, "write_bytes", lambda self, data: (_ for _ in ()).throw(
        PermissionError(13, "нет")) if self.name.startswith(".probe-") else real(self, data))
    assert not updater.can_update()


def test_installer_rights_and_location():
    text = (ROOT / "installer.iss").read_text(encoding="utf-8")
    # пользователям запись не выдаётся никуда: без прав программа пишет в %LOCALAPPDATA%
    assert "/grant *S-1-5-32-545:(OI)(CI)M" not in text
    assert "*S-1-5-32-545:(OI)(CI)RX" in text
    assert '#define InstallDir "{autopf}\\StretchBIT"' in text
    assert "UsePreviousAppDir=no" in text and "MoveOldInstall();" in text


def test_installer_does_not_overwrite_loaded_windivert():
    """Драйвер WinDivert держит свой .sys (zapret подключается к уже загруженному): та же
    версия не заменяется, занятый новый — после перезагрузки (Windows 10, 14.11.2026)."""
    text = (ROOT / "installer.iss").read_text(encoding="utf-8")
    lines = [s for s in text.splitlines() if s.startswith("Source:")]
    main = next(s for s in lines if '"{#SourceDir}\\*"' in s)
    assert 'Excludes: "\\app\\native\\windivert"' in main
    driver = next(s for s in lines if "windivert" in s and s is not main)
    assert "ignoreversion" not in driver
    assert all(f in driver for f in ("restartreplace", "uninsrestartdelete",
                                     "skipifsourcedoesntexist"))
