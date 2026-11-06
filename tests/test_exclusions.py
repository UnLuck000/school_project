from types import SimpleNamespace

from scanner import exclusions


def _patch(monkeypatch, tmp_path):
    monkeypatch.setattr(exclusions, "EXCLUSIONS_FILE", tmp_path / "exclusions.json")
    monkeypatch.setattr(exclusions, "RELEASE_FILE", tmp_path / "release_exclusions.json")


def test_add_match_remove(tmp_path, monkeypatch):
    _patch(monkeypatch, tmp_path)
    entry = SimpleNamespace(kind="run", location="HKCU\\Run", name="App", command="app.exe -x")
    key = exclusions.entry_key(entry)
    exclusions.add("autoruns", key, "App", entry.command, [10, 20])

    data = exclusions.load()
    assert exclusions.matches(data, "autoruns", key, [10, 20])
    assert not exclusions.matches(data, "autoruns", key, [10, 21])   # файл изменился
    assert not exclusions.matches(data, "checks", key, [10, 20])     # другая категория

    changed = SimpleNamespace(kind="run", location="HKCU\\Run", name="App", command="evil.exe")
    assert not exclusions.matches(data, "autoruns", exclusions.entry_key(changed), [10, 20])

    assert exclusions.remove("autoruns", key) is True
    assert exclusions.remove("autoruns", key) is False
    assert exclusions.items() == []


def test_finding_exclusion_depends_on_content(tmp_path, monkeypatch):
    _patch(monkeypatch, tmp_path)
    f = SimpleNamespace(category="proxy", title="Прокси-сервер", status="Включён",
                        detail="Адрес: 10.0.0.1:8080")
    exclusions.add("checks", exclusions.finding_key(f), f.title, f.detail)
    data = exclusions.load()
    assert exclusions.matches(data, "checks", exclusions.finding_key(f))
    f.detail = "Адрес: 6.6.6.6:8080"
    assert not exclusions.matches(data, "checks", exclusions.finding_key(f))


def test_fingerprint(tmp_path):
    f = tmp_path / "a.exe"
    f.write_bytes(b"abc")
    first = exclusions.fingerprint(f)
    assert first[0] == 3
    f.write_bytes(b"abcdef")
    assert exclusions.fingerprint(f) != first
    assert exclusions.fingerprint(tmp_path / "missing.exe") is None