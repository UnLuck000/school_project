"""Возврат файлов из теневых копий (recovery/shadow.py). Снимок изображает обычная папка."""
import os

import pytest

from recovery import journal, shadow


@pytest.fixture
def snap(tmp_path, monkeypatch):
    monkeypatch.setattr(journal, "JOURNAL_DIR", tmp_path / "journal")
    monkeypatch.setattr(journal, "JOURNAL_FILE", tmp_path / "journal" / "actions.jsonl")
    drive = os.path.splitdrive(str(tmp_path))[0].upper()
    device = tmp_path / "snapshot"
    monkeypatch.setattr(shadow, "shadow_path", lambda s, path: device / os.path.relpath(
        str(path), str(tmp_path / "docs")))
    (tmp_path / "docs").mkdir()
    device.mkdir()
    return tmp_path, [shadow.Shadow(drive, str(device), "2026-11-12 03:00:00")]


def test_parse_sorts_fresh_first_and_skips_volumes_without_letter():
    import json
    device = r"\\?\GLOBALROOT\Device\Shadow"
    text = json.dumps([
        {"drive": "C:", "device": device + "1", "created": "2026-11-01 10:00:00"},
        {"drive": None, "device": "x", "created": "2026-11-05 10:00:00"},
        {"drive": "c:", "device": device + "2", "created": "2026-11-10 10:00:00"}])
    found = shadow.parse(text)
    assert [s.created[:10] for s in found] == ["2026-11-10", "2026-11-01"]
    assert found[0].drive == "C:" and shadow.parse("не json") == []
    assert len(shadow.parse('{"drive":"D:","device":"y","created":"2026-01-01 00:00:00"}')) == 1


def test_restore_and_undo(snap):
    root, known = snap
    doc = root / "docs" / "report.docx"
    doc.write_bytes(b"ENCRYPTED GARBAGE")
    (root / "snapshot" / "report.docx").write_bytes(b"PK original text")
    locked = root / "docs" / "plan.xlsx.locked"      # дописанное расширение
    locked.write_bytes(b"noise")
    (root / "snapshot" / "plan.xlsx").write_bytes(b"PK plan")
    lost = root / "docs" / "new.pdf"                 # в снимке такого файла нет
    lost.write_bytes(b"noise")

    done, missing = shadow.restore([doc, locked, lost], known)
    assert sorted(os.path.basename(p) for p in done) == ["plan.xlsx", "report.docx"]
    assert missing == [str(lost)]
    assert doc.read_bytes() == b"PK original text"
    assert (root / "docs" / ("report.docx" + shadow.DAMAGED_SUFFIX)).read_bytes() == \
        b"ENCRYPTED GARBAGE"
    assert (root / "docs" / "plan.xlsx").read_bytes() == b"PK plan" and locked.exists()

    record = journal._read()[-1]
    assert record["op"] == "shadow_restore" and len(record["data"]["files"]) == 2
    data = record["data"]
    shadow._undo_restore(data)
    assert doc.read_bytes() == b"ENCRYPTED GARBAGE"
    assert not (root / "docs" / "plan.xlsx").exists()


def test_same_file_in_snapshot_is_not_a_previous_version(snap):
    import shutil
    root, known = snap
    doc = root / "docs" / "same.txt"
    doc.write_text("unchanged")
    shutil.copy2(doc, root / "snapshot" / "same.txt")
    assert shadow.previous_version(doc, known) is None
