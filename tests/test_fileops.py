import os
import sys

import pytest

from analyzer import fileops
from analyzer.folderview import classify
from recovery import journal


@pytest.fixture
def temp_journal(tmp_path, monkeypatch):
    monkeypatch.setattr(journal, "JOURNAL_DIR", tmp_path / "journal")
    monkeypatch.setattr(journal, "JOURNAL_FILE", tmp_path / "journal" / "actions.jsonl")
    return tmp_path


def test_classify_engine_answers():
    assert classify(None) == ("clean", "Чисто")
    assert classify("hash match")[0] == "threat"
    assert classify("YARA: Rule1")[0] == "threat"
    assert classify("Heuristic: 9 баллов")[0] == "suspicious"


def test_rename_is_undone_from_journal(temp_journal):
    folder = temp_journal / "files"
    folder.mkdir()
    old = folder / "a.txt"
    old.write_text("x")
    new = fileops.rename(str(old), "b.txt")
    assert os.path.exists(new) and not old.exists()
    with pytest.raises(ValueError):
        fileops.rename(new, "bad:name.txt")
    record = journal.read_all()[-1]
    assert record["op"] == "file_rename"
    journal.undo(record["id"])
    assert old.exists() and not os.path.exists(new)


def test_folder_properties_counts_only_contents(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "x.bin").write_bytes(b"1" * 10)
    (tmp_path / "y.txt").write_text("hello")
    rows = dict(fileops.folder_properties(str(tmp_path)))
    assert rows["Содержит"] == "файлов: 2, папок: 1"
    assert "15 байт" in rows["Размер"]


@pytest.mark.skipif(sys.platform != "win32", reason="нужен Windows")
def test_file_properties_on_windows(tmp_path):
    f = tmp_path / "z.txt"
    f.write_text("abc")
    rows = dict(fileops.file_properties(str(f)))
    assert rows["SHA-256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert rows["Владелец"] != "—"
    assert fileops.size_on_disk(str(f)) >= 3
