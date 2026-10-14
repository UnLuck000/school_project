from scanner import whitelist
from scanner.engine import scan_tree
from scanner.hashing import sha256_of


def test_whitelisted_file_is_skipped(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_text("some content")
    digest = sha256_of(f)

    assert [p for p, _ in scan_tree(tmp_path, {digest})] == [f]
    assert list(scan_tree(tmp_path, {digest}, whitelist={digest})) == []


def test_add_and_remove(tmp_path, monkeypatch):
    monkeypatch.setattr(whitelist, "WHITELIST_FILE", tmp_path / "wl.json")

    assert whitelist.add_to_whitelist("ABC123", "C:/x.exe") is True
    assert whitelist.add_to_whitelist("abc123", "C:/x.exe") is False  # дубликат
    assert "abc123" in whitelist.load_whitelist()
    assert whitelist.remove_from_whitelist("abc123") is True
    assert whitelist.load_whitelist() == {}