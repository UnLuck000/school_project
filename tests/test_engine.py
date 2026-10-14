from scanner.engine import check_file
from scanner.hashing import sha256_of


def test_check_file(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("content")
    digest = sha256_of(f)

    assert check_file(f, {digest}) == "hash match"
    assert check_file(f, {digest}, whitelist={digest}) is None
    assert check_file(f, set()) is None