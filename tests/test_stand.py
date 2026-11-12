"""Исследовательский стенд TPR/FPR (bench/stand.py)."""
from bench import stand


def _layers():
    return {
        "hash": lambda p, data: "hash match" if data.startswith(b"KNOWN") else None,
        "yara": lambda p, data: "Rule" if b"evil" in data else None,
        "heuristic": lambda p, data: None,
        "engine": lambda p, data: "x" if data.startswith(b"KNOWN") or b"evil!" in data else None,
    }


def test_metrics_by_layer(tmp_path):
    mal, clean = tmp_path / "mal", tmp_path / "clean"
    mal.mkdir()
    clean.mkdir()
    (mal / "a.bin").write_bytes(b"KNOWN sample")
    (mal / "b.bin").write_bytes(b"new evil! sample")
    (mal / "c.bin").write_bytes(b"missed sample")
    (mal / "d.bin").write_bytes(b"another evil! one")
    (clean / "x.bin").write_bytes(b"just evil word in a clean tool")   # ложное у YARA
    for i in range(4):
        (clean / f"ok{i}.bin").write_bytes(b"fine %d" % i)

    result = stand.run(stand.collect(mal), stand.collect(clean), _layers())
    by = {m["layer"]: m for m in stand.metrics(result)}
    assert (by["hash"]["tp"], by["hash"]["fp"]) == (1, 0) and by["hash"]["tpr"] == 0.25
    assert by["yara"]["tpr"] == 0.5 and by["yara"]["fpr"] == 0.2
    assert by["yara"]["precision"] == 2 / 3
    assert by["engine"]["tpr"] == 0.75 and by["engine"]["fpr"] == 0.0
    assert by["heuristic"]["precision"] is None        # ничего не помечено — точности нет

    summary = stand.save(result, tmp_path / "out", "проверка")
    text = summary.read_text(encoding="utf-8")
    assert "| Движок целиком | 3 из 4 | 75.0% | 0 из 5 | 0.0% | 100.0% |" in text
    rows = (tmp_path / "out" / "files.csv").read_text(encoding="utf-8-sig").splitlines()
    assert len(rows) == 1 + 9 and rows[0].startswith("набор;файл;размер;hash;yara")


def test_only_clean_set_and_limit(tmp_path):
    for i in range(6):
        (tmp_path / f"f{i}.bin").write_bytes(b"data")
    files = stand.collect(tmp_path, 4)
    assert len(files) == 4
    result = stand.run([], files, _layers())
    assert stand.metrics(result)[0]["tpr"] is None and result.clean.total == 4
    assert "—" in stand.table(result)
