from scanner.yara_engine import load_rules, match_file


def test_rule_matches_marker(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "t.yar").write_text(
        'rule T { strings: $a = "MARKER_123" condition: $a }', encoding="utf-8")

    rules, errors = load_rules(rules_dir)
    assert not errors

    infected = tmp_path / "sample.txt"
    infected.write_text("abc MARKER_123 xyz")
    clean = tmp_path / "clean.txt"
    clean.write_text("nothing here")

    assert match_file(rules, infected) == ["T"]
    assert match_file(rules, clean) == []