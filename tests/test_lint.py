"""Исходники проходят tools/lint.py (ruff по ruff.toml, без ruff — pyflakes)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import lint

HAVE_LINTER = lint._ruff() is not None or __import__("importlib.util").util.find_spec("pyflakes")
needs_linter = pytest.mark.skipif(not HAVE_LINTER, reason="нет ruff и pyflakes "
                                  "(pip install -r requirements-dev.txt)")


@needs_linter
def test_sources_are_clean():
    code, text = lint.run()
    assert code == 0, text


@needs_linter
def test_lint_catches_the_reset_bug(tmp_path):
    """Ошибка сброса настроек («store = store()» — UnboundLocalError) ловится."""
    bad = tmp_path / "bad.py"
    bad.write_text("def store():\n    return 1\n\n\ndef reset():\n    store = store()\n"
                   "    return store\n", encoding="utf-8")
    code, text = lint.run(paths=[str(bad)])
    assert code != 0 and ("F823" in text or "referenced before assignment" in text), text


@pytest.mark.skipif(lint._ruff() is None, reason="нет ruff")
def test_silent_except_needs_reason(tmp_path):
    bad = tmp_path / "silent.py"
    bad.write_text("try:\n    x = 1\nexcept Exception:\n    pass\n", encoding="utf-8")
    ok = tmp_path / "ok.py"
    ok.write_text("try:\n    x = 1\nexcept Exception:  # noqa: S110 — причина\n    pass\n",
                  encoding="utf-8")
    assert lint.run(paths=[str(bad)])[0] != 0
    assert lint.run(paths=[str(ok)])[0] == 0
