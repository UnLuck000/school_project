"""Проверка исходников: ruff по настройкам ruff.toml, без ruff — pyflakes.

    python tools/lint.py            — показать находки
    python tools/lint.py --fix      — исправить то, что ruff исправляет сам (импорты, пробелы...)

Что ловит (см. ruff.toml): pyflakes — неиспользуемые импорты и переменные, неизвестные имена,
«store = store()» в функции (F823: так ломался сброс настроек); pycodestyle — синтаксис,
неверные escape-последовательности, длина строки; bugbear — частые ошибки (замыкание переменной
цикла, изменяемое значение по умолчанию); S110 — «except Exception: pass» без причины: причину
пишут в «# noqa: S110 — ...» на строке except (или ошибку пишут в журнал:
diag.log.swallowed(где)). Тот же прогон делает tests/test_lint.py.
Пакеты: pip install -r requirements-dev.txt (нужны только для разработки, в сборку не входят).
"""
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _ruff() -> list[str] | None:
    exe = shutil.which("ruff")
    if exe:
        return [exe]
    try:
        import ruff  # noqa: F401 — пакет есть, а Scripts нет в PATH
    except ImportError:
        return None
    return [sys.executable, "-m", "ruff"]


def sources() -> list[Path]:
    """Файлы, которые проверяет ruff (с учётом исключений ruff.toml); без ruff — все .py
    проекта, кроме служебных папок."""
    ruff = _ruff()
    if ruff:
        out = subprocess.run(ruff + ["check", "--show-files", "."], cwd=ROOT,
                             capture_output=True, text=True, encoding="utf-8").stdout
        return sorted(Path(line.strip()) for line in out.splitlines() if line.strip().endswith(".py"))
    skip = {"dist", "build", "release", "user_reports", "inspections", "cache", "logs", "reports",
            "signatures", "quarantine_data", "test_samples", "native", "bin", ".git",
            "__pycache__"}
    return sorted(p for p in ROOT.rglob("*.py")
                  if not set(p.relative_to(ROOT).parts[:-1]) & skip)


def run(fix: bool = False, paths: list[str] | None = None) -> tuple[int, str]:
    """(код возврата, вывод). Код 0 — чисто."""
    ruff = _ruff()
    if ruff:
        cmd = ruff + ["check", "--output-format", "concise"] + (["--fix"] if fix else [])
        result = subprocess.run(cmd + (paths or ["."]), cwd=ROOT, capture_output=True,
                                text=True, encoding="utf-8")
        return result.returncode, (result.stdout + result.stderr).strip()
    try:
        import pyflakes  # noqa: F401
    except ImportError:
        return 2, "Нет ни ruff, ни pyflakes: pip install -r requirements-dev.txt"
    files = paths or [str(p) for p in sources()]
    result = subprocess.run([sys.executable, "-m", "pyflakes"] + files, cwd=ROOT,
                            capture_output=True, text=True, encoding="utf-8")
    note = "ruff не найден — проверено только pyflakes (без стиля и S110)"
    return result.returncode, (result.stdout + result.stderr).strip() + "\n" + note


def main() -> int:
    code, text = run(fix="--fix" in sys.argv)
    if text:
        print(text)
    return code


if __name__ == "__main__":
    sys.exit(main())
