r"""Исследовательский стенд: сколько ловит каждый слой проверки и сколько ошибается.

Два набора файлов: заведомо вредоносные (--malware) и заведомо чистые (--clean). Для
каждого файла отдельно спрашивается каждый слой:
  hash       — совпадение SHA-256/MD5 с базами;
  yara       — совпало хоть одно правило (до учёта подписи);
  heuristic  — оценка эвристики PE не ниже порога (до учёта подписи);
  engine     — итог движка, как в программе: слои вместе, с подписью, связью с подписанной
               программой, исключениями и вложенными файлами архивов.
Метрики по слою:
  TPR (полнота)  = найдено вредоносных / всего вредоносных;
  FPR (ложные)   = помечено чистых / всего чистых;
  точность       = найдено вредоносных / всего помеченных.
Разница между «yara + heuristic» и «engine» на чистом наборе показывает, сколько ложных
срабатываний снимают подпись и связь с подписанной программой.

Запуск:  python tools/stand.py --malware D:\samples\mal --clean "C:\Program Files" --limit 5000
Итог — таблица на экране, reports/stand/<дата>/summary.md и files.csv (вердикт каждого файла
по слоям). Кэш вердиктов не используется. Образцы вредоносов программа не скачивает: набор
готовится отдельно (и хранится в папке, исключённой из защиты, иначе их заберёт карантин).
"""
import csv
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

LAYERS = ("hash", "yara", "heuristic", "engine")
TITLES = {"hash": "Хэши", "yara": "YARA (без подписи)", "heuristic": "Эвристика PE (без подписи)",
          "engine": "Движок целиком"}


@dataclass
class Counts:
    total: int = 0
    hits: dict = field(default_factory=lambda: dict.fromkeys(LAYERS, 0))
    errors: int = 0
    seconds: float = 0.0


@dataclass
class Result:
    malware: Counts = field(default_factory=Counts)
    clean: Counts = field(default_factory=Counts)
    rows: list = field(default_factory=list)   # (набор, путь, размер, {слой: причина})


def collect(folder, limit: int | None = None) -> list[Path]:
    files = []
    for base, _dirs, names in os.walk(folder):
        for name in sorted(names):
            files.append(Path(base) / name)
            if limit and len(files) >= limit:
                return files
    return files


def make_layers(signatures, rules, threshold: int | None = None) -> dict:
    """Слои настоящего движка: {имя: функция(путь, данные) -> причина или None}."""
    from scanner import engine
    from scanner.hashing import data_hashes
    from scanner.heuristics import analyze_pe, get_threshold
    from scanner.yara_engine import match_details
    threshold = get_threshold() if threshold is None else threshold

    def by_hash(p, data):
        digest, md5 = data_hashes(data)
        return engine.hash_verdict(len(data), digest, md5, signatures)

    def by_yara(p, data):
        found = match_details(rules, p, data=data) if rules is not None else []
        return ", ".join(m.rule for m in found) or None

    def by_heuristic(p, data):
        report = analyze_pe(p, data)
        return report.summary() if report.score >= threshold else None

    def by_engine(p, data):
        return engine.check_file(p, signatures, rules, use_cache=False)

    return {"hash": by_hash, "yara": by_yara, "heuristic": by_heuristic, "engine": by_engine}


def run(malware: list[Path], clean: list[Path], layers: dict, progress=None,
        size_limit: int = 32 * 1024 * 1024) -> Result:
    result = Result()
    done, total = 0, len(malware) + len(clean)
    for label, files, counts in (("malware", malware, result.malware),
                                 ("clean", clean, result.clean)):
        for path in files:
            done += 1
            if progress and done % 50 == 0:
                progress(done, total)
            try:
                if path.stat().st_size > size_limit:
                    continue
                data = path.read_bytes()
            except OSError:
                counts.errors += 1
                continue
            counts.total += 1
            verdicts = {}
            start = time.perf_counter()
            for name in LAYERS:
                try:
                    verdicts[name] = layers[name](path, data)
                except Exception as e:  # noqa: BLE001 — битый файл не останавливает стенд
                    verdicts[name] = None
                    counts.errors += name == "engine"
                    verdicts[name + "_error"] = f"{type(e).__name__}: {e}"
                counts.hits[name] += verdicts[name] is not None
            counts.seconds += time.perf_counter() - start
            result.rows.append((label, str(path), len(data), verdicts))
    return result


def rate(part: int, whole: int) -> float | None:
    return part / whole if whole else None


def metrics(result: Result) -> list[dict]:
    """Строка на слой: TPR, FPR, точность и сами числа."""
    out = []
    for name in LAYERS:
        tp, fp = result.malware.hits[name], result.clean.hits[name]
        out.append({"layer": name, "title": TITLES[name], "tp": tp, "fp": fp,
                    "malware": result.malware.total, "clean": result.clean.total,
                    "tpr": rate(tp, result.malware.total), "fpr": rate(fp, result.clean.total),
                    "precision": rate(tp, tp + fp)})
    return out


def _pct(value: float | None) -> str:
    return "—" if value is None else f"{100 * value:.1f}%"


def table(result: Result) -> str:
    lines = ["| Слой | Найдено вредоносных | TPR | Помечено чистых | FPR | Точность |",
             "|---|---|---|---|---|---|"]
    for m in metrics(result):
        lines.append(f"| {m['title']} | {m['tp']} из {m['malware']} | {_pct(m['tpr'])} | "
                     f"{m['fp']} из {m['clean']} | {_pct(m['fpr'])} | {_pct(m['precision'])} |")
    return "\n".join(lines)


def save(result: Result, folder: Path, note: str = "") -> Path:
    """summary.md и files.csv в folder. Возвращает путь к summary.md."""
    folder.mkdir(parents=True, exist_ok=True)
    with open(folder / "files.csv", "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f, delimiter=";")
        writer.writerow(["набор", "файл", "размер", *LAYERS])
        for label, path, size, verdicts in result.rows:
            writer.writerow([label, path, size, *[verdicts.get(n) or "" for n in LAYERS]])
    files = result.malware.total + result.clean.total
    spent = result.malware.seconds + result.clean.seconds
    text = (f"# Стенд: слои обнаружения\n\n{note}\n\n"
            f"Вредоносных файлов: {result.malware.total}, чистых: {result.clean.total}. "
            f"Не прочитано: {result.malware.errors + result.clean.errors}. "
            f"Время: {spent:.1f} с ({files / spent:.0f} файлов/с).\n\n" if spent else
            f"# Стенд: слои обнаружения\n\n{note}\n\nФайлов нет.\n\n") + table(result) + "\n"
    summary = folder / "summary.md"
    summary.write_text(text, encoding="utf-8")
    return summary
