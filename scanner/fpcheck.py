"""Разбор срабатываний для поиска ложных: что именно сработало (хэш, правило, эвристика),
откуда это в базе, чем подписан файл и насколько вероятно, что срабатывание ложное.
В отличие от check_file здесь видно всё, в том числе то, что уже подавлено подписью
или ручными исключениями."""
import os
from dataclasses import dataclass
from pathlib import Path

from scanner import overrides
from scanner.hashing import file_hashes
from scanner.relations import signed_partner, weak_match
from scanner.heuristics import analyze_pe, get_threshold
from scanner.signature import VALID, check_revocation, describe, inspect_signature
from scanner.yara_engine import match_details, rule_source

SYSTEM_DIRS = tuple(os.path.normcase(os.environ.get(name, default)) + os.sep for name, default in (
    ("SystemRoot", r"C:\Windows"), ("ProgramFiles", r"C:\Program Files"),
    ("ProgramFiles(x86)", r"C:\Program Files (x86)")))

LAYER_TEXT = {"hash": "Хэш", "yara": "YARA", "heuristic": "Эвристика"}


@dataclass
class Hit:
    path: str
    layer: str        # hash | yara | heuristic
    value: str        # хэш, имя правила или баллы
    source: str       # файл базы или правил
    detail: str       # описание правила, причины эвристики
    signature: str    # «Действительна: Microsoft Windows» и т. п.
    sig_valid: bool
    excluded: bool    # хэш убран или правило отключено вручную
    verdict: str      # оценка: ложное / вероятно ложное / проверить
    weak: bool = False    # слабое срабатывание (эвристика, правило класса PUA и т. п.)
    partner: str = ""     # связь с подписанным файлом из той же папки (scanner.relations)

    @property
    def active(self) -> bool:
        """Считается ли это срабатывание угрозой при обычной проверке."""
        if self.excluded:
            return False
        if self.layer == "hash":
            return True
        return not self.sig_valid and not (self.partner and self.weak)


def _assess(hit: Hit) -> str:
    if hit.excluded:
        return "Исключено вручную"
    if hit.sig_valid and hit.layer != "hash":
        return "Ложное: подпись действительна, угрозой не считается"
    if hit.sig_valid:
        return "Вероятно ложное: подписанный файл в базе хэшей"
    if hit.partner and hit.weak and hit.layer != "hash":
        return f"Ложное: часть подписанной программы ({hit.partner}), угрозой не считается"
    if hit.partner:
        return f"Проверить: связан с подписанным файлом ({hit.partner}), но срабатывание сильное"
    if os.path.normcase(hit.path).startswith(SYSTEM_DIRS):
        return "Вероятно ложное: системная папка, но без подписи — проверить"
    return "Проверить"


def explain_file(path: Path, signatures, rules) -> list[Hit]:
    """Все срабатывания по файлу (пустой список, если ни один слой не сработал).
    OSError, если файл нельзя прочитать."""
    size = path.stat().st_size
    sha256, md5 = file_hashes(path)
    raw: list[tuple] = []  # слой, значение, источник, детали, исключено, слабое
    if size > 0:
        for digest in (sha256, md5):
            if digest in signatures:
                source = signatures.source(digest) if hasattr(signatures, "source") else ""
                raw.append(("hash", digest, source, "MD5" if len(digest) == 32 else "SHA-256",
                            overrides.hash_ignored(digest), False))
    if rules is not None:
        for m in match_details(rules, path, raw=True):
            description = str(m.meta.get("description", "")) if m.meta else ""
            raw.append(("yara", m.rule, rule_source(m), description,
                        overrides.rule_disabled(m.rule), weak_match(m)))
    report = analyze_pe(path)
    if report.score >= get_threshold():
        raw.append(("heuristic", f"{report.score} баллов", "эвристика PE", report.summary(),
                    False, True))
    if not raw:
        return []
    sig = inspect_signature(path)
    from scanner.engine import revocation_enabled
    if revocation_enabled():
        sig = check_revocation(path, sig)
    partner = ""
    if sig.status != VALID:
        found = signed_partner(path)
        partner = found[1] if found else ""
    hits = []
    for layer, value, source, detail, excluded, weak in raw:
        hit = Hit(str(path), layer, value, source, detail, describe(sig), sig.status == VALID,
                  excluded, "", weak, partner)
        hit.verdict = _assess(hit)
        hits.append(hit)
    return hits


def iter_files(root: Path, recursive: bool):
    if root.is_file():
        yield root
        return
    if recursive:
        for folder, _, names in os.walk(root):
            for name in names:
                yield Path(folder) / name
    else:
        try:
            for entry in os.scandir(root):
                if entry.is_file():
                    yield Path(entry.path)
        except OSError:
            return
