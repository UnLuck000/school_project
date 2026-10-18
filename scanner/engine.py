from pathlib import Path

from scanner.hashing import sha256_of
from scanner.heuristics import HEURISTIC_THRESHOLD, analyze_pe
from scanner.yara_engine import match_file
from scanner.signature import UNSIGNED, VALID, verify_signature


def check_file(p: Path, signatures: set[str], rules=None,
               whitelist: set[str] | None = None, heuristics: bool = True) -> str | None:
    """Возвращает причину обнаружения или None, если файл чистый.
    Может бросить OSError, если файл нельзя прочитать."""
    digest = sha256_of(p)
    if whitelist and digest in whitelist:
        return None
    if digest in signatures:
        return "hash match"
    if rules is not None:
        names = match_file(rules, p)
        if names:
            return "YARA: " + ", ".join(names)
    if heuristics:
        report = analyze_pe(p)
        if report.score >= HEURISTIC_THRESHOLD:
            sig = verify_signature(p)
            if sig == VALID:
                return None  # подписан доверенным издателем: эвристику не применяем
            note = {UNSIGNED: " [нет подписи]", "invalid": " [подпись недействительна]"}
            return "Heuristic: " + report.summary() + note.get(sig, "")
    return None


def scan_tree(root: Path, signatures: set[str], rules=None,
              exclude: list[Path] | None = None, on_file=None, stop=None,
              whitelist: set[str] | None = None, heuristics: bool = True):
    """Обходит папку и выдаёт пары (путь, причина) для подозрительных файлов."""
    excluded = [e.resolve() for e in (exclude or [])]

    for p in root.rglob("*"):
        if stop is not None and stop.is_set():
            return
        try:
            if not p.is_file():
                continue
            rp = p.resolve()
            if any(e in rp.parents for e in excluded):
                continue
            if on_file:
                on_file(p)
            reason = check_file(p, signatures, rules, whitelist, heuristics)
            if reason:
                yield p, reason
        except (PermissionError, OSError):
            continue