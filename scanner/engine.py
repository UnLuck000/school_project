from pathlib import Path

from scanner import media, overrides, verdict_cache
from scanner.hashing import file_hashes
from scanner.heuristics import analyze_pe, get_threshold
from scanner.relations import signed_partner, weak_match
from scanner.yara_engine import match_details, rules_version
from scanner.signature import (INVALID, REVOKED, UNSIGNED, VALID, check_revocation,
                               inspect_signature)

ENGINE_VERSION = "6"  # меняется вместе с логикой проверки: старые вердикты в кэше не годятся

# проверять отзыв сертификата, прежде чем по подписи признать срабатывание ложным
# (настройка scan/revocation; нужен интернет, без связи подпись считается как раньше)
_revocation = True


def set_revocation(on: bool) -> None:
    global _revocation
    _revocation = bool(on)


def revocation_enabled() -> bool:
    return _revocation


def _trusted_signature(p: Path, sig, revocation: bool):
    """Подпись, которой можно снять срабатывание: действительна и сертификат не отозван."""
    if sig.status == VALID and revocation:
        sig = check_revocation(p, sig)
    return sig


def cache_version(signatures, rules, heuristics: bool = True) -> str | None:
    """Версия проверки для кэша вердиктов. None: базы неизвестного происхождения
    (например, обычное множество хэшей в тестах), кэш не используется."""
    hashes = getattr(signatures, "version", None)
    ruleset = rules_version(rules)
    if hashes is None or ruleset is None:
        return None
    threshold = get_threshold() if heuristics else "-"
    return (f"{ENGINE_VERSION}|{hashes}|{ruleset}|{overrides.version()}|{threshold}"
            f"|{int(_revocation)}")


def check_file(p: Path, signatures, rules=None,
               whitelist: set[str] | None = None, heuristics: bool = True,
               use_cache: bool = True) -> str | None:
    """Возвращает причину обнаружения или None, если файл чистый.
    Может бросить OSError, если файл нельзя прочитать.

    Неизменённый файл при тех же базах повторно не читается: ответ берётся из кэша."""
    st = p.stat()
    version = cache_version(signatures, rules, heuristics) if use_cache else None
    if version:
        cached = verdict_cache.get(p, st, version)
        if cached is not None:
            digest, reason = cached
            return None if whitelist and digest in whitelist else reason
    kind = media.plain_media(p, st.st_size)  # видео и аудио: без YARA и эвристики
    if kind and st.st_size > media.MEDIA_HASH_LIMIT:
        digest, reason = "", None  # крупный медиафайл целиком не читается
    else:
        digest, md5 = file_hashes(p)
        if whitelist and digest in whitelist:
            return None
        reason = hash_verdict(st.st_size, digest, md5, signatures) or (
            None if kind else analyze(p, rules, heuristics))
    if version:
        verdict_cache.put(p, st, version, digest, reason)
    return reason


def hash_verdict(size: int, digest: str, md5: str, signatures) -> str | None:
    """Слой хэшей. Пустой файл есть в любой базе (MD5 d41d8cd9...): по хэшу его не судим."""
    if size > 0:
        if digest in signatures and not overrides.hash_ignored(digest):
            return "hash match"
        if md5 in signatures and not overrides.hash_ignored(md5):  # VirusShare: только MD5
            return "hash match (MD5)"
    return None


def analyze(p: Path, rules, heuristics: bool = True, threshold: int | None = None,
            revocation: bool | None = None) -> str | None:
    """Слои без хэшей: YARA, эвристика PE, подпись и связь с подписанной программой.
    Выполняется и в рабочих процессах (scanner.pool), поэтому настройки передаются явно."""
    threshold = get_threshold() if threshold is None else threshold
    revocation = _revocation if revocation is None else revocation
    sig = None
    partner = False  # False: связь ещё не искали
    if rules is not None:
        matches = match_details(rules, p)
        if matches:
            sig = _trusted_signature(p, inspect_signature(p), revocation)
            if sig.status == REVOKED:
                return "YARA: " + ", ".join(m.rule for m in matches) + " [сертификат отозван]"
            # действительная подпись доверенного издателя (Microsoft, JetBrains...):
            # совпадение правила считается ложным, как и у эвристики ниже
            if sig.status != VALID:
                if all(weak_match(m) for m in matches):
                    partner = signed_partner(p)
                if not partner:
                    return "YARA: " + ", ".join(m.rule for m in matches)
    if heuristics:
        report = analyze_pe(p)
        if report.score >= threshold:
            sig = sig or _trusted_signature(p, inspect_signature(p), revocation)
            if sig.status == VALID:
                return None  # подписан доверенным издателем: эвристику не применяем
            if partner is False:
                partner = signed_partner(p)
            if partner:
                return None  # библиотека подписанной программы из той же папки
            note = {UNSIGNED: " [нет подписи]", INVALID: " [подпись недействительна]",
                    REVOKED: " [сертификат отозван]"}
            return "Heuristic: " + report.summary() + note.get(sig.status, "")
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