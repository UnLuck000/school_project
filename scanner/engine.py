import re
from pathlib import Path

from scanner import media, overrides, verdict_cache
from scanner.hashing import data_hashes, file_hashes
from scanner.heuristics import analyze_pe, get_threshold
from scanner.relations import signed_partner, weak_match
from scanner.yara_engine import match_details, rules_version
from scanner.signature import (INVALID, REVOKED, UNSIGNED, VALID, check_revocation, trusted_fast,
                               inspect_signature)

ENGINE_VERSION = "8"
# файлы до этого размера читаются один раз: хэши, YARA и эвристика берут байты из памяти
ONE_READ_LIMIT = 32 * 1024 * 1024  # меняется вместе с логикой проверки: старые вердикты в кэше не годятся

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
        data = read_small(p, st.st_size)  # одно чтение на хэши, YARA и эвристику
        digest, md5 = data_hashes(data) if data is not None else file_hashes(p)
        if whitelist and digest in whitelist:
            return None
        found = hash_verdict(st.st_size, digest, md5, signatures)
        if found is None and not kind:
            from scanner import archive
            found = analyze(p, rules, heuristics, data=data)
            # вложенные файлы ZIP: правила — сразу, хэши сверяются с базами здесь же
            found = archive.resolve(archive.pack(found, p, data, rules), signatures,
                                    hash_verdict)
        reason = overrides.filter_reason(digest, found)
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


def read_small(p: Path, size: int) -> bytes | None:
    """Содержимое файла до ONE_READ_LIMIT (для одного чтения на все слои), иначе None."""
    return p.read_bytes() if size <= ONE_READ_LIMIT else None


LAUNCHER_SCHEMES = ("steam", "com.epicgames.launcher", "uplay", "origin", "origin2", "battlenet",
                    "heroic", "goggalaxy", "minecraft", "roblox-player", "discord", "spotify",
                    "ms-settings", "ms-windows-store", "tg", "zoommtg")
_URL_RE = re.compile(rb"^\s*URL\s*=\s*([a-z0-9.+\-]+):", re.I | re.M)


def launcher_shortcut(p: Path, data: bytes | None = None) -> bool:
    """Интернет-ярлык (.url), который открывает известную программу: Steam, Epic, Discord..."""
    if p.suffix.lower() != ".url":
        return False
    try:
        text = data if data is not None else p.read_bytes()[:8192]
    except OSError:
        return False
    schemes = [s.decode("ascii", "replace").lower() for s in _URL_RE.findall(text[:8192])]
    return bool(schemes) and all(s in LAUNCHER_SCHEMES for s in schemes)


SIGNATURE_FIRST = 256 * 1024  # с этого размера у программы сначала проверяется подпись


def _large_program(p: Path, data: bytes | None) -> bool:
    """PE-файл от SIGNATURE_FIRST: проверка подписи (3–8 мс) дешевле YARA по такому файлу."""
    try:
        if data is not None:
            return len(data) >= SIGNATURE_FIRST and data[:2] == b"MZ"
        if p.stat().st_size < SIGNATURE_FIRST:
            return False
        with open(p, "rb") as f:
            return f.read(2) == b"MZ"
    except OSError:
        return False


def analyze(p: Path, rules, heuristics: bool = True, threshold: int | None = None,
            revocation: bool | None = None, data: bytes | None = None) -> str | None:
    """Слои без хэшей: YARA, эвристика PE, подпись и связь с подписанной программой.
    Выполняется и в рабочих процессах (scanner.pool), поэтому настройки передаются явно."""
    threshold = get_threshold() if threshold is None else threshold
    revocation = _revocation if revocation is None else revocation
    sig = None
    partner = False  # False: связь ещё не искали
    if _large_program(p, data):
        # Быстрый путь. При действительной подписи совпадения YARA и эвристика всё равно
        # отбрасываются (ниже), а YARA — 88% времени проверки файла: крупную подписанную
        # программу правилами не проверяем. Отозванный сертификат — обычный путь.
        sig = trusted_fast(p, inspect_signature(p), revocation)
        if sig.status == VALID:
            return None
    if rules is not None:
        matches = match_details(rules, p, data=data)
        if matches and launcher_shortcut(p, data):
            # ярлык игры (steam://rungameid/...): правила «Methodology» ловят любую схему,
            # кроме http — это способ запуска, а не признак вредоноса
            matches = [m for m in matches if not m.rule.startswith("Methodology_")]
        if matches:
            sig = sig or _trusted_signature(p, inspect_signature(p), revocation)
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
        report = analyze_pe(p, data)
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
