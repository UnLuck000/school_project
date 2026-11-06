import hashlib
import json
import re
from datetime import datetime
from itertools import chain
from pathlib import Path

import yara

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "logs" / "yara_errors.log"
CACHE_DIR = BASE_DIR / "cache"
MAX_FILE_SIZE = 100 * 1024 * 1024  # файлы больше 100 МБ пропускаем
MAX_FIXES = 60  # сколько исправлений пробовать в одном файле правил
RULE_RE = re.compile(r"^\s*(?:(?:private|global)\s+)*rule\s+[A-Za-z_]\w*", re.MULTILINE)
RULE_HEAD_RE = re.compile(r"^[ \t]*(?:(?:private|global)\s+)*rule\s+([A-Za-z_]\w*)", re.MULTILINE)
UNDEFINED_RE = re.compile(r'undefined identifier "(\w+)"')
ERROR_LINE_RE = re.compile(r"line (\d+)")
INFO_RE = re.compile(r'\bcategory\s*=\s*"INFO"', re.IGNORECASE)  # в разделе meta
# правила не для Windows: ОС в meta (Elastic), ОС в имени правила или файла (ReversingLabs,
# Elastic), заголовок ELF или Mach-O в условии без проверки PE (signature-base)
OTHER_OS_META_RE = re.compile(r'\bos\s*=\s*"(?:linux|macos|android|ios)"', re.IGNORECASE)
OTHER_OS_NAME_RE = re.compile(r"(?:^|[_.\-])(?:linux|macos|osx|elf|unix|mach-?o|android|ios)"
                              r"(?:[_.\-]|$)", re.IGNORECASE)
OTHER_FORMAT_RE = re.compile(r"0x464c457f|0xfeedfac[ef]|0xcefaedfe|0xcffaedfe|\belf\.|"
                             r"\bmacho\.", re.IGNORECASE)
PE_FORMAT_RE = re.compile(r"0x5a4d|\bpe\.|\bdotnet\.", re.IGNORECASE)
MEMORY_ONLY_RE = re.compile(r'\bscan_context\s*=\s*"memory"', re.IGNORECASE)
# файлы, целиком повторяющие другой файл того же источника
REDUNDANT_FILES = {
    # те же 507 правил уязвимых драйверов, что в yara-rules_vuln_drivers_strict.yar, но
    # только для переименованных файлов: первый файл их уже находит
    "yara-rules_vuln_drivers_strict_renamed.yar",
}
FILTER_VERSION = "2"  # меняется вместе с отбором правил: кэш скомпилированных правил устаревает
DROP_TEXT = {"other_os": "для Linux, macOS, Android", "memory_only": "только для памяти",
             "duplicate": "дубли (правил или целых файлов)"}
# внешние переменные, которые задают сканеры THOR/LOKI: правила signature-base на них
# опираются. При проверке файла подставляются его имя и путь, при проверке памяти пусто
EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": ""}


def count_rules(rules_dir: Path) -> tuple[int, int]:
    """(файлов правил, правил). Приблизительный подсчёт по тексту, без компиляции."""
    files = list(chain(rules_dir.rglob("*.yar"), rules_dir.rglob("*.yara")))
    total = 0
    for f in files:
        try:
            total += len(RULE_RE.findall(f.read_text(encoding="utf-8", errors="ignore")))
        except OSError:
            continue
    return len(files), total


def _externals(path: Path | None = None) -> dict:
    if path is None:
        return dict(EXTERNALS)
    return {**EXTERNALS, "filename": path.name, "filepath": str(path),
            "extension": path.suffix.lower()}


# ---------- исправление правил ----------
def _rule_at(text: str, line: int) -> tuple[int, int, str] | None:
    """Границы правила, в котором стоит строка line (с единицы): (начало, конец, имя)."""
    heads = list(RULE_HEAD_RE.finditer(text))
    offset = 0
    for _ in range(line - 1):  # смещение начала нужной строки
        offset = text.find("\n", offset) + 1
        if offset == 0:
            return None
    for i, head in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        if head.start() <= offset < end:
            return head.start(), end, head.group(1)
    return None


def _blank(text: str, start: int, end: int) -> str:
    """Убирает кусок текста, оставляя переводы строк: номера строк в ошибках не сдвигаются."""
    return text[:start] + "\n" * text.count("\n", start, end) + text[end:]


def _drop_info_rules(text: str) -> tuple[str, list[str]]:
    """Правила с category = "INFO" только сообщают тип файла («это скрипт AutoIt»),
    но не говорят об угрозе: для антивируса это ложные срабатывания."""
    if not INFO_RE.search(text):
        return text, []
    heads = list(RULE_HEAD_RE.finditer(text))
    dropped = []
    for i in range(len(heads) - 1, -1, -1):  # с конца: смещения начала не сдвигаются
        start = heads[i].start()
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        if INFO_RE.search(text, start, end):
            text = _blank(text, start, end)
            dropped.append(heads[i].group(1))
    return text, dropped[::-1]


def _core(body: str) -> str:
    """Суть правила для поиска дублей: строки и условие без имени, meta и пробелов."""
    part = body.split("strings:", 1)[-1] if "strings:" in body else body.split("condition:", 1)[-1]
    return hashlib.sha1(re.sub(r"\s+", " ", part).strip().encode()).hexdigest()


def filter_rules(text: str, file_name: str, purpose: str = "file",
                 seen: set[str] | None = None) -> tuple[str, dict[str, list[str]]]:
    """Убирает правила, бесполезные для Windows-антивируса (текст заменяется пустыми
    строками, номера строк не сдвигаются).

    - для Linux, macOS, Android (по meta os, имени правила или файла, заголовку ELF/Mach-O
      в условии, если там нет проверки PE);
    - purpose="file": правила только для памяти (meta scan_context = "memory");
    - дубли: то же самое правило (строки и условие) уже было в другом файле (seen — общие
      для всех файлов набора отпечатки). Правило, на которое ссылаются другие, не трогаем.
    Возвращает (текст, {причина: [имена правил]})."""
    dropped: dict[str, list[str]] = {}
    heads = list(RULE_HEAD_RE.finditer(text))
    whole_file_os = bool(OTHER_OS_NAME_RE.search(Path(file_name).stem))
    for i in range(len(heads) - 1, -1, -1):  # с конца: смещения начала не сдвигаются
        start = heads[i].start()
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        body = text[start:end]
        name = heads[i].group(1)
        condition = body.split("condition:", 1)[-1]
        reason = None
        if (whole_file_os or OTHER_OS_META_RE.search(body) or OTHER_OS_NAME_RE.search(name)
                or (OTHER_FORMAT_RE.search(condition) and not PE_FORMAT_RE.search(condition))):
            reason = "other_os"
        elif purpose == "file" and MEMORY_ONLY_RE.search(body):
            reason = "memory_only"
        elif seen is not None:
            core = _core(body)
            if core in seen and len(re.findall(rf"\b{re.escape(name)}\b", text)) == 1:
                reason = "duplicate"  # ссылки ищем только у дублей: их единицы
            seen.add(core)
        if reason:
            text = _blank(text, start, end)
            dropped.setdefault(reason, []).append(name)
    return text, dropped


def fix_rules_source(text: str, removed: set[str] | None = None
                     ) -> tuple[str | None, dict, list[str], str]:
    """Компилирует текст правил и чинит то, что можно починить.

    - неизвестный идентификатор, который не является правилом, объявляется внешней
      переменной (filename, filepath и т. п.: их задают сканеры THOR/LOKI);
    - правило с иной ошибкой (неизвестный модуль, повтор имени, ссылка на отключённое
      правило) отключается, остальные правила файла остаются рабочими.
    Возвращает (исправленный текст или None, внешние переменные, исправления, ошибка).
    """
    externals = dict(EXTERNALS)
    fixes: list[str] = []
    removed = set(removed or ())  # уже убранные правила: ссылки на них — не внешние переменные
    text, info = _drop_info_rules(text)
    if info:
        removed |= set(info)
        fixes.append("отключены информационные правила (не признак угрозы): " + ", ".join(info))
    for _ in range(MAX_FIXES):
        try:
            yara.compile(source=text, externals=externals)
            return text, externals, fixes, ""
        except yara.Error as e:
            message = str(e)
        undefined = UNDEFINED_RE.search(message)
        if (undefined and undefined.group(1) not in removed
                and undefined.group(1) not in externals):
            name = undefined.group(1)
            externals[name] = ""
            fixes.append(f"объявлена внешняя переменная «{name}»")
            continue
        line = ERROR_LINE_RE.search(message)
        span = _rule_at(text, int(line.group(1))) if line else None
        if span is None:
            return None, externals, fixes, message  # ошибка вне правил (импорт, синтаксис)
        start, end, name = span
        text = _blank(text, start, end)
        removed.add(name)
        fixes.append(f"отключено правило {name}: {message.split(': ', 1)[-1]}")
        if not RULE_HEAD_RE.search(text):
            return None, externals, fixes, "после исправлений не осталось правил"
    return None, externals, fixes, "слишком много ошибок"


def _dump_log(skipped: list[str], fixed: list[str]) -> None:
    """Пишет в лог отключённые файлы и сделанные исправления (перезаписывается)."""
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        lines = [f"# {datetime.now():%Y-%m-%d %H:%M:%S}: файлов исправлено {len(fixed)}, "
                 f"отключено целиком {len(skipped)}"]
        if skipped:
            lines += ["", "## Не удалось исправить (файл не используется)"] + skipped
        if fixed:
            lines += ["", "## Исправлено автоматически"] + fixed
        LOG_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError:
        pass  # лог не критичен


# ---------- загрузка с кэшем ----------
_fingerprints: dict[int, str] = {}  # id(rules) -> отпечаток файлов, из которых собраны


def _remember(rules, fingerprint: str) -> None:
    _fingerprints[id(rules)] = fingerprint


def rules_version(rules) -> str | None:
    """Отпечаток набора правил (для кэша вердиктов). None: неизвестно откуда правила."""
    if rules is None:
        return "none"
    return _fingerprints.get(id(rules))


def _fingerprint(files: list[Path]) -> str:
    h = hashlib.sha256(yara.__version__.encode())
    for f in files:
        st = f.stat()
        h.update(f"{f}|{st.st_size}|{st.st_mtime_ns}\n".encode())
    return h.hexdigest()


def _cache_paths(dirs: list[Path], skip: str, purpose: str = "file") -> tuple[Path, Path]:
    key = "|".join(str(d.resolve()).lower() for d in dirs) + "|" + skip + "|" + purpose
    tag = hashlib.sha256(key.encode()).hexdigest()[:12]
    return CACHE_DIR / f"yara_{tag}.bin", CACHE_DIR / f"yara_{tag}.json"


def rule_files(dirs, skip: str = "") -> list[Path]:
    """Файлы правил из папок; skip: регулярное выражение для путей, которые не брать."""
    pattern = re.compile(skip, re.IGNORECASE) if skip else None
    files = []
    for d in dirs:
        for f in sorted(chain(d.rglob("*.yar"), d.rglob("*.yara"))):
            if pattern is None or not pattern.search(f.as_posix()):
                files.append(f)
    return files


def load_rules(rules_dir, use_cache: bool = True, skip: str = "", purpose: str = "file"):
    """Компилирует все .yar/.yara из папки (или списка папок). Возвращает
    (rules | None, список ошибок). skip: регулярное выражение для путей, которые не брать.
    purpose: "file" или "memory" — для чего набор (см. filter_rules).

    Каждый файл проверяется отдельно: одно битое правило не ломает остальные, а то,
    что можно исправить, исправляется (см. fix_rules_source). Скомпилированные правила
    сохраняются в cache/ и при неизменных файлах загружаются оттуда за доли секунды.
    """
    dirs = [rules_dir] if isinstance(rules_dir, Path) else list(rules_dir)
    files = rule_files(dirs, skip)
    if not files:
        return None, []
    fingerprint = _fingerprint(files) + FILTER_VERSION
    bin_path, meta_path = _cache_paths(dirs, skip, purpose)
    if use_cache:
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            if meta.get("fingerprint") == fingerprint:
                rules = yara.load(str(bin_path))
                _remember(rules, fingerprint)
                return rules, meta.get("errors", [])
        except (OSError, ValueError, yara.Error):
            pass

    sources: dict[str, str] = {}
    externals = dict(EXTERNALS)
    errors: list[str] = []
    fixed: list[str] = []
    seen: set[str] = set()
    dropped_total: dict[str, int] = {}
    for i, path in enumerate(files):
        if path.name.lower() in REDUNDANT_FILES:
            dropped_total["duplicate"] = dropped_total.get("duplicate", 0) + 1
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            errors.append(f"{path.name}: {e}")
            continue
        namespace = f"{i}_{re.sub(r'[^0-9A-Za-z_]', '_', path.stem)}"
        if re.search(r'^\s*include\s+"', text, re.MULTILINE):
            try:  # include ищется относительно файла: компилируем как есть
                yara.compile(filepath=str(path), externals=externals)
                sources[namespace] = f'include "{path.as_posix()}"'
            except yara.Error as e:
                errors.append(f"{path.name}: {e}")
            continue
        text, dropped = filter_rules(text, path.name, purpose, seen)
        for reason, names in dropped.items():
            dropped_total[reason] = dropped_total.get(reason, 0) + len(names)
        removed = {n for names in dropped.values() for n in names}
        if removed and not RULE_HEAD_RE.search(text):
            continue  # в файле не осталось правил (например, всё для Linux)
        source, file_externals, fixes, error = fix_rules_source(text, removed)
        rel = _relative(path, dirs)
        if source is None:
            errors.append(f"{rel}: {error}")
            continue
        externals.update(file_externals)
        sources[namespace] = source
        if fixes:
            fixed.append(f"{rel}:\n    " + "\n    ".join(fixes))
    if dropped_total:
        fixed.insert(0, "Отобрано для Windows (правила не загружаются): " + ", ".join(
            f"{DROP_TEXT.get(k, k)} — {v}" for k, v in dropped_total.items()))
    _dump_log(errors, fixed)
    if not sources:
        return None, errors
    rules = yara.compile(sources=sources, externals=externals)
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        rules.save(str(bin_path))
        meta_path.write_text(json.dumps({"fingerprint": fingerprint, "errors": errors},
                                        ensure_ascii=False), encoding="utf-8")
    except (OSError, yara.Error):
        pass  # без кэша просто медленнее
    _remember(rules, fingerprint)
    return rules, errors


def _relative(path: Path, dirs: list[Path]) -> str:
    for d in dirs:
        if path.is_relative_to(d):
            return path.relative_to(d.parent).as_posix()
    return path.name


def match_file(rules, path: Path, timeout: int = 30, raw: bool = False) -> list[str]:
    """Возвращает названия сработавших правил (пустой список, если ничего нет).
    Правила, отключённые вручную (scanner.overrides), не возвращаются, если не raw."""
    return [m.rule for m in match_details(rules, path, timeout, raw)]


def match_details(rules, path: Path, timeout: int = 30, raw: bool = False) -> list:
    """То же, но объекты совпадений yara (rule, namespace, meta)."""
    from scanner import overrides
    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            return []
        matches = rules.match(str(path), timeout=timeout, externals=_externals(path))
    except (yara.Error, OSError):  # TimeoutError тоже наследуется от yara.Error
        return []
    if raw:
        return list(matches)
    return [m for m in matches if not overrides.rule_disabled(m.rule)]


def rule_source(match) -> str:
    """Файл правил, из которого правило (по пространству имён «N_имя_файла»)."""
    return match.namespace.split("_", 1)[-1] if "_" in match.namespace else match.namespace
