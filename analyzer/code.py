import base64
import binascii
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

MAX_TEXT_BYTES = 2 * 1024 * 1024
MAX_FINDINGS = 200
DUMP_BYTES = 512
LANGUAGES = {
    ".bat": "bat", ".cmd": "bat", ".ps1": "ps1", ".psm1": "ps1", ".vbs": "vbs", ".vbe": "vbs",
    ".js": "js", ".jse": "js", ".hta": "html", ".html": "html", ".htm": "html",
    ".wsf": "xml", ".xml": "xml", ".py": "py", ".sh": "sh", ".reg": "reg",
    ".inf": "ini", ".ini": "ini",
}
RISKY_IN_ARCHIVE = {".exe", ".dll", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1",
                    ".lnk", ".hta", ".msi", ".jar"}

PS_ENC = re.compile(r"-(?:e|ec|en\w*)\s+['\"]?([A-Za-z0-9+/=]{16,})", re.IGNORECASE)
BASE64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
URL = re.compile(r"(?:https?|ftp)://[^\s'\"<>)\]]+", re.IGNORECASE)
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b")
CHR_CHAIN = re.compile(r"(?:chr[wb]?\(\s*\d+\s*\)\s*&?\s*){3,}", re.IGNORECASE)
FROM_CHAR = re.compile(r"String\.fromCharCode\(([\d,\s]+)\)", re.IGNORECASE)
SUBSTRING = re.compile(r"%[A-Za-z_]\w*:~-?\d+(?:,-?\d+)?%")

# (шаблон, название, пояснение)
PATTERNS = [(re.compile(p, re.IGNORECASE), t, d) for p, t, d in [
    (r"-w(?:in(?:dowstyle)?)?\s+h(?:idden)?", "Скрытое окно PowerShell",
     "Программа запускается без видимого окна"),
    (r"-ep\s+bypass|executionpolicy\s+bypass", "Обход политики выполнения PowerShell",
     "Скрипт обходит ограничения запуска сценариев"),
    (r"downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient|start-bitstransfer",
     "Загрузка из сети", "Скрипт скачивает данные или файлы"),
    (r"invoke-expression|\biex\b", "Выполнение строки как кода (IEX)",
     "Часто используется вместе с загрузкой или расшифровкой"),
    (r"frombase64string", "Декодирование Base64", "Код прячет полезную нагрузку"),
    (r"certutil[^\r\n]*-(?:urlcache|decode)", "certutil для загрузки или декодирования",
     "Системная утилита используется не по назначению"),
    (r"bitsadmin[^\r\n]*/transfer", "Загрузка через bitsadmin", "Системная утилита скачивает файл"),
    (r"mshta|regsvr32[^\r\n]*(?:/i:|scrobj)|rundll32[^\r\n]*javascript",
     "Запуск кода через системные утилиты (LOLBin)", "Приём обхода защиты"),
    (r"reg(?:\.exe)?\s+add[^\r\n]*\\run", "Запись в автозапуск",
     "Скрипт закрепляется в системе"),
    (r"schtasks[^\r\n]*/create", "Создание задачи планировщика", "Возможное закрепление в системе"),
    (r"net\s+user[^\r\n]*/add|net\s+localgroup\s+administrators",
     "Создание пользователя или права администратора", "Добавление учётной записи"),
    (r"vssadmin[^\r\n]*delete\s+shadows|wmic[^\r\n]*shadowcopy[^\r\n]*delete|wbadmin[^\r\n]*delete",
     "Удаление теневых копий", "Типичный признак шифровальщика"),
    (r"bcdedit[^\r\n]*(?:recoveryenabled|bootstatuspolicy)",
     "Отключение среды восстановления", "Типичный признак шифровальщика"),
    (r"taskkill[^\r\n]*/f", "Принудительное завершение процессов",
     "Может останавливать программы защиты"),
    (r"attrib[^\r\n]*\+[hs]", "Скрытие файлов атрибутами", "Файлы прячутся от пользователя"),
    (r"createobject\(\s*[\"'](?:wscript\.shell|adodb\.stream|msxml2\.xmlhttp)",
     "Объекты для запуска команд и загрузки (VBScript)", "Запуск программ и скачивание"),
    (r"\beval\s*\(|unescape\s*\(|activexobject", "eval, unescape или ActiveXObject",
     "Выполнение скрытого кода (JavaScript)"),
    (r"set-mppreference|add-mppreference|disableantispyware",
     "Изменение настроек защиты Windows", "Скрипт пытается ослабить защиту"),
]]


@dataclass
class CodeFinding:
    category: str            # decoded | suspicious | ioc | info
    title: str
    value: str
    line: int | None = None


@dataclass
class CodeView:
    title: str
    language: str
    text: str
    note: str
    findings: list = field(default_factory=list)


def hexdump(data: bytes, base: int = 0) -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + i:08X}  {hex_part:<47}  {ascii_part}")
    return "\n".join(lines)


def read_text(path: Path) -> tuple[str, str]:
    data = path.read_bytes()[:MAX_TEXT_BYTES]
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig", "replace"), "UTF-8 с BOM"
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", "replace"), "UTF-16"
    try:
        return data.decode("utf-8"), "UTF-8"
    except UnicodeDecodeError:
        return data.decode("cp1251", "replace"), "Windows-1251 (предположительно)"


def _ascii_ratio(text: str) -> float:
    if not text:
        return 0.0
    good = sum(1 for c in text if 32 <= ord(c) < 127 or c in "\r\n\t")
    return good / len(text)


def _decode_base64(blob: str):
    """(вид содержимого, текст) или None, если это не похоже на осмысленные данные."""
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    if raw[:2] == b"MZ":
        return "исполняемый файл (MZ)", f"Исполняемый файл Windows, {len(raw)} байт"
    for encoding in ("utf-16-le", "utf-8"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if len(text) >= 4 and _ascii_ratio(text) >= 0.85:
            return f"текст ({encoding})", text
    return None


def analyze_text(text: str, language: str) -> list[CodeFinding]:
    findings: list[CodeFinding] = []

    def line_of(pos: int) -> int:
        return text.count("\n", 0, pos) + 1

    done_blobs = set()
    for m in PS_ENC.finditer(text):
        result = _decode_base64(m.group(1))
        if result:
            done_blobs.add(m.group(1))
            findings.append(CodeFinding("decoded", "PowerShell -EncodedCommand (расшифровано)",
                                        result[1], line_of(m.start())))
    for m in BASE64.finditer(text):
        if m.group(0) in done_blobs:
            continue
        result = _decode_base64(m.group(0))
        if result:
            findings.append(CodeFinding("decoded", f"Base64: {result[0]}", result[1],
                                        line_of(m.start())))
    for m in CHR_CHAIN.finditer(text):
        decoded = "".join(chr(int(n)) for n in re.findall(r"\d+", m.group(0))
                          if int(n) < 0x110000)
        findings.append(CodeFinding("decoded", "Строка из chr(...) (расшифровано)",
                                    decoded, line_of(m.start())))
    for m in FROM_CHAR.finditer(text):
        numbers = [int(n) for n in re.findall(r"\d+", m.group(1)) if int(n) < 0x110000]
        findings.append(CodeFinding("decoded", "String.fromCharCode (расшифровано)",
                                    "".join(map(chr, numbers)), line_of(m.start())))

    if language == "bat":
        if text.count("^") >= 5:
            cleaned = re.sub(r"\^(.)", r"\1", text, flags=re.DOTALL)
            if cleaned != text:
                findings.append(CodeFinding(
                    "decoded", "Символы ^ убраны (маскировка в bat)", cleaned[:4000], None))
        if len(SUBSTRING.findall(text)) >= 5:
            findings.append(CodeFinding(
                "suspicious", "Подстановки подстрок %var:~n,m%",
                "Так в bat собирают команды из кусочков переменных, чтобы скрыть их смысл", None))

    for regex, title, why in PATTERNS:
        m = regex.search(text)
        if m:
            findings.append(CodeFinding("suspicious", title, why, line_of(m.start())))

    seen = set()
    for m in URL.finditer(text):
        url = m.group(0).rstrip(".,;")
        if url not in seen and len(seen) < 50:
            seen.add(url)
            findings.append(CodeFinding("ioc", "Адрес (URL)", url, line_of(m.start())))
    for m in IPV4.finditer(text):
        ip = m.group(0)
        octets = ip.split(":")[0].split(".")
        if ip not in seen and len(seen) < 80 and all(int(o) <= 255 for o in octets):
            seen.add(ip)
            findings.append(CodeFinding("ioc", "IP-адрес", ip, line_of(m.start())))

    findings.sort(key=lambda f: f.line or 0)
    return findings[:MAX_FINDINGS]


# ---------- разные виды файлов ----------
def _shortcut_view(path: Path) -> CodeView:
    from autoruns.scanner import resolve_shortcuts  # поздний импорт: тяжёлый модуль
    target, args = resolve_shortcuts([str(path)]).get(str(path), ("", ""))
    text = f"Ярлык: {path}\nЦель: {target or 'не удалось определить'}\nАргументы: {args}\n"
    note = ("Ярлык запускает программу с аргументами. Вредоносные ярлыки часто вызывают "
            "powershell или cmd с длинной командой.")
    return CodeView("Ярлык Windows", "text", text, note, analyze_text(f"{target} {args}", "bat"))


def _zip_view(path: Path) -> CodeView:
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()[:300]
    except zipfile.BadZipFile:
        return CodeView("Архив ZIP", "text", "", "Не удалось прочитать архив: файл повреждён.", [])
    lines, findings = [], []
    for info in infos:
        lines.append(f"{info.file_size:>12}  {info.filename}")
        if Path(info.filename).suffix.lower() in RISKY_IN_ARCHIVE:
            findings.append(CodeFinding("suspicious", "Исполняемый файл или скрипт внутри архива",
                                        info.filename, None))
    return CodeView("Содержимое архива", "text", "\n".join(lines),
                    f"Файлов в списке: {len(infos)} (не более 300). Размер указан в байтах.", findings)


def _pdf_findings(head: bytes) -> list[CodeFinding]:
    marks = {b"/JavaScript": "JavaScript", b"/JS": "JavaScript", b"/OpenAction": "автоматическое действие",
             b"/Launch": "запуск программы", b"/EmbeddedFile": "вложенный файл"}
    return [CodeFinding("suspicious", f"PDF содержит {title}", mark.decode(), None)
            for mark, title in marks.items() if mark in head]


def _pe_view(path: Path, pe) -> CodeView:
    import pefile
    dotnet = pe is not None and any(d.lower() == "mscoree.dll" for d in pe.imports)
    note = ""
    if dotnet:
        note = (".NET-программа: исходный код восстанавливают ILSpy или dnSpy (бесплатные "
                "декомпиляторы). Ниже код точки входа. ")
    image = pefile.PE(str(path), fast_load=True)
    try:
        ep = image.OPTIONAL_HEADER.AddressOfEntryPoint
        machine = image.FILE_HEADER.Machine
        base = image.OPTIONAL_HEADER.ImageBase + ep
        data = image.get_data(ep, 512) if ep else b""
    finally:
        image.close()
    if not data:
        return CodeView("Программа (PE)", "text", "", note + "У файла нет точки входа.", [])
    from analyzer.disasm import capstone_status  # поздний импорт: disasm импортирует этот модуль
    capstone, error = capstone_status()
    if capstone is None:
        return CodeView("Программа (PE): байты точки входа", "text", hexdump(data, base),
                        note + error + "\nСейчас показан дамп байтов в точке входа.", [])
    modes = {0x8664: capstone.CS_MODE_64, 0x14C: capstone.CS_MODE_32}
    if machine not in modes:
        return CodeView("Программа (PE): байты точки входа", "text", hexdump(data, base),
                        note + "Эта архитектура не поддерживается дизассемблером.", [])
    md = capstone.Cs(capstone.CS_ARCH_X86, modes[machine])
    lines = [f"{i.address:016X}  {i.mnemonic:<8} {i.op_str}" for i in md.disasm(data, base)]
    return CodeView(
        "Дизассемблер: точка входа", "asm", "\n".join(lines[:200]),
        note + "Это ассемблерный код начала программы, а не исходный текст: полноценные "
        "декомпиляторы (Ghidra, IDA) работают с программой целиком.", [])


def _build(path: Path, key: str, ext: str, pe) -> CodeView:
    if key == "empty":
        return CodeView("Пустой файл", "text", "", "В файле нет данных.", [])
    if key == "lnk":
        return _shortcut_view(path)
    if key in ("script", "text"):
        language = LANGUAGES.get(ext, "text")
        text, encoding = read_text(path)
        note = f"Язык: {language}. Кодировка: {encoding}."
        if path.stat().st_size > MAX_TEXT_BYTES:
            note += " Показаны первые 2 МБ."
        return CodeView("Скрипт" if key == "script" else "Текстовый файл", language, text, note,
                        analyze_text(text, language))
    if key == "pe":
        return _pe_view(path, pe)
    if key == "zip":
        return _zip_view(path)
    with path.open("rb") as f:
        head = f.read(8 * 1024 * 1024)
    note = f"Двоичный формат: показан дамп первых {DUMP_BYTES} байт."
    findings = []
    if key == "pdf":
        findings = _pdf_findings(head)
    elif key == "ole":
        note += " Макросы Office проверяют инструментом oletools (olevba)."
    return CodeView("Двоичный файл", "text", hexdump(head[:DUMP_BYTES]), note, findings)


def build_code_view(path: Path, key: str, ext: str, pe=None) -> CodeView:
    try:
        return _build(path, key, ext, pe)
    except Exception as e:  # просмотр кода не должен ломать анализ файла
        return CodeView("Код недоступен", "text", "", f"Не удалось подготовить просмотр: {e}", [])