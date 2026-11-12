import os
import re
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from recovery import policies
from recovery import system as rsys
from recovery.registry import NO_WINDOW, REG_DWORD, hives_to_scan, list_values, read_value
from recovery.system import Finding

LOOPBACK = {"0.0.0.0", "127.0.0.1", "::1"}
# производители защиты: слово не должно быть частью другого (preset не содержит eset)
SECURITY_RE = re.compile(
    r"(?<![a-z])(kaspersky|eset|avast|avg|malwarebytes|bitdefender|norton|mcafee|symantec|"
    r"sophos|drweb|avira|comodo|f-secure|virustotal)|windowsupdate|update\.microsoft|"
    r"microsoft\.com", re.IGNORECASE)
USER_DIR_MARKERS = ("\\appdata\\local\\temp\\", "\\temp\\", "\\downloads\\", "\\users\\public\\")


# ---------- hosts ----------
def check_hosts() -> list[Finding]:
    try:
        text = rsys.HOSTS_FILE.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return [Finding("hosts", "Файл hosts", "Не удалось прочитать", str(e), "warning")]

    entries = []
    for raw in text.splitlines():
        parts = raw.split("#", 1)[0].split()
        if len(parts) >= 2:
            entries.append((parts[0], parts[1:], raw.strip()))
    if not entries:
        return [Finding("hosts", "Файл hosts", "Чисто",
                        "Активных записей нет (стандартное состояние)", "ok")]

    findings: list[Finding] = []
    quiet = 0  # обычные блокировки рекламы и трекеров
    for ip, names, raw in entries:
        security = any(SECURITY_RE.search(n) for n in names)
        blocking = ip in LOOPBACK
        if not security and blocking:
            quiet += 1
            continue
        if security:
            status = ("Заблокирован домен защиты или обновлений" if blocking
                      else "Перенаправлен домен защиты или обновлений")
            level = "bad"
        else:
            status, level = "Перенаправление на внешний адрес", "warning"
        if len(findings) < 100:
            findings.append(Finding("hosts", f"hosts: {', '.join(names)[:80]}", status, raw,
                                    level, "Удалить строку из hosts",
                                    {"op": "hosts_remove", "raw": raw}))
    if quiet:
        findings.append(Finding(
            "hosts", "hosts: блокировки доменов", f"{quiet} записей",
            "Домены направлены на 0.0.0.0 или 127.0.0.1 (так работают списки блокировки "
            "рекламы). Среди них нет доменов защиты и обновлений.", "info"))
    return findings


# ---------- прокси (WinINET) ----------
INET = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def check_proxy() -> list[Finding]:
    findings: list[Finding] = []
    for hive in hives_to_scan():
        if hive == "HKLM":
            continue
        who = "текущий пользователь" if hive == "HKCU" else f"пользователь {hive[4:]}"
        enabled = read_value(hive, INET, "ProxyEnable")
        server = read_value(hive, INET, "ProxyServer")
        pac = read_value(hive, INET, "AutoConfigURL")
        if enabled[0] and enabled[1] == 1:
            findings.append(Finding(
                "proxy", f"Прокси-сервер ({who})", "Включён",
                f"Адрес: {server[1] or 'не указан'}", "warning", "Отключить прокси",
                {"op": "reg_set", "hive": hive, "path": INET, "name": "ProxyEnable",
                 "value": 0, "type": REG_DWORD}))
        if pac[0] and pac[1]:
            findings.append(Finding(
                "proxy", f"Скрипт автоконфигурации PAC ({who})", "Задан", str(pac[1]),
                "warning", "Удалить адрес скрипта",
                {"op": "reg_delete", "hive": hive, "path": INET, "name": "AutoConfigURL"}))
    if not findings:
        findings.append(Finding("proxy", "Прокси", "Не настроены",
                                "Системный прокси и PAC-скрипт не заданы", "ok"))
    return findings


# ---------- WinHTTP-прокси ----------
WINHTTP_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"


def parse_winhttp(data: bytes):
    """(прокси, исключения) из значения WinHttpSettings или None, если прокси не задан.
    Формат: заголовок 8 байт, флаги (0x2 = прокси), длина и строка прокси, длина и строка исключений."""
    if len(data) < 16:
        return None
    flags = int.from_bytes(data[8:12], "little")
    if not flags & 0x2:
        return None
    length = int.from_bytes(data[12:16], "little")
    proxy = data[16:16 + length].decode("ascii", "replace")
    rest = data[16 + length:]
    bypass = ""
    if len(rest) >= 4:
        size = int.from_bytes(rest[:4], "little")
        bypass = rest[4:4 + size].decode("ascii", "replace")
    return proxy, bypass


def check_winhttp() -> list[Finding]:
    exists, data, _ = read_value("HKLM", WINHTTP_KEY, "WinHttpSettings")
    parsed = parse_winhttp(data) if exists and isinstance(data, bytes) else None
    if parsed is None:
        return [Finding("winhttp", "WinHTTP-прокси", "Не задан",
                        "Службы Windows подключаются напрямую", "ok")]
    proxy, bypass = parsed
    return [Finding(
        "winhttp", "WinHTTP-прокси", "Задан",
        f"Прокси: {proxy}" + (f"; исключения: {bypass}" if bypass else ""), "warning",
        "Сбросить WinHTTP-прокси",
        {"op": "reg_delete", "hive": "HKLM", "path": WINHTTP_KEY, "name": "WinHttpSettings"})]


# ---------- расписания и службы обновлений ----------
WU = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
UPDATE_POLICIES = [
    (WU + r"\AU", "NoAutoUpdate", (1,), "Автоматическое обновление Windows отключено политикой"),
    (WU + r"\AU", "AUOptions", (1,), "Проверка обновлений отключена политикой (AUOptions = 1)"),
    (WU, "DisableWindowsUpdateAccess", (1,), "Доступ к Центру обновления закрыт политикой"),
    (WU, "DoNotConnectToWindowsUpdateInternetLocations", (1,),
     "Подключение к серверам обновлений запрещено политикой"),
]
SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"
UPDATE_SERVICES = {"wuauserv": "Центр обновления Windows", "UsoSvc": "Оркестратор обновлений",
                   "WaaSMedicSvc": "Служба медика обновлений"}
UPDATE_TASKS = [r"\Microsoft\Windows\WindowsUpdate\Scheduled Start",
                r"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan"]
TASK_NS = {"t": "https://schemas.microsoft.com/windows/2004/02/mit/task"}


def _task_enabled(task: str):
    path = Path(rsys.SYSTEM_ROOT) / "System32" / "Tasks" / task.lstrip("\\")
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return None  # нет задачи или нет прав на чтение
    return root.findtext("t:Settings/t:Enabled", "true", TASK_NS).strip().lower() != "false"


def check_updates() -> list[Finding]:
    findings: list[Finding] = []
    for path, name, bad, text in UPDATE_POLICIES:
        exists, value, _ = read_value("HKLM", path, name)
        if exists and value in bad:
            findings.append(Finding(
                "updates", text, f"{name} = {value}", f"HKLM\\{path}", "warning",
                "Убрать политику",
                {"op": "reg_delete", "hive": "HKLM", "path": path, "name": name}))
    for service, title in UPDATE_SERVICES.items():
        exists, start, _ = read_value("HKLM", f"{SERVICES_KEY}\\{service}", "Start")
        if exists and start == 4:
            findings.append(Finding(
                "updates", f"Служба «{title}» отключена", f"{service}: Start = 4",
                "Без неё Windows не получает обновления (если вы отключили её сами, это нормально)",
                "warning", "Включить службу (ручной запуск)",
                {"op": "service_mode", "name": service, "mode": "demand", "prev": "disabled"}))
    unreadable = 0
    for task in UPDATE_TASKS:
        enabled = _task_enabled(task)
        if enabled is None:
            unreadable += 1
        elif not enabled:
            findings.append(Finding(
                "updates", "Задача расписания обновлений отключена", task,
                "Отключённая задача не запускает проверку обновлений по расписанию", "warning",
                "Включить задачу", {"op": "task_enabled", "name": task, "enable": True}))
    if unreadable == len(UPDATE_TASKS):
        findings.append(Finding(
            "updates", "Задачи расписания обновлений", "Недоступны",
            "Не удалось прочитать задачи планировщика (нужны права администратора)", "info"))
    if not any(f.level in ("warning", "bad") for f in findings):
        findings.insert(0, Finding("updates", "Обновления Windows", "В норме",
                                   "Политики, службы и расписание не отключены", "ok"))
    return findings


# ---------- брандмауэр ----------
FW_POLICY = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
FW_RULES = FW_POLICY + r"\FirewallRules"
FW_PROFILES = {"DomainProfile": ("domain", "доменный"), "StandardProfile": ("private", "частный"),
               "PublicProfile": ("public", "общедоступный")}


def parse_rule(text: str) -> dict:
    """Правило брандмауэра из реестра: 'v2.31|Action=Allow|Active=TRUE|Dir=In|App=...|Name=...|'."""
    rule = {}
    for part in text.split("|")[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            rule[key] = value
    return rule


def analyze_rule(rule_id: str, text: str):
    rule = parse_rule(text)
    if rule.get("Active", "").upper() != "TRUE":
        return None
    action, direction = rule.get("Action", ""), rule.get("Dir", "")
    app = os.path.expandvars(rule.get("App", ""))
    name = rule.get("Name", "")
    shown = name if name and not name.startswith("@") else rule_id
    fix = {"op": "reg_delete", "hive": "HKLM", "path": FW_RULES, "name": rule_id}
    if action == "Allow" and direction == "In" and any(m in app.lower() for m in USER_DIR_MARKERS):
        return Finding("firewall", f"Правило: {shown}",
                       "Входящий доступ для программы из временной или пользовательской папки",
                       app, "warning", "Удалить правило", fix)
    if action == "Block" and SECURITY_RE.search(app + " " + name):
        return Finding("firewall", f"Правило: {shown}", "Блокировка программы защиты",
                       app or name, "bad", "Удалить правило", fix)
    return None


def check_firewall() -> list[Finding]:
    findings: list[Finding] = []
    for key, (profile, title) in FW_PROFILES.items():
        exists, enabled, _ = read_value("HKLM", f"{FW_POLICY}\\{key}", "EnableFirewall")
        if exists and enabled == 0:
            findings.append(Finding(
                "firewall", f"Брандмауэр: {title} профиль", "Выключен",
                "Если установлен сторонний брандмауэр, это нормально", "warning",
                "Включить брандмауэр",
                {"op": "firewall_state", "profile": profile, "state": "on", "prev": "off"}))
    rules = list_values("HKLM", FW_RULES)
    flagged = 0
    for rule_id, (text, _) in rules.items():
        if isinstance(text, str) and flagged < 100:
            finding = analyze_rule(rule_id, text)
            if finding:
                findings.append(finding)
                flagged += 1
    if not findings:
        findings.append(Finding("firewall", "Брандмауэр", "В норме",
                                f"Профили включены, подозрительных правил нет (всего правил: {len(rules)})",
                                "ok"))
    return findings


# ---------- BCD ----------
TRUE_WORDS = {"yes", "да", "on", "true", "1"}
FALSE_WORDS = {"no", "нет", "off", "false", "0"}


def parse_bcd(text: str) -> dict:
    """Параметры записи загрузки. Имена параметров bcdedit не переводятся."""
    elements = {}
    for line in text.splitlines():
        match = re.match(r"^([A-Za-z][A-Za-z0-9_]*)\s{2,}(.+?)\s*$", line)
        if match:
            elements[match.group(1).lower()] = match.group(2)
    return elements


def analyze_bcd(elements: dict) -> list[Finding]:
    def truthy(key: str) -> bool:
        return elements.get(key, "").strip().lower() in TRUE_WORDS

    def setter(element: str, value, prev):
        return {"op": "bcd_set", "element": element, "value": value, "prev": prev}

    findings = []
    if truthy("testsigning"):
        findings.append(Finding("bcd", "Тестовый режим подписи драйверов", "testsigning = Да",
                                "Можно загружать неподписанные драйверы", "bad", "Выключить",
                                setter("testsigning", "off", "yes")))
    if truthy("nointegritychecks"):
        findings.append(Finding("bcd", "Отключена проверка целостности", "nointegritychecks = Да",
                                "Загрузчик не проверяет подписи", "bad", "Включить проверку",
                                setter("nointegritychecks", "off", "yes")))
    if elements.get("recoveryenabled", "").strip().lower() in FALSE_WORDS:
        findings.append(Finding("bcd", "Среда восстановления отключена", "recoveryenabled = Нет",
                                "Так часто делают шифровальщики", "warning", "Включить",
                                setter("recoveryenabled", "yes", "no")))
    if "ignoreallfailures" in elements.get("bootstatuspolicy", "").lower():
        findings.append(Finding("bcd", "Ошибки загрузки игнорируются",
                                "bootstatuspolicy = IgnoreAllFailures",
                                "Windows не предлагает восстановление при сбоях загрузки",
                                "warning", "Вернуть стандартное поведение",
                                setter("bootstatuspolicy", "displayallfailures", "ignoreallfailures")))
    if "safeboot" in elements:
        findings.append(Finding("bcd", "Включена загрузка в безопасном режиме",
                                f"safeboot = {elements['safeboot']}",
                                "Система будет загружаться в безопасном режиме", "warning",
                                "Отключить", setter("safeboot", None, elements["safeboot"].lower())))
    if truthy("debug"):
        findings.append(Finding("bcd", "Включена отладка ядра", "debug = Да", "", "warning",
                                "Выключить", setter("debug", "off", "yes")))
    if "disable_integrity_checks" in elements.get("loadoptions", "").lower():
        findings.append(Finding("bcd", "Отключена проверка подписей драйверов",
                                f"loadoptions = {elements['loadoptions']}", "", "bad",
                                "Удалить параметр",
                                setter("loadoptions", None, elements["loadoptions"])))
    return findings


def check_bcd() -> list[Finding]:
    try:
        result = subprocess.run(["bcdedit.exe", "/enum", "{current}"], capture_output=True,
                                timeout=20, creationflags=NO_WINDOW)
    except (OSError, subprocess.SubprocessError) as e:
        return [Finding("bcd", "Записи BCD", "Недоступно", str(e), "info")]
    if result.returncode != 0:
        return [Finding("bcd", "Записи BCD", "Недоступно",
                        "Нужны права администратора (или система загружена без BCD)", "info")]
    findings = analyze_bcd(parse_bcd(rsys.decode_console(result.stdout)))
    return findings or [Finding(
        "bcd", "Записи BCD", "В норме",
        "Тестовый режим драйверов, отключение проверок целостности и среды восстановления "
        "не обнаружены", "ok")]


# ---------- всё вместе ----------
CHECKS = {"hosts": check_hosts, "proxy": check_proxy, "winhttp": check_winhttp,
          "updates": check_updates, "firewall": check_firewall, "bcd": check_bcd}


@dataclass
class CheckResults:
    findings: dict = field(default_factory=dict)  # категория -> список Finding
    hits: list = field(default_factory=list)      # ограничения реестра (PolicyHit)
    policy_error: str = ""


def run_all() -> CheckResults:
    results = CheckResults()
    for category, check in CHECKS.items():
        try:
            results.findings[category] = check()
        except Exception as e:  # сбой одной проверки не отменяет остальные
            results.findings[category] = [
                Finding(category, "Проверка не выполнена", str(e), "", "warning")]
    try:
        results.hits = policies.scan_restrictions()
    except Exception as e:
        results.policy_error = str(e)
    return results
