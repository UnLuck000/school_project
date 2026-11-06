import ipaddress
from dataclasses import dataclass

import psutil

LOLBINS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
}
USER_DIR_MARKERS = ("\\appdata\\local\\temp\\", "\\downloads\\", "\\users\\public\\")
PROTECTED = {"system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
             "winlogon.exe", "services.exe", "lsass.exe"}

LEVEL_TEXT = {"critical": "Критично", "warning": "Подозрительно"}


@dataclass(frozen=True)
class Conn:
    pid: int
    name: str
    exe: str
    create_time: float
    rip: str
    rport: int
    inbound: bool
    lport: int = 0


@dataclass(frozen=True)
class Alert:
    time: str
    level: str          # critical | warning
    rule: str           # IOC | LOLBIN | USERDIR
    pid: int
    name: str
    exe: str
    create_time: float
    remote: str
    detail: str


def _normalize(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    mapped = getattr(addr, "ipv4_mapped", None)  # ::ffff:1.2.3.4 -> 1.2.3.4
    return str(mapped or addr)


def is_external(ip: str) -> bool:
    try:
        return ipaddress.ip_address(_normalize(ip)).is_global
    except ValueError:
        return False


def _proc_info(pid: int) -> tuple[str, str, float]:
    try:
        p = psutil.Process(pid)
        name = p.name()
        create_time = p.create_time()
    except psutil.Error:
        return "?", "", 0.0
    try:
        exe = p.exe()
    except psutil.Error:  # нет прав на чужие процессы
        exe = ""
    return name, exe, create_time


def snapshot() -> list[Conn]:
    """Текущие установленные соединения во внешнюю сеть (TCP)."""
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.Error:
        return []

    listening: dict[int, set[int]] = {}
    for c in conns:
        if c.status == psutil.CONN_LISTEN and c.pid:
            listening.setdefault(c.pid, set()).add(c.laddr.port)

    cache: dict[int, tuple[str, str, float]] = {}
    result: list[Conn] = []
    for c in conns:
        if c.status != psutil.CONN_ESTABLISHED or not c.raddr or not c.pid:
            continue
        if not is_external(c.raddr.ip):
            continue
        if c.pid not in cache:
            cache[c.pid] = _proc_info(c.pid)
        name, exe, created = cache[c.pid]
        result.append(Conn(
            pid=c.pid, name=name, exe=exe, create_time=created,
            rip=_normalize(c.raddr.ip), rport=c.raddr.port,
            inbound=c.laddr.port in listening.get(c.pid, ()),
            lport=c.laddr.port,
        ))
    return result


def analyze(c: Conn, blocklist: set[str]) -> list[tuple[str, str, str]]:
    """Возвращает список (уровень, правило, описание)."""
    direction = "входящее" if c.inbound else "исходящее"
    findings = []
    if c.rip in blocklist:
        findings.append(("critical", "IOC", "адрес есть в списке C2-серверов"))
    if c.name.lower() in LOLBINS:
        findings.append(("warning", "LOLBIN",
                         f"{c.name}: {direction} соединение во внешнюю сеть"))
    exe_l = c.exe.lower().replace("/", "\\")
    if any(m in exe_l for m in USER_DIR_MARKERS):
        findings.append(("warning", "USERDIR",
                         f"программа запущена из временной или пользовательской "
                         f"папки ({direction} соединение)"))
    return findings


def terminate_process(alert: Alert) -> str:
    """Завершает процесс из оповещения. Возвращает сообщение для пользователя."""
    try:
        p = psutil.Process(alert.pid)
        if abs(p.create_time() - alert.create_time) > 1:
            return "Этот PID уже занят другой программой, ничего не завершено"
        if alert.pid in (0, 4) or p.name().lower() in PROTECTED:
            return "Системный процесс, завершение запрещено"
        p.terminate()
        p.wait(3)
        return f"Процесс {alert.name} (PID {alert.pid}) завершён"
    except psutil.NoSuchProcess:
        return "Процесс уже завершён"
    except psutil.AccessDenied:
        return "Нет прав. Запустите программу от имени администратора"
    except psutil.TimeoutExpired:
        return "Процесс не завершился за 3 секунды"