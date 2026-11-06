"""Блокировка адресов и программ брандмауэром Windows (с откатом через журнал).

Правила создаются в группе GROUP, у каждого своё имя (Name) вида «myav-<номер>»: по нему
правило удаляется при откате и в списке блокировок. Нужны права администратора.
Значения (адрес, путь программы) передаются в PowerShell через переменные окружения.
"""
import ipaddress
import json
import uuid
from dataclasses import dataclass

from recovery import journal
from recovery.journal import undo_op
from recovery.system import run_powershell

GROUP = "myav"


@dataclass
class Rule:
    name: str          # myav-...
    title: str         # что видит пользователь
    direction: str     # Inbound | Outbound
    target: str        # адрес или путь программы
    enabled: bool


def _check_ip(ip: str) -> str:
    addr = ipaddress.ip_address(ip.strip().strip("[]"))
    if not addr.is_global:
        raise ValueError(f"{addr} — не внешний адрес: блокировать его опасно для работы сети")
    return str(addr)


def _create(title: str, direction: str, env: dict, target_param: str) -> str:
    name = f"{GROUP}-{uuid.uuid4().hex[:12]}"
    script = (f"New-NetFirewallRule -Name $env:MYAV_NAME -DisplayName $env:MYAV_TITLE "
              f"-Group '{GROUP}' -Direction {direction} -Action Block "
              f"-Description 'Создано myav' {target_param} | Out-Null")
    code, _, err = run_powershell(script, {"MYAV_NAME": name, "MYAV_TITLE": title, **env})
    if code != 0:
        if "Access is denied" in err or "Отказано в доступе" in err or "0x80070005" in err:
            raise PermissionError("Нет прав. Запустите программу от имени администратора")
        raise OSError(err.strip().splitlines()[0] if err.strip() else f"код {code}")
    return name


def block_ip(ip: str) -> list[str]:
    """Блокирует входящие и исходящие соединения с адресом. Возвращает имена правил."""
    ip = _check_ip(ip)
    names: list[str] = []
    try:
        for d in ("Outbound", "Inbound"):
            names.append(_create(f"myav: блокировка {ip} ({d})", d, {"MYAV_IP": ip},
                                 "-RemoteAddress $env:MYAV_IP"))
    except OSError:
        if names:  # второе правило не создалось: первое без записи в журнал не оставляем
            _remove(names)
        raise
    journal.log_action(f"Брандмауэр: заблокирован адрес {ip}", "firewall_remove",
                       {"names": names, "target": ip})
    return names


def block_program(exe: str) -> list[str]:
    """Запрещает программе исходящие соединения."""
    if not exe:
        raise ValueError("Путь программы неизвестен")
    names = [_create(f"myav: блокировка программы {exe}", "Outbound", {"MYAV_EXE": exe},
                     "-Program $env:MYAV_EXE")]
    journal.log_action(f"Брандмауэр: программе запрещён выход в сеть: {exe}", "firewall_remove",
                       {"names": names, "target": exe})
    return names


def _remove(names: list[str]) -> None:
    code, _, err = run_powershell(
        "$env:MYAV_NAMES -split ';' | ForEach-Object { "
        "Remove-NetFirewallRule -Name $_ -ErrorAction SilentlyContinue }",
        {"MYAV_NAMES": ";".join(names)})
    if code != 0:
        raise OSError(err.strip() or f"код {code}")


@undo_op("firewall_remove")
def _undo_block(d: dict) -> str:
    _remove(d["names"])
    return f"Блокировка снята: {d['target']}"


def unblock(rule_names: list[str], target: str) -> None:
    """Снимает блокировку из списка (журнал: можно вернуть)."""
    rules = {r.name: r for r in list_rules()}
    saved = [rules[n] for n in rule_names if n in rules]
    _remove(rule_names)
    journal.log_action(f"Брандмауэр: снята блокировка {target}", "firewall_restore",
                       {"rules": [r.__dict__ for r in saved], "target": target})


@undo_op("firewall_restore")
def _undo_unblock(d: dict) -> str:
    for r in d["rules"]:
        param = "-Program $env:MYAV_EXE" if r["target"].lower().endswith(".exe") \
            else "-RemoteAddress $env:MYAV_IP"
        script = (f"New-NetFirewallRule -Name $env:MYAV_NAME -DisplayName $env:MYAV_TITLE "
                  f"-Group '{GROUP}' -Direction {r['direction']} -Action Block {param} | Out-Null")
        code, _, err = run_powershell(script, {
            "MYAV_NAME": r["name"], "MYAV_TITLE": r["title"],
            "MYAV_EXE": r["target"], "MYAV_IP": r["target"]})
        if code != 0:
            raise OSError(err.strip() or f"код {code}")
    return f"Блокировка возвращена: {d['target']}"


def list_rules() -> list[Rule]:
    """Правила программы в брандмауэре (группа myav)."""
    script = (f"$r = Get-NetFirewallRule -Group '{GROUP}' -ErrorAction SilentlyContinue; "
              "$r | ForEach-Object { $a = $_ | Get-NetFirewallAddressFilter; "
              "$p = $_ | Get-NetFirewallApplicationFilter; "
              "[pscustomobject]@{name=$_.Name; title=$_.DisplayName; "
              "direction=[string]$_.Direction; enabled=[string]$_.Enabled; "
              "ip=($a.RemoteAddress -join ','); exe=$p.Program} } | ConvertTo-Json -Compress")
    code, out, err = run_powershell(script, timeout=60)
    if code != 0 or not out.strip():
        return []
    data = json.loads(out)
    if isinstance(data, dict):
        data = [data]
    rules = []
    for item in data:
        exe = item.get("exe") or ""
        target = exe if exe and exe.lower() != "any" else item.get("ip") or ""
        rules.append(Rule(item["name"], item.get("title") or "", item.get("direction") or "",
                          target, f"{item.get('enabled')}".lower() == "true"))
    return rules
