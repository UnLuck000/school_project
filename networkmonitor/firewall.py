"""Блокировка адресов и программ брандмауэром Windows (с откатом через журнал).

Правила создаются в группе GROUP, у каждого своё имя (Name) вида «myav-<номер>»: по нему
правило удаляется при откате и в списке блокировок. Нужны права администратора.
Значения (адрес, путь программы) передаются в PowerShell через переменные окружения.
"""
import ipaddress
import json
import os
import uuid
from dataclasses import dataclass

from recovery import journal
from recovery.journal import active_check, undo_op
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


RULES_KEY = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"


def rules_present(names: list[str]) -> list[bool]:
    """Есть ли правила с такими именами (быстро: по реестру, без PowerShell)."""
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, RULES_KEY) as key:
            found = []
            for name in names:
                try:
                    winreg.QueryValueEx(key, name)
                    found.append(True)
                except OSError:
                    found.append(False)
            return found
    except OSError:
        return [True] * len(names)  # не прочитали — считаем, что есть


@active_check("firewall_remove")
def _block_active(d: dict) -> bool:
    return any(rules_present(d["names"]))


@active_check("firewall_restore")
def _unblock_active(d: dict) -> bool:
    return not any(rules_present([r["name"] for r in d["rules"]]))


@undo_op("firewall_remove")
def _undo_block(d: dict) -> str:
    _remove(d["names"])
    return f"Блокировка снята: {d['target']}"


def unblock(rule_names: list[str], target: str) -> None:
    """Снимает блокировку из списка (журнал: можно вернуть)."""
    rules = {r.name: r for r in list_rules()}
    saved = [rules[n] for n in rule_names if n in rules]
    _remove(rule_names)
    # блокировка из журнала снята здесь — её запись убирается, второй не появляется
    if journal.forget("firewall_remove", lambda d: set(d["names"]) & set(rule_names)):
        return
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


@dataclass
class SystemRule:
    """Правило брандмауэра Windows (встроенное или другой программы) — только для просмотра."""
    name: str
    title: str
    direction: str     # Входящее | Исходящее
    action: str        # Разрешить | Блокировать
    target: str        # программа, служба, адреса, порты
    enabled: bool
    group: str
    own: bool          # создано этой программой (группа myav)


_indirect: dict[str, str] = {}


def _resolve(text: str) -> str:
    """«@FirewallAPI.dll,-28502» → текст из ресурсов (SHLoadIndirectString)."""
    if not text.startswith("@"):
        return text
    if text not in _indirect:
        import ctypes
        buf = ctypes.create_unicode_buffer(1024)
        ok = ctypes.windll.shlwapi.SHLoadIndirectString(text, buf, 1024, None) == 0
        _indirect[text] = buf.value if ok and buf.value else text
    return _indirect[text]


def parse_rule_string(raw: str) -> dict[str, list[str]]:
    """«v2.33|Action=Block|Dir=Out|App=...|» → {поле: [значения]} (поля повторяются)."""
    fields: dict[str, list[str]] = {}
    for part in raw.split("|")[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            fields.setdefault(key, []).append(value)
    return fields


def list_system_rules() -> list[SystemRule]:
    """Все правила брандмауэра Windows (встроенные, других программ и свои) — из реестра,
    за доли секунды: Get-NetFirewallRule с фильтрами адресов на тысячах правил идёт минутами."""
    import winreg
    rules = []
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, RULES_KEY)
    except OSError:
        return rules
    with key:
        i = 0
        while True:
            try:
                rule_id, raw, _ = winreg.EnumValue(key, i)
            except OSError:
                break
            i += 1
            if not isinstance(raw, str):
                continue
            f = parse_rule_string(raw)
            first = lambda k: (f.get(k) or [""])[0]  # noqa: E731
            parts = []
            if first("App"):
                parts.append(os.path.expandvars(first("App")))
            if first("Svc"):
                parts.append("служба " + first("Svc"))
            addresses = f.get("RA4", []) + f.get("RA6", [])
            if addresses:
                parts.append("адреса " + ", ".join(addresses[:4]) +
                             ("…" if len(addresses) > 4 else ""))
            ports = f.get("RPort", []) + f.get("LPort", [])
            if ports:
                parts.append("порты " + ", ".join(ports[:4]))
            group = _resolve(first("EmbedCtxt"))
            rules.append(SystemRule(
                rule_id, _resolve(first("Name")) or rule_id,
                "Исходящее" if first("Dir") == "Out" else "Входящее",
                "Блокировать" if first("Action") == "Block" else "Разрешить",
                "; ".join(parts) or "все", first("Active").upper() == "TRUE",
                group, rule_id.startswith("myav-") or group == GROUP))
    return rules


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
