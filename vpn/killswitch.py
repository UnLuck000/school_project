"""Kill switch: пока VPN подключён, в интернет можно только через туннель.

Брандмауэр Windows: исходящие соединения по умолчанию запрещены (DefaultOutboundAction
Block во всех профилях), разрешены — интерфейс туннеля, наши xray.exe и sing-box.exe
(соединение с сервером и прямые соединения в локальную сеть), DHCP (иначе компьютер
потеряет адрес в сети) и локальная сеть LAN (принтеры, роутер; DNS к роутеру не утекает —
на время VPN он подменён, vpn/dnsguard.py). Правила — в группе GROUP. Значения передаются в PowerShell через
переменные окружения.

Включение пишется в журнал действий с откатом и копией прежних значений в настройку
vpn/killswitch_backup. Обычное отключение VPN снимает блокировку сразу; если VPN оборвался
сам, блокировка остаётся (в этом и смысл), снять её — кнопкой в окне VPN, откатом в журнале
или при следующем запуске программы (recover).
"""
import json
import os
import subprocess

from recovery import journal
import syscmd

GROUP = "SBIT-killswitch"
LEGACY_GROUP = "myav-killswitch"  # правила прежних версий — снимаются вместе с нашими
LAN = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4",
       "255.255.255.255"]
CREATE_NO_WINDOW = 0x08000000


def _powershell(script: str, env: dict | None = None) -> subprocess.CompletedProcess:
    script = "[Console]::OutputEncoding = [Text.Encoding]::UTF8; $ErrorActionPreference = " \
             "'Stop'; " + script
    return subprocess.run(syscmd.PS_ARGS + [script],
                          capture_output=True, text=True, encoding="utf-8", errors="replace",
                          env={**os.environ, **(env or {})}, creationflags=CREATE_NO_WINDOW)


def _error(result: subprocess.CompletedProcess) -> str:
    return (result.stderr or result.stdout).strip().splitlines()[-1:][0] if \
        (result.stderr or result.stdout).strip() else f"код {result.returncode}"


def profiles() -> dict[str, dict]:
    """{профиль: {"enabled": bool, "outbound": "Allow" | "Block" | "NotConfigured"}}."""
    result = _powershell("Get-NetFirewallProfile | ForEach-Object { '{0}|{1}|{2}' -f "
                         "$_.Name, $_.Enabled, $_.DefaultOutboundAction }")
    if result.returncode:
        raise OSError(f"брандмауэр недоступен: {_error(result)}")
    data = {}
    for line in result.stdout.splitlines():
        parts = line.strip().split("|")
        if len(parts) == 3:
            data[parts[0]] = {"enabled": parts[1] == "True", "outbound": parts[2]}
    return data


def active() -> bool:
    try:
        from ui import settings as cfg
        return bool(cfg.get("vpn/killswitch_backup"))
    except Exception:
        return False


def enable(tun_alias: str, programs: list[str]) -> None:
    """Перекрыть интернет мимо туннеля. Нужны права администратора."""
    old = profiles()
    off = [name for name, p in old.items() if not p["enabled"]]
    if off:
        raise OSError("брандмауэр Windows выключен для профилей " + ", ".join(off) +
                      ": kill switch не сработает")
    env = {"KS_GROUP": GROUP, "KS_TUN": tun_alias, "KS_LAN": ",".join(LAN),
           "KS_PROGRAMS": "\n".join(p for p in programs if p)}
    script = (
        "Remove-NetFirewallRule -Group $env:KS_GROUP -EA SilentlyContinue; "
        "New-NetFirewallRule -Group $env:KS_GROUP -DisplayName 'SBIT kill switch: туннель' "
        "-Direction Outbound -Action Allow -InterfaceAlias $env:KS_TUN | Out-Null; "
        "foreach ($p in ($env:KS_PROGRAMS -split \"`n\")) { if ($p) { "
        "New-NetFirewallRule -Group $env:KS_GROUP -DisplayName ('SBIT kill switch: ' + "
        "(Split-Path $p -Leaf)) -Direction Outbound -Action Allow -Program $p | Out-Null } }; "
        "New-NetFirewallRule -Group $env:KS_GROUP -DisplayName 'SBIT kill switch: DHCP' "
        "-Direction Outbound -Action Allow -Protocol UDP -LocalPort 68 -RemotePort 67 "
        "| Out-Null; "
        "New-NetFirewallRule -Group $env:KS_GROUP -DisplayName 'SBIT kill switch: локальная "
        "сеть' -Direction Outbound -Action Allow -RemoteAddress ($env:KS_LAN -split ',') "
        "| Out-Null; "
        "Set-NetFirewallProfile -All -DefaultOutboundAction Block")
    result = _powershell(script, env)
    if result.returncode:
        _restore({name: p["outbound"] for name, p in old.items()})
        raise OSError(f"kill switch не включён: {_error(result)}")
    backup = {name: p["outbound"] for name, p in old.items()}
    _save_backup(backup)
    journal.log_action("VPN: kill switch — интернет только через туннель", "vpn_killswitch_off",
                       {"outbound": backup})


def disable() -> bool:
    """Снять блокировку (вернуть прежние значения). False — блокировки не было."""
    backup = _load_backup()
    if backup is None:
        return False
    _restore(backup)
    _save_backup(None)
    journal.forget("vpn_killswitch_off")  # снята обычным путём: в журнале отменять нечего
    return True


def _restore(outbound: dict[str, str]) -> None:
    env = {"KS_GROUP": GROUP, "KS_LEGACY": LEGACY_GROUP, "KS_OLD": json.dumps(outbound)}
    _powershell(
        "$old = $env:KS_OLD | ConvertFrom-Json; "
        "foreach ($p in $old.PSObject.Properties) { "
        "Set-NetFirewallProfile -Name $p.Name -DefaultOutboundAction $p.Value }; "
        "Remove-NetFirewallRule -Group $env:KS_GROUP -EA SilentlyContinue; "
        "Remove-NetFirewallRule -Group $env:KS_LEGACY -EA SilentlyContinue", env)


@journal.active_check("vpn_killswitch_off")
def _active(d: dict) -> bool:
    return _load_backup() is not None  # копии нет — блокировку уже сняли


@journal.undo_op("vpn_killswitch_off")
def _undo(d: dict) -> str:
    _restore(d["outbound"])
    _save_backup(None)
    return "Kill switch снят: брандмауэр вернулся к прежним настройкам"


def _save_backup(value: dict | None) -> None:
    from ui import settings as cfg
    cfg.set_("vpn/killswitch_backup", json.dumps(value) if value is not None else "")


def _load_backup() -> dict | None:
    try:
        from ui import settings as cfg
        raw = cfg.get("vpn/killswitch_backup")
        return json.loads(raw) if raw else None
    except Exception:
        return None


def recover() -> bool:
    """Запуск программы: блокировка осталась после обрыва VPN или сбоя — снять."""
    return disable()
