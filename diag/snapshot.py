"""Снимок при запуске: настройки, отличные от стандартных, базы, версии ядер VPN и чужие
программы, которые могут мешать (zapret, другие VPN и антивирусы)."""
import os
import subprocess
import time
from pathlib import Path

CREATE_NO_WINDOW = 0x08000000
# имя процесса (нижний регистр) → что это и чем может мешать
INTERFERING = {
    "winws.exe": "zapret (WinDivert): с kill switch VPN соединения на 80/443 не проходят",
    "goodbyedpi.exe": "GoodbyeDPI (WinDivert): мешает kill switch VPN",
    "throne.exe": "Throne (VPN-клиент): занятые порты, второй TUN",
    "thronecore.exe": "ядро Throne",
    "happ.exe": "Happ (VPN-клиент)",
    "v2rayn.exe": "v2rayN (VPN-клиент)",
    "nekoray.exe": "NekoRay (VPN-клиент)",
    "hiddify.exe": "Hiddify (VPN-клиент)",
    "clash-verge.exe": "Clash Verge (VPN-клиент)",
    "wireguard.exe": "WireGuard",
    "openvpn.exe": "OpenVPN",
    "outline.exe": "Outline (VPN-клиент)",
    "msmpeng.exe": "Microsoft Defender",
    "avp.exe": "Kaspersky",
    "ekrn.exe": "ESET",
    "avastsvc.exe": "Avast",
    "avgsvc.exe": "AVG",
    "mbamservice.exe": "Malwarebytes",
    "dwservice.exe": "Dr.Web",
    "360tray.exe": "360 Total Security",
    "bdagent.exe": "Bitdefender",
}


def settings_diff() -> list[str]:
    from ui import settings as cfg
    out = []
    for key, default in cfg.DEFAULTS.items():
        try:
            value = cfg.get(key)
        except Exception:
            continue
        if value != default:
            text = str(value).replace("\n", " | ")
            out.append(f"{key} = {text[:200]}{'…' if len(text) > 200 else ''}")
    return out


def bases() -> list[str]:
    from ui import settings as cfg
    sig = Path("signatures")
    out = []
    try:
        last = float(cfg.get("db/last_update") or 0)
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(last)) if last else "не было"
        out.append("Обновление баз: " + when)
    except (TypeError, ValueError):
        pass
    for folder in ("feeds", "netfeeds"):
        files = [p for p in (sig / folder).glob("*") if p.is_file()]
        size = sum(p.stat().st_size for p in files) / 2 ** 20
        out.append(f"signatures/{folder}: файлов {len(files)}, {size:.1f} МБ")
    rules = list((sig / "rules").rglob("*.yar")) + list((sig / "rules").rglob("*.yara"))
    out.append(f"Правила YARA: файлов {len(rules)}")
    return out


def _version(exe: str) -> str:
    if not exe:
        return "не найден"
    try:
        r = subprocess.run([exe, "version"], capture_output=True, text=True, timeout=10,
                           encoding="utf-8", errors="replace", creationflags=CREATE_NO_WINDOW)
        return (r.stdout.strip().splitlines() or ["?"])[0][:80]
    except (OSError, subprocess.SubprocessError):
        return "не запускается"


def cores() -> list[str]:
    try:
        from vpn import singbox, xray
        return [f"Xray: {_version(xray.find_xray())}",
                f"sing-box: {_version(singbox.find_singbox())}"]
    except Exception as e:
        return [f"Ядра VPN: ошибка {e}"]


def interfering() -> list[str]:
    try:
        from processmanager import ntsnap
        names = {p.name.lower() for p in ntsnap.list_processes()}
    except Exception:
        return []
    found = [f"{name}: {why}" for name, why in INTERFERING.items() if name in names]
    return found or ["мешающих программ не найдено"]


def lines() -> list[str]:
    out = ["Настройки, отличные от стандартных:"]
    out += ["  " + s for s in settings_diff()] or ["  нет"]
    out += bases() + cores()
    out += ["Запущены: " + s for s in interfering()]
    out.append(f"Папка программы: {os.getcwd()}")
    return out
