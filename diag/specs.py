"""Характеристики компьютера для журнала и отчёта: процессор, видеокарта, память, накопители,
сетевые адаптеры (без IP и MAC), Windows, экраны, антивирусы и брандмауэр.

Один вызов PowerShell (CIM) → JSON, результат кэшируется в logs/specs.json на сутки: сбор
занимает 1–3 с и при каждом запуске не нужен.
"""
import json
import platform
import subprocess
import time
from pathlib import Path

CACHE = Path("logs") / "specs.json"
MAX_AGE = 86400
CREATE_NO_WINDOW = 0x08000000

SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
function Pick($items, $props) { @($items | ForEach-Object { $o = [ordered]@{}; foreach ($p in $props) { $o[$p] = $_.$p }; $o }) }
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$r = [ordered]@{
  os = [ordered]@{ caption = $os.Caption; version = $os.Version; build = $os.BuildNumber;
                   arch = $os.OSArchitecture; locale = $os.Locale; installed = "$($os.InstallDate)";
                   display_version = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion;
                   ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR }
  computer = [ordered]@{ manufacturer = $cs.Manufacturer; model = $cs.Model; ram_bytes = $cs.TotalPhysicalMemory;
                         hypervisor = $cs.HypervisorPresent }
  cpu = Pick (Get-CimInstance Win32_Processor) @('Name','NumberOfCores','NumberOfLogicalProcessors','MaxClockSpeed','L3CacheSize','VirtualizationFirmwareEnabled')
  gpu = Pick (Get-CimInstance Win32_VideoController) @('Name','DriverVersion','AdapterRAM','CurrentHorizontalResolution','CurrentVerticalResolution','CurrentRefreshRate')
  memory = Pick (Get-CimInstance Win32_PhysicalMemory) @('Capacity','Speed','ConfiguredClockSpeed','Manufacturer','PartNumber')
  disks = Pick (Get-PhysicalDisk) @('FriendlyName','MediaType','BusType','Size','HealthStatus')
  volumes = Pick (Get-Volume | Where-Object DriveLetter) @('DriveLetter','FileSystem','Size','SizeRemaining','DriveType')
  network = Pick (Get-NetAdapter) @('InterfaceDescription','Status','LinkSpeed','MediaType','Virtual')
  antivirus = Pick (Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct) @('displayName','productState')
  firewall = Pick (Get-NetFirewallProfile) @('Name','Enabled','DefaultOutboundAction')
  secure_boot = (Confirm-SecureBootUEFI)
  bios = (Get-CimInstance Win32_BIOS).SMBIOSBIOSVersion
  power = Pick (Get-CimInstance Win32_Battery) @('Name','EstimatedChargeRemaining')
}
$r | ConvertTo-Json -Depth 4 -Compress
"""


def collect(timeout: int = 40) -> dict:
    """Свежий сбор (без кэша). При ошибке — то, что знает Python."""
    data: dict = {}
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", SCRIPT],
                           capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout, creationflags=CREATE_NO_WINDOW)
        data = json.loads(r.stdout.strip() or "{}")
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    data["python"] = platform.python_version()
    try:
        from PySide6 import __version__ as qt
        data["pyside6"] = qt
    except ImportError:
        pass
    try:
        from scanner import cpucores
        data["cpu_cores"] = cpucores.describe()
    except Exception:
        pass
    data["collected"] = time.time()
    return data


def cached() -> dict | None:
    """Последний сбор без нового (отчёт строится в главном потоке)."""
    try:
        return json.loads(CACHE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def get(max_age: int = MAX_AGE) -> dict:
    try:
        cached = json.loads(CACHE.read_text(encoding="utf-8"))
        if time.time() - cached.get("collected", 0) < max_age:
            return cached
    except (OSError, ValueError):
        pass
    data = collect()
    try:
        CACHE.parent.mkdir(exist_ok=True)
        CACHE.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass
    return data


def _gb(value) -> str:
    try:
        return f"{int(value) / 2 ** 30:.1f} ГБ"
    except (TypeError, ValueError):
        return "?"


def _list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def describe(data: dict | None = None) -> list[str]:
    """Характеристики строками — для журнала и отчёта."""
    d = data if data is not None else get()
    o = d.get("os") or {}
    c = d.get("computer") or {}
    lines = [f"Windows: {o.get('caption', platform.platform())} {o.get('display_version') or ''} "
             f"(сборка {o.get('build', '?')}.{o.get('ubr', '?')}, {o.get('arch', '?')}, "
             f"язык {o.get('locale', '?')})",
             f"Компьютер: {c.get('manufacturer', '?')} {c.get('model', '?')}, ОЗУ "
             f"{_gb(c.get('ram_bytes'))}, гипервизор: {c.get('hypervisor')}, "
             f"Secure Boot: {d.get('secure_boot')}, BIOS {d.get('bios', '?')}"]
    for p in _list(d.get("cpu")):
        lines.append(f"Процессор: {(p.get('Name') or '').strip()} — ядер {p.get('NumberOfCores')}, "
                     f"потоков {p.get('NumberOfLogicalProcessors')}, {p.get('MaxClockSpeed')} МГц, "
                     f"L3 {p.get('L3CacheSize')} КБ, виртуализация {p.get('VirtualizationFirmwareEnabled')}")
    if d.get("cpu_cores"):
        lines.append(f"Ядра P/E: {d['cpu_cores']}")
    for g in _list(d.get("gpu")):
        lines.append(f"Видеокарта: {g.get('Name')} (драйвер {g.get('DriverVersion')}, "
                     f"{g.get('CurrentHorizontalResolution')}×{g.get('CurrentVerticalResolution')} "
                     f"{g.get('CurrentRefreshRate')} Гц)")
    mem = _list(d.get("memory"))
    if mem:
        lines.append("Память: " + ", ".join(
            f"{_gb(m.get('Capacity'))} {m.get('ConfiguredClockSpeed') or m.get('Speed')} МГц "
            f"{(m.get('PartNumber') or '').strip()}" for m in mem))
    for k in _list(d.get("disks")):
        lines.append(f"Накопитель: {k.get('FriendlyName')} — {k.get('MediaType')}, "
                     f"{k.get('BusType')}, {_gb(k.get('Size'))}, {k.get('HealthStatus')}")
    for v in _list(d.get("volumes")):
        lines.append(f"Том {v.get('DriveLetter')}: {v.get('FileSystem')}, {_gb(v.get('Size'))}, "
                     f"свободно {_gb(v.get('SizeRemaining'))} ({v.get('DriveType')})")
    for n in _list(d.get("network")):
        lines.append(f"Сеть: {n.get('InterfaceDescription')} — {n.get('Status')}, "
                     f"{n.get('LinkSpeed')}{', виртуальный' if n.get('Virtual') else ''}")
    av = [a.get("displayName") for a in _list(d.get("antivirus"))]
    lines.append("Антивирусы (Центр безопасности): " + (", ".join(av) if av else "нет данных"))
    fw = ", ".join(f"{f.get('Name')}={'вкл' if f.get('Enabled') else 'выкл'}"
                   for f in _list(d.get("firewall")))
    lines.append("Брандмауэр: " + (fw or "нет данных"))
    if _list(d.get("power")):
        lines.append("Батарея: есть (ноутбук)")
    lines.append(f"Python {d.get('python', platform.python_version())}, "
                 f"PySide6 {d.get('pyside6', '?')}")
    return lines


def screens() -> list[str]:
    """Экраны и масштаб — только из Qt (нужен QApplication)."""
    try:
        from PySide6.QtGui import QGuiApplication
        return [f"Экран: {s.size().width()}×{s.size().height()} логич., масштаб "
                f"{s.devicePixelRatio():.2f}, {s.refreshRate():.0f} Гц"
                for s in QGuiApplication.screens()]
    except Exception:
        return []


def is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False

