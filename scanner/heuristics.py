import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

import pefile

from scanner.features import _native, entropy

HEURISTIC_THRESHOLD = 7        # с какой суммы баллов файл считается подозрительным
PACK_CAP = 4                   # потолок баллов за «упаковку»
MAX_PE_SIZE = 64 * 1024 * 1024
ENTROPY_LIMIT = 4 * 1024 * 1024  # сколько байт секции берём для энтропии

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000

PACKER_SECTIONS = {
    "upx0", "upx1", "upx2", ".aspack", ".adata", ".themida", ".vmp0", ".vmp1",
    ".vmp2", ".enigma1", ".enigma2", ".petite", ".nsp0", ".nsp1", ".mpress1",
    ".mpress2", ".packed", ".perplex",
}

# (описание, [наборы «любая из функций»; нужно по одной из каждого набора], баллы)
API_GROUPS = [
    ("внедрение кода в чужой процесс",
     [{"virtualallocex", "ntallocatevirtualmemory"},
      {"writeprocessmemory", "ntwritevirtualmemory"},
      {"createremotethread", "ntcreatethreadex", "queueuserapc",
       "rtlcreateuserthread", "setthreadcontext"}], 4),
    ("подмена кода процесса (process hollowing)",
     [{"ntunmapviewofsection", "zwunmapviewofsection"},
      {"writeprocessmemory", "ntwritevirtualmemory"},
      {"setthreadcontext", "resumethread"}], 4),
    ("перехват клавиатуры",
     [{"setwindowshookex"},
      {"getasynckeystate", "getkeystate", "getkeyboardstate"}], 2),
    ("загрузка из сети и запуск",
     [{"urldownloadtofile", "internetreadfile", "winhttpreaddata"},
      {"shellexecute", "shellexecuteex", "winexec", "createprocess"}], 2),
]

_threshold = HEURISTIC_THRESHOLD


def set_threshold(value: int) -> None:
    global _threshold
    _threshold = int(value)


def get_threshold() -> int:
    return _threshold


class Finding(NamedTuple):
    category: str   # "pack" | "api"
    text: str
    points: int


def combine(findings: list[Finding]) -> int:
    pack = sum(f.points for f in findings if f.category == "pack")
    api = sum(f.points for f in findings if f.category == "api")
    return min(pack, PACK_CAP) + api


@dataclass
class PEReport:
    is_pe: bool = False
    findings: list[Finding] = field(default_factory=list)
    dotnet: bool = False

    @property
    def score(self) -> int:
        return combine(self.findings)

    def summary(self, limit: int = 4) -> str:
        top = sorted(self.findings, key=lambda f: -f.points)[:limit]
        return f"{self.score} баллов: " + "; ".join(f.text for f in top)


def api_findings(names: set[str]) -> list[Finding]:
    return [Finding("api", label, points)
            for label, needs, points in API_GROUPS
            if all(names & options for options in needs)]


# ---------- сведения о PE ----------
# Оба способа дают одинаковый словарь: dll, entry, entry_section (-1 — вне секций),
# sections [(имя bytes, флаги, размер на диске, размер в памяти, энтропия или -1)],
# imports (имена функций в нижнем регистре), total_imports (вместе с импортом по номеру).
# Основной — нативный модуль (C++, native/src/pe.cpp): в 5-10 раз быстрее и не держит GIL;
# запасной — pefile, если модуль не собран.
def _native_info(path: Path) -> dict | None:
    return _native.pe_info(str(path), ENTROPY_LIMIT, MAX_PE_SIZE)


def _pefile_info(path: Path) -> dict | None:
    if path.stat().st_size > MAX_PE_SIZE:
        return None
    with path.open("rb") as fh:
        if fh.read(2) != b"MZ":
            return None
        pe = pefile.PE(str(path), fast_load=True)
        try:
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            imports, total = [], 0
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                for imp in entry.imports:
                    total += 1
                    if imp.name:
                        imports.append(imp.name.decode("ascii", "ignore").lower())
            sections = []
            for s in pe.sections:
                value = -1.0
                if s.SizeOfRawData >= 1024:
                    fh.seek(s.PointerToRawData)
                    value = entropy(fh.read(min(s.SizeOfRawData, ENTROPY_LIMIT)))
                sections.append((s.Name.rstrip(b"\x00"), s.Characteristics, s.SizeOfRawData,
                                 s.Misc_VirtualSize, value))
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            section = pe.get_section_by_rva(ep)
            return {"dll": pe.is_dll(), "entry": ep,
                    "entry_section": -1 if section is None else pe.sections.index(section),
                    "sections": sections, "imports": imports, "total_imports": total}
        finally:
            pe.close()


def pe_info(path: Path) -> dict | None:
    """Сведения о PE-файле для эвристики. None — не PE (или слишком большой, битый)."""
    if _native is not None and hasattr(_native, "pe_info"):
        return _native_info(path)
    return _pefile_info(path)


def pe_backend() -> str:
    return "C++" if _native is not None and hasattr(_native, "pe_info") else "pefile"


# ---------- признаки ----------
def _import_names(imports: list[str]) -> set[str]:
    names: set[str] = set()
    for n in imports:
        names.add(n)
        if n.endswith(("a", "w")):  # CreateProcessA/W -> createprocess
            names.add(n[:-1])
    return names


def _import_findings(names: set[str], total: int) -> list[Finding]:
    if "_corexemain" in names or "_cordllmain" in names:
        return []  # .NET-программы почти ничего не импортируют, это нормально
    if total < 3 or (total < 12 and {"getprocaddress", "loadlibrary"} <= names):
        return [Finding("pack", f"почти нет импортов ({total})", 2)]
    return []


def _entry_findings(info: dict) -> list[Finding]:
    if info["entry"] == 0:
        return []
    index, count = info["entry_section"], len(info["sections"])
    if index < 0:
        return [Finding("pack", "точка входа вне секций файла", 2)]
    if count >= 3 and index == count - 1:
        return [Finding("pack", "точка входа в последней секции", 2)]
    return []


def _section_findings(sections) -> list[Finding]:
    out: list[Finding] = []
    for raw_name, ch, raw, virt, e in sections:
        name = raw_name.rstrip(b"\x00").decode("latin-1")
        execu = bool(ch & IMAGE_SCN_MEM_EXECUTE)
        write = bool(ch & IMAGE_SCN_MEM_WRITE)

        if name.lower() in PACKER_SECTIONS:
            out.append(Finding("pack", f"секция упаковщика {name}", 3))
        if execu and write:
            out.append(Finding("pack", f"секция {name} исполняемая и записываемая", 2))
        if execu and raw < 512 and virt > 100_000:
            out.append(Finding(
                "pack", f"секция {name}: на диске пусто, в памяти {virt // 1024} КБ "
                        f"(распаковка на лету)", 2))
        if raw >= 1024 and e >= 0:
            if execu and e > 7.0:
                out.append(Finding(
                    "pack", f"исполняемая секция {name}: энтропия {e:.2f} "
                            f"(сжатый или зашифрованный код)", 3))
            elif not execu and e > 7.6 and raw > 200 * 1024:
                out.append(Finding("pack", f"секция {name}: энтропия {e:.2f}", 1))
    return out


def report_from_info(info: dict | None) -> PEReport:
    if info is None:
        return PEReport()
    names = _import_names(info["imports"])
    findings = _section_findings(info["sections"])
    if not info["dll"]:
        findings += _entry_findings(info)
        findings += _import_findings(names, info["total_imports"])
    findings += api_findings(names)
    dotnet = "_corexemain" in names or "_cordllmain" in names
    return PEReport(is_pe=True, findings=findings, dotnet=dotnet)


def analyze_pe(path: Path) -> PEReport:
    """Анализ PE-файла. Для остальных файлов возвращает пустой отчёт."""
    try:
        return report_from_info(pe_info(path))
    except Exception:  # битый или необычный файл не должен ронять сканирование
        return PEReport()


if __name__ == "__main__":
    # python -m scanner.heuristics путь1 путь2 ...
    for arg in sys.argv[1:]:
        report = analyze_pe(Path(arg))
        print(f"\n{arg}\n  PE: {report.is_pe}, баллы: {report.score} "
              f"(порог {HEURISTIC_THRESHOLD})")
        for f in report.findings:
            print(f"  [{f.category}] +{f.points}  {f.text}")