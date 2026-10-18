import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

import pefile

from scanner.features import entropy

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


def _collect_imports(pe) -> tuple[set[str], int]:
    names: set[str] = set()
    total = 0
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for imp in entry.imports:
            total += 1
            if imp.name:
                n = imp.name.decode("ascii", "ignore").lower()
                names.add(n)
                if n.endswith(("a", "w")):  # CreateProcessA/W -> createprocess
                    names.add(n[:-1])
    return names, total


def _import_findings(names: set[str], total: int) -> list[Finding]:
    if "_corexemain" in names or "_cordllmain" in names:
        return []  # .NET-программы почти ничего не импортируют, это нормально
    if total < 3 or (total < 12 and {"getprocaddress", "loadlibrary"} <= names):
        return [Finding("pack", f"почти нет импортов ({total})", 2)]
    return []


def _entry_findings(pe) -> list[Finding]:
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    if ep == 0:
        return []
    section = pe.get_section_by_rva(ep)
    if section is None:
        return [Finding("pack", "точка входа вне секций файла", 2)]
    if len(pe.sections) >= 3 and section is pe.sections[-1]:
        return [Finding("pack", "точка входа в последней секции", 2)]
    return []


def _section_findings(pe, fh) -> list[Finding]:
    out: list[Finding] = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin-1")
        ch = s.Characteristics
        execu = bool(ch & IMAGE_SCN_MEM_EXECUTE)
        write = bool(ch & IMAGE_SCN_MEM_WRITE)
        raw = s.SizeOfRawData
        virt = s.Misc_VirtualSize

        if name.lower() in PACKER_SECTIONS:
            out.append(Finding("pack", f"секция упаковщика {name}", 3))
        if execu and write:
            out.append(Finding("pack", f"секция {name} исполняемая и записываемая", 2))
        if execu and raw < 512 and virt > 100_000:
            out.append(Finding(
                "pack", f"секция {name}: на диске пусто, в памяти {virt // 1024} КБ "
                        f"(распаковка на лету)", 2))
        if raw >= 1024:
            fh.seek(s.PointerToRawData)
            e = entropy(fh.read(min(raw, ENTROPY_LIMIT)))
            if execu and e > 7.0:
                out.append(Finding(
                    "pack", f"исполняемая секция {name}: энтропия {e:.2f} "
                            f"(сжатый или зашифрованный код)", 3))
            elif not execu and e > 7.6 and raw > 200 * 1024:
                out.append(Finding("pack", f"секция {name}: энтропия {e:.2f}", 1))
    return out


def analyze_pe(path: Path) -> PEReport:
    """Анализ PE-файла. Для остальных файлов возвращает пустой отчёт."""
    try:
        if path.stat().st_size > MAX_PE_SIZE:
            return PEReport()
        with path.open("rb") as fh:
            if fh.read(2) != b"MZ":
                return PEReport()
            pe = pefile.PE(str(path), fast_load=True)
            try:
                pe.parse_data_directories(directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
                names, total = _collect_imports(pe)
                findings = _section_findings(pe, fh)
                if not pe.is_dll():
                    findings += _entry_findings(pe)
                    findings += _import_findings(names, total)
                findings += api_findings(names)
                return PEReport(is_pe=True, findings=findings)
            finally:
                pe.close()
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