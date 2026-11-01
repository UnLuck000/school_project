"""Дизассемблер и постраничный hex-просмотр для вкладки «Код»."""
import mmap
import sys
from dataclasses import dataclass, field
from pathlib import Path

from analyzer.code import hexdump

HEX_PAGE = 64 * 1024           # байт на страницу hex-просмотра
DISASM_SIZES = [4 * 1024, 16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024]
MAX_DISASM_LINES = 60000


def capstone_status() -> tuple[object | None, str]:
    """(модуль capstone или None, текст ошибки с путём интерпретатора)."""
    try:
        import capstone
        return capstone, ""
    except Exception as e:  # не только ImportError: бывает сбой загрузки DLL
        return None, (f"Не удалось загрузить capstone: {type(e).__name__}: {e}\n"
                      f"Интерпретатор: {sys.executable}\n"
                      f"Установить в этот интерпретатор: \"{sys.executable}\" -m pip install capstone")


@dataclass
class Region:
    title: str
    rva: int          # относительный адрес начала
    offset: int       # смещение в файле
    size: int         # сколько байт есть в файле
    executable: bool


@dataclass
class PEMap:
    machine: int
    image_base: int
    entry: int
    regions: list[Region] = field(default_factory=list)
    imports: dict[int, str] = field(default_factory=dict)  # адрес ячейки IAT -> dll!функция
    exports: dict[int, str] = field(default_factory=dict)  # RVA -> имя


def load_pe_map(path: Path) -> PEMap | None:
    import pefile
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except Exception:
        return None
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        opt = pe.OPTIONAL_HEADER
        result = PEMap(pe.FILE_HEADER.Machine, opt.ImageBase, opt.AddressOfEntryPoint)
        entry_region = None
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode("latin-1") or "?"
            executable = bool(s.Characteristics & 0x20000000)
            region = Region(f"Секция {name}" + (" (код)" if executable else ""),
                            s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData, executable)
            result.regions.append(region)
            if s.VirtualAddress <= opt.AddressOfEntryPoint < s.VirtualAddress + max(
                    s.Misc_VirtualSize, s.SizeOfRawData):
                delta = opt.AddressOfEntryPoint - s.VirtualAddress
                entry_region = Region("Точка входа", opt.AddressOfEntryPoint,
                                      s.PointerToRawData + delta,
                                      max(0, s.SizeOfRawData - delta), True)
        if entry_region is not None:
            result.regions.insert(0, entry_region)
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = entry.dll.decode("ascii", "ignore")
            for imp in entry.imports:
                name = imp.name.decode("ascii", "ignore") if imp.name else f"#{imp.ordinal}"
                result.imports[imp.address] = f"{dll}!{name}"
        exports = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if exports is not None:
            for sym in exports.symbols:
                if sym.name:
                    result.exports[sym.address] = sym.name.decode("ascii", "ignore")
        return result
    except Exception:
        return None
    finally:
        pe.close()


def _read(path: Path, offset: int, size: int) -> bytes:
    with path.open("rb") as f:
        f.seek(offset)
        return f.read(size)


def disassemble(path: Path, pe_map: PEMap, region: Region, size: int,
                cancel=None) -> tuple[str, str]:
    """(текст листинга, пояснение). Вызывать не из GUI-потока."""
    capstone, error = capstone_status()
    data = _read(path, region.offset, min(size, region.size))
    base = pe_map.image_base + region.rva
    if capstone is None:
        return hexdump(data, base), error
    modes = {0x8664: capstone.CS_MODE_64, 0x14C: capstone.CS_MODE_32}
    if pe_map.machine not in modes:
        return hexdump(data, base), "Эта архитектура не поддерживается дизассемблером."
    md = capstone.Cs(capstone.CS_ARCH_X86, modes[pe_map.machine])
    md.skipdata = True  # неразбираемые байты показываются как .byte, разбор не обрывается

    calls = {pe_map.image_base + rva: name for rva, name in pe_map.exports.items()}
    lines: list[str] = []
    stats = {"call": 0, "api": 0}
    for i in md.disasm_lite(data, base):
        address, length, mnemonic, op_str = i
        raw = data[address - base:address - base + length]
        comment = ""
        if mnemonic in ("call", "jmp") or "ptr [" in op_str:
            target = _target(op_str, address, length)
            if target is not None:
                name = pe_map.imports.get(target) or calls.get(target)
                if name:
                    comment = f"  ; {name}"
                    stats["api"] += 1
        if mnemonic == "call":
            stats["call"] += 1
        if address in calls:
            lines.append(f"\n; ---- экспорт: {calls[address]} ----")
        lines.append(f"{address:016X}  {raw.hex(' ').upper()[:29]:<29}  {mnemonic:<8} {op_str}{comment}")
        if len(lines) >= MAX_DISASM_LINES or (cancel is not None and cancel.is_set()):
            lines.append("; ... листинг обрезан")
            break
    note = (f"{region.title}: адрес {base:X}, разобрано {len(data):,} байт, "
            f"инструкций {len(lines):,}, вызовов {stats['call']:,}, "
            f"с известным именем функции {stats['api']:,}.").replace(",", " ")
    return "\n".join(lines), note


def _target(op_str: str, address: int, length: int) -> int | None:
    """Адрес, на который ссылается операнд: call 0x401000, call [rip + 0x1234], call [0x402000]."""
    text = op_str.replace("qword ptr ", "").replace("dword ptr ", "").strip()
    try:
        if text.startswith("0x"):
            return int(text, 16)
        if text.startswith("[rip + 0x") and text.endswith("]"):
            return address + length + int(text[9:-1], 16)
        if text.startswith("[0x") and text.endswith("]"):
            return int(text[1:-1], 16)
    except ValueError:
        return None
    return None


def hex_page(path: Path, page: int) -> tuple[str, int, int]:
    """(дамп страницы, номер страницы после проверки границ, всего страниц)."""
    size = path.stat().st_size
    pages = max(1, (size + HEX_PAGE - 1) // HEX_PAGE)
    page = min(max(0, page), pages - 1)
    if size == 0:
        return "", 0, 1
    with path.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
        start = page * HEX_PAGE
        return hexdump(m[start:start + HEX_PAGE], start), page, pages
