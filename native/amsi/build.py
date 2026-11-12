"""Сборка провайдера AMSI: python native/amsi/build.py [--selftest]

Нужна Visual Studio (C++, Windows SDK). Результат — native/amsi/bin (вне Git):
  sbit_amsi64.dll, sbit_amsi32.dll — провайдер для 64- и 32-битных процессов
  (32-битные Office и PowerShell из SysWOW64 грузят 32-битную);
  amsi_selftest64.exe — самопроверка для tests/test_amsi.py (с --selftest).
CRT статическая (/MT): библиотека грузится в чужие процессы, у которых может не быть нужной
версии vcruntime.
"""
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BIN = HERE / "bin"
VS_ROOTS = [Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Microsoft Visual Studio",
            Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
            / "Microsoft Visual Studio"]
CFLAGS = "/nologo /O2 /MT /EHsc /W4 /DUNICODE /D_UNICODE /std:c++17"
LIBS = "ole32.lib advapi32.lib"


def find_vcvarsall() -> Path | None:
    found = []
    for root in VS_ROOTS:
        if root.is_dir():
            found += root.glob("*/*/VC/Auxiliary/Build/vcvarsall.bat")
    return max(found, default=None, key=lambda p: p.parts[-6])  # самая новая версия


def _cl(vcvars: Path, arch: str, command: str) -> None:
    script = f'call "{vcvars}" {arch} >nul && cd /d "{HERE}" && {command}'
    # строкой, а не списком: иначе subprocess экранирует кавычки так, что cmd их не понимает
    result = subprocess.run(f'cmd /s /c "{script}"', capture_output=True, text=True,
                            encoding="oem", errors="replace")
    if result.returncode:
        raise SystemExit(f"Сборка ({arch}) не удалась:\n{result.stdout}\n{result.stderr}")


def build(selftest: bool = False) -> list[Path]:
    vcvars = find_vcvarsall()
    if vcvars is None:
        raise SystemExit("Не найдена Visual Studio с C++ (vcvarsall.bat)")
    BIN.mkdir(exist_ok=True)
    out = []
    for arch, bits in (("x64", "64"), ("amd64_x86", "32")):
        obj = BIN / f"obj{bits}"
        obj.mkdir(exist_ok=True)
        dll = BIN / f"sbit_amsi{bits}.dll"
        # .lib и .exp компоновщик иначе кладёт рядом с исходниками — в папку obj (вне Git)
        _cl(vcvars, arch, f'cl {CFLAGS} /LD /Fo"{obj}\\\\" sbit_amsi.cpp /link /DEF:sbit_amsi.def '
                          f'/OUT:"{dll}" /IMPLIB:"{obj / "sbit_amsi.lib"}" {LIBS}')
        out.append(dll)
    if selftest:
        exe = BIN / "amsi_selftest64.exe"
        _cl(vcvars, "x64", f'cl {CFLAGS} /Fo"{BIN / "obj64"}\\\\" selftest.cpp /link '
                           f'/OUT:"{exe}" {LIBS}')
        out.append(exe)
    return out


if __name__ == "__main__":
    for path in build("--selftest" in sys.argv):
        print(path, path.stat().st_size, "байт")
