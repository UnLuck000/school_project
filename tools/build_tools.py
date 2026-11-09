"""Инструменты вкладки «Декомпилятор» → tools/bin (см. tools/bin/THIRD_PARTY.md).

    python tools/build_tools.py [dotnet] [pycdc] [upx] [cfr] [rizin]   (без аргументов — всё)

rizin — rizin + rz-ghidra (декомпилятор Ghidra) из выпуска Cutter, ~116 МБ;

dotnet — публикует свой sbit-dotnet (tools/dotnet, нужен .NET SDK 10): один .exe со средой
выполнения, на чужом ПК .NET не нужен; pycdc — скачивает исходники Decompyle++ и собирает
MSVC (Visual Studio 18, /MT: без отдельной среды выполнения C++); upx, cfr — скачивает
официальные выпуски с GitHub. Скачанное сначала ложится во временную папку.
"""
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "tools" / "bin"
UPX_URL = "https://github.com/upx/upx/releases/download/v5.3.0/upx-5.3.0-win64.zip"
CFR_URL = "https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar"
PYCDC_COMMIT = "b4289760970dbc399684f1e155ec6d1ea1cc787e"
PYCDC_URL = f"https://github.com/zrax/pycdc/archive/{PYCDC_COMMIT}.zip"
VCVARS = Path(r"C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat")
# rizin + rz-ghidra для Windows отдельно не выпускаются: берём из выпуска Cutter
CUTTER_URL = ("https://github.com/rizinorg/cutter/releases/download/v2.5.0/"
              "Cutter-v2.5.0-Windows-x86_64.zip")
VC_REDIST = Path(r"C:\Program Files\Microsoft Visual Studio\18\Community\VC\Redist\MSVC")


def _get(url: str, target: Path) -> Path:
    print("Скачиваю", url)
    request = urllib.request.Request(url, headers={"User-Agent": "sbit-build"})
    # без системного прокси: через локальный прокси GitHub отвечал 504 на крупные файлы
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=300) as r, open(target, "wb") as f:
        shutil.copyfileobj(r, f)
    return target


def dotnet() -> None:
    subprocess.run(["dotnet", "publish", str(ROOT / "tools" / "dotnet" / "SbitDotnet.csproj"),
                    "-c", "Release", "-r", "win-x64", "--self-contained", "true",
                    "-p:PublishSingleFile=true", "-p:IncludeNativeLibrariesForSelfExtract=true",
                    "-p:EnableCompressionInSingleFile=true", "-p:DebugType=none",
                    "-o", str(BIN / "dotnet"), "-nologo"], check=True)


def upx(tmp: Path) -> None:
    with zipfile.ZipFile(_get(UPX_URL, tmp / "upx.zip")) as z:
        z.extractall(tmp / "upx")
    folder = next((tmp / "upx").iterdir())
    (BIN / "upx").mkdir(parents=True, exist_ok=True)
    shutil.copy(folder / "upx.exe", BIN / "upx" / "upx.exe")
    shutil.copy(folder / "COPYING", BIN / "upx" / "LICENSE-upx.txt")


def cfr(tmp: Path) -> None:
    (BIN / "cfr").mkdir(parents=True, exist_ok=True)
    _get(CFR_URL, BIN / "cfr" / "cfr-0.152.jar")


def pycdc(tmp: Path) -> None:
    with zipfile.ZipFile(_get(PYCDC_URL, tmp / "pycdc.zip")) as z:
        z.extractall(tmp)
    src = tmp / f"pycdc-{PYCDC_COMMIT}"
    lib = ["bytecode.cpp", "data.cpp", "pyc_code.cpp", "pyc_module.cpp", "pyc_numeric.cpp",
           "pyc_object.cpp", "pyc_sequence.cpp", "pyc_string.cpp", r"bytes\*.cpp"]
    flags = '/nologo /O2 /MT /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS /I. /Fo"out\\\\"'
    script = src / "build.cmd"
    script.write_text("\r\n".join([
        "@echo off", f'call "{VCVARS}" >nul', f'cd /d "{src}"', "mkdir out",
        f"cl {flags} /c {' '.join(lib)} || exit /b 1",
        "lib /nologo /out:out\\pycxx.lib out\\*.obj || exit /b 1",
        f'cl {flags} pycdc.cpp ASTree.cpp ASTNode.cpp out\\pycxx.lib /Fe"out\\pycdc.exe" || exit /b 1',
        f'cl {flags} pycdas.cpp out\\pycxx.lib /Fe"out\\pycdas.exe" || exit /b 1']),
        encoding="ascii")
    subprocess.run(["cmd", "/c", str(script)], check=True)
    (BIN / "pycdc").mkdir(parents=True, exist_ok=True)
    for name in ("pycdc.exe", "pycdas.exe"):
        shutil.copy(src / "out" / name, BIN / "pycdc" / name)
    shutil.copy(src / "LICENSE", BIN / "pycdc" / "LICENSE-pycdc.txt")


def rizin(tmp: Path) -> None:
    """Из Cutter — только консольный rizin, модуль rz-ghidra и данные (без Qt и Python)."""
    with zipfile.ZipFile(_get(CUTTER_URL, tmp / "cutter.zip")) as z:
        z.extractall(tmp / "cutter")
    src = next((tmp / "cutter").iterdir())
    dst = BIN / "rizin"
    shutil.rmtree(dst, ignore_errors=True)
    (dst / "lib" / "rizin" / "plugins").mkdir(parents=True)
    for f in [src / "rizin.exe", src / "z.dll", *src.glob("rz_*.dll")]:
        shutil.copy(f, dst)
    plugins = src / "lib" / "rizin" / "plugins"
    shutil.copy(plugins / "core_ghidra.dll", dst / "lib" / "rizin" / "plugins")
    shutil.copytree(plugins / "rz_ghidra_sleigh", dst / "lib" / "rizin" / "plugins" / "rz_ghidra_sleigh")
    shutil.copytree(src / "share", dst / "share",
                    ignore=shutil.ignore_patterns("elf", "fortunes", "man", "gittip"))
    # среда выполнения Visual C++ рядом с rizin: на чужом ПК её может не быть
    crt = next(VC_REDIST.glob(r"*\x64\Microsoft.VC*.CRT"))
    for name in ("msvcp140.dll", "vcruntime140.dll", "vcruntime140_1.dll"):
        shutil.copy(crt / name, dst)


def main() -> None:
    wanted = set(sys.argv[1:]) or {"dotnet", "pycdc", "upx", "cfr", "rizin"}
    BIN.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        for name in ("dotnet", "pycdc", "upx", "cfr", "rizin"):
            if name in wanted:
                if name == "dotnet":
                    dotnet()
                else:
                    globals()[name](Path(tmp))
    print("Готово:", BIN)


if __name__ == "__main__":
    main()
