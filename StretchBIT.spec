# Сборка StretchBIT в папку dist/StretchBIT (PyInstaller 6+). Запускать через build_release.py:
# он ещё кладёт рядом ядра VPN и базы и упаковывает архив.
#
# contents_directory="app" — рядом с .exe только папка app, в ней всё остальное: библиотеки,
# базы, ядра VPN, а потом и журнал, кэш, карантин. В коде данные ищутся от расположения модулей
# (Path(__file__).parent.parent / "signatures", "journal", "cache"), а рабочая папка в собранной
# программе — app (gui.py: sys._MEIPASS): так оба пути указывают на одно место.
# Папка, не один файл: рабочие процессы проверки (gui.py --scan-worker) запускаются часто,
# а однофайловый .exe распаковывал бы себя при каждом запуске.
import sys
from pathlib import Path

ROOT = Path(SPECPATH)
sys.path.insert(0, str(ROOT))
import appinfo  # noqa: E402

datas = [
    (str(ROOT / "ui" / "designer"), "ui/designer"),
    (str(ROOT / "ui" / "assets"), "ui/assets"),
    (str(ROOT / "signatures" / "release_exclusions.json"), "signatures"),
    (str(ROOT / "diag" / "baseline.json"), "diag"),  # эталон исправных функций (diag/features)
]
# провайдер AMSI (native/amsi/build.py; build_release собирает его сам, если нет)
for _dll in ("sbit_amsi64.dll", "sbit_amsi32.dll"):
    if (ROOT / "native" / "amsi" / "bin" / _dll).is_file():
        datas.append((str(ROOT / "native" / "amsi" / "bin" / _dll), "native/amsi/bin"))

a = Analysis(
    [str(ROOT / "gui.py")],
    pathex=[str(ROOT)],
    datas=datas,
    hiddenimports=[
        "scanner._native",   # importlib.import_module в processmanager/memscan.py
        "scanner.worker",
    ],
    excludes=["tkinter", "pytest", "_pytest", "IPython", "matplotlib", "pybind11"],
    noarchive=False,
)
# Лишнее из Qt (~45 МБ): программная замена OpenGL (окнам Qt Widgets не нужна), переводы
# Qt (программа их не загружает), плагин экранной клавиатуры и картинок PDF — только из-за
# них в сборку попадали Qt Quick, QML и Qt PDF.
QT_DROP = ("opengl32sw.dll", "qt6quick", "qt6qml", "qt6pdf", "qt6virtualkeyboard",
           "/translations/", "/platforminputcontexts/", "qpdf.dll")


def _keep(entry) -> bool:
    name = entry[0].replace("\\", "/").lower()
    return not any(part in name if "/" in part else part in name.rsplit("/", 1)[-1]
                   for part in QT_DROP)


a.binaries = [b for b in a.binaries if _keep(b)]
a.datas = [d for d in a.datas if _keep(d)]
pyz = PYZ(a.pure)

version_file = ROOT / "build" / "version_info.txt"
version_file.parent.mkdir(exist_ok=True)
# в числовые поля Windows — только цифры: «1.0.0-beta» → (1, 0, 0, 0); полная строка
# остаётся в FileVersion/ProductVersion ниже
import re
numbers = [int(x) for x in re.findall(r"\d+", appinfo.VERSION.split("-")[0].split("+")[0])][:4]
v = tuple(numbers + [0] * (4 - len(numbers)))
version_file.write_text(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={v}, prodvers={v}),
  kids=[StringFileInfo([StringTable('041904B0', [
    StringStruct('FileDescription', '{appinfo.APP_NAME}'),
    StringStruct('ProductName', '{appinfo.APP_NAME}'),
    StringStruct('FileVersion', '{appinfo.VERSION}'),
    StringStruct('ProductVersion', '{appinfo.VERSION}'),
    StringStruct('LegalCopyright', '{appinfo.YEAR} {appinfo.AUTHOR}'),
    StringStruct('OriginalFilename', '{appinfo.APP_NAME}.exe')])]),
    VarFileInfo([VarStruct('Translation', [1049, 1200])])])
""", encoding="utf-8")

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name=appinfo.APP_NAME,
    icon=str(ROOT / "ui" / "assets" / "icon.ico"),
    version=str(version_file),
    console=False,
    upx=False,
    contents_directory="app",
)
coll = COLLECT(exe, a.binaries, a.datas, name=appinfo.APP_NAME, upx=False)
