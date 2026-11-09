# Сторонние инструменты вкладки «Декомпилятор»

Программы лежат в `tools/bin` (вне Git, кладутся в релиз `build_release.py`). Собрать или
скачать заново: `python tools/build_tools.py`. Все инструменты только читают файл, ничего не
запускают.

| Папка | Программа | Версия | Лицензия | Исходники |
|---|---|---|---|---|
| `upx/` | UPX — распаковка `upx -d` | 5.3.0 (win64) | GPL-2.0+ с исключением UPX (`LICENSE-upx.txt`) | https://github.com/upx/upx |
| `pycdc/` | Decompyle++ (`pycdc.exe`, `pycdas.exe`) — .pyc → Python / байт-код | master b4289760 (07.04.2026), собран MSVC /MT | GPL-3.0 (`LICENSE-pycdc.txt`) | https://github.com/zrax/pycdc |
| `cfr/` | CFR — .class → Java (нужна Java) | 0.152 | MIT | https://github.com/leibnitz27/cfr |
| `rizin/` | rizin (анализ функций) + rz-ghidra (`lib/rizin/plugins/core_ghidra.dll`, движок декомпиляции Ghidra на C++, описания процессоров `rz_ghidra_sleigh`) + данные `share` с сигнатурами библиотечных функций `sigdb/pe`; взяты из выпуска Cutter (Qt, Python и интерфейс Cutter не входят); рядом `msvcp140.dll`, `vcruntime140*.dll` из Visual Studio Redist | rizin 0.9.1, Cutter 2.5.0 | rizin, rz-ghidra, sigdb — LGPL-3.0; декомпилятор и SLEIGH Ghidra — Apache-2.0; среда Visual C++ — по лицензии распространяемых файлов Visual Studio | https://github.com/rizinorg/rizin, https://github.com/rizinorg/rz-ghidra, https://github.com/rizinorg/cutter, https://github.com/NationalSecurityAgency/ghidra |
| `dotnet/` | `sbit-dotnet.exe` — свой помощник (исходники `tools/dotnet`) на ICSharpCode.Decompiler (ILSpy) | ICSharpCode.Decompiler 11.2.0.10050, .NET 10 self-contained | MIT | https://github.com/icsharpcode/ILSpy |
