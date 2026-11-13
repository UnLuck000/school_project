# WinDivert

Перехват ClientHello (SNI и JA3) на вкладке «Сеть» → «TLS» (networkmonitor/tls.py), режим
SNIFF | RECV_ONLY — только чтение копий пакетов, трафик не меняется.

* Версия: 2.2.2, x64 (WinDivert.dll, WinDivert64.sys) из официального выпуска
  https://github.com/basil00/WinDivert/releases/tag/v2.2.2 (WinDivert-2.2.2-A.zip).
* Лицензия: LGPL v3 (или GPL v2 — на выбор), текст — LICENSE рядом. Исходники:
  https://github.com/basil00/WinDivert
* SHA-256:
  * WinDivert-2.2.2-A.zip — 63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15
  * WinDivert.dll — c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2
  * WinDivert64.sys — 8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2
* Microsoft Defender считает архив угрозой (Misleading:Win32/Malgent!AMTB) — как и у zapret,
  где лежат те же файлы: драйвер перехвата пакетов используют и вредоносы.

Файлы .dll и .sys в Git не хранятся (.gitignore); build_release.copy_windivert (только с ключом --windivert) кладёт их в
app/native/windivert.
