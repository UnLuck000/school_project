# Сторонние программы в vpn/bin

Программа запускает их отдельными процессами (не встраивает их код). Сами исполняемые файлы
в Git не хранятся (размер ~130 МБ) и кладутся в сборку релиза вместе с этим файлом и
текстами лицензий. Файлы взяты без изменений из официальных выпусков.

| Компонент | Версия | Лицензия | Текст лицензии | Исходный код |
|---|---|---|---|---|
| Xray-core (`xray.exe`, `geoip.dat`, `geosite.dat`) | 26.10.31 | MPL-2.0 | `LICENSE-Xray` | https://github.com/XTLS/Xray-core/tree/v26.10.31 |
| sing-box (`sing-box.exe`, `libcronet.dll`) | 1.14.4 | GPL-3.0-or-later | `LICENSE-sing-box` (уведомление), `COPYING-GPL-3.0` (полный текст GPL) | https://github.com/SagerNet/sing-box/tree/v1.14.4 |
| Wintun (`wintun.dll`) | из архива Xray 26.10.31 | Prebuilt Binaries License (WireGuard LLC) | `LICENSE-Wintun` | https://git.zx2c4.com/wintun |

Где скачаны:
- https://github.com/XTLS/Xray-core/releases/tag/v26.10.31 — `Xray-windows-64.zip`,
  SHA-256 `2e04a9995a6f2ad1b28c0bb25c708ecb2695e43a1c9c7889c4b6ac2b48cf7a6a`
- https://github.com/SagerNet/sing-box/releases/tag/v1.14.4 — `sing-box-1.14.4-windows-amd64.zip`,
  SHA-256 `99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df`

`COPYING-GPL-3.0` — https://www.gnu.org/licenses/gpl-3.0.txt.

При обновлении версий — обновить эту таблицу и тексты лицензий.
