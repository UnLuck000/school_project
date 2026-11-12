"""Расширения браузеров и сайты, которым разрешены уведомления.

Как рекламу 18+ ставят «на весь компьютер»:
1. Сайт просит «Разрешите уведомления, чтобы продолжить» — после «Разрешить» сайт шлёт
   всплывающие уведомления Windows даже при закрытой вкладке (список: notification_sites).
2. Расширение ставится не из магазина, а через политику (ExtensionInstallForcelist:
   «Браузером управляет ваша организация», удалить из браузера нельзя) или через ключ реестра
   внешних расширений (браузер сам ставит его заново после удаления). Поэтому мало удалить
   расширение в браузере: нужно убрать запись политики или реестра и папку расширения.

Что читаем (только чтение, браузер может работать):
• Chromium (Chrome, Edge, Яндекс, Opera, Brave, Vivaldi): профили в «User Data» —
  Preferences и Secure Preferences (extensions.settings: откуда установлено, включено ли,
  путь), manifest.json из папки расширения (права, название);
• Firefox: extensions.json профиля (путь к .xpi, права), permissions.sqlite (уведомления);
• политики HKLM/HKCU\\Software\\Policies\\<браузер>\\ExtensionInstallForcelist и ключи
  внешних расширений HKLM/HKCU\\Software\\[Wow6432Node\\]<браузер>\\Extensions\\<id>.

Изменения (браузер должен быть закрыт) пишутся в журнал с откатом: копии файлов настроек,
папки расширения и значений реестра лежат в journal/ext_backup.
"""
import json
import os
import shutil
import sqlite3
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from recovery import journal

BACKUP_DIR = journal.JOURNAL_DIR / "ext_backup"

# (название, папка User Data от %LOCALAPPDATA% или %APPDATA%, программа, ветки реестра)
CHROMIUM = [
    ("Google Chrome", ("local", r"Google\Chrome\User Data"), "chrome.exe",
     r"Google\Chrome"),
    ("Microsoft Edge", ("local", r"Microsoft\Edge\User Data"), "msedge.exe",
     r"Microsoft\Edge"),
    ("Яндекс Браузер", ("local", r"Yandex\YandexBrowser\User Data"), "browser.exe",
     "YandexBrowser"),
    ("Brave", ("local", r"BraveSoftware\Brave-Browser\User Data"), "brave.exe",
     r"BraveSoftware\Brave"),
    ("Vivaldi", ("local", r"Vivaldi\User Data"), "vivaldi.exe", "Vivaldi"),
    ("Chromium", ("local", r"Chromium\User Data"), "chrome.exe", "Chromium"),
    ("Opera", ("roaming", r"Opera Software\Opera Stable"), "opera.exe", r"Opera Software"),
    ("Opera GX", ("roaming", r"Opera Software\Opera GX Stable"), "opera.exe",
     r"Opera Software"),
]
FIREFOX = ("Firefox", r"Mozilla\Firefox\Profiles", "firefox.exe")

# location в настройках Chromium
LOCATIONS = {1: "из магазина", 2: "внешнее (файл настроек)", 3: "внешнее (реестр)",
             4: "распакованное (режим разработчика)", 5: "встроенное", 6: "внешнее",
             7: "политика (загрузка)", 8: "из командной строки", 9: "политика",
             10: "встроенное"}
COMPONENT = {5, 10}
# адреса обновления магазинов: расширение из реестра или политики, но из магазина
STORE_URLS = ("clients2.google.com/service/update2/crx", "edge.microsoft.com/extensionwebstore",
              "addons.opera.com", "addons.mozilla.org", "browser-extensions.s3.yandex.net")
FORCED = {2, 3, 6, 7, 9}
ALL_SITES = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*/"}
DANGEROUS = {
    "nativeMessaging": "запуск программ на компьютере",
    "proxy": "перенаправление всего трафика",
    "debugger": "полный доступ к вкладкам (отладчик)",
    "management": "управление другими расширениями",
    "webRequestBlocking": "подмена загружаемых страниц",
    "cookies": "cookies всех сайтов",
    "history": "история браузера",
    "downloads": "загрузки",
    "privacy": "настройки приватности",
    "clipboardRead": "чтение буфера обмена",
    "desktopCapture": "снимки экрана",
}


@dataclass
class Extension:
    browser: str
    profile: str
    ext_id: str
    name: str = ""
    version: str = ""
    enabled: bool = True
    source: str = ""          # откуда установлено (LOCATIONS, политика, реестр)
    path: str = ""            # папка или .xpi на диске
    permissions: list[str] = field(default_factory=list)
    all_sites: bool = False
    from_store: bool = False
    forced: bool = False      # политика или реестр: браузер не даст удалить / поставит снова
    registry: list[tuple[str, str, str]] = field(default_factory=list)  # (ветка, ключ, имя)
    prefs: str = ""           # папка профиля (Chromium)
    exe: str = ""             # программа браузера (проверка, закрыт ли)
    removed: bool = False     # папки нет: удалено, в настройках осталась пометка браузера

    @property
    def risk(self) -> tuple[str, list[str]]:
        """(danger | warning | ok | removed, причины)."""
        if self.removed:
            return "removed", ["папки расширения нет; запись в настройках — пометка браузера "
                               "«удалено пользователем», чтобы не поставить его снова"]
        reasons = []
        if self.forced:
            reasons.append("установлено политикой или через реестр: из браузера не удалить")
        if not self.from_store and not self.forced and self.source != "встроенное":
            reasons.append("установлено не из магазина")
        if self.all_sites:
            reasons.append("доступ ко всем сайтам")
        dangerous = [DANGEROUS[p] for p in self.permissions if p in DANGEROUS]
        reasons += dangerous
        if self.forced and not self.from_store and (self.all_sites or dangerous):
            return "danger", reasons
        if (not self.from_store and self.all_sites) or len(dangerous) >= 3:
            return "danger", reasons
        if self.all_sites or dangerous or not self.from_store:
            return "warning", reasons
        return "ok", reasons


@dataclass
class NotificationSite:
    browser: str
    profile: str
    site: str
    allowed: bool
    store: str        # файл Preferences или permissions.sqlite
    key: str          # ключ в настройках
    exe: str


# ---------- общее ----------
def _base(kind: str) -> Path:
    env = "LOCALAPPDATA" if kind == "local" else "APPDATA"
    default = Path.home() / "AppData" / ("Local" if kind == "local" else "Roaming")
    return Path(os.environ.get(env, default))


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _profiles(user_data: Path) -> list[Path]:
    """Папки профилей: Default, Profile N; у Opera профиль — сама папка."""
    if (user_data / "Preferences").is_file() and not (user_data / "Default").is_dir():
        return [user_data]
    try:
        return sorted(p for p in user_data.iterdir() if p.is_dir()
                      and (p / "Preferences").is_file()
                      and (p.name == "Default" or p.name.startswith("Profile ")))
    except OSError:
        return []


def _profile_name(profile: Path, local_state: dict) -> str:
    info = local_state.get("profile", {}).get("info_cache", {}).get(profile.name, {})
    name = info.get("name") or profile.name
    return name if name == profile.name else f"{name} ({profile.name})"


def _message(folder: Path, text: str, locale: str) -> str:
    """«__MSG_appName__» → строка из _locales/<язык>/messages.json."""
    if not text.startswith("__MSG_"):
        return text
    key = text[6:-2].lower()
    for lang in ("ru", locale or "en", "en", "en_US"):
        data = _read_json(folder / "_locales" / lang / "messages.json")
        for k, v in data.items():
            if k.lower() == key and isinstance(v, dict):
                return v.get("message", text)
    return text


def _version_dir(folder: Path) -> Path:
    """Extensions/<id>/<версия>: последняя версия с manifest.json."""
    if (folder / "manifest.json").is_file():
        return folder
    try:
        versions = sorted((p for p in folder.iterdir() if (p / "manifest.json").is_file()),
                          key=lambda p: p.stat().st_mtime)
    except OSError:
        return folder
    return versions[-1] if versions else folder


def _apply_manifest(ext: Extension, manifest: dict, folder: Path) -> None:
    ext.version = ext.version or str(manifest.get("version", ""))
    ext.name = ext.name or _message(folder, str(manifest.get("name", "")),
                                    manifest.get("default_locale", ""))
    perms = list(manifest.get("permissions", [])) + list(manifest.get("host_permissions", []))
    perms += list(manifest.get("optional_permissions", []) and [])
    for script in manifest.get("content_scripts", []) or []:
        perms += script.get("matches", []) if isinstance(script, dict) else []
    ext.permissions = sorted({p for p in perms if isinstance(p, str)})
    ext.all_sites = any(p in ALL_SITES for p in ext.permissions)


# ---------- Chromium ----------
def chromium_extensions() -> list[Extension]:
    result = []
    for browser, (kind, rel), exe, _ in CHROMIUM:
        user_data = _base(kind) / rel
        if not user_data.is_dir():
            continue
        local_state = _read_json(user_data / "Local State")
        for profile in _profiles(user_data):
            settings = {}
            for name in ("Preferences", "Secure Preferences"):
                data = _read_json(profile / name)
                for ext_id, value in data.get("extensions", {}).get("settings", {}).items():
                    if isinstance(value, dict):
                        settings.setdefault(ext_id, {}).update(value)
            for ext_id, value in settings.items():
                location = value.get("location")
                if location in COMPONENT:
                    continue
                if location is None and not value.get("path") and not value.get("manifest"):
                    continue  # обрывок настроек (служебные расширения Edge), не расширение
                ext = Extension(browser, _profile_name(profile, local_state), ext_id,
                                prefs=str(profile), exe=exe)
                ext.source = LOCATIONS.get(location, f"способ {location}")
                ext.from_store = bool(value.get("from_webstore")) or location == 1
                ext.forced = location in FORCED
                reasons = value.get("disable_reasons")
                ext.enabled = (value.get("state", 1) == 1 and not reasons)
                raw = value.get("path", "")
                folder = Path(raw) if raw and os.path.isabs(raw) else \
                    profile / "Extensions" / (raw or ext_id)
                if not raw:
                    folder = _version_dir(folder)
                ext.path = str(folder)
                # браузер хранит запись об удалённом внешнем расширении (location 2/3/6),
                # чтобы не установить его снова: папки нет — расширения нет
                ext.removed = not folder.exists() and location not in (4, 8)
                if ext.removed:
                    ext.enabled = False
                manifest = value.get("manifest") or _read_json(folder / "manifest.json")
                _apply_manifest(ext, manifest, folder)
                ext.name = ext.name or ext_id
                result.append(ext)
    return result


# ---------- Firefox ----------
def firefox_extensions() -> list[Extension]:
    browser, rel, exe = FIREFOX
    root = _base("roaming") / rel
    result = []
    if not root.is_dir():
        return result
    for profile in sorted(p for p in root.iterdir() if p.is_dir()):
        data = _read_json(profile / "extensions.json")
        for addon in data.get("addons", []):
            if addon.get("type") != "extension":
                continue
            location = addon.get("location", "")
            if location.startswith("app-builtin") or location.startswith("app-system"):
                continue
            ext = Extension(browser, profile.name.split(".", 1)[-1], addon.get("id", ""),
                            exe=exe)
            ext.name = (addon.get("defaultLocale") or {}).get("name") or ext.ext_id
            ext.version = addon.get("version", "")
            ext.enabled = bool(addon.get("active"))
            ext.path = addon.get("path", "")
            ext.from_store = "addons.mozilla.org" in str(addon.get("sourceURI", "")) or \
                addon.get("signedState", 0) == 2
            ext.forced = location != "app-profile"
            ext.source = "из магазина" if ext.from_store else (
                "политика или реестр" if ext.forced else "не из магазина")
            perms = addon.get("userPermissions") or {}
            ext.permissions = sorted(set(perms.get("permissions", []) +
                                         perms.get("origins", [])))
            ext.all_sites = any(p in ALL_SITES for p in ext.permissions)
            result.append(ext)
    return result


# ---------- реестр ----------
def _reg_values(hive, path: str) -> dict[str, Any]:
    import winreg
    values = {}
    try:
        with winreg.OpenKey(hive, path) as key:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                except OSError:
                    break
                values[name] = value
                i += 1
    except OSError:
        pass
    return values


def _reg_subkeys(hive, path: str) -> list[str]:
    import winreg
    names = []
    try:
        with winreg.OpenKey(hive, path) as key:
            i = 0
            while True:
                try:
                    names.append(winreg.EnumKey(key, i))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return names


HIVES = {"HKLM": "HKEY_LOCAL_MACHINE", "HKCU": "HKEY_CURRENT_USER"}


def _hive(name: str):
    import winreg
    return getattr(winreg, HIVES[name])


def registry_entries() -> dict[str, list[tuple[str, str, str, str, str, str]]]:
    """{id: [(куст, ключ, имя значения или "", что это, браузер, адрес обновления)]} —
    политики и внешние расширения."""
    try:
        import winreg  # noqa: F401
    except ImportError:
        return {}
    found: dict[str, list] = {}
    for browser, _, _, reg in CHROMIUM:
        for hive in HIVES:
            for policy in (rf"Software\Policies\{reg}\ExtensionInstallForcelist",):
                for name, value in _reg_values(_hive(hive), policy).items():
                    ext_id, _, url = str(value).partition(";")
                    found.setdefault(ext_id.strip(), []).append(
                        (hive, policy, name, f"политика {browser}: {value}", browser, url))
            for root in (rf"Software\{reg}\Extensions", rf"Software\Wow6432Node\{reg}\Extensions"):
                for ext_id in _reg_subkeys(_hive(hive), root):
                    values = _reg_values(_hive(hive), root + "\\" + ext_id)
                    url = str(values.get("update_url") or "")
                    where = values.get("path") or url
                    found.setdefault(ext_id, []).append(
                        (hive, root + "\\" + ext_id, "", f"внешнее {browser}: {where}",
                         browser, url))
    for hive in HIVES:  # Firefox: политика ExtensionSettings / Extensions\Install
        path = r"Software\Policies\Mozilla\Firefox\Extensions\Install"
        for name, value in _reg_values(_hive(hive), path).items():
            found.setdefault(str(value), []).append(
                (hive, path, name, "политика Firefox", "Firefox", ""))
    return found


def all_extensions() -> list[Extension]:
    items = chromium_extensions() + firefox_extensions()
    registry = registry_entries()
    used = set()
    for ext in items:
        for i, (hive, key, name, what, browser, url) in enumerate(registry.get(ext.ext_id, [])):
            # ветки реестра свои у каждого браузера; Opera и Opera GX делят одну
            if browser != ext.browser and not ext.browser.startswith(browser):
                continue
            used.add((ext.ext_id, i))
            ext.registry.append((hive, key, name))
            ext.forced = True
            ext.source = what
            ext.from_store = ext.from_store or any(u in url for u in STORE_URLS)
    for ext_id, entries in registry.items():  # в реестре есть, браузер ещё не поставил
        rest = [e for i, e in enumerate(entries) if (ext_id, i) not in used]
        if not rest:
            continue
        ext = Extension(rest[0][4], "—", ext_id, name=f"(не установлено) {ext_id}",
                        forced=True, source=rest[0][3], enabled=False)
        ext.from_store = any(u in e[5] for e in rest for u in STORE_URLS)
        ext.registry = [(h, k, n) for h, k, n, *_ in rest]
        items.append(ext)
    return items


# ---------- уведомления ----------
def notification_sites() -> list[NotificationSite]:
    result = []
    for browser, (kind, rel), exe, _ in CHROMIUM:
        user_data = _base(kind) / rel
        if not user_data.is_dir():
            continue
        local_state = _read_json(user_data / "Local State")
        for profile in _profiles(user_data):
            prefs = _read_json(profile / "Preferences")
            exceptions = prefs.get("profile", {}).get("content_settings", {}) \
                .get("exceptions", {}).get("notifications", {})
            for key, value in exceptions.items():
                if isinstance(value, dict) and value.get("setting") in (1, 2):
                    site = key.split(",")[0]
                    result.append(NotificationSite(browser, _profile_name(profile, local_state),
                                                   site, value["setting"] == 1,
                                                   str(profile / "Preferences"), key, exe))
    root = _base("roaming") / FIREFOX[1]
    if root.is_dir():
        for profile in root.iterdir():
            db = profile / "permissions.sqlite"
            if not db.is_file():
                continue
            try:
                con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=1)
                rows = con.execute("SELECT origin, permission FROM moz_perms "
                                   "WHERE type='desktop-notification'").fetchall()
                con.close()
            except sqlite3.Error:
                continue
            for origin, permission in rows:
                if permission in (1, 2):
                    result.append(NotificationSite("Firefox", profile.name.split(".", 1)[-1],
                                                   origin, permission == 1, str(db), origin,
                                                   FIREFOX[2]))
    return result


# ---------- изменения ----------
def browser_running(exe: str) -> bool:
    from processmanager import ntsnap
    try:
        return any(p.name.lower() == exe.lower() for p in ntsnap.list_processes())
    except OSError:
        return False


def _backup(path: Path, slot: Path) -> str:
    """Копия файла или папки в journal/ext_backup/<slot>; путь копии."""
    slot.mkdir(parents=True, exist_ok=True)
    target = slot / (uuid.uuid4().hex[:8] + "_" + path.name)
    if path.is_dir():
        shutil.copytree(path, target)
    else:
        shutil.copy2(path, target)
    return str(target)


def _edit_json(path: Path, change) -> bool:
    data = _read_json(path)
    if not data or not change(data):
        return False
    tmp = path.with_name(path.name + ".sbit-tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")),
                   encoding="utf-8")
    os.replace(tmp, path)
    return True


def remove_extension(ext: Extension) -> str:
    """Удаляет расширение целиком: записи политики и реестра, папку (или .xpi) и запись в
    настройках профиля. Всё с резервной копией и откатом через журнал."""
    if ext.exe and browser_running(ext.exe):
        raise OSError(f"Закройте браузер ({ext.exe}): он перезапишет настройки")
    slot = BACKUP_DIR / uuid.uuid4().hex
    undo: dict = {"files": [], "registry": [], "slot": str(slot)}
    done = []
    for hive, key, name in ext.registry:
        undo["registry"].append(_delete_registry(hive, key, name))
        done.append(f"реестр: {HIVES[hive]}\\{key}" + (f" [{name}]" if name else ""))
    if ext.prefs:
        profile = Path(ext.prefs)
        for pref in ("Preferences", "Secure Preferences"):
            file = profile / pref
            if not file.is_file():
                continue
            copy = _backup(file, slot)

            def drop(data, ext_id=ext.ext_id):
                changed = data.get("extensions", {}).get("settings", {}).pop(ext_id, None)
                macs = data.get("protection", {}).get("macs", {}).get("extensions", {}) \
                    .get("settings", {})
                changed = macs.pop(ext_id, None) is not None or changed is not None
                pinned = data.get("extensions", {}).get("pinned_extensions")
                if isinstance(pinned, list) and ext_id in pinned:
                    pinned.remove(ext_id)
                return changed
            if _edit_json(file, drop):
                undo["files"].append({"original": str(file), "copy": copy})
                done.append(f"настройки профиля: {pref}")
    if ext.path and Path(ext.path).exists():
        target = Path(ext.path)
        # папка версии внутри Extensions\<id> — удаляем всю папку расширения
        if target.parent.name == ext.ext_id and target.parent.parent.name == "Extensions":
            target = target.parent
        if target.is_dir() and not (target / "manifest.json").exists() and \
                target.name != ext.ext_id:
            target = None  # не похоже на папку расширения: не трогаем
        if target is not None:
            copy = _backup(target, slot)
            if target.is_dir():
                shutil.rmtree(target, ignore_errors=True)
            else:
                target.unlink()
            undo["files"].append({"original": str(target), "copy": copy})
            done.append(f"файлы: {target}")
    if not done:
        return "Нечего удалять: записи и файлы расширения не найдены"
    journal.log_action(f"Удалено расширение {ext.name} ({ext.browser}, {ext.ext_id})",
                       "ext_restore", undo)
    return "Удалено: " + "; ".join(done)


def _delete_registry(hive: str, key: str, name: str) -> dict:
    import winreg
    root = _hive(hive)
    if name:  # значение политики
        value = _reg_values(root, key).get(name)
        with winreg.OpenKey(root, key, 0, winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, name)
        return {"hive": hive, "key": key, "values": {name: value}}
    values = _reg_values(root, key)
    winreg.DeleteKey(root, key)
    return {"hive": hive, "key": key, "values": values, "whole": True}


@journal.undo_op("ext_restore")
def _undo_remove(d: dict) -> str:
    import winreg
    for item in d["files"]:
        original, copy = Path(item["original"]), Path(item["copy"])
        if copy.is_dir():
            if original.exists():
                shutil.rmtree(original, ignore_errors=True)
            shutil.copytree(copy, original)
        else:
            shutil.copy2(copy, original)
    for item in d["registry"]:
        with winreg.CreateKeyEx(_hive(item["hive"]), item["key"], 0,
                                winreg.KEY_SET_VALUE) as k:
            for name, value in item["values"].items():
                kind = winreg.REG_DWORD if isinstance(value, int) else winreg.REG_SZ
                winreg.SetValueEx(k, name, 0, kind, value)
    return "Расширение восстановлено (браузер должен быть закрыт)"


def block_notifications(site: NotificationSite) -> str:
    """Запретить сайту уведомления (с откатом)."""
    if browser_running(site.exe):
        raise OSError(f"Закройте браузер ({site.exe}): он перезапишет настройки")
    if site.store.endswith(".sqlite"):
        con = sqlite3.connect(site.store, timeout=2)
        with con:
            con.execute("UPDATE moz_perms SET permission=2 WHERE origin=? AND "
                        "type='desktop-notification'", (site.key,))
        con.close()
    else:
        def block(data):
            entry = data.get("profile", {}).get("content_settings", {}).get("exceptions", {}) \
                .get("notifications", {}).get(site.key)
            if not isinstance(entry, dict):
                return False
            entry["setting"] = 2
            return True
        if not _edit_json(Path(site.store), block):
            return "Сайт не найден в настройках"
    journal.log_action(f"Запрещены уведомления сайта {site.site} ({site.browser})",
                       "notify_allow", {"store": site.store, "key": site.key})
    return f"Сайт {site.site} больше не сможет присылать уведомления"


@journal.undo_op("notify_allow")
def _undo_block(d: dict) -> str:
    if d["store"].endswith(".sqlite"):
        con = sqlite3.connect(d["store"], timeout=2)
        with con:
            con.execute("UPDATE moz_perms SET permission=1 WHERE origin=? AND "
                        "type='desktop-notification'", (d["key"],))
        con.close()
    else:
        def allow(data):
            entry = data.get("profile", {}).get("content_settings", {}).get("exceptions", {}) \
                .get("notifications", {}).get(d["key"])
            if isinstance(entry, dict):
                entry["setting"] = 1
                return True
            return False
        _edit_json(Path(d["store"]), allow)
    return "Уведомления сайта снова разрешены"
