"""Профили маршрутизации VPN, WARP, DNS через VPN и строгая маршрутизация (без сети)."""
import base64
import json
import zipfile

import pytest

from vpn import routing, singbox, warp, xray

VLESS = ("vless://11111111-2222-3333-4444-555555555555@vpn.example.com:443"
         "?type=tcp&security=reality&pbk=key&sid=ab#x")


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _ld(field: int, payload: bytes) -> bytes:
    return bytes([field << 3 | 2]) + _varint(len(payload)) + payload


def geosite(*tags: str) -> bytes:
    return b"".join(_ld(1, _ld(1, t.encode()) + _ld(2, _ld(2, b"ads.example")))
                    for t in tags)


def geoip(*tags: str) -> bytes:
    return b"".join(_ld(1, _ld(1, t.encode()) + _ld(2, _ld(1, bytes(4)) + b"\x10\x08"))
                    for t in tags)


@pytest.fixture
def store(tmp_path, monkeypatch):
    from ui import settings as cfg
    values = {"vpn/route_ru": False, "vpn/block_ads": True, "vpn/block_quic": True,
              "vpn/block_udp": False, "vpn/rules_direct": "old.example\n",
              "vpn/routing_profile": "default"}
    monkeypatch.setattr(routing, "ROUTING_DIR", tmp_path / "routing")
    monkeypatch.setattr(routing, "ASSETS_DIR", tmp_path / "assets")
    monkeypatch.setattr(cfg, "get", lambda k: values.get(k, cfg.DEFAULTS.get(k)))
    monkeypatch.setattr(cfg, "set_", lambda k, v: values.__setitem__(k, v))
    return values


def test_unique_names():
    from vpn import profiles
    assert routing.unique_name("Дом", ["Работа"]) == "Дом"
    assert routing.unique_name("Дом", ["дом"]) == "Дом (1)"
    assert routing.unique_name("Дом", ["Дом", "Дом (1)"]) == "Дом (2)"
    assert routing.unique_name("Дом (1)", ["Дом", "Дом (1)"]) == "Дом (2)"
    assert profiles.unique_name("NL", ["NL", "NL (1)", "NL (2)"]) == "NL (3)"


def test_x25519_rfc7748_and_keys():
    alice = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    assert warp.x25519(alice, (9).to_bytes(32, "little")).hex() == \
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    private, public = warp.keypair()
    assert len(base64.b64decode(private)) == 32 and warp.public_key(private) == public


def test_warp_conf_and_registration():
    private, _ = warp.keypair()
    conf = (f"[Interface]\nPrivateKey = {private}\nAddress = 172.16.0.2/32, 2606:4700::1/128\n"
            "MTU = 1280\nJc = 5\nJmin = 50\nJmax = 1000\nS1 = 0\nH1 = 1\n"
            "[Peer]\nPublicKey = peerkey=\nEndpoint = 162.159.193.5:500\nReserved = 1, 2, 3\n")
    w = warp.parse_conf(conf)
    assert w["protocol"] == "amneziawg" and (w["jc"], w["jmin"], w["jmax"]) == (5, 50, 1000)
    assert w["address_v6"] == "2606:4700::1/128" and w["reserved"] == [1, 2, 3]
    assert w["endpoint"] == "162.159.193.5:500" and "s1" not in w
    with pytest.raises(ValueError):
        warp.parse_conf("[Interface]\nAddress = 10.0.0.2/32\n")
    reg = {"config": {"client_id": base64.b64encode(b"\x07\x08\x09").decode(),
                      "peers": [{"public_key": "pk=", "endpoint": {"host": "x:2408"}}],
                      "interface": {"addresses": {"v4": "172.16.0.2", "v6": "2606::5"}}}}
    got = warp.from_registration(reg, private)
    assert got["reserved"] == [7, 8, 9] and got["address_v4"] == "172.16.0.2/32"
    assert got["address_v6"] == "2606::5/128" and got["peer_public_key"] == "pk="
    assert warp.problems(dict(warp.default(), **got)) == []
    assert warp.problems(warp.default())  # без ключа — нельзя


def test_warp_chains_in_xray():
    private, _ = warp.keypair()
    w = dict(warp.default(), enabled=True, private_key=private)
    v = xray.parse_vless(VLESS)
    said = []
    over = xray.build_config(v, "proxy", options={"warp": w, "rules_proxy": ["yt.example"],
                                                 "advanced": [{"outbound": "vpn",
                                                               "domain": ["only-vpn.example"]}]},
                             log=said.append)
    assert over["outbounds"][0]["tag"] == "warp"  # остальное — через WARP
    assert over["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"] == "proxy"
    rules = over["routing"]["rules"]
    assert {"type": "field", "domain": ["domain:yt.example"], "outboundTag": "warp"} in rules
    assert {"type": "field", "domain": ["domain:only-vpn.example"],
            "outboundTag": "proxy"} in rules
    assert rules[0]["inboundTag"] == ["dns-internal"] and over["dns"]["tag"] == "dns-internal"
    under = xray.build_config(v, "proxy", options={
        "warp": dict(w, chain="under_vpn", protocol="amneziawg", jc=3), "fragment": True},
        log=said.append)
    tags = [o["tag"] for o in under["outbounds"]]
    assert tags[0] == "proxy" and "warp" in tags and "warp-noise" in tags and \
        "fragment" not in tags
    proxy = under["outbounds"][0]
    assert proxy["streamSettings"]["sockopt"]["dialerProxy"] == "warp"
    noise = next(o for o in under["outbounds"] if o["tag"] == "warp-noise")
    assert len(noise["settings"]["noises"]) == 3
    assert any("Фрагментация" in s for s in said)


def test_advanced_rules_and_files():
    v = xray.parse_vless(VLESS)
    adv = [{"inbound": ["tun"], "domain": ["games.example"], "port": "27000-27100",
            "network": "udp", "outbound": "direct"},
           {"inbound": ["proxy"], "ip": ["GeoIP:US"], "outbound": "block"},
           {"protocol": ["bittorrent"], "outbound": "block"},
           {"enabled": False, "domain": ["off.example"], "outbound": "block"}]
    opts = {"advanced": adv, "mode": "singbox", "adblock": ["ads.one", "ads.two"],
            "rules_direct": ["ext:ru.dat:ru", "ext:sites.dat:news"], "ip_files": {"ru.dat"}}
    rules = xray.build_config(v, "proxy", options=opts)["routing"]["rules"]
    first = rules[0]
    assert first == {"type": "field", "inboundTag": ["socks-in"], "domain": ["domain:games.example"],
                     "port": "27000-27100", "network": "udp", "outboundTag": "direct"}
    # входящего «системный прокси» в режиме sing-box нет — правило не ловит всё подряд
    assert not any(r.get("ip") == ["geoip:us"] for r in rules)
    assert {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"} in rules
    assert not any("domain:off.example" in r.get("domain", []) for r in rules)
    assert {"type": "field", "domain": ["domain:ads.one", "domain:ads.two"],
            "outboundTag": "block"} in rules
    assert {"type": "field", "ip": ["ext:ru.dat:ru"], "outboundTag": "direct"} in rules
    assert {"type": "field", "domain": ["ext:sites.dat:news"], "outboundTag": "direct"} in rules
    proxy_mode = xray.build_config(v, "proxy", options=dict(opts, mode="proxy"))
    assert {"type": "field", "inboundTag": ["http-in", "socks-in"], "ip": ["geoip:us"],
            "outboundTag": "block"} in proxy_mode["routing"]["rules"]
    assert routing.rule_problems({"port": "70000"}) and routing.rule_problems({"ip": ["x.y"]})
    assert routing.rule_problems({"port": "80,443-445", "ip": ["10.0.0.0/8", "geoip:ru"]}) == []


def test_profiles_store_import_export(store, tmp_path):
    profiles = routing.load_all()
    default = profiles[0]
    assert default.is_default and default.name == "Default"
    # прежние настройки окна перенесены
    assert (default.route_ru, default.block_ads, default.rules_direct) == \
        (False, True, ["old.example"])
    assert routing.active().id == "default"
    with pytest.raises(ValueError):
        routing.delete(default)
    with pytest.raises(ValueError):
        routing._write_file(default, "a.dat", geosite("A"))
    mine = routing.create("Мой", ["Default"])
    site, ip = tmp_path / "sites.dat", tmp_path / "geoip.dat"
    site.write_bytes(geosite("NEWS", "ADS"))
    ip.write_bytes(geoip("RU"))
    assert routing.add_files(mine, [site, ip]) == ["sites.dat", "geoip.dat"]
    assert routing.dat_info(mine.files_dir / "sites.dat") == ("geosite", ["NEWS", "ADS"])
    assert routing.file_kinds(mine) == {"geoip.dat": "geoip", "sites.dat": "geosite"}
    bad = tmp_path / "bad.dat"
    bad.write_bytes(b"not a dat file")
    with pytest.raises(ValueError):
        routing.add_files(mine, [bad])
    assert not (mine.files_dir / "bad.dat").exists()
    copy = routing.duplicate(mine, ["Default", "Мой"])
    assert copy.name == "Мой (1)" and [f.name for f in copy.files()] == ["geoip.dat",
                                                                         "sites.dat"]
    # geo-файлы для Xray: свои главнее встроенных
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "geoip.dat").write_bytes(geoip("XX"))
    (bin_dir / "geosite.dat").write_bytes(geosite("CATEGORY-RU"))
    assets = routing.assets_dir(mine, bin_dir)
    from pathlib import Path
    assert sorted(p.name for p in Path(assets).iterdir()) == ["geoip.dat", "geosite.dat",
                                                              "sites.dat"]
    assert routing.dat_info(Path(assets) / "geoip.dat")[1] == ["RU"]
    assert routing.assets_dir(default, bin_dir) == ""
    # экспорт: с файлами — zip, ключ WARP — только по согласию
    mine.warp = dict(mine.warp, private_key="secret")
    routing.save(mine)
    out = routing.export(mine, tmp_path / "out.json")
    assert out.suffix == ".zip"
    with zipfile.ZipFile(out) as z:
        assert sorted(z.namelist()) == ["files/geoip.dat", "files/sites.dat", "profile.json"]
        assert json.loads(z.read("profile.json"))["profile"]["warp"]["private_key"] == ""
    plain = routing.export(default, tmp_path / "d.json")
    names = [p.name for p in routing.load_all()]
    shown, notes = routing.import_paths([out, plain, site], default, names)
    assert shown.name == "Мой (2)" and len(notes) == 3
    imported = {p.name: p for p in routing.load_all()}
    assert "Default (импорт)" in imported
    assert [f.name for f in imported["Мой (2)"].files()] == ["geoip.dat", "sites.dat"]
    routing.delete(copy)
    assert not copy.folder.exists()


def test_link_sources_and_updates(store, tmp_path, monkeypatch):
    names = [p.name for p in routing.load_all()]
    default = routing.active()
    url = "https://github.com/user/repo/blob/main/lists/ru.dat"
    assert routing.raw_url(url) == "https://raw.githubusercontent.com/user/repo/main/lists/ru.dat"
    p, text = routing.import_url(url, 12, default, names, data=geoip("RU"))
    assert p.name == "ru" and "ru.dat" in text
    assert p.sources["ru.dat"]["interval"] == 12 and routing.due(p) == []
    assert routing.due(p, now=p.sources["ru.dat"]["updated"] + 12 * 3600) == ["ru.dat"]
    routing.set_source(p, "ru.dat", "https://example.com/ru2.dat", 5)
    assert routing.due(p) == ["ru.dat"]  # новая ссылка — скачать при ближайшей проверке
    assert "обновлён" in routing.update_source(p, "ru.dat", data=geoip("RU", "BY"))
    assert routing.dat_info(p.files_dir / "ru.dat")[1] == ["RU", "BY"]
    with pytest.raises(ValueError):
        routing.update_source(p, "ru.dat", data=b"garbage")
    assert routing.get(p.id).sources["ru.dat"]["error"]
    # ни профиль, ни .dat — ошибка, лишний профиль не остаётся
    before = len(routing.load_all())
    with pytest.raises(ValueError):
        routing.import_url("https://example.com/x.txt", 24, default, names, data=b"hello")
    assert len(routing.load_all()) == before
    # профиль по ссылке: настройки меняются, имя и ключ WARP остаются
    remote = routing.from_dict({"name": "Удалённый", "route_ru": True,
                                "rules_block": ["bad.example"]}, "x")
    blob = json.dumps({"format": routing.FORMAT, "version": 1,
                       "profile": routing.to_dict(remote)}).encode()
    q, _ = routing.import_url("https://example.com/p.json", 1, default, names, data=blob)
    assert q.sources[""]["url"] == "https://example.com/p.json" and q.rules_block == ["bad.example"]
    q.name, q.warp = "Свой", dict(q.warp, private_key="mine")
    routing.save(q)
    remote.rules_block = ["worse.example"]
    blob = json.dumps({"format": routing.FORMAT, "profile": routing.to_dict(remote)}).encode()
    routing.update_source(q, "", data=blob)
    q = routing.get(q.id)
    assert (q.name, q.rules_block, q.warp["private_key"]) == ("Свой", ["worse.example"], "mine")


def test_adblock_parse_and_options(store, monkeypatch):
    text = ("! comment\n||ads.example.com^\n||track.example^$important\n@@||good.example^\n"
            "||good.example^\n||x.example^$third-party\n||*.wild^\n0.0.0.0 hosts.example\n"
            "plain.example\n/regex/\n")
    assert routing.parse_adblock(text) == ["ads.example.com", "hosts.example",
                                           "plain.example", "track.example"]
    p = routing.active()
    p.adblock = True
    path = routing.adblock_file(p.adblock_url)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    o = routing.options(p, download=False)
    assert o["adblock"] == routing.parse_adblock(text) and o["block_ads"] is True
    p.warp = dict(p.warp, enabled=True)
    with pytest.raises(ValueError, match="WARP"):
        routing.options(p, download=False)


def test_dns_and_strict_route():
    assert singbox.parse_dns("1.1.1.1") == {"type": "udp", "server": "1.1.1.1",
                                            "server_port": 53}
    assert singbox.parse_dns("tls://8.8.8.8")["server_port"] == 853
    assert singbox.parse_dns("https://1.0.0.1/dns-query") == {
        "type": "https", "server": "1.0.0.1", "server_port": 443, "path": "/dns-query"}
    for bad in ("", "ftp://1.1.1.1", "1.1.1.1:99999", "tls://1.1.1.1/path", "not a host"):
        with pytest.raises(ValueError):
            singbox.parse_dns(bad)
    for preset in singbox.DNS_PRESETS:
        singbox.parse_dns(preset)
    named = singbox.dns_servers("https://dns.google/dns-query", "dns-remote")
    assert named[0]["domain_resolver"] == "dns-remote-boot" and named[1]["server"] == "1.1.1.1"
    assert singbox.dns_servers("1.1.1.1", "d", "tcp")[0]["type"] == "tcp"
    with pytest.raises(ValueError):
        singbox.dns_servers("quic://1.1.1.1", "d", "tcp")
    cfg = singbox.build_config(10808, r"C:\x\xray.exe", dns_server="tls://1.1.1.1",
                               strict_route=False)
    assert cfg["inbounds"][0]["strict_route"] is False
    assert cfg["dns"]["servers"][0] == {"tag": "dns-remote", "type": "tls", "server": "1.1.1.1",
                                        "server_port": 853, "detour": "proxy"}
    assert singbox.build_config(10808, r"C:\x\xray.exe")["inbounds"][0]["strict_route"] is True


def test_mask_ip():
    from vpn.window import mask_ip
    assert mask_ip("185.12.34.56") == "185*******56"
    assert mask_ip("2001:db8::1") == "200******:1"
    assert mask_ip("1.2") == "***"
