"""Правила YARA качаются заново, только если архив изменился (updater.update_rules, ETag)."""
import io
import urllib.error
import zipfile

import pytest

import updater


def _zip(text: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("repo-main/rules/a.yar", text)
    return buf.getvalue()


class _Resp:
    def __init__(self, body: bytes, etag: str):
        self.body, self.headers = body, {"ETag": etag}
        self.read_called = False

    def read(self):
        self.read_called = True
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setattr(updater, "COMMUNITY_RULES_DIR", tmp_path / "community")
    monkeypatch.setattr(updater, "RULE_SOURCES",
                        {"one": ("https://example.invalid/one.zip", "/rules/")})
    state = {"etag": '"v1"', "body": _zip("rule a { condition: true }"), "seen": [],
             "honor": True, "full": 0}

    def urlopen(req, timeout=0):
        sent = req.headers.get("If-none-match", "")
        state["seen"].append(sent)
        if state["honor"] and sent and sent == state["etag"]:
            raise urllib.error.HTTPError(req.full_url, 304, "Not Modified", {}, None)
        state["full"] += 1
        state["last"] = _Resp(state["body"], state["etag"])
        return state["last"]

    monkeypatch.setattr(updater.urllib.request, "urlopen", urlopen)
    return state


def test_unchanged_archive_not_downloaded(server):
    assert updater.update_rules()
    assert server["seen"] == [""] and server["full"] == 1          # первый раз — без ETag
    assert updater.update_rules()
    assert server["seen"][-1] == '"v1"' and server["full"] == 1    # 304 — не качали
    rules = updater.COMMUNITY_RULES_DIR / "one" / "a.yar"
    assert rules.read_text() == "rule a { condition: true }"


def test_changed_archive_replaces_rules(server):
    updater.update_rules()
    server.update(etag='"v2"', body=_zip("rule b { condition: false }"))
    assert updater.update_rules()
    assert server["full"] == 2
    assert "rule b" in (updater.COMMUNITY_RULES_DIR / "one" / "a.yar").read_text()
    assert updater._load_etags() == {"one": '"v2"'}


def test_server_ignoring_if_none_match(server):
    server["honor"] = False
    updater.update_rules()
    updater.update_rules()            # тот же ETag в ответе 200 — тело не читается
    assert server["full"] == 2 and not server["last"].read_called


def test_missing_rules_folder_downloads_again(server):
    import shutil
    updater.update_rules()
    shutil.rmtree(updater.COMMUNITY_RULES_DIR / "one")
    updater.update_rules()
    assert server["seen"][-1] == "" and server["full"] == 2       # ETag без правил не шлём
    assert (updater.COMMUNITY_RULES_DIR / "one" / "a.yar").exists()
