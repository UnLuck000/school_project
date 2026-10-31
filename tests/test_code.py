import base64
import zipfile

from analyzer import code


def test_powershell_encoded_command_is_decoded():
    payload = base64.b64encode("Write-Host hello".encode("utf-16-le")).decode()
    findings = code.analyze_text(f"powershell -nop -w hidden -enc {payload}", "bat")
    assert any(f.category == "decoded" and "Write-Host hello" in f.value for f in findings)
    assert any("Скрытое окно" in f.title for f in findings)


def test_urls_and_ips_are_found():
    text = "curl https://example.com/a.exe -o x\nping 10.1.2.3:8080\nping 999.1.1.1"
    values = [f.value for f in code.analyze_text(text, "bat") if f.category == "ioc"]
    assert "https://example.com/a.exe" in values
    assert "10.1.2.3:8080" in values
    assert "999.1.1.1" not in values


def test_bat_caret_obfuscation():
    findings = code.analyze_text("^e^c^h^o ^h^e^l^l^o", "bat")
    decoded = [f for f in findings if f.category == "decoded"]
    assert decoded and "echo hello" in decoded[0].value


def test_chr_chain_and_fromcharcode():
    vbs = code.analyze_text("x = chr(104) & chr(116) & chr(116) & chr(112)", "vbs")
    assert any(f.value == "http" for f in vbs if f.category == "decoded")
    js = code.analyze_text("String.fromCharCode(104,116,116,112)", "js")
    assert any(f.value == "http" for f in js if f.category == "decoded")


def test_read_text_encodings(tmp_path):
    cp = tmp_path / "a.bat"
    cp.write_bytes("echo привет".encode("cp1251"))
    assert code.read_text(cp)[0] == "echo привет"
    utf16 = tmp_path / "b.ps1"
    utf16.write_bytes("Write-Host ok".encode("utf-16"))
    assert code.read_text(utf16)[0] == "Write-Host ok"


def test_script_view(tmp_path):
    f = tmp_path / "run.bat"
    f.write_text("@echo off\nstart https://example.com\n", encoding="utf-8")
    view = code.build_code_view(f, "script", ".bat", None)
    assert view.language == "bat" and "@echo off" in view.text
    assert any(x.category == "ioc" for x in view.findings)


def test_zip_view_flags_executables(tmp_path):
    archive = tmp_path / "a.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("readme.txt", "hi")
        z.writestr("setup.exe", "MZ")
    view = code.build_code_view(archive, "zip", ".zip", None)
    assert "setup.exe" in view.text
    assert any("Исполняемый" in f.title for f in view.findings)


def test_hexdump():
    assert code.hexdump(b"ABC").startswith("00000000  41 42 43")