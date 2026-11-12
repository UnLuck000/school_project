from networkmonitor.connections import Conn, analyze, is_external
from networkmonitor.ioc import load_ip_blocklist

def conn(**kw):
    base = dict(pid=1, name="app.exe", exe=r"C:\Program Files\App\app.exe",
                create_time=1.0, rip="8.8.8.8", rport=443, inbound=False)
    base.update(kw)
    return Conn(**base)


def test_is_external():
    assert is_external("8.8.8.8")
    assert is_external("::ffff:8.8.8.8")
    assert not is_external("192.168.1.10")
    assert not is_external("127.0.0.1")


def test_rules():
    assert analyze(conn(), set()) == []
    assert analyze(conn(), {"8.8.8.8"})[0][:2] == ("critical", "IOC")
    assert analyze(conn(name="PowerShell.exe"), set())[0][1] == "LOLBIN"
    temp = conn(exe=r"C:\Users\me\AppData\Local\Temp\x.exe")
    assert analyze(temp, set())[0][1] == "USERDIR"


def test_load_blocklist(tmp_path):
    (tmp_path / "f.txt").write_text("# comment\n1.2.3.4\nnot-an-ip\n\n5.6.7.8\n")
    assert load_ip_blocklist(tmp_path) == {"1.2.3.4", "5.6.7.8"}
