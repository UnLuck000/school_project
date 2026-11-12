"""«Почему нет интернета?» (vpn/netdiag.py): разбор фильтров WFP и чужие TUN-клиенты."""
from types import SimpleNamespace

from vpn import netdiag

WFP = r"""<wfpdiag><filters>
<item><filterKey>{1}</filterKey><displayData><name>sing-tun (C:\Utils\Throne\ThroneCore.exe)</name></displayData>
<action><type>FWP_ACTION_BLOCK</type></action></item>
<item><filterKey>{2}</filterKey><displayData><name>sing-tun</name></displayData>
<action><type>FWP_ACTION_BLOCK</type></action></item>
<item><filterKey>{3}</filterKey><displayData><name>sing-tun</name></displayData>
<action><type>FWP_ACTION_PERMIT</type></action></item>
<item><filterKey>{4}</filterKey><displayData><name>Quarantine Default Inbound Tunnel Block</name></displayData>
<providerKey>FWPM_PROVIDER_MPSSVC_WF</providerKey><action><type>FWP_ACTION_BLOCK</type></action></item>
<item><filterKey>{5}</filterKey><displayData><name>SBIT kill switch: туннель</name></displayData>
<action><type>FWP_ACTION_BLOCK</type></action></item>
</filters></wfpdiag>"""


def test_wfp_blocks_only_foreign_tunnels():
    found = dict(netdiag.parse_wfp_blocks(WFP))
    assert found == {r"sing-tun (C:\Utils\Throne\ThroneCore.exe)": 1, "sing-tun": 1}


def test_foreign_tunnels_skip_own_cores(monkeypatch):
    from processmanager import ntsnap
    procs = [SimpleNamespace(pid=1, name="ThroneCore.exe"), SimpleNamespace(pid=2, name="xray.exe"),
             SimpleNamespace(pid=4, name="Throne.exe"),
             SimpleNamespace(pid=3, name="notepad.exe")]
    monkeypatch.setattr(ntsnap, "list_processes", lambda: procs)
    import psutil
    own = netdiag._our_dir() + r"\xray.exe"
    monkeypatch.setattr(psutil, "Process", lambda pid: SimpleNamespace(exe=lambda: own))
    monkeypatch.setattr(psutil, "net_if_stats", lambda: {
        "throne-tun": SimpleNamespace(isup=True), "sbit-tun": SimpleNamespace(isup=True),
        "Ethernet": SimpleNamespace(isup=True)})
    assert netdiag.foreign_tunnels() == ["Throne (ThroneCore.exe, Throne.exe)",
                                        "адаптер throne-tun"]


def test_report_marks_levels():
    text = netdiag.report([netdiag.Finding(netdiag.OK, "Связь есть"),
                           netdiag.Finding(netdiag.BAD, "Связи нет", "1.1.1.1:443 — тайм-аут")])
    assert text.startswith("✓  Связь есть") and "✗  Связи нет\n1.1.1.1" in text
