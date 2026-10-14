from datetime import date

from scr.adapters import load_edr, merge
from scr.controls import tag
from scr.core import read, reconcile


def test_vendor_formats_normalize():
    d = load_edr("samples/defender_laptops.csv", "defender")
    assert d[0]["hostname"] == "WS-1042" and d[0]["last_seen"] == "2026-10-14"
    s = load_edr("samples/s1_servers.csv", "sentinelone")
    assert s[0]["last_seen"].startswith("2026-10-14T08:10")


def test_merge_keeps_latest_per_host():
    a = [{"hostname": "h1", "last_seen": "2026-10-01"}]
    b = [{"hostname": "H1.corp", "last_seen": "2026-10-10"}]
    assert merge(a, b)[0]["last_seen"] == "2026-10-10"


def test_mixed_edr_fleet_finds_stale_laptop():
    edr = merge(load_edr("samples/defender_laptops.csv", "defender"), load_edr("samples/s1_servers.csv", "sentinelone"))
    gaps, _ = reconcile(read("samples/inventory.csv"), {"edr": edr}, date(2026, 10, 14))
    assert any(g["host"] == "ws-1043" and g["issue"].startswith("stale") for g in gaps)
    assert any(g["host"] == "trade-gw02" and g["issue"] == "missing" for g in gaps)


def test_control_mapping():
    t = tag([{"host": "x", "tool": "edr", "issue": "missing", "owner": "", "criticality": "high"}], ["y"])
    assert t[0]["cis"].startswith("CIS 10.1") and t[1]["nist_csf"] == "ID.AM-01"
