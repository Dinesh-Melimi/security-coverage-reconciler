from datetime import date

from scr.core import coverage, read, reconcile

INV = read("samples/inventory.csv")
TOOLS = {k: read(f"samples/{k}.csv") for k in ("edr", "siem", "scanner", "runtime")}
GAPS, UNKNOWN = reconcile(INV, TOOLS, date(2026, 10, 14), min_sensor="7.15.0")


def has(host, tool, issue):
    return any(g["host"] == host and g["tool"] == tool and g["issue"].startswith(issue) for g in GAPS)


def test_name_normalization():
    assert not has("trade-gw01", "edr", "missing")   # FQDN in EDR matches short name


def test_stale_edr():
    assert has("trade-gw02", "edr", "stale")


def test_missing_edr_on_cloud_vm():
    assert has("fin-app01", "edr", "missing")


def test_container_runtime_gap():
    assert has("k8s-node-02", "runtime", "missing") and not has("k8s-node-01", "runtime", "missing")


def test_stale_siem_and_scan():
    assert has("fin-app01", "siem", "stale") and has("fin-app01", "scanner", "stale")


def test_outdated_sensor():
    assert has("k8s-node-01", "edr", "outdated")


def test_shadow_host():
    assert UNKNOWN == ["build-tmp-07"]


def test_coverage_numbers():
    c = coverage(INV, GAPS)
    assert c["runtime"] == 50.0 and c["edr"] < 100
