from datetime import datetime

from scr.cli import main
from scr.health import check, load, summary

NOW = datetime(2026, 10, 15, 9, 0)


def _issues():
    return check(load("samples/tool_health.csv"), NOW)


def test_silent_feeds_by_age():
    feeds = {i["component"]: i for i in _issues() if i["issue"] == "feed silent"}
    assert feeds["Palo Alto firewall feed"]["priority"] == "P1"  # 31 h silent
    assert feeds["Okta feed"]["priority"] == "P2"                # 7 h silent
    assert "Windows event forwarder" not in feeds


def test_failed_integration_escalates_after_24h():
    i = next(x for x in _issues() if x["issue"] == "integration failing")
    assert "401" in i["detail"] and i["escalate_l3"]


def test_version_licence_and_cert():
    kinds = {(i["tool"], i["issue"]) for i in _issues()}
    assert ("CrowdStrike", "below minimum version") in kinds
    assert ("CrowdStrike", "licence near capacity") in kinds   # 92%
    assert ("Tanium", "certificate expiring") in kinds          # 5 days
    assert ("Ping Identity", "certificate expiring") not in kinds  # 46 days out
    assert not any(t == "Delinea" for t, _ in kinds)


def test_priorities_sorted_and_runbook_present():
    iss = _issues()
    assert [i["priority"] for i in iss] == sorted(i["priority"] for i in iss)
    assert all(i["action"] for i in iss)


def test_summary_states():
    s = summary(load("samples/tool_health.csv"), _issues())
    assert s["Google SecOps"] == "degraded" and s["Delinea"] == "healthy"


def test_cli_health(capsys):
    rc = main(["--health", "samples/tool_health.csv", "--now", "2026-10-15T09:00:00"])
    out = capsys.readouterr().out
    assert rc == 1 and "P1" in out and "Palo Alto firewall feed" in out
