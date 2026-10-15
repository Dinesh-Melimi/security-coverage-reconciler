"""Operational health checks for the security tools themselves (L2 security operations).

Coverage asks "is every host in every tool?". Health asks "is every tool working?":
silent SIEM feeds, failed integrations, platforms behind on patches, licences near
capacity, and certificates about to expire. Each issue gets a priority, a first-step
runbook action, and an L3 escalation flag.

Input CSV columns (blank where not relevant):
tool,component,type,status,last_success,version,min_version,licence_used,licence_total,cert_expires,error
type is one of: feed, integration, platform, connector
"""
import csv
from datetime import date, datetime, timedelta

RUNBOOK = {
    "feed silent": "Check the forwarder/collector service and its credentials, then confirm the source is still sending.",
    "integration failing": "Read the error, re-test the API credential or token, and confirm network/firewall reachability.",
    "below minimum version": "Schedule the upgrade in the next maintenance window; check vendor release notes first.",
    "licence near capacity": "Reclaim licences from retired assets, then raise a purchase request if still above 90%.",
    "certificate expiring": "Renew the certificate and update it on the connector before the expiry date.",
    "certificate expired": "Renew now; the integration is likely failing TLS handshakes.",
    "status unknown": "Confirm the component still exists and that health reporting is enabled.",
}


def _ts(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def _ver(v):
    return tuple(int(p) for p in v.split(".") if p.isdigit()) if v else ()


def check(rows, now, feed_silent_hours=6, l3_after_hours=24, cert_warn_days=30):
    issues = []

    def add(r, issue, priority, detail, failing_since=None):
        hours = (now - failing_since).total_seconds() / 3600 if failing_since else 0
        issues.append({"tool": r["tool"], "component": r["component"], "issue": issue, "priority": priority,
                       "detail": detail, "action": RUNBOOK[issue],
                       "escalate_l3": priority == "P1" or hours >= l3_after_hours})

    for r in rows:
        kind, status = r.get("type", ""), (r.get("status") or "").lower()
        last = _ts(r.get("last_success"))
        if kind == "feed":
            if last is None:
                add(r, "status unknown", "P3", "no last-ingest time reported")
            elif now - last > timedelta(hours=feed_silent_hours):
                gap = now - last
                add(r, "feed silent", "P1" if gap > timedelta(hours=24) else "P2",
                    f"no events for {gap.total_seconds() / 3600:.0f} h", last)
        if kind in ("integration", "connector") and status in ("error", "failed", "degraded"):
            add(r, "integration failing", "P2", r.get("error") or status, last)
        if r.get("min_version") and _ver(r.get("version")) < _ver(r["min_version"]):
            add(r, "below minimum version", "P3", f"{r['version']} < {r['min_version']}")
        if r.get("licence_used") and r.get("licence_total"):
            used, total = int(r["licence_used"]), int(r["licence_total"])
            if total and used / total >= 0.9:
                add(r, "licence near capacity", "P3", f"{used}/{total} ({used / total:.0%})")
        exp = r.get("cert_expires")
        if exp:
            days = (date.fromisoformat(exp) - now.date()).days
            if days < 0:
                add(r, "certificate expired", "P1", f"expired {-days} days ago")
            elif days <= cert_warn_days:
                add(r, "certificate expiring", "P2" if days <= 7 else "P3", f"expires in {days} days")
    return sorted(issues, key=lambda i: (i["priority"], i["tool"], i["component"]))


def summary(rows, issues):
    tools = sorted({r["tool"] for r in rows})
    bad = {i["tool"] for i in issues if i["priority"] in ("P1", "P2")}
    return {t: ("degraded" if t in bad else "warning" if any(i["tool"] == t for i in issues) else "healthy")
            for t in tools}


def load(path):
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))
