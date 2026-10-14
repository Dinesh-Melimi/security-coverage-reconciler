"""Every security tool keeps its own list of hosts. The gaps between those lists are where attackers live.

Inputs (CSV):
  inventory.csv : hostname, type (server|workstation|container_host|cloud_vm), env, owner, criticality
  edr.csv       : hostname, last_seen, sensor_version
  siem.csv      : hostname, last_event
  scanner.csv   : hostname, last_scan
  runtime.csv   : hostname, agent   (container runtime protection, container hosts only)
"""
import csv
from datetime import date, datetime

REQUIRED = {
    "server": ["edr", "siem", "scanner"],
    "workstation": ["edr", "scanner"],
    "cloud_vm": ["edr", "siem", "scanner"],
    "container_host": ["edr", "siem", "scanner", "runtime"],
}
STALE_DAYS = {"edr": 7, "siem": 1, "scanner": 30, "runtime": 7}
DATE_FIELD = {"edr": "last_seen", "siem": "last_event", "scanner": "last_scan", "runtime": None}


def norm(h):
    """Tools disagree on names (FQDN vs short, case). Compare on lowercase short name."""
    return h.strip().lower().split(".")[0]


def read(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def index(rows):
    return {norm(r["hostname"]): r for r in rows}


def _age(value, today):
    d = datetime.fromisoformat(value).date() if "T" in value else date.fromisoformat(value)
    return (today - d).days


def reconcile(inventory, tools, today, min_sensor=None):
    """tools: {'edr': rows, 'siem': rows, 'scanner': rows, 'runtime': rows}"""
    idx = {name: index(rows) for name, rows in tools.items()}
    inv = index(inventory)
    gaps = []
    for host, a in inv.items():
        for tool in REQUIRED.get(a["type"], []):
            rec = idx.get(tool, {}).get(host)
            if rec is None:
                gaps.append({"host": host, "owner": a["owner"], "criticality": a["criticality"], "tool": tool,
                             "issue": "missing"})
                continue
            field = DATE_FIELD[tool]
            if field and rec.get(field):
                age = _age(rec[field], today)
                if age > STALE_DAYS[tool]:
                    gaps.append({"host": host, "owner": a["owner"], "criticality": a["criticality"], "tool": tool,
                                 "issue": f"stale ({age} days)"})
            if tool == "edr" and min_sensor and _ver(rec.get("sensor_version", "0")) < _ver(min_sensor):
                gaps.append({"host": host, "owner": a["owner"], "criticality": a["criticality"], "tool": tool,
                             "issue": f"outdated sensor {rec['sensor_version']} < {min_sensor}"})
    # Hosts tools know about but inventory doesn't: shadow IT or stale CMDB.
    unknown = sorted({h for t in idx.values() for h in t} - set(inv))
    return gaps, unknown


def _ver(v):
    return tuple(int(x) for x in v.split(".") if x.isdigit())


def coverage(inventory, gaps):
    """Percent of in-scope hosts with each required tool present and current."""
    inv = index(inventory)
    out = {}
    for tool in ("edr", "siem", "scanner", "runtime"):
        scope = [h for h, a in inv.items() if tool in REQUIRED.get(a["type"], [])]
        bad = {g["host"] for g in gaps if g["tool"] == tool and not g["issue"].startswith("outdated")}
        if scope:
            out[tool] = round(100 * (len(scope) - len(bad & set(scope))) / len(scope), 1)
    return out
