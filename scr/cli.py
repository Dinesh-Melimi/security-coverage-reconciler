import argparse
import sys
from datetime import date

from .adapters import VENDORS, load_edr, merge
from .controls import tag
from .core import coverage, read, reconcile
from .health import check, load, summary
from .metrics import render_prometheus

CRIT = {"high": 0, "medium": 1, "low": 2}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Find hosts missing or stale in security tools.")
    ap.add_argument("--inventory", help="Asset inventory CSV (required for coverage checks)")
    ap.add_argument("--edr", action="append", default=[], help="EDR export, as PATH or VENDOR:PATH (repeatable)"); ap.add_argument("--siem"); ap.add_argument("--scanner"); ap.add_argument("--runtime")
    ap.add_argument("--min-sensor", help="Minimum acceptable EDR sensor version")
    ap.add_argument("--today", default=date.today().isoformat())
    ap.add_argument("--controls", action="store_true", help="Show CIS v8 / NIST CSF mapping for each gap")
    ap.add_argument("--health", help="Tool health CSV: check the security tools themselves instead of coverage")
    ap.add_argument("--now", help="Override current time for --health (ISO)")
    ap.add_argument("--prometheus", help="With --health, write Prometheus metrics to this file")
    a = ap.parse_args(argv)
    if a.health:
        return _health(a)
    if not a.inventory:
        ap.error("--inventory is required unless --health is used")
    ap_controls = a.controls
    tools = {k: read(getattr(a, k)) for k in ("siem", "scanner", "runtime") if getattr(a, k)}
    if a.edr:
        parts = []
        for spec in a.edr:
            vendor, _, path = spec.partition(":") if spec.split(":")[0] in VENDORS else ("generic", "", spec)
            parts.append(load_edr(path, vendor))
        tools["edr"] = merge(*parts)
    inv = read(a.inventory)
    gaps, unknown = reconcile(inv, tools, date.fromisoformat(a.today), a.min_sensor)
    cov = coverage(inv, gaps, tuple(tools))
    print("Coverage: " + "  ".join(f"{k.upper()} {v}%" for k, v in cov.items()))
    for g in sorted(gaps, key=lambda g: (CRIT.get(g["criticality"], 9), g["host"])):
        line = f"  [{g['criticality']:6}] {g['host']:14} {g['tool']:8} {g['issue']:28} owner={g['owner']}"
        if ap_controls:
            t = tag([g], [])[0]
            line += f"  | {t['cis']} | {t['nist_csf']}"
        print(line)
    if unknown:
        print("Seen by tools but not in inventory: " + ", ".join(unknown))
    return 1 if any(g["criticality"] == "high" and g["issue"] == "missing" for g in gaps) else 0


def _health(a):
    from datetime import datetime

    rows = load(a.health)
    issues = check(rows, datetime.fromisoformat(a.now) if a.now else datetime.now())
    print("Tool health: " + "  ".join(f"{t}={st}" for t, st in summary(rows, issues).items()))
    for i in issues:
        esc = "  -> escalate to L3" if i["escalate_l3"] else ""
        print(f"  [{i['priority']}] {i['tool']:14} {i['component']:32} {i['issue']:22} {i['detail']}{esc}")
        print(f"        next step: {i['action']}")
    if a.prometheus:
        states = summary(rows, issues)
        with open(a.prometheus, "w") as fh:
            fh.write(render_prometheus(rows, issues, states))
        print(f"Prometheus metrics written to {a.prometheus}")
    return 1 if any(i["priority"] == "P1" for i in issues) else 0


if __name__ == "__main__":
    sys.exit(main())
