import argparse
import sys
from datetime import date

from .adapters import VENDORS, load_edr, merge
from .controls import tag
from .core import coverage, read, reconcile

CRIT = {"high": 0, "medium": 1, "low": 2}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Find hosts missing or stale in security tools.")
    ap.add_argument("--inventory", required=True)
    ap.add_argument("--edr", action="append", default=[], help="EDR export, as PATH or VENDOR:PATH (repeatable)"); ap.add_argument("--siem"); ap.add_argument("--scanner"); ap.add_argument("--runtime")
    ap.add_argument("--min-sensor", help="Minimum acceptable EDR sensor version")
    ap.add_argument("--today", default=date.today().isoformat())
    ap.add_argument("--controls", action="store_true", help="Show CIS v8 / NIST CSF mapping for each gap")
    a = ap.parse_args(argv)
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


if __name__ == "__main__":
    sys.exit(main())
