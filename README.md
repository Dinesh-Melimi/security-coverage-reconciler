# Security Coverage Reconciler

Every security tool keeps its own host list: the EDR console, the SIEM's log sources, the vulnerability scanner, the container runtime agent. Nobody's job is to compare them, so the gaps sit there until an incident lands on the one server with no sensor.

This tool reconciles the asset inventory against each tool and reports:

- **Missing coverage** by asset type (servers need EDR + SIEM + scanner; container hosts also need runtime protection)
- **Stale agents**: EDR not checked in for 7 days, no SIEM events in a day, no scan in 30 days
- **Outdated EDR sensors** below a minimum version
- **Shadow hosts** that tools can see but the inventory does not
- **Coverage percentage** per tool, the number leadership asks for

Host names are normalized (FQDN vs short name, case), because tools rarely agree on them.

## Run

```bash
python -m scr.cli --inventory samples/inventory.csv --edr samples/edr.csv --siem samples/siem.csv \
  --scanner samples/scanner.csv --runtime samples/runtime.csv --min-sensor 7.15.0 --today 2026-10-14
```

Feed it nightly exports (CrowdStrike/Defender host lists, SIEM source inventory, Tenable assets, CMDB) and it exits non-zero when a high-criticality host is missing a control.
