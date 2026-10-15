# Security Coverage Reconciler

Every security tool keeps its own host list: the EDR console, the SIEM's log sources, the vulnerability scanner, the container runtime agent. Nobody's job is to compare them, so the gaps sit there until an incident lands on the one server with no sensor.

This tool reconciles the asset inventory against each tool and reports:

- **Missing coverage** by asset type (servers need EDR + SIEM + scanner; container hosts also need runtime protection)
- **Stale agents**: EDR not checked in for 7 days, no SIEM events in a day, no scan in 30 days
- **Outdated EDR sensors** below a minimum version
- **Shadow hosts** that tools can see but the inventory does not
- **Coverage percentage** per tool, the number leadership asks for

Host names are normalized (FQDN vs short name, case), because tools rarely agree on them.

### Mixed EDR fleets

Many environments run more than one EDR (CrowdStrike on servers, Defender on laptops, SentinelOne after an acquisition). Pass each console's raw export with its vendor and the tool merges them, keeping the latest check-in per host:

```bash
python -m scr.cli --inventory samples/inventory.csv \
  --edr defender:samples/defender_laptops.csv --edr sentinelone:samples/s1_servers.csv \
  --scanner samples/scanner.csv --today 2026-10-14 --controls
```

Supported exports: CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne, or a generic CSV.

### Audit mapping

`--controls` tags every gap with the CIS Controls v8 safeguard and NIST CSF 2.0 subcategory it affects (for example a missing EDR agent maps to CIS 10.1 / DE.CM-09, an unknown host to CIS 1.1 / ID.AM-01), so the output can go straight into an audit or posture report.

## Run

```bash
python -m scr.cli --inventory samples/inventory.csv --edr samples/edr.csv --siem samples/siem.csv \
  --scanner samples/scanner.csv --runtime samples/runtime.csv --min-sensor 7.15.0 --today 2026-10-14
```

Feed it nightly exports (CrowdStrike/Defender host lists, SIEM source inventory, Tenable assets, CMDB) and it exits non-zero when a high-criticality host is missing a control.

## Security tool health (L2 operations)

Coverage asks "is every host in every tool?". `--health` asks "is every tool working?":

```bash
python -m scr.cli --health samples/tool_health.csv
```

```
Tool health: CrowdStrike=degraded  Delinea=healthy  Google SecOps=degraded  Ping Identity=healthy  Tanium=degraded
  [P1] Google SecOps  Palo Alto firewall feed   feed silent            no events for 31 h  -> escalate to L3
  [P2] CrowdStrike    SIEM streaming API        integration failing    401 Unauthorized: API client secret rotated  -> escalate to L3
  [P2] Tanium         Tanium Server             certificate expiring   expires in 5 days
  [P3] CrowdStrike    Falcon platform           below minimum version  7.16.1 < 7.18.0
```

- **Silent SIEM feeds** (Google SecOps, Splunk, Sentinel): P2 after 6 hours, P1 after 24
- **Failing integrations and connectors** with the vendor error, e.g. an expired API secret
- **Platforms below the minimum version**, for patch and upgrade planning
- **Licences at 90%+** and **TLS certificates** expiring within 30 days or already expired
- Every issue gets a priority, a first-step runbook action, and an L3 escalation flag when it is P1 or failing for over 24 hours. Exit code 1 on any P1, so it can run on a schedule and page.

The input is one row per tool component, exported from each platform's health/status API or filled by a scheduled script.
