"""Normalize host exports from different EDR consoles into one shape: hostname, last_seen, sensor_version.

Each vendor names the same fields differently. Add a mapping here instead of hand-editing CSVs.
"""
import csv

VENDORS = {
    # CrowdStrike Falcon "Hosts" export
    "crowdstrike": {"hostname": "Hostname", "last_seen": "Last Seen", "sensor_version": "Sensor Version"},
    # Microsoft Defender for Endpoint "Device inventory" export
    "defender": {"hostname": "Device Name", "last_seen": "Last device update", "sensor_version": "Sensor version"},
    # SentinelOne "Endpoints" export
    "sentinelone": {"hostname": "Endpoint Name", "last_seen": "Last Active", "sensor_version": "Agent Version"},
    # Already-normalized CSV
    "generic": {"hostname": "hostname", "last_seen": "last_seen", "sensor_version": "sensor_version"},
}


def _date(value):
    """Accept '2026-10-14', '2026-10-14T08:10:00', '2026-10-14 08:10:00', '10/14/2026 08:10'."""
    v = value.strip()
    if "/" in v:
        m, d, y = v.split()[0].split("/")
        return f"{int(y):04d}-{int(m):02d}-{int(d):02d}"
    return v.replace(" ", "T")[:19] if "T" in v or " " in v else v[:10]


def load_edr(path, vendor="generic"):
    cols = VENDORS[vendor]
    with open(path, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    out = []
    for r in rows:
        out.append({
            "hostname": r[cols["hostname"]],
            "last_seen": _date(r[cols["last_seen"]]),
            "sensor_version": r.get(cols["sensor_version"], "") or "",
            "vendor": vendor,
        })
    return out


def merge(*lists):
    """Combine several EDR exports (e.g. CrowdStrike on servers, Defender on laptops).
    Keeps the most recent record per host."""
    best = {}
    for rows in lists:
        for r in rows:
            k = r["hostname"].strip().lower().split(".")[0]
            if k not in best or r["last_seen"] > best[k]["last_seen"]:
                best[k] = r
    return list(best.values())
