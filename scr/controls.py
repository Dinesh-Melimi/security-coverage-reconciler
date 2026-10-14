"""Map coverage gaps to CIS Controls v8 and NIST CSF 2.0 so findings land in audit language."""

MAP = {
    "edr": ("CIS 10.1 Deploy and maintain anti-malware software", "DE.CM-09"),
    "siem": ("CIS 8.2 Collect audit logs", "DE.CM-01"),
    "scanner": ("CIS 7.5 Perform automated vulnerability scans of internal assets", "ID.RA-01"),
    "runtime": ("CIS 13.2 Deploy a host-based intrusion detection solution", "DE.CM-09"),
    "inventory": ("CIS 1.1 Establish and maintain a detailed enterprise asset inventory", "ID.AM-01"),
}


def tag(gaps, unknown):
    out = [dict(g, cis=MAP[g["tool"]][0], nist_csf=MAP[g["tool"]][1]) for g in gaps]
    out += [{"host": h, "tool": "inventory", "issue": "not in asset inventory", "owner": "", "criticality": "unknown",
             "cis": MAP["inventory"][0], "nist_csf": MAP["inventory"][1]} for h in unknown]
    return out
