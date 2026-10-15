"""Export tool-health results as Prometheus metrics for Grafana dashboards and alerting.

A scheduled run writes a text-exposition file a Prometheus node_exporter textfile collector (or a
Pushgateway) picks up, so the same checks that gate CI also drive the NOC's Grafana health board.
"""
from __future__ import annotations

PRIORITY_VALUE = {"P1": 1, "P2": 2, "P3": 3}
STATE_VALUE = {"healthy": 0, "warning": 1, "degraded": 2}


def _label(s):
    return str(s).replace("\\", "\\\\").replace('"', '\\"')


def render_prometheus(rows, issues, summary_states):
    lines = [
        "# HELP security_tool_up Tool health state (0 healthy, 1 warning, 2 degraded).",
        "# TYPE security_tool_up gauge",
    ]
    for tool, state in sorted(summary_states.items()):
        lines.append(f'security_tool_up{{tool="{_label(tool)}"}} {STATE_VALUE[state]}')

    counts = {}
    for i in issues:
        counts[i["priority"]] = counts.get(i["priority"], 0) + 1
    lines += ["# HELP security_tool_issues_total Open tool-health issues by priority.",
              "# TYPE security_tool_issues_total gauge"]
    for p in ("P1", "P2", "P3"):
        lines.append(f'security_tool_issues_total{{priority="{p}"}} {counts.get(p, 0)}')

    lines += ["# HELP security_tool_issue Individual open issue (value is priority: 1=P1,2=P2,3=P3).",
              "# TYPE security_tool_issue gauge"]
    for i in issues:
        lines.append(
            f'security_tool_issue{{tool="{_label(i["tool"])}",component="{_label(i["component"])}",'
            f'issue="{_label(i["issue"])}",escalate_l3="{str(i["escalate_l3"]).lower()}"}} '
            f'{PRIORITY_VALUE[i["priority"]]}'
        )

    lines += ["# HELP security_tool_components_total Monitored components per tool.",
              "# TYPE security_tool_components_total gauge"]
    per_tool = {}
    for r in rows:
        per_tool[r["tool"]] = per_tool.get(r["tool"], 0) + 1
    for tool, n in sorted(per_tool.items()):
        lines.append(f'security_tool_components_total{{tool="{_label(tool)}"}} {n}')
    return "\n".join(lines) + "\n"
