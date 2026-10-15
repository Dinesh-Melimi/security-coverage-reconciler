from datetime import datetime

from scr.cli import main
from scr.health import check, load, summary
from scr.metrics import render_prometheus

NOW = datetime(2026, 10, 15, 9, 0)  # noqa: DTZ001


def _data():
    rows = load("samples/tool_health.csv")
    issues = check(rows, NOW)
    return rows, issues, summary(rows, issues)


def test_prometheus_format():
    rows, issues, states = _data()
    out = render_prometheus(rows, issues, states)
    assert "# TYPE security_tool_up gauge" in out
    assert 'security_tool_up{tool="Google SecOps"} 2' in out      # degraded
    assert 'security_tool_up{tool="Delinea"} 0' in out            # healthy
    assert 'security_tool_issues_total{priority="P1"} 1' in out
    assert 'escalate_l3="true"' in out
    # every metric line is key{labels} value
    for line in out.splitlines():
        if line and not line.startswith("#"):
            assert line.rsplit(" ", 1)[1].lstrip("-").isdigit()


def test_label_escaping():
    rows = [{"tool": 'weird"tool', "component": "c", "type": "feed"}]
    out = render_prometheus(rows, [], {'weird"tool': "healthy"})
    assert 'tool="weird\\"tool"' in out


def test_cli_writes_prometheus(tmp_path):
    out = tmp_path / "metrics.prom"
    main(["--health", "samples/tool_health.csv", "--now", "2026-10-15T09:00:00", "--prometheus", str(out)])
    assert "security_tool_issue{" in out.read_text()
