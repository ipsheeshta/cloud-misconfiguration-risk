from database.db import (
    get_all_findings,
    get_latest_scan_findings
)


def test_get_all_findings():
    findings = get_all_findings()

    assert len(findings) > 0
    assert "rule_id" in findings[0]
    assert "risk_score" in findings[0]


def test_get_latest_scan_findings():
    findings = get_latest_scan_findings()

    assert len(findings) == 9
    assert findings[0]["risk_score"] >= findings[-1]["risk_score"]