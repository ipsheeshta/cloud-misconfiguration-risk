from risk.prioritizer import prioritize_findings


def test_findings_are_prioritized():

    findings = [
        {
            "rule_id": "S3-03",
            "severity": 3,
            "exposure": 2,
            "impact": 4
        },
        {
            "rule_id": "SG-01",
            "severity": 5,
            "exposure": 5,
            "impact": 5
        },
        {
            "rule_id": "IAM-02",
            "severity": 4,
            "exposure": 4,
            "impact": 5
        }
    ]

    results = prioritize_findings(findings)

    assert results[0]["rule_id"] == "SG-01"
    assert results[0]["risk_score"] == 125
    assert results[0]["priority"] == "CRITICAL"

    assert results[1]["rule_id"] == "IAM-02"
    assert results[1]["risk_score"] == 80

    assert results[2]["rule_id"] == "S3-03"
    assert results[2]["risk_score"] == 24