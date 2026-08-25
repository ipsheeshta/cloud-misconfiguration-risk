from risk.risk_engine import calculate_risk


def prioritize_findings(findings):
    """
    Calculate risk for every finding and sort them
    from highest to lowest risk.
    """

    prioritized = []

    for finding in findings:
        risk = calculate_risk(
            finding["severity"],
            finding["exposure"],
            finding["impact"]
        )

        result = finding.copy()

        result["risk_score"] = risk["score"]
        result["priority"] = risk["priority"]

        prioritized.append(result)

    prioritized.sort(
        key=lambda finding: finding["risk_score"],
        reverse=True
    )

    return prioritized
