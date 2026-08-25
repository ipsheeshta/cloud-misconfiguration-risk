def calculate_risk(severity, exposure, impact):
    """
    Calculate the risk score of a cloud security finding.

    Risk Score = Severity × Exposure × Impact
    """

    score = severity * exposure * impact

    if score >= 100:
        priority = "CRITICAL"
    elif score >= 70:
        priority = "HIGH"
    elif score >= 40:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    return {
        "score": score,
        "priority": priority
    }