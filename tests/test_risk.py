from risk.risk_engine import calculate_risk


def test_critical_risk():
    result = calculate_risk(5, 5, 5)

    assert result["score"] == 125
    assert result["priority"] == "CRITICAL"


def test_medium_risk():
    result = calculate_risk(3, 3, 5)

    assert result["score"] == 45
    assert result["priority"] == "MEDIUM"


def test_low_risk():
    result = calculate_risk(2, 2, 2)

    assert result["score"] == 8
    assert result["priority"] == "LOW"