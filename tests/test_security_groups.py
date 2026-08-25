from detection.rules import detect_ssh_open_to_internet


def test_ssh_open_to_internet():
    rule = {
        "protocol": "tcp",
        "port": 22,
        "source": "0.0.0.0/0"
    }

    result = detect_ssh_open_to_internet(rule)

    assert result is not None
    assert result["rule_id"] == "SG-01"
    assert result["severity"] == 5



from risk.risk_engine import calculate_risk


def test_ssh_open_to_internet_risk():
    rule = {
        "protocol": "tcp",
        "port": 22,
        "source": "0.0.0.0/0"
    }

    finding = detect_ssh_open_to_internet(rule)

    risk = calculate_risk(
        finding["severity"],
        finding["exposure"],
        finding["impact"]
    )

    assert finding["rule_id"] == "SG-01"
    assert risk["score"] == 125
    assert risk["priority"] == "CRITICAL"



from detection.rules import detect_rdp_open_to_internet


def test_rdp_open_to_internet():
    rule = {
        "protocol": "tcp",
        "port": 3389,
        "source": "0.0.0.0/0"
    }

    finding = detect_rdp_open_to_internet(rule)

    assert finding is not None
    assert finding["rule_id"] == "SG-02"
    assert finding["severity"] == 5


from detection.rules import detect_unrestricted_inbound_port


def test_unrestricted_inbound_port():
    rule = {
        "protocol": "tcp",
        "port": 8080,
        "source": "0.0.0.0/0"
    }

    finding = detect_unrestricted_inbound_port(rule)

    assert finding is not None
    assert finding["rule_id"] == "SG-03"
    assert finding["severity"] == 4