from detection.rules import (
    detect_overly_permissive_iam_policy,
    detect_privileged_user_without_mfa,
    detect_unused_access_key
)

def test_overly_permissive_iam_policy():
    policy = {
        "effect": "Allow",
        "action": "*",
        "resource": "*"
    }

    finding = detect_overly_permissive_iam_policy(policy)

    assert finding is not None
    assert finding["rule_id"] == "IAM-01"
    assert finding["severity"] == 5


def test_privileged_user_without_mfa():
    user = {
        "privileged": True,
        "mfa_enabled": False
    }

    finding = detect_privileged_user_without_mfa(user)

    assert finding is not None
    assert finding["rule_id"] == "IAM-02"
    assert finding["severity"] == 4
    


def test_unused_access_key():
    access_key = {
        "last_used_days": 120
    }

    finding = detect_unused_access_key(access_key)

    assert finding is not None
    assert finding["rule_id"] == "IAM-03"
    assert finding["severity"] == 3






    