def detect_ssh_open_to_internet(rule):
    """
    Detects whether SSH (port 22) is open to the entire internet.
    """

    if (
        rule.get("protocol") == "tcp"
        and rule.get("port") == 22
        and rule.get("source") == "0.0.0.0/0"
    ):
        return {
            "rule_id": "SG-01",
            "title": "SSH exposed to the internet",
            "description": "Port 22 is open to all IPv4 addresses.",
            "severity": 5,
            "exposure": 5,
            "impact": 5
        }

    return None


def detect_rdp_open_to_internet(rule):
    """
    Detects whether RDP (port 3389) is open to the entire internet.
    """

    if (
        rule.get("protocol") == "tcp"
        and rule.get("port") == 3389
        and rule.get("source") == "0.0.0.0/0"
    ):
        return {
            "rule_id": "SG-02",
            "title": "RDP exposed to the internet",
            "description": "Port 3389 is open to all IPv4 addresses.",
            "severity": 5,
            "exposure": 5,
            "impact": 5
        }

    return None



def detect_unrestricted_inbound_port(rule):
    """
    Detects non-standard inbound ports exposed to the entire internet.
    """

    excluded_ports = {22, 3389}

    if (
        rule.get("protocol") == "tcp"
        and rule.get("source") == "0.0.0.0/0"
        and rule.get("port") not in excluded_ports
    ):
        return {
            "rule_id": "SG-03",
            "title": "Unrestricted inbound port",
            "description": (
                f"TCP port {rule.get('port')} is open to all IPv4 addresses."
            ),
            "severity": 4,
            "exposure": 5,
            "impact": 4
        }

    return None

def detect_public_s3_bucket(bucket):
    """
    Detects whether an S3 bucket allows public access.
    """

    if bucket.get("public_access") is True:
        return {
            "rule_id": "S3-01",
            "title": "S3 bucket publicly accessible",
            "description": "The S3 bucket allows public access.",
            "severity": 5,
            "exposure": 5,
            "impact": 5
        }

    return None

def detect_public_s3_objects(bucket):
    """
    Detects whether objects in an S3 bucket can be publicly accessed.
    """

    if bucket.get("public_object_access") is True:
        return {
            "rule_id": "S3-02",
            "title": "S3 objects publicly accessible",
            "description": "Objects in the S3 bucket can be publicly accessed.",
            "severity": 4,
            "exposure": 5,
            "impact": 4
        }

    return None


def detect_s3_encryption_disabled(bucket):
    """
    Detects whether server-side encryption is disabled for an S3 bucket.
    """

    if bucket.get("encryption_enabled") is False:
        return {
            "rule_id": "S3-03",
            "title": "S3 bucket encryption disabled",
            "description": "The S3 bucket does not have server-side encryption enabled.",
            "severity": 3,
            "exposure": 2,
            "impact": 4
        }

    return None


def detect_overly_permissive_iam_policy(policy):
    """
    Detects an IAM policy that allows all actions on all resources.
    """

    if (
        policy.get("action") == "*"
        and policy.get("resource") == "*"
        and policy.get("effect") == "Allow"
    ):
        return {
            "rule_id": "IAM-01",
            "title": "Overly permissive IAM policy",
            "description": "The policy allows all actions on all resources.",
            "severity": 5,
            "exposure": 4,
            "impact": 5
        }

    return None


def detect_privileged_user_without_mfa(user):
    """
    Detects whether a privileged IAM user does not have MFA enabled.
    """

    if (
        user.get("privileged") is True
        and user.get("mfa_enabled") is False
    ):
        return {
            "rule_id": "IAM-02",
            "title": "Privileged IAM user without MFA",
            "description": "A privileged IAM user does not have MFA enabled.",
            "severity": 4,
            "exposure": 4,
            "impact": 5
        }

    return None


def detect_unused_access_key(access_key):
    """
    Detects an IAM access key that has not been used for 90 days or more.
    """

    if access_key.get("last_used_days", 0) >= 90:
        return {
            "rule_id": "IAM-03",
            "title": "Unused IAM access key",
            "description": "The access key has not been used for 90 days or more.",
            "severity": 3,
            "exposure": 3,
            "impact": 4
        }

    return None