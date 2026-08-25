from detection.rules import (
    detect_ssh_open_to_internet,
    detect_rdp_open_to_internet,
    detect_unrestricted_inbound_port,
    detect_public_s3_bucket,
    detect_public_s3_objects,
    detect_s3_encryption_disabled,
    detect_overly_permissive_iam_policy,
    detect_privileged_user_without_mfa,
    detect_unused_access_key
)


def scan_security_groups(security_groups):
    findings = []

    for rule in security_groups:
        detectors = [
            detect_ssh_open_to_internet,
            detect_rdp_open_to_internet,
            detect_unrestricted_inbound_port
        ]

        for detector in detectors:
            finding = detector(rule)

            if finding:
                findings.append(finding)

    return findings


def scan_s3(buckets):
    findings = []

    for bucket in buckets:
        detectors = [
            detect_public_s3_bucket,
            detect_public_s3_objects,
            detect_s3_encryption_disabled
        ]

        for detector in detectors:
            finding = detector(bucket)

            if finding:
                findings.append(finding)

    return findings


def scan_iam(resources):
    findings = []

    for resource in resources:
        resource_type = resource.get("type")

        if resource_type == "policy":
            finding = detect_overly_permissive_iam_policy(resource)

        elif resource_type == "user":
            finding = detect_privileged_user_without_mfa(resource)

        elif resource_type == "access_key":
            finding = detect_unused_access_key(resource)

        else:
            finding = None

        if finding:
            findings.append(finding)

    return findings