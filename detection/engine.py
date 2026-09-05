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


def add_resource_context(finding, resource):
    """Attach service and resource information to a finding."""

    result = finding.copy()

    result["resource_id"] = resource.get("id")
    result["resource_name"] = resource.get("name")
    
    return result


def scan_security_groups(security_groups):
    findings = []

    detectors = [
        detect_ssh_open_to_internet,
        detect_rdp_open_to_internet,
        detect_unrestricted_inbound_port
    ]

    for rule in security_groups:
        for detector in detectors:
            finding = detector(rule)

            if finding:
                findings.append(
                    add_resource_context(finding, rule)
                )

    return findings


def scan_s3(buckets):
    findings = []

    detectors = [
        detect_public_s3_bucket,
        detect_public_s3_objects,
        detect_s3_encryption_disabled
    ]

    for bucket in buckets:
        for detector in detectors:
            finding = detector(bucket)

            if finding:
                findings.append(
                    add_resource_context(finding, bucket)
                )

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
            findings.append(
                add_resource_context(finding, resource)
            )

    return findings