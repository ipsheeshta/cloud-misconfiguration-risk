import json
from database.db import (initialize_database, create_scan, save_finding)

from detection.engine import (
    scan_security_groups,
    scan_s3,
    scan_iam
)

from risk.prioritizer import prioritize_findings


def load_config(file_path):
    """Load simulated AWS configuration from a JSON file."""

    with open(file_path, "r") as file:
        return json.load(file)


def run_scan(file_path):
    """Run the complete misconfiguration scan."""

    config = load_config(file_path)

    findings = []

    findings.extend(
        scan_security_groups(
            config.get("security_groups", [])
        )
    )

    findings.extend(
        scan_s3(
            config.get("s3", [])
        )
    )

    findings.extend(
        scan_iam(
            config.get("iam", [])
        )
    )

    prioritized_findings = prioritize_findings(findings)

    return prioritized_findings


if __name__ == "__main__":
    initialize_database()

    scan_id = create_scan()

    results = run_scan("mock_data/aws_config.json")

    for finding in results:
        save_finding(finding, scan_id)

    print("\n" + "=" * 75)
    print(" CLOUD MISCONFIGURATION SCAN")
    print("=" * 75)

    for finding in results:
        print(
            f"{finding['priority']:<10} "
            f"{finding['risk_score']:<5} "
            f"{finding['rule_id']:<8} "
            f"{finding['resource_name']:<25} "
            f"{finding['title']}"
        )

    print("=" * 75)
    print(f"Total findings: {len(results)}")
    print(f"Scan ID: {scan_id}")
    print("Findings saved to database.")