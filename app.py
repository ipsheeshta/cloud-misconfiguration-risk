from flask import Flask, render_template, redirect, url_for

from database.db import (
    get_latest_scan_findings,
    get_latest_scan_info,
    initialize_database,
    create_scan,
    save_finding
)

from scanner.mock_scanner import run_scan

app = Flask(__name__)

def get_service_counts(findings):
    """Count findings by AWS service."""

    counts = {
        "Security Groups": 0,
        "S3": 0,
        "IAM": 0
    }

    for finding in findings:
        rule_id = finding["rule_id"]

        if rule_id.startswith("SG-"):
            counts["Security Groups"] += 1

        elif rule_id.startswith("S3-"):
            counts["S3"] += 1

        elif rule_id.startswith("IAM-"):
            counts["IAM"] += 1

    return counts

@app.route("/")
def dashboard():
    findings = get_latest_scan_findings()
    scan = get_latest_scan_info()

    service_counts = get_service_counts(findings)

    return render_template(
        "dashboard.html",
        findings=findings,
        scan=scan,
        service_counts=service_counts
    )


@app.route("/scan", methods=["POST"])
def run_new_scan():
    initialize_database()

    scan_id = create_scan()

    results = run_scan("mock_data/aws_config.json")

    for finding in results:
        save_finding(finding, scan_id)

    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(debug=True)