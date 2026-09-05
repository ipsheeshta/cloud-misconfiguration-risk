import sqlite3


DATABASE = "database/findings.db"


def get_connection():
    """Create a connection to the SQLite database."""
    return sqlite3.connect(DATABASE)


def initialize_database():
    """Create database tables if they don't exist."""

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            rule_id TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            resource_id TEXT,
            resource_name TEXT,
            severity INTEGER,
            exposure INTEGER,
            impact INTEGER,
            risk_score INTEGER,
            priority TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    connection.commit()
    connection.close()


def create_scan():
    """Create a new scan record and return its ID."""

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("INSERT INTO scans DEFAULT VALUES")

    scan_id = cursor.lastrowid

    connection.commit()
    connection.close()

    return scan_id


def save_finding(finding, scan_id):

    """Save a security finding to the database."""

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""

        INSERT INTO findings (
            scan_id,
            rule_id,
            title,
            description,
            resource_id,
            resource_name,
            severity,
            exposure,
            impact,
            risk_score,
            priority
        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

    """, (
        scan_id,
        finding["rule_id"],
        finding["title"],
        finding["description"],
        finding.get("resource_id"),
        finding.get("resource_name"),
        finding["severity"],
        finding["exposure"],
        finding["impact"],
        finding["risk_score"],
        finding["priority"]
    )) 

    connection.commit()
    connection.close()


def get_all_findings():
    """Return all findings from the database."""

    connection = get_connection()
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM findings
        ORDER BY risk_score DESC
    """)

    findings = [dict(row) for row in cursor.fetchall()]

    connection.close()

    return findings


def get_latest_scan_findings():
    """Return findings belonging to the most recent scan."""

    connection = get_connection()
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM findings
        WHERE scan_id = (
            SELECT MAX(id)
            FROM scans
        )
        ORDER BY risk_score DESC
    """)

    findings = [dict(row) for row in cursor.fetchall()]

    connection.close()

    return findings

def get_latest_scan_info():
    """Return information about the most recent scan."""

    connection = get_connection()
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM scans
        ORDER BY id DESC
        LIMIT 1
    """)

    scan = cursor.fetchone()

    connection.close()

    return dict(scan) if scan else None
