from datetime import datetime


def create_scan(target):
    """
    Creates the central scan structure.

    Individual modules will be connected to this
    structure as we build the tool.
    """

    return {
        "target": target,
        "started_at": datetime.utcnow().isoformat() + "Z",
        "status": "running",

        "infrastructure": {
            "dns": None,
            "subdomains": [],
            "certificates": [],
            "asn_bgp": None,
            "staging": [],
            "eol_assets": [],
            "cloud_storage": []
        },

        "services": {
            "ports": [],
            "technologies": [],
            "admin_panels": [],
            "remote_services": [],
            "email_security": None,
            "apis": [],
            "cicd": [],
            "container_registries": [],
            "shadow_saas": []
        },

        "people": {
            "executives": [],
            "employees": [],
            "organization": [],
            "public_contacts": [],
            "documents": [],
            "social_exposure": [],
            "schedule_exposure": []
        },

        "credentials": {
            "breach_exposure": [],
            "combolist_exposure": [],
            "infostealer_exposure": [],
            "credential_reuse": [],
            "session_exposure": [],
            "secret_exposure": []
        },

        "code_documents": {
            "github": [],
            "gitlab": [],
            "secrets": [],
            "mobile_analysis": [],
            "paste_exposure": [],
            "archives": [],
            "technical_docs": [],
            "urls": []
        },

        "threat_landscape": {
            "adversary_chatter": [],
            "ransomware": [],
            "iab": [],
            "typosquatting": [],
            "phishing": [],
            "suppliers": [],
            "ttps": []
        },

        "findings": [],

        "summary": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
    }


def add_finding(scan, finding):
    """
    Adds a normalized security finding
    and automatically updates severity counts.
    """

    scan["findings"].append(finding)

    severity = finding.get(
        "severity",
        "Info"
    ).lower()

    if severity == "critical":
        scan["summary"]["critical"] += 1

    elif severity == "high":
        scan["summary"]["high"] += 1

    elif severity == "medium":
        scan["summary"]["medium"] += 1

    elif severity == "low":
        scan["summary"]["low"] += 1

    else:
        scan["summary"]["info"] += 1


def complete_scan(scan):
    """
    Marks the scan as completed.
    """

    scan["status"] = "completed"

    scan["completed_at"] = (
        datetime.utcnow().isoformat() + "Z"
    )

    return scan