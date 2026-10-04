from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
import csv
import html as html_lib
import io
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import threading
import uuid
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

# ============================================================
# OPTIONAL EXISTING PROJECT MODULES
# ============================================================

try:
    from modules.infrastructure.dns import scan_dns
except Exception:
    scan_dns = None

try:
    from modules.infrastructure.subdomains import enumerate_subdomains
except Exception:
    enumerate_subdomains = None

try:
    from modules.infrastructure.cert_transparency import enumerate_certificates
except Exception:
    enumerate_certificates = None

try:
    from modules.services_port_scan import scan_ports
except Exception:
    scan_ports = None

try:
    from modules.web_security import scan_web_security
except Exception:
    scan_web_security = None

try:
    from modules.web_crawler import crawl_site
except Exception:
    crawl_site = None

try:
    from core.scanner import create_scan as db_create_scan
    from core.scanner import complete_scan as db_complete_scan
except Exception:
    db_create_scan = None
    db_complete_scan = None


# ============================================================
# APPLICATION
# ============================================================

app = Flask(__name__)

# Session signing key is supplied by the deployment environment.
# Never hard-code production secrets in source control.
app.secret_key = os.environ.get(
    "VAPT_SECRET_KEY",
    "development-only-change-me",
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,
)
DB_PATH = os.path.join(os.path.dirname(__file__), "vapt.db")

scan_jobs = {}
scan_jobs_lock = threading.RLock()

DEFAULT_SCAN_PROFILE = "fast"

# ============================================================
# HIBP TEST MODE
# ============================================================

HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"

# Official HIBP test key.
# This key is only intended for HIBP's integration-test addresses.
HIBP_TEST_API_KEY = "00000000000000000000000000000000"

HIBP_REAL_API_KEY = os.environ.get("HIBP_API_KEY", "").strip()

# Keep test mode enabled until a real HIBP subscription is configured.
HIBP_TEST_MODE = os.environ.get(
    "HIBP_TEST_MODE",
    "true"
).strip().lower() in ("1", "true", "yes", "on")

HIBP_USER_AGENT = os.environ.get(
    "HIBP_USER_AGENT",
    "VAPT-Automation-Tool/1.0"
).strip()

HIBP_TEST_ACCOUNTS = {
    "account-exists@hibp-integration-tests.com",
    "multiple-breaches@hibp-integration-tests.com",
    "not-active-and-active-breach@hibp-integration-tests.com",
    "not-active-breach@hibp-integration-tests.com",
    "opt-out@hibp-integration-tests.com",
    "opt-out-breach@hibp-integration-tests.com",
    "paste-sensitive-breach@hibp-integration-tests.com",
    "unverified-breach@hibp-integration-tests.com",
    "spam-list-only@hibp-integration-tests.com",
    "stealer-log@hibp-integration-tests.com",
}

NMAP_PROFILES = {
    "fast": {
        "label": "Fast",
        "ports": "top-1000",
    },
    "standard": {
        "label": "Standard",
        "ports": "top-5000",
    },
    "full": {
        "label": "Full",
        "ports": "1-65535",
    },
}


# ============================================================
# BASIC HELPERS
# ============================================================

def utc_now():
    return datetime.now(timezone.utc).isoformat()


def json_safe(value):
    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        return str(value)


def shutil_which(name):
    return shutil.which(name)


def normalize_target(target):
    target = str(target or "").strip()

    if not target:
        raise ValueError("Target is required")

    if not re.match(r"^https?://", target, re.I):
        target = "https://" + target

    parsed = urllib.parse.urlparse(target)

    if not parsed.hostname:
        raise ValueError("Invalid target")

    return target.rstrip("/")


def extract_target_host(target):
    target = normalize_target(target)
    return urllib.parse.urlparse(target).hostname.lower().rstrip(".")


def normalize_profile(profile):
    profile = str(profile or DEFAULT_SCAN_PROFILE).lower().strip()
    return profile if profile in NMAP_PROFILES else DEFAULT_SCAN_PROFILE


def unique_list(values):
    result = []
    seen = set()

    for value in values or []:
        if value is None:
            continue

        value = str(value).strip()

        if not value:
            continue

        key = value.lower()

        if key not in seen:
            seen.add(key)
            result.append(value)

    return result


# ============================================================
# HTTP HELPERS
# ============================================================

def http_json_get(url, headers=None, timeout=15):
    req = urllib.request.Request(
        url,
        headers=headers or {
            "User-Agent": "VAPT-Automation-Tool/1.0"
        },
        method="GET",
    )

    with urllib.request.urlopen(req, timeout=timeout) as response:
        body = response.read().decode("utf-8", errors="replace")

        if not body:
            return {}

        return json.loads(body)


def http_text_get(url, headers=None, timeout=10, method="GET", max_bytes=512000):
    """Return HTTP details even for HTTPError responses such as 401/403/404."""
    req = urllib.request.Request(
        url,
        headers=headers or {"User-Agent": "VAPT-Automation-Tool/1.0"},
        method=method,
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read(max_bytes)
            return {
                "status_code": response.status,
                "headers": dict(response.headers),
                "body": raw.decode("utf-8", errors="replace"),
                "url": response.geturl(),
                "error": None,
            }
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(max_bytes)
        except Exception:
            raw = b""
        return {
            "status_code": exc.code,
            "headers": dict(exc.headers or {}),
            "body": raw.decode("utf-8", errors="replace"),
            "url": exc.geturl() or url,
            "error": f"HTTP {exc.code}",
        }

def check_http_methods(url, timeout=10):
    """Detect HTTP methods advertised by the target using OPTIONS."""
    result = {
        "status_code": None,
        "allowed_methods": [],
        "allow_header": None,
        "error": None,
    }

    headers = {
        "User-Agent": "VAPT-Automation-Tool/1.0"
    }

    try:
        req = urllib.request.Request(
            url,
            headers=headers,
            method="OPTIONS",
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                status = response.status
                response_headers = dict(response.headers or {})

        except urllib.error.HTTPError as exc:
            # OPTIONS commonly returns 405, but the response may still
            # contain the Allow header we need.
            status = exc.code
            response_headers = dict(exc.headers or {})

        allow = response_headers.get("Allow")

        if allow:
            methods = [
                method.strip().upper()
                for method in allow.split(",")
                if method.strip()
            ]
        else:
            methods = []

        result.update({
            "status_code": status,
            "allowed_methods": methods,
            "allow_header": allow,
        })

    except Exception as exc:
        result["error"] = str(exc)

    return result
# ============================================================
# JOB HELPERS
# ============================================================

def create_job(scan_id, target, profile):
    with scan_jobs_lock:
        scan_jobs[scan_id] = {
            "scan_id": scan_id,
            "target": target,
            "profile": profile,
            "profile_label": NMAP_PROFILES[profile]["label"],
            "status": "starting",
            "phase": "Initializing",
            "message": "Preparing security assessment...",
            "progress": 0,
            "started_at": utc_now(),
            "completed_at": None,

            "module_status": {},
            "module_progress": {},

            "http": {},
            "dns": {},
            "subdomains": {},
            "certificates": {},
            "technologies": [],
            "web_security": {},
            "crawler": {},
            "nmap": {},

            "subdomain_enumeration": {},
            "certificate_transparency": {},
            "dns_history_ns_recon": {},
            "asn_bgp": {},
            "dev_staging": {},
            "eol_assets": {},
            "cloud_storage": {},

            "port_technology_fingerprint": {},
            "admin_panels": {},
            "remote_services": {},
            "email_gateway": {},
            "public_apis": {},
            "cicd_registries": {},
            "shadow_saas": {},

            "executives": {},
            "linkedin": {},
            "org_chart": {},
            "public_contacts": {},
            "document_metadata": {},
            "social_media": {},
            "travel_schedule": {},

            "breach_corpus": {},
            "combolist": {},
            "infostealer": {},
            "credential_reuse": {},
            "corporate_cookies": {},
            "session_tokens": {},
            "git_paste_secrets": {},

            "git_orgs": {},
            "repo_secrets": {},
            "mobile_keys": {},
            "paste_leaks": {},
            "archive_snapshots": {},
            "technical_docs": {},
            "internal_urls": {},

            "adversary_chatter": {},
            "ransomware": {},
            "iab": {},
            "typosquats": {},
            "phishing": {},
            "supplier_risk": {},
            "sector_ttps": {},

            "findings": [],
            "summary": {},

            "features": {
                "infrastructure": {},
                "services": {},
                "people": {},
                "credentials": {},
                "code_docs": {},
                "threat_landscape": {},
            },

            "error": None,
        }


def get_job(scan_id):
    with scan_jobs_lock:
        job = scan_jobs.get(scan_id)

        if not job:
            return None

        return json_safe(job)


def update_job(scan_id, **updates):
    with scan_jobs_lock:
        job = scan_jobs.get(scan_id)

        if not job:
            return None

        for key, value in updates.items():
            job[key] = value

        return json_safe(job)


def update_module(scan_id, module, status, progress=0):
    with scan_jobs_lock:
        job = scan_jobs.get(scan_id)

        if not job:
            return None

        job.setdefault("module_status", {})
        job.setdefault("module_progress", {})

        job["module_status"][module] = status
        job["module_progress"][module] = max(
            0,
            min(100, int(progress)),
        )

        return json_safe(job)


def set_module_progress(
    scan_id,
    module,
    progress,
    message=None,
    status=None,
):
    with scan_jobs_lock:
        job = scan_jobs.get(scan_id)

        if not job:
            return None

        job.setdefault("module_progress", {})
        job.setdefault("module_status", {})

        job["module_progress"][module] = max(
            0,
            min(100, int(progress)),
        )

        if status is not None:
            job["module_status"][module] = status

        if message:
            job["message"] = message

        return json_safe(job)


def calculate_overall_progress(scan_id):
    """Return live progress without allowing 100% before finalization.

    100% is reserved for the single final state where the complete result
    has been assembled and the job status is changed to ``completed``.
    This prevents the UI from seeing 100% while the background thread is
    still building features/results.
    """
    with scan_jobs_lock:
        job = scan_jobs.get(scan_id)

        if not job:
            return 0

        values = list(
            job.get("module_progress", {}).values()
        )

        if not values:
            current = int(job.get("progress", 0) or 0)
        else:
            current = int(sum(values) / len(values))

        # Never expose 100% while the scan is still running.
        if job.get("status") != "completed":
            return min(99, max(0, current))

        return min(100, max(0, current))


# ============================================================
# DNS / NS RECON
# ============================================================

def resolve_target_ips(host):
    results = []

    try:
        infos = socket.getaddrinfo(
            host,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )

        seen = set()

        for info in infos:
            address = info[4][0]

            if address in seen:
                continue

            seen.add(address)

            try:
                ip_version = ipaddress.ip_address(address).version
            except Exception:
                ip_version = None

            results.append({
                "ip": address,
                "version": ip_version,
            })

    except Exception as exc:
        return {
            "ips": [],
            "count": 0,
            "error": str(exc),
        }

    return {
        "ips": results,
        "count": len(results),
    }


def collect_dns_ns_recon(target):
    host = extract_target_host(target)

    result = {
        "target": host,
        "status": "completed",
        "source": "DNS resolution / nslookup",
        "records": {},
        "nameservers": [],
        "ips": [],
        "errors": [],
    }

    ip_result = resolve_target_ips(host)

    result["ips"] = ip_result.get("ips", [])

    if ip_result.get("error"):
        result["errors"].append(ip_result["error"])

    record_types = [
        "A",
        "AAAA",
        "MX",
        "NS",
        "TXT",
        "CNAME",
    ]

    for record_type in record_types:
        try:
            if record_type == "A":
                values = socket.gethostbyname_ex(host)[2]

            elif record_type == "AAAA":
                values = []

                infos = socket.getaddrinfo(
                    host,
                    None,
                    socket.AF_INET6,
                )

                for info in infos:
                    values.append(info[4][0])

            else:
                command = [
                    "nslookup",
                    "-type=" + record_type,
                    host,
                ]

                proc = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                output = proc.stdout + "\n" + proc.stderr
                values = []

                for line in output.splitlines():
                    line = line.strip()

                    if not line:
                        continue

                    low = line.lower()

                    if (
                        record_type == "NS"
                        and "nameserver" in low
                    ):
                        parts = line.split("=")

                        if len(parts) >= 2:
                            values.append(
                                parts[-1].strip().rstrip(".")
                            )

                    elif (
                        record_type == "MX"
                        and "mail exchanger" in low
                    ):
                        parts = line.split("=")

                        if len(parts) >= 2:
                            value = (
                                parts[-1]
                                .strip()
                                .rstrip(".")
                            )

                            if value and value != "(root)":
                                values.append(value)

                    elif (
                        record_type == "TXT"
                        and "text =" in low
                    ):
                        values.append(
                            line.split("=", 1)[1].strip()
                        )

                    elif (
                        record_type == "CNAME"
                        and "canonical name" in low
                    ):
                        parts = line.split("=")

                        if len(parts) >= 2:
                            values.append(
                                parts[-1]
                                .strip()
                                .rstrip(".")
                            )

            result["records"][record_type] = unique_list(values)

        except Exception as exc:
            result["records"][record_type] = []
            result["errors"].append(
                f"{record_type}: {exc}"
            )

    result["nameservers"] = result["records"].get(
        "NS",
        [],
    )

    return result
# ============================================================
# CERTIFICATE TRANSPARENCY
# ============================================================

def collect_certificate_transparency(target):
    host = extract_target_host(target)

    result = {
        "target": host,
        "status": "completed",
        "source": "crt.sh Certificate Transparency",
        "source_status": "primary",
        "primary_source": "crt.sh Certificate Transparency",
        "fallback_used": False,
        "certificates": [],
        "subdomains": [],
        "count": 0,
        "errors": [],
    }

    def normalize_certspotter(data):
        certificates = []
        discovered_names = set()
        seen_certs = set()

        if not isinstance(data, list):
            raise ValueError("Cert Spotter returned an unexpected response format")

        for cert in data:
            if not isinstance(cert, dict):
                continue

            names = []

            raw_names = cert.get("dns_names", [])

            if isinstance(raw_names, str):
                raw_names = [raw_names]

            if not isinstance(raw_names, list):
                raw_names = []

            for name in raw_names:
                name = str(name).strip().lower()

                if not name:
                    continue

                if name.startswith("*."):
                    name = name[2:]

                if (
                    name == host
                    or name.endswith("." + host)
                ):
                    discovered_names.add(name)
                    names.append(name)

            names = unique_list(names)

            if not names:
                continue

            issuer = cert.get("issuer")

            if isinstance(issuer, dict):
                issuer_name = (
                    issuer.get("friendly_name")
                    or issuer.get("name")
                    or issuer.get("organization")
                )
            else:
                issuer_name = issuer

            cert_key = (
                cert.get("id"),
                cert.get("cert_sha256"),
                cert.get("serial_number"),
                cert.get("not_before"),
                cert.get("not_after"),
                tuple(names),
            )

            if cert_key in seen_certs:
                continue

            seen_certs.add(cert_key)

            certificates.append({
                "id": cert.get("id"),
                "common_name": (
                    names[0]
                    if names
                    else None
                ),
                "issuer_name": issuer_name,
                "name_value": names,
                "dns_names": names,
                "not_before": cert.get("not_before"),
                "not_after": cert.get("not_after"),
                "serial_number": cert.get("serial_number"),
                "cert_sha256": cert.get("cert_sha256"),
                "revoked": cert.get("revoked"),
            })

        return (
            certificates,
            sorted(discovered_names),
        )

    # --------------------------------------------------------
    # PRIMARY SOURCE: crt.sh
    # --------------------------------------------------------

    try:
        query = urllib.parse.quote(
            "%." + host,
            safe="",
        )

        url = (
            "https://crt.sh/"
            "?q=" + query +
            "&output=json"
        )

        data = http_json_get(
            url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 "
                    "(Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 "
                    "Chrome/154 Safari/537.36"
                ),
                "Accept": "application/json,text/plain,*/*",
            },
            timeout=30,
        )

        if not isinstance(data, list):
            raise ValueError(
                "crt.sh returned an unexpected response format"
            )

        certificates = []
        discovered_names = set()
        seen_certs = set()

        for cert in data:
            if not isinstance(cert, dict):
                continue

            names = []
            raw_names = cert.get(
                "name_value",
                "",
            )

            for name in str(raw_names).splitlines():
                name = name.strip().lower()

                if not name:
                    continue

                if name.startswith("*."):
                    name = name[2:]

                if (
                    name == host
                    or name.endswith("." + host)
                ):
                    discovered_names.add(name)
                    names.append(name)

            names = unique_list(names)

            cert_key = (
                cert.get("serial_number"),
                cert.get("common_name"),
                cert.get("not_before"),
                cert.get("not_after"),
                tuple(names),
            )

            if cert_key in seen_certs:
                continue

            seen_certs.add(cert_key)

            certificates.append({
                "id": cert.get("id"),
                "common_name": cert.get("common_name"),
                "issuer_name": cert.get("issuer_name"),
                "name_value": names,
                "not_before": cert.get("not_before"),
                "not_after": cert.get("not_after"),
                "serial_number": cert.get("serial_number"),
            })

        # A valid empty response means the source itself worked.
        result["certificates"] = certificates
        result["subdomains"] = sorted(discovered_names)
        result["count"] = len(certificates)

        return result

    except Exception as primary_exc:
        primary_error = str(primary_exc)

        result["errors"].append(
            "crt.sh: " + primary_error
        )

    # --------------------------------------------------------
    # FALLBACK SOURCE: Cert Spotter / SSLMate
    # --------------------------------------------------------

    try:
        fallback_url = (
            "https://api.certspotter.com/v1/issuances"
            "?domain=" + urllib.parse.quote(host, safe="")
            + "&include_subdomains=true"
            + "&match_wildcards=true"
            + "&expand=dns_names"
        )

        fallback_data = http_json_get(
            fallback_url,
            headers={
                "User-Agent": "VAPT-Automation-Tool/1.0",
                "Accept": "application/json",
            },
            timeout=20,
        )

        certificates, discovered_names = normalize_certspotter(
            fallback_data
        )

        result["status"] = "completed"
        result["source"] = (
            "Cert Spotter Certificate Transparency"
        )
        result["source_status"] = "fallback"
        result["fallback_used"] = True
        result["certificates"] = certificates
        result["subdomains"] = discovered_names
        result["count"] = len(certificates)

        return result

    except Exception as fallback_exc:
        fallback_error = str(fallback_exc)

        result["status"] = "unavailable"
        result["source"] = (
            "Certificate Transparency sources"
        )
        result["source_status"] = "unavailable"
        result["fallback_used"] = True
        result["error"] = (
            "Both Certificate Transparency sources "
            "were unavailable."
        )
        result["errors"].append(
            "Cert Spotter: " + fallback_error
        )

        return result


# ============================================================
# HTTP SECURITY ASSESSMENT
# ============================================================

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]


def _header_map(headers):
    return {str(k).lower(): str(v) for k, v in (headers or {}).items()}


def _csv_header_values(value):
    if not value:
        return []
    return unique_list([x.strip().upper() for x in str(value).split(",") if x.strip()])


def _safe_http_probe(url, method="GET", headers=None, timeout=10):
    return http_text_get(url, headers=headers, timeout=timeout, method=method, max_bytes=256000)


def http_assessment(target, scan_id=None):
    if scan_id:
        set_module_progress(scan_id, "http", 10, "Starting HTTP assessment", "running")

    result = {
        "target": target,
        "status": "error",
        "status_code": None,
        "final_url": target,
        "headers": {},
        "security_headers": [],
        "missing_security_headers": [],
        "cors": {
            "enabled": False,
            "allow_origin": None,
            "allow_credentials": None,
            "allow_methods": None,
            "allow_headers": None,
            "vary": None,
            "preflight": {},
        },
        "http_methods": {
            "status_code": None,
            "allow": [],
            "methods": [],
            "tested": ["OPTIONS", "HEAD"],
            "responses": {},
        },
        "technologies": [],
        "tls": {},
        "errors": [],
    }

    try:
        response = http_text_get(target, timeout=15)
        headers = response.get("headers", {}) or {}
        lower_headers = _header_map(headers)

        result["status"] = "completed"
        result["status_code"] = response.get("status_code")
        result["final_url"] = response.get("url") or target
        result["headers"] = headers

        for header in SECURITY_HEADERS:
            value = lower_headers.get(header.lower(), "")
            result["security_headers"].append({
                "name": header,
                "present": bool(value),
                "value": value,
            })
            if not value:
                result["missing_security_headers"].append(header)

        # --------------------------------------------------------
        # CORS: make an actual cross-origin-style request instead
        # of relying only on the normal page response.
        # --------------------------------------------------------
        origin = "https://security-test.invalid"
        cors_headers = {
            "User-Agent": "VAPT-Automation-Tool/1.0",
            "Origin": origin,
        }
        cors_response = _safe_http_probe(target, "GET", cors_headers, 10)
        ch = _header_map(cors_response.get("headers", {}))

        preflight = _safe_http_probe(
            target,
            "OPTIONS",
            {
                "User-Agent": "VAPT-Automation-Tool/1.0",
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Content-Type, Authorization",
            },
            10,
        )
        ph = _header_map(preflight.get("headers", {}))

        allow_origin = ch.get("access-control-allow-origin") or ph.get("access-control-allow-origin")
        allow_credentials = ch.get("access-control-allow-credentials") or ph.get("access-control-allow-credentials")
        allow_methods = ch.get("access-control-allow-methods") or ph.get("access-control-allow-methods")
        allow_headers = ch.get("access-control-allow-headers") or ph.get("access-control-allow-headers")
        vary = ch.get("vary") or ph.get("vary")

        result["cors"] = {
            "enabled": bool(allow_origin or allow_credentials or allow_methods or allow_headers),
            "allow_origin": allow_origin,
            "allow_credentials": allow_credentials,
            "allow_methods": allow_methods,
            "allow_headers": allow_headers,
            "vary": vary,
            "preflight": {
                "status_code": preflight.get("status_code"),
                "headers": preflight.get("headers", {}),
            },
        }

        # --------------------------------------------------------
        # HTTP methods: OPTIONS is authoritative when Allow exists.
        # HEAD is safe to probe. Do not send state-changing methods.
        # --------------------------------------------------------
        opt = _safe_http_probe(
            target,
            "OPTIONS",
            {"User-Agent": "VAPT-Automation-Tool/1.0", "Origin": origin},
            10,
        )
        oh = _header_map(opt.get("headers", {}))
        allowed = _csv_header_values(oh.get("allow"))
        ac_methods = _csv_header_values(oh.get("access-control-allow-methods"))
        methods = unique_list(allowed + ac_methods)

        head = _safe_http_probe(
            target,
            "HEAD",
            {"User-Agent": "VAPT-Automation-Tool/1.0"},
            10,
        )
        result["http_methods"] = {
            "status_code": opt.get("status_code"),
            "allow": allowed,
            "allowed_methods": methods,
            "methods": methods,
            "tested": ["OPTIONS", "HEAD"],
            "responses": {
                "OPTIONS": {
                    "status_code": opt.get("status_code"),
                    "allow": oh.get("allow"),
                    "access_control_allow_methods": oh.get("access-control-allow-methods"),
                },
                "HEAD": {"status_code": head.get("status_code")},
            },
        }

        result["technologies"] = detect_technologies(
            headers,
            response.get("body", ""),
        )

        # TLS certificate details from the final HTTPS endpoint.
        parsed = urllib.parse.urlparse(response.get("url") or target)
        if parsed.scheme.lower() == "https" and parsed.hostname:
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection(
                    (parsed.hostname, parsed.port or 443), timeout=8
                ) as sock:
                    with ctx.wrap_socket(sock, server_hostname=parsed.hostname) as tls_sock:
                        cert = tls_sock.getpeercert()
                        result["tls"] = {
                            "version": tls_sock.version(),
                            "cipher": tls_sock.cipher(),
                            "subject": cert.get("subject"),
                            "issuer": cert.get("issuer"),
                            "not_before": cert.get("notBefore"),
                            "not_after": cert.get("notAfter"),
                        }
            except Exception as exc:
                result["tls"] = {"error": str(exc)}

        if response.get("error"):
            result["errors"].append(response["error"])

    except Exception as exc:
        result["errors"].append(str(exc))

    if scan_id:
        set_module_progress(scan_id, "http", 100, "HTTP assessment completed", "completed")

    return result


def detect_technologies(headers, body):
    technologies = []
    text = (
        json.dumps(headers)
        + "\n"
        + str(body or "")
    ).lower()

    server = ""

    for key, value in headers.items():
        if str(key).lower() == "server":
            server = str(value)

    if server:
        technologies.append({
            "name": server,
            "technology": server,
            "source": "HTTP Server header",
        })

    for header_name in ("x-powered-by", "x-generator", "via"):
        value = headers.get(header_name) or headers.get(header_name.title())
        if value:
            technologies.append({
                "name": str(value),
                "technology": str(value),
                "source": f"HTTP {header_name} header",
            })

    for key, value in headers.items():
        if str(key).lower() == "set-cookie":
            cookie_text = str(value).lower()
            for cookie, tech in (("phpsessid", "PHP"), ("jsessionid", "Java"), ("asp.net_sessionid", "ASP.NET"), ("laravel_session", "Laravel"), ("csrftoken", "Django")):
                if cookie in cookie_text:
                    technologies.append({
                        "name": tech,
                        "technology": tech,
                        "source": "Set-Cookie fingerprint",
                    })

    signatures = [
        ("WordPress", "wp-content"),
        ("WordPress", "wp-includes"),
        ("Drupal", "drupal-settings"),
        ("Joomla", "joomla"),
        ("React", "__react"),
        ("Next.js", "_next/"),
        ("Laravel", "laravel"),
        ("Django", "csrfmiddlewaretoken"),
        ("ASP.NET", "asp.net"),
        ("PHP", "x-powered-by"),
    ]

    for name, signature in signatures:
        if signature in text:
            technologies.append({
                "name": name,
                "technology": name,
                "source": "HTTP content/signature",
            })

    return merge_technologies(
        [],
        technologies,
    )


def merge_technologies(first, second):
    result = []
    seen = set()

    for item in (first or []) + (second or []):
        if isinstance(item, str):
            item = {
                "name": item,
                "technology": item,
                "source": "scanner",
            }

        if not isinstance(item, dict):
            continue

        key = (
            str(item.get("name", "")).lower(),
            str(item.get("technology", "")).lower(),
            str(item.get("source", "")).lower(),
        )

        if key in seen:
            continue

        seen.add(key)
        result.append(json_safe(item))

    return result


# ============================================================
# EXISTING MODULE WRAPPERS
# ============================================================

def run_dns(scan_id, target):
    set_module_progress(
        scan_id,
        "dns",
        10,
        "Starting DNS / NS reconnaissance",
        "running",
    )

    result = collect_dns_ns_recon(target)

    update_job(
        scan_id,
        dns=result,
        dns_history_ns_recon=result,
    )

    set_module_progress(
        scan_id,
        "dns",
        100,
        "DNS / NS reconnaissance completed",
        "completed",
    )

    return result


def run_certificates(scan_id, target):
    set_module_progress(
        scan_id,
        "certificates",
        10,
        "Querying Certificate Transparency logs",
        "running",
    )

    result = collect_certificate_transparency(target)

    update_job(
        scan_id,
        certificates=result,
        certificate_transparency=result,
    )

    set_module_progress(
        scan_id,
        "certificates",
        100,
        "Certificate Transparency scan completed",
        "completed",
    )

    return result


def run_subdomains(scan_id, target):
    update_module(
        scan_id,
        "subdomains",
        "running",
        10,
    )

    try:
        if enumerate_subdomains:
            result = enumerate_subdomains(
                extract_target_host(target)
            )
        else:
            # Certificate Transparency is a real public fallback when the
            # optional local subdomain module is unavailable.
            ct = collect_certificate_transparency(target)
            values = unique_list(ct.get("subdomains", []))
            result = {
                "status": "completed",
                "subdomains": values,
                "items": values,
                "count": len(values),
                "source": "crt.sh Certificate Transparency fallback",
                "checked": 1,
                "found": len(values),
                "evidence": ct.get("certificates", []),
            }

    except Exception as exc:
        result = {
            "status": "error",
            "subdomains": [],
            "count": 0,
            "error": str(exc),
        }

    update_job(
        scan_id,
        subdomains=json_safe(result),
        subdomain_enumeration=json_safe(result),
    )

    update_module(
        scan_id,
        "subdomains",
        "completed",
        100,
    )

    return result


def run_technologies(scan_id, target):
    update_module(
        scan_id,
        "technologies",
        "running",
        10,
    )

    try:
        result = http_assessment(
            target,
            None,
        ).get(
            "technologies",
            [],
        )

    except Exception as exc:
        result = [{
            "name": "error",
            "technology": "error",
            "source": str(exc),
        }]

    update_job(
        scan_id,
        technologies=json_safe(result),
    )

    update_module(
        scan_id,
        "technologies",
        "completed",
        100,
    )

    return result


def normalize_findings(data):
    if not data:
        return []

    if isinstance(data, list):
        return json_safe(data)

    if isinstance(data, dict):
        findings = (
            data.get("findings")
            or data.get("vulnerabilities")
            or data.get("results")
            or []
        )

        if isinstance(findings, dict):
            findings = [findings]

        return json_safe(findings)

    return []


def run_web_security(scan_id, target):
    update_module(
        scan_id,
        "web_security",
        "running",
        10,
    )

    try:
        if scan_web_security:
            result = scan_web_security(target)
        else:
            result = {
                "status": "not_configured",
                "findings": [],
                "message": "Web security module unavailable",
            }

    except Exception as exc:
        result = {
            "status": "error",
            "findings": [],
            "error": str(exc),
        }

    update_job(
        scan_id,
        web_security=json_safe(result),
        findings=normalize_findings(result),
    )

    update_module(
        scan_id,
        "web_security",
        "completed",
        100,
    )

    return result
def normalize_crawler(data):
    if not isinstance(data, dict):
        data = {}

    data = json_safe(data)

    # web_crawler.py returns "javascript_files"
    # dashboard expects "js_files"
    js_files = (
        data.get("js_files")
        or data.get("javascript_files")
        or []
    )

    css_files = (
        data.get("css_files")
        or data.get("stylesheet_files")
        or []
    )

    if not isinstance(js_files, list):
        js_files = list(js_files)

    if not isinstance(css_files, list):
        css_files = list(css_files)

    # Keep both names available
    data["js_files"] = js_files
    data["javascript_files"] = js_files
    data["css_files"] = css_files

    # Make sure crawler collections exist
    collection_keys = (
        "pages",
        "internal_urls",
        "external_urls",
        "parameters",
        "api_endpoints",
        "forms",
        "robots",
        "sitemap",
    )

    for key in collection_keys:
        if key not in data or not isinstance(data[key], list):
            data[key] = []

    # Normalize statistics
    statistics = data.get("statistics")

    if not isinstance(statistics, dict):
        statistics = {}

    statistics["pages"] = len(data["pages"])
    statistics["internal_urls"] = len(data["internal_urls"])
    statistics["external_urls"] = len(data["external_urls"])
    statistics["parameters"] = len(data["parameters"])
    statistics["api_endpoints"] = len(data["api_endpoints"])
    statistics["forms"] = len(data["forms"])
    statistics["javascript_files"] = len(js_files)
    statistics["js_files"] = len(js_files)
    statistics["css_files"] = len(css_files)

    data["statistics"] = statistics

    return data


def run_crawler(scan_id, target):
    update_module(
        scan_id,
        "crawler",
        "running",
        10,
    )

    try:
        if crawl_site:
            result = crawl_site(
                target,
                30,
            )
        else:
            result = {
                "status": "not_configured",
                "statistics": {},
                "pages": [],
                "internal_urls": [],
                "external_urls": [],
                "parameters": [],
                "api_endpoints": [],
                "forms": [],
                "js_files": [],
                "css_files": [],
                "robots": [],
                "sitemap": [],
            }

    except Exception as exc:
        result = {
            "status": "error",
            "statistics": {},
            "error": str(exc),
            "pages": [],
            "internal_urls": [],
            "external_urls": [],
            "parameters": [],
            "api_endpoints": [],
            "forms": [],
            "js_files": [],
            "css_files": [],
            "robots": [],
            "sitemap": [],
        }

    # IMPORTANT:
    # web_crawler.py uses "javascript_files".
    # Convert it to the "js_files" field used by the dashboard.
    if isinstance(result, dict):
        result["js_files"] = (
            result.get("js_files")
            or result.get("javascript_files")
            or []
        )

        result["css_files"] = (
            result.get("css_files")
            or result.get("stylesheet_files")
            or []
        )

    result = normalize_crawler(result)

    update_job(
        scan_id,
        crawler=result,
        internal_urls={
            "source": "web crawler",
            "data": result.get(
                "internal_urls",
                [],
            ),
        },
    )

    update_module(
        scan_id,
        "crawler",
        "completed",
        100,
    )

    return result


def find_nmap_executable():
    candidates = [
        shutil.which("nmap"),
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
    ]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


def parse_nmap_text_line(line):
    """Best-effort live parser. Final results are taken from Nmap XML."""
    m = re.match(r"^\s*(\d+)\/([A-Za-z0-9]+)\s+(open|closed|filtered)\s+(\S+)(?:\s+(.*))?$", line.strip())
    if not m:
        return None

    port = int(m.group(1))
    protocol = m.group(2)
    state = m.group(3)
    service = m.group(4)
    tail = (m.group(5) or "").strip()

    # --reason places strings such as "syn-ack ttl 49" before service data.
    reason = ""
    reason_match = re.match(
        r"^(syn-ack(?:\s+ttl\s+\d+)?|syn-ack|conn-refused|reset|no-response|admin-prohibited|echo-reply|time-exceeded)(?:\s+|$)(.*)$",
        tail,
        re.I,
    )
    if reason_match:
        reason = reason_match.group(1)
        tail = reason_match.group(2).strip()

    return {
        "port": port,
        "protocol": protocol,
        "state": state,
        "service": service,
        "reason": reason,
        "product": tail,
        "version": "",
    }


def parse_nmap_xml(xml_text):
    """Parse authoritative Nmap service/product/version data from XML."""
    import xml.etree.ElementTree as ET
    ports = []
    if not xml_text:
        return ports
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return ports

    for port in root.findall(".//port"):
        state_node = port.find("state")
        if state_node is None or state_node.get("state") != "open":
            continue

        service_node = port.find("service")
        service = service_node.get("name", "") if service_node is not None else ""
        product = service_node.get("product", "") if service_node is not None else ""
        version = service_node.get("version", "") if service_node is not None else ""
        extrainfo = service_node.get("extrainfo", "") if service_node is not None else ""
        reason = state_node.get("reason", "")

        if not product and extrainfo:
            product = extrainfo

        ports.append({
            "port": int(port.get("portid", 0)),
            "protocol": port.get("protocol", "tcp"),
            "state": state_node.get("state", "open"),
            "service": service,
            "reason": reason,
            "product": product,
            "version": version,
            "extrainfo": extrainfo,
            "cpe": [c.get("name") for c in (service_node.findall("cpe") if service_node is not None else []) if c.get("name")],
        })

    return sorted(ports, key=lambda x: (x["port"], x["protocol"]))


def nmap_tcp_scan(host, scan_id, profile):
    update_module(scan_id, "nmap", "running", 5)

    result = {
        "target": host,
        "profile": profile,
        "profile_label": NMAP_PROFILES[profile]["label"],
        "status": "not_started",
        "open_ports": [],
        "open_port_count": 0,
        "raw": "",
        "errors": [],
        "progress": 0,
        "scan_method": "default",
        "nmap_path": "",
    }

    nmap_path = find_nmap_executable()

    if not nmap_path:
        result["status"] = "not_available"
        result["errors"].append(
            "Nmap executable not found in PATH or standard installation paths"
        )
        update_job(
            scan_id,
            nmap=json_safe(result),
            port_technology_fingerprint=json_safe(result),
        )
        update_module(scan_id, "nmap", "completed", 100)
        return result

    result["nmap_path"] = nmap_path

    if profile == "full":
        port_args = ["-p", "1-65535"]
    elif profile == "standard":
        port_args = ["--top-ports", "5000"]
    else:
        port_args = ["--top-ports", "1000"]

    import tempfile

    def run_nmap(scan_args, method_name):
        fd, xml_path = tempfile.mkstemp(
            prefix="vapt_nmap_",
            suffix=".xml",
        )
        os.close(fd)

        command = [
            nmap_path,
            "-Pn",
            "-4",
            "-sV",
            "--reason",
            "--open",
            "-T4",
            "--stats-every",
            "2s",
            *scan_args,
            "-oN",
            "-",
            "-oX",
            xml_path,
            host,
        ]

        lines = []

        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )

            for line in iter(proc.stdout.readline, ""):
                if not line:
                    break

                line = line.rstrip("\r\n")
                lines.append(line)

                pct = re.search(
                    r"About\s+(\d+(?:\.\d+)?)%\s+done",
                    line,
                    re.I,
                )

                if pct:
                    try:
                        p = float(pct.group(1))
                        mapped = int(5 + min(90.0, p * 0.90))
                        set_module_progress(
                            scan_id,
                            "nmap",
                            mapped,
                            f"Nmap scanning {p:.1f}%",
                            "running",
                        )
                    except Exception:
                        pass

                parsed = parse_nmap_text_line(line)

                if parsed and parsed.get("state") == "open":
                    if not any(
                        x.get("port") == parsed.get("port")
                        and x.get("protocol") == parsed.get("protocol")
                        for x in result["open_ports"]
                    ):
                        result["open_ports"].append(parsed)
                        result["open_port_count"] = len(result["open_ports"])

                        update_job(
                            scan_id,
                            nmap=json_safe(result),
                            port_technology_fingerprint=json_safe(result),
                        )

            proc.wait(timeout=900)

            raw = "\n".join(lines)
            xml_ports = []

            try:
                xml_text = Path(xml_path).read_text(
                    encoding="utf-8",
                    errors="replace",
                )
                xml_ports = parse_nmap_xml(xml_text)
            except Exception as exc:
                return {
                    "method": method_name,
                    "command": command,
                    "return_code": proc.returncode,
                    "raw": raw,
                    "xml_ports": [],
                    "error": f"Nmap XML parse error: {exc}",
                }

            return {
                "method": method_name,
                "command": command,
                "return_code": proc.returncode,
                "raw": raw,
                "xml_ports": xml_ports,
                "error": "",
            }

        except subprocess.TimeoutExpired:
            try:
                proc.kill()
                proc.wait(timeout=10)
            except Exception:
                pass

            return {
                "method": method_name,
                "command": command,
                "return_code": -1,
                "raw": "\n".join(lines),
                "xml_ports": [],
                "error": "Nmap scan timed out after 900 seconds",
            }

        except Exception as exc:
            return {
                "method": method_name,
                "command": command,
                "return_code": -1,
                "raw": "\n".join(lines),
                "xml_ports": [],
                "error": str(exc),
            }

        finally:
            try:
                os.remove(xml_path)
            except Exception:
                pass

    def apply_scan_result(scan_result):
        xml_ports = scan_result.get("xml_ports", []) or []

        if xml_ports:
            result["open_ports"] = xml_ports

        result["open_port_count"] = len(result["open_ports"])
        result["raw"] = scan_result.get("raw", result["raw"])

    # First attempt: normal Nmap service/version scan.
    first = run_nmap(port_args, "default")
    apply_scan_result(first)

    if first.get("return_code") == 0:
        result["status"] = "completed"
        result["scan_method"] = "default"

    else:
        first_error = first.get("error") or ""
        result["errors"].append("Default Nmap scan failed")
        result["errors"].append(
            f"Nmap exited with code {first.get('return_code')}"
        )

        if first_error:
            result["errors"].append(first_error)

        # Render/Linux-compatible fallback using TCP connect scanning.
        fallback = run_nmap(
            port_args + ["-sT"],
            "tcp_connect",
        )
        apply_scan_result(fallback)

        if fallback.get("return_code") == 0:
            result["status"] = "completed"
            result["scan_method"] = "tcp_connect"
            result["errors"].append(
                "Default Nmap scan failed; TCP Connect scan succeeded"
            )
        else:
            result["status"] = "error"
            result["errors"].append(
                "TCP Connect fallback also failed"
            )
            result["errors"].append(
                f"TCP Connect Nmap exited with code {fallback.get('return_code')}"
            )

            if fallback.get("error"):
                result["errors"].append(
                    fallback.get("error")
                )

            result["raw"] = (
                result["raw"]
                + "\n\n===== TCP CONNECT FALLBACK =====\n\n"
                + fallback.get("raw", "")
            )

    result["open_ports"] = sorted(
        result["open_ports"],
        key=lambda x: (
            x.get("port", 0),
            x.get("protocol", ""),
        ),
    )
    result["open_port_count"] = len(result["open_ports"])
    result["progress"] = 100

    update_job(
        scan_id,
        nmap=json_safe(result),
        port_technology_fingerprint=json_safe(result),
    )
    update_module(scan_id, "nmap", "completed", 100)

    return result

def not_configured_feature(
    feature,
    reason="Requires an authorized external data provider",
):
    return {
        "status": "not_configured",
        "feature": feature,
        "source": "provider/integration required",
        "authorized_only": True,
        "items": [],
        "count": 0,
        "message": reason,
    }


def _probe_result_is_interesting(item):
    status = item.get("status_code")
    return isinstance(status, int) and status in {200, 201, 202, 204, 206, 301, 302, 307, 308, 401, 403}


def public_http_probe(target, paths, timeout=8, keywords=None):
    """Perform real safe GET probes and return checked + found evidence.

    No response body is returned to the dashboard. Only metadata and small
    keyword matches are retained so that the scanner does not turn discovery
    into a content/secret collection mechanism.
    """
    results = []
    keywords = [str(x).lower() for x in (keywords or [])]

    for path in unique_list(paths):
        url = target.rstrip("/") + "/" + path.lstrip("/")
        try:
            response = http_text_get(url, timeout=timeout, max_bytes=8192)
            headers = response.get("headers", {}) or {}
            body = str(response.get("body", "") or "")
            low_body = body.lower()
            matched = [k for k in keywords if k in low_body]
            item = {
                "path": path,
                "url": response.get("url", url),
                "status_code": response.get("status_code"),
                "content_type": headers.get("Content-Type", headers.get("content-type", "")),
                "content_length": len(body),
                "server": headers.get("Server", headers.get("server", "")),
                "location": headers.get("Location", headers.get("location", "")),
                "interesting_status": _probe_result_is_interesting({"status_code": response.get("status_code")}),
                "keyword_matches": matched,
            }
            results.append(item)
        except Exception as exc:
            results.append({
                "path": path,
                "url": url,
                "status_code": None,
                "reachable": False,
                "error": str(exc),
            })

    found = [x for x in results if x.get("interesting_status") or x.get("keyword_matches")]
    return {
        "status": "completed",
        "checked": len(results),
        "found": len(found),
        "items": found,
        "evidence": results,
    }


def _feature_from_probe(name, probe, source):
    return {
        "status": "completed",
        "feature": name,
        "source": source,
        "checked": int(probe.get("checked", 0)),
        "found": int(probe.get("found", 0)),
        "count": int(probe.get("found", 0)),
        "items": json_safe(probe.get("items", [])),
        "evidence": json_safe(probe.get("evidence", [])),
    }


def _extract_subdomain_values(data):
    if isinstance(data, list):
        raw = data
    elif isinstance(data, dict):
        raw = (
            data.get("subdomains")
            or data.get("items")
            or data.get("domains")
            or data.get("results")
            or []
        )
    else:
        raw = []

    values = []
    for item in raw:
        if isinstance(item, str):
            values.append(item)
        elif isinstance(item, dict):
            value = item.get("hostname") or item.get("subdomain") or item.get("domain") or item.get("name")
            if value:
                values.append(value)
    return unique_list(values)


def collect_public_service_exposure(target, crawler=None, subdomains=None):
    probes = {
        "admin_panels": [
            "admin/", "administrator/", "wp-admin/", "wp-login.php", "login", "signin", "manage/", "dashboard/",
        ],
        "public_apis": [
            "api/", "api/v1/", "api/v2/", "api/docs", "swagger/", "swagger-ui/", "swagger.json",
            "openapi.json", "api/openapi.json", "redoc/", "graphql", "graphiql/",
        ],
        "technical_docs": [
            "robots.txt", "sitemap.xml", ".well-known/security.txt", "swagger.json", "openapi.json",
            "api/docs", "docs/", "documentation/", "redoc/",
        ],
        "dev_staging": [
            "dev/", "development/", "test/", "testing/", "staging/", "stage/", "uat/", "qa/", "beta/", "sandbox/", "demo/",
        ],
        "cicd_registries": [
            ".git/HEAD", ".git/config", ".gitlab-ci.yml", ".github/", "Jenkinsfile", "docker-compose.yml",
            "registry/", "v2/", "artifactory/", "nexus/", "packages/",
        ],
    }

    keyword_map = {
        "admin_panels": ["login", "administrator", "dashboard", "wp-admin", "sign in"],
        "public_apis": ["swagger", "openapi", "graphql", "api"],
        "technical_docs": ["sitemap", "swagger", "openapi", "security contact", "documentation"],
        "dev_staging": ["development", "staging", "test environment", "qa", "uat"],
        "cicd_registries": ["jenkins", "gitlab", "github", "docker", "registry", "nexus", "artifactory"],
    }

    result = {}
    for name, paths in probes.items():
        probe = public_http_probe(target, paths, keywords=keyword_map.get(name, []))
        result[name] = _feature_from_probe(name, probe, "live HTTP endpoint probing")

    # Merge real crawler observations into the relevant feature evidence.
    crawler = crawler if isinstance(crawler, dict) else {}
    internal_urls = crawler.get("internal_urls", []) or []
    all_urls = crawler.get("pages", []) or []
    all_urls += internal_urls

    def url_strings(values):
        out = []
        for x in values:
            if isinstance(x, str):
                out.append(x)
            elif isinstance(x, dict):
                u = x.get("url") or x.get("href") or x.get("path")
                if u:
                    out.append(str(u))
        return unique_list(out)

    discovered = url_strings(all_urls)

    admin_extra = [u for u in discovered if re.search(r"/(admin|administrator|wp-admin|login|signin|dashboard|manage)(/|$|\?)", u, re.I)]
    api_extra = [u for u in discovered if re.search(r"/(api|swagger|openapi|graphql|graphiql)(/|\.|$|\?)", u, re.I)]
    docs_extra = [u for u in discovered if re.search(r"/(docs?|documentation|swagger|openapi|redoc)(/|\.|$|\?)", u, re.I)]
    cicd_extra = [u for u in discovered if re.search(r"/(\.git|\.github|\.gitlab|jenkins|registry|artifactory|nexus|docker)(/|$|\?)", u, re.I)]

    for key, extra in (("admin_panels", admin_extra), ("public_apis", api_extra), ("technical_docs", docs_extra), ("cicd_registries", cicd_extra)):
        if extra:
            result[key]["items"].extend({"url": u, "source": "web crawler", "observed": True} for u in extra)
            result[key]["items"] = json_safe(result[key]["items"])
            result[key]["found"] = len(result[key]["items"])
            result[key]["count"] = result[key]["found"]

    # Real CT/subdomain observations are stronger evidence for dev/staging hosts.
    sd = _extract_subdomain_values(subdomains)
    dev_names = [
        x for x in sd
        if re.search(r"(^|[.-])(dev|development|test|testing|staging|stage|uat|qa|beta|sandbox|demo)([.-]|$)", x, re.I)
    ]
    if dev_names:
        result["dev_staging"]["items"].extend({"hostname": x, "source": "CT/subdomain enumeration"} for x in dev_names)
        result["dev_staging"]["items"] = json_safe(result["dev_staging"]["items"])
        result["dev_staging"]["found"] = len(result["dev_staging"]["items"])
        result["dev_staging"]["count"] = result["dev_staging"]["found"]

    return result


def collect_cloud_storage_indicators(target, crawler=None):
    host = extract_target_host(target)
    candidates = [
        f"https://{host}.s3.amazonaws.com",
        f"https://{host}.blob.core.windows.net",
        f"https://{host}.storage.googleapis.com",
    ]

    # Also inspect actual page URLs for cloud-storage references.
    crawler = crawler if isinstance(crawler, dict) else {}
    discovered_text = json.dumps(crawler, default=str).lower()
    references = []
    for pattern in [r"https?://[^\s\"'<>]+\.s3\.amazonaws\.com[^\s\"'<>]*", r"https?://[^\s\"'<>]+\.blob\.core\.windows\.net[^\s\"'<>]*", r"https?://storage\.googleapis\.com/[^\s\"'<>]*"]:
        references.extend(re.findall(pattern, discovered_text, re.I))
    candidates.extend(references)
    candidates = unique_list(candidates)

    evidence = []
    for url in candidates:
        try:
            response = http_text_get(url, timeout=6, max_bytes=4096)
            status = response.get("status_code")
            evidence.append({
                "url": url,
                "status_code": status,
                "reachable": status is not None,
                "interesting": status in {200, 204, 206, 301, 302, 307, 308, 401, 403},
                "content_type": (response.get("headers") or {}).get("Content-Type", ""),
            })
        except Exception as exc:
            evidence.append({"url": url, "status_code": None, "reachable": False, "error": str(exc)})

    found = [x for x in evidence if x.get("interesting")]
    return {
        "status": "completed",
        "feature": "S3 / GCS / Azure Blob",
        "source": "live public endpoint probing + crawler references",
        "checked": len(evidence),
        "found": len(found),
        "count": len(found),
        "items": found,
        "evidence": evidence,
        "note": "Only endpoint reachability/metadata is tested; bucket/container contents are not downloaded.",
    }


def collect_remote_services(nmap_result):
    ports = (nmap_result or {}).get("open_ports", []) if isinstance(nmap_result, dict) else []
    interesting_services = {
        22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC", 5901: "VNC",
        1723: "PPTP", 1194: "OpenVPN", 500: "IKE/IPsec", 4500: "IPsec NAT-T",
        51820: "WireGuard",
    }
    checked = []
    found = []
    for p in ports:
        port = int(p.get("port", 0) or 0)
        service = str(p.get("service", ""))
        product = str(p.get("product", ""))
        version = str(p.get("version", ""))
        item = {"port": port, "protocol": p.get("protocol", "tcp"), "service": service, "product": product, "version": version}
        checked.append(item)
        label = interesting_services.get(port)
        if not label:
            low = (service + " " + product).lower()
            if any(x in low for x in ("ssh", "rdp", "remote desktop", "openvpn", "wireguard", "ike", "ipsec", "vnc", "pptp")):
                label = service or product
        if label:
            item = dict(item)
            item["category"] = label
            found.append(item)
    return {
        "status": "completed",
        "feature": "VPN / RDP / SSH",
        "source": "Nmap service/version detection",
        "checked": len(checked),
        "found": len(found),
        "count": len(found),
        "items": found,
        "evidence": checked,
    }


def collect_email_gateway(dns_result):
    records = (dns_result or {}).get("records", {}) if isinstance(dns_result, dict) else {}
    mx = unique_list(records.get("MX", []))
    items = [{"mail_exchange": x, "source": "DNS MX"} for x in mx]
    return {
        "status": "completed",
        "feature": "Corporate email gateway",
        "source": "live DNS MX lookup",
        "checked": 1,
        "found": len(items),
        "count": len(items),
        "items": items,
        "evidence": [{"record_type": "MX", "values": mx}],
    }


def collect_shadow_saas(crawler):
    crawler = crawler if isinstance(crawler, dict) else {}
    values = crawler.get("external_urls", []) or []
    domains = set()
    evidence = []
    for item in values:
        url = item if isinstance(item, str) else (item.get("url") or item.get("href") if isinstance(item, dict) else "")
        if not url:
            continue
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.hostname:
                domains.add(parsed.hostname.lower())
        except Exception:
            pass
    for domain in sorted(domains):
        evidence.append({"domain": domain, "source": "web crawler external URL"})
    return {
        "status": "completed",
        "feature": "Shadow SaaS observations",
        "source": "web crawler external-domain discovery",
        "checked": len(domains),
        "found": len(domains),
        "count": len(domains),
        "items": evidence,
        "evidence": evidence,
        "note": "These are externally referenced domains observed by the crawler, not a confirmation that each is an unmanaged SaaS service.",
    }


def collect_eol_assets(nmap_result, technologies=None):
    """Check observed software against public endoflife.date data where a product mapping exists."""
    import datetime as _dt
    ports = (nmap_result or {}).get("open_ports", []) if isinstance(nmap_result, dict) else []
    observed = []
    mapping = {
        "mariadb": "mariadb", "mysql": "mysql", "nginx": "nginx", "apache httpd": "apache",
        "apache": "apache", "php": "php", "node": "nodejs", "node.js": "nodejs", "python": "python",
        "openssl": "openssl", "wordpress": "wordpress", "drupal": "drupal", "joomla": "joomla",
    }
    for p in ports:
        product = str(p.get("product", "") or "").strip()
        version = str(p.get("version", "") or "").strip()
        service = str(p.get("service", "") or "").strip()
        low = (product + " " + service).lower()
        slug = next((v for k, v in mapping.items() if k in low), None)
        if product or version or service:
            observed.append({"port": p.get("port"), "service": service, "product": product, "version": version, "lifecycle_product": slug})

    checked = []
    confirmed = []
    for item in observed:
        slug = item.get("lifecycle_product")
        if not slug:
            checked.append({**item, "lifecycle_status": "unmapped"})
            continue
        try:
            data = http_json_get(f"https://endoflife.date/api/{urllib.parse.quote(slug)}.json", timeout=10)
            version = item.get("version", "")
            matched = None
            for cycle in data if isinstance(data, list) else []:
                cycle_name = str(cycle.get("cycle", ""))
                if version and (version == cycle_name or version.startswith(cycle_name + ".")):
                    matched = cycle
                    break
            entry = {**item, "lifecycle_status": "checked", "cycle": matched.get("cycle") if matched else None, "eol": matched.get("eol") if matched else None, "source": "endoflife.date"}
            if matched and matched.get("eol") and matched.get("eol") is not False:
                eol = str(matched.get("eol"))
                try:
                    if eol[:10] <= _dt.date.today().isoformat():
                        entry["lifecycle_status"] = "eol"
                        confirmed.append(entry)
                except Exception:
                    pass
            checked.append(entry)
        except Exception as exc:
            checked.append({**item, "lifecycle_status": "provider_error", "error": str(exc)})

    return {
        "status": "completed",
        "feature": "Forgotten / EOL Assets",
        "source": "Nmap observed versions + endoflife.date where product mapping exists",
        "checked": len(checked),
        "found": len(confirmed),
        "count": len(confirmed),
        "items": confirmed,
        "evidence": checked,
        "note": "An asset is not labelled EOL unless the public lifecycle source confirms the observed cycle is past EOL. Unmapped versions remain evidence only.",
    }


def collect_dns_feature(dns_result):
    records = (dns_result or {}).get("records", {}) if isinstance(dns_result, dict) else {}
    values = []
    for rtype, vals in records.items():
        for value in vals or []:
            values.append({"record_type": rtype, "value": value})
    return {
        "status": "completed",
        "feature": "DNS History & NS Recon",
        "source": "live DNS resolution / nslookup",
        "checked": len(records),
        "found": len(values),
        "count": len(values),
        "items": values,
        "evidence": {
            "records": records,
            "nameservers": (dns_result or {}).get("nameservers", []),
            "ips": (dns_result or {}).get("ips", []),
        },
        "history_note": "Current DNS/NS records are live-checked. Historical DNS requires a historical DNS provider and is not fabricated.",
    }

def collect_asn_bgp(host):
    """Live public IP/ASN enrichment plus public BGP prefix lookup."""
    result = {
        "status": "completed",
        "feature": "ASN & BGP Sweep",
        "target": host,
        "source": "live DNS + ipwho.is + bgpview.io public APIs",
        "checked": 0,
        "found": 0,
        "count": 0,
        "items": [],
        "evidence": [],
        "ips": [],
        "asn": [],
        "bgp": [],
        "errors": [],
    }

    ip_result = resolve_target_ips(host)
    ips = ip_result.get("ips", [])
    result["ips"] = ips
    result["checked"] = len(ips)

    for item in ips:
        ip = item.get("ip")
        if not ip:
            continue
        record = {"ip": ip}
        try:
            data = http_json_get("https://ipwho.is/" + urllib.parse.quote(ip), timeout=8)
            connection = data.get("connection", {}) if isinstance(data, dict) else {}
            record.update({
                "asn": connection.get("asn"),
                "org": connection.get("org"),
                "isp": connection.get("isp"),
                "domain": connection.get("domain"),
                "country": data.get("country") if isinstance(data, dict) else None,
                "city": data.get("city") if isinstance(data, dict) else None,
                "source": "ipwho.is",
            })
            result["asn"].append(record)
            result["items"].append(record)
        except Exception as exc:
            result["errors"].append(f"ASN {ip}: {exc}")

        try:
            bgp = http_json_get("https://api.bgpview.io/ip/" + urllib.parse.quote(ip), timeout=10)
            data = bgp.get("data", {}) if isinstance(bgp, dict) else {}
            prefixes = data.get("prefixes", []) or []
            entry = {
                "ip": ip,
                "prefix_count": len(prefixes),
                "prefixes": prefixes[:100],
                "source": "bgpview.io",
            }
            result["bgp"].append(entry)
            result["evidence"].append(entry)
        except Exception as exc:
            result["errors"].append(f"BGP {ip}: {exc}")

    result["found"] = len(result["items"])
    result["count"] = result["found"]
    result["evidence"].extend(result["asn"])
    return result


def nmap_technology_records(nmap_result):
    records = []
    for port in (nmap_result or {}).get("open_ports", []) if isinstance(nmap_result, dict) else []:
        service = str(port.get("service", "") or "").strip()
        product = str(port.get("product", "") or "").strip()
        version = str(port.get("version", "") or "").strip()
        if not (service or product or version):
            continue
        display = " ".join(x for x in [product, version] if x).strip() or service
        records.append({
            "name": display,
            "technology": service or product,
            "source": "Nmap service/version detection",
            "port": port.get("port"),
            "protocol": port.get("protocol", "tcp"),
            "product": product,
            "version": version,
            "reason": port.get("reason", ""),
            "cpe": port.get("cpe", []),
        })
    return records


# ============================================================
# FEATURE BUILDERS
# ============================================================

def build_features(job):
    infrastructure = {
        "subdomain_enumeration": job.get(
            "subdomain_enumeration",
            job.get("subdomains", {}),
        ),
        "certificate_transparency": job.get(
            "certificate_transparency",
            job.get("certificates", {}),
        ),
        "dns_history_ns_recon": job.get(
            "dns_history_ns_recon",
            job.get("dns", {}),
        ),
        "asn_bgp_sweep": job.get(
            "asn_bgp",
            {},
        ),
        "exposed_dev_staging": job.get(
            "dev_staging",
            {},
        ),
        "forgotten_eol_assets": job.get(
            "eol_assets",
            {},
        ),
        "cloud_storage": job.get(
            "cloud_storage",
            {},
        ),
    }

    services = {
        "port_technology_fingerprint": job.get(
            "port_technology_fingerprint",
            job.get("nmap", {}),
        ),
        "exposed_admin_panels": job.get(
            "admin_panels",
            {},
        ),
        "vpn_rdp_ssh": job.get(
            "remote_services",
            {},
        ),
        "corp_email_gateway": job.get(
            "email_gateway",
            {},
        ),
        "public_apis_docs": job.get(
            "public_apis",
            {},
        ),
        "cicd_registry_leaks": job.get(
            "cicd_registries",
            {},
        ),
        "shadow_saas": job.get(
            "shadow_saas",
            {},
        ),
    }

    people = {
        "executive_osint": job.get(
            "executives",
            {},
        ),
        "employee_linkedin": job.get(
            "linkedin",
            {},
        ),
        "org_chart": job.get(
            "org_chart",
            {},
        ),
        "personal_email_phone": job.get(
            "public_contacts",
            {},
        ),
        "public_document_metadata": job.get(
            "document_metadata",
            {},
        ),
        "social_media_posture": job.get(
            "social_media",
            {},
        ),
        "travel_schedule_leaks": job.get(
            "travel_schedule",
            {},
        ),
    }

    credentials = {
        "breach_corpus_cross_check": (
    job.get("breach_corpus")
    if job.get("breach_corpus")
    else run_hibp_breach_test()
),
        "combolist_appearances": job.get(
            "combolist",
            {},
        ),
        "infostealer_logs": job.get(
            "infostealer",
            {},
        ),
        "valid_reuse_verification": job.get(
            "credential_reuse",
            {},
        ),
        "corporate_cookie_theft": job.get(
            "corporate_cookies",
            {},
        ),
        "session_token_leaks": job.get(
            "session_tokens",
            {},
        ),
        "git_paste_secrets": job.get(
            "git_paste_secrets",
            {},
        ),
    }

    code_docs = {
        "github_gitlab_org_scan": job.get(
            "git_orgs",
            {},
        ),
        "public_repo_gist_secrets": job.get(
            "repo_secrets",
            {},
        ),
        "mobile_app_extracted_keys": job.get(
            "mobile_keys",
            {},
        ),
        "paste_leaks": job.get(
            "paste_leaks",
            {},
        ),
        "archive_snapshots": job.get(
            "archive_snapshots",
            {},
        ),
        "technical_docs_indexed": job.get(
            "technical_docs",
            {},
        ),
        "internal_url_enumeration": job.get(
            "internal_urls",
            {},
        ),
    }

    threat_landscape = {
        "targeted_adversary_chatter": job.get(
            "adversary_chatter",
            {},
        ),
        "ransomware_leak_site_hits": job.get(
            "ransomware",
            {},
        ),
        "initial_access_broker_listings": job.get(
            "iab",
            {},
        ),
        "impersonation_typosquat": job.get(
            "typosquats",
            {},
        ),
        "phishing_kit_observations": job.get(
            "phishing",
            {},
        ),
        "third_party_supplier_risk": job.get(
            "supplier_risk",
            {},
        ),
        "sectoral_ttp_matching": job.get(
            "sector_ttps",
            {},
        ),
    }

    return {
        "infrastructure": infrastructure,
        "services": services,
        "people": people,
        "credentials": credentials,
        "code_docs": code_docs,
        "threat_landscape": threat_landscape,
    }
# ============================================================
# HIBP BREACH INTELLIGENCE
# ============================================================

def hibp_config():
    """
    Returns the current HIBP configuration.

    Test mode:
        Uses the official HIBP integration test key.

    Production mode:
        Uses HIBP_API_KEY from the Windows environment.
    """

    if HIBP_TEST_MODE:
        return {
            "configured": True,
            "mode": "TEST_MODE",
            "api_key": HIBP_TEST_API_KEY,
        }

    if HIBP_REAL_API_KEY:
        return {
            "configured": True,
            "mode": "PRODUCTION",
            "api_key": HIBP_REAL_API_KEY,
        }

    return {
        "configured": False,
        "mode": "NOT_CONFIGURED",
        "api_key": "",
    }


def hibp_test_account_allowed(account):
    """
    Test mode is intentionally restricted to HIBP's
    documented integration-test addresses.
    """

    return (
        isinstance(account, str)
        and account.strip().lower() in HIBP_TEST_ACCOUNTS
    )


def hibp_breached_account(account):
    """
    Query HIBP's breachedAccount endpoint.

    In TEST_MODE only HIBP's official test addresses are allowed.

    Returns a normalized, dashboard-safe structure.
    """

    account = (account or "").strip().lower()

    if not account:
        return {
            "status": "INVALID_INPUT",
            "provider": "HIBP",
            "mode": "UNKNOWN",
            "items": 0,
            "results": [],
            "message": "No account/email supplied.",
        }

    config = hibp_config()

    if not config["configured"]:
        return {
            "status": "NOT_CONFIGURED",
            "provider": "HIBP",
            "mode": "NOT_CONFIGURED",
            "items": 0,
            "results": [],
            "message": "HIBP API subscription key is not configured.",
        }

    if (
        config["mode"] == "TEST_MODE"
        and not hibp_test_account_allowed(account)
    ):
        return {
            "status": "TEST_MODE",
            "provider": "HIBP",
            "mode": "TEST_MODE",
            "items": 0,
            "results": [],
            "message": (
                "Test mode only permits HIBP integration-test accounts."
            ),
        }

    encoded_account = urllib.parse.quote(account, safe="")

    url = (
        f"{HIBP_BASE_URL}/breachedaccount/"
        f"{encoded_account}"
    )

    headers = {
        "hibp-api-key": config["api_key"],
        "user-agent": HIBP_USER_AGENT,
        "accept": "application/json",
    }

    try:
        req = urllib.request.Request(
            url,
            headers=headers,
            method="GET",
        )

        with urllib.request.urlopen(req, timeout=20) as response:
            status_code = response.getcode()
            raw = response.read().decode(
                "utf-8",
                errors="replace"
            )

        if status_code == 200:
            try:
                data = json.loads(raw)
            except Exception:
                data = []

            if not isinstance(data, list):
                data = []

            results = []

            for breach in data:
                if not isinstance(breach, dict):
                    continue

                results.append({
                    "name": breach.get("Name"),
                    "title": breach.get("Title"),
                    "domain": breach.get("Domain"),
                    "breach_date": breach.get("BreachDate"),
                    "added_date": breach.get("AddedDate"),
                    "modified_date": breach.get("ModifiedDate"),
                    "pwn_count": breach.get("PwnCount"),
                    "data_classes": breach.get("DataClasses", []),
                    "is_verified": breach.get("IsVerified"),
                    "is_fabricated": breach.get("IsFabricated"),
                    "is_sensitive": breach.get("IsSensitive"),
                    "is_retired": breach.get("IsRetired"),
                    "is_spam_list": breach.get("IsSpamList"),
                })

            return {
                "status": "COMPLETED",
                "provider": "HIBP",
                "mode": config["mode"],
                "account": account,
                "items": len(results),
                "results": results,
                "message": (
                    f"HIBP returned {len(results)} breach record(s)."
                ),
            }

    except urllib.error.HTTPError as exc:

        if exc.code == 404:
            return {
                "status": "COMPLETED",
                "provider": "HIBP",
                "mode": config["mode"],
                "account": account,
                "items": 0,
                "results": [],
                "message": "No breach records found.",
            }

        if exc.code == 401:
            return {
                "status": "AUTH_ERROR",
                "provider": "HIBP",
                "mode": config["mode"],
                "items": 0,
                "results": [],
                "message": "HIBP API key was rejected.",
            }

        if exc.code == 403:
            return {
                "status": "FORBIDDEN",
                "provider": "HIBP",
                "mode": config["mode"],
                "items": 0,
                "results": [],
                "message": (
                    "HIBP denied the request. "
                    "Check API permissions and User-Agent."
                ),
            }

        if exc.code == 429:
            retry_after = exc.headers.get("Retry-After", "")

            return {
                "status": "RATE_LIMITED",
                "provider": "HIBP",
                "mode": config["mode"],
                "items": 0,
                "results": [],
                "retry_after": retry_after,
                "message": "HIBP rate limit exceeded.",
            }

        return {
            "status": "PROVIDER_ERROR",
            "provider": "HIBP",
            "mode": config["mode"],
            "items": 0,
            "results": [],
            "message": f"HIBP HTTP error {exc.code}.",
        }

    except Exception as exc:
        return {
            "status": "PROVIDER_ERROR",
            "provider": "HIBP",
            "mode": config["mode"],
            "items": 0,
            "results": [],
            "message": str(exc),
        }


def run_hibp_breach_test():
    """
    Runs the official HIBP integration test.

    This intentionally does NOT accept arbitrary target emails
    while HIBP_TEST_MODE is enabled.
    """

    config = hibp_config()

    if not config["configured"]:
        return {
            "status": "NOT_CONFIGURED",
            "provider": "HIBP",
            "mode": "NOT_CONFIGURED",
            "items": 0,
            "results": [],
            "test_account": None,
            "message": "HIBP provider is not configured.",
        }

    if config["mode"] == "TEST_MODE":
        account = "account-exists@hibp-integration-tests.com"

        result = hibp_breached_account(account)

        result["test_account"] = account
        result["test_mode"] = True

        return result

    return {
        "status": "READY",
        "provider": "HIBP",
        "mode": "PRODUCTION",
        "items": 0,
        "results": [],
        "test_account": None,
        "test_mode": False,
        "message": (
            "HIBP production API is configured. "
            "Provide an explicitly authorized account for a real lookup."
        ),
    }
# ============================================================
# SAFE FEATURE EXECUTION
# ============================================================


# ============================================================
# PEOPLE / PUBLIC ORGANIZATION INTELLIGENCE
# ============================================================

def _feature_contract(feature, source, checked=0, items=None, evidence=None, note=""):
    items = json_safe(items or [])
    evidence = json_safe(evidence or [])
    return {
        "status": "completed",
        "feature": feature,
        "source": source,
        "checked": int(checked or 0),
        "found": len(items),
        "count": len(items),
        "items": items,
        "evidence": evidence,
        "note": note,
    }


def _absolute_url(base, value):
    try:
        return urllib.parse.urljoin(base.rstrip("/") + "/", str(value).strip())
    except Exception:
        return ""


def _public_site_urls(target, crawler, limit=80):
    # Return public URLs already observed by the crawler plus common people/document pages.
    urls=[]
    crawler=crawler if isinstance(crawler, dict) else {}
    for key in ("pages", "internal_urls", "external_urls", "api_endpoints"):
        for item in crawler.get(key, []) or []:
            if isinstance(item, str):
                u=item
            elif isinstance(item, dict):
                u=item.get("url") or item.get("href") or item.get("path") or ""
            else:
                u=""
            if u:
                u=_absolute_url(target,u)
                if u.lower().startswith(("http://","https://")):
                    urls.append(u)
    for path in [
        "about", "about-us", "company", "team", "our-team", "leadership", "management",
        "executives", "board", "board-of-directors", "contact", "contact-us", "careers",
        "people", "directory", "news", "press", "media", "events", "calendar", "conference",
        "resources", "downloads", "documents", "publications", "investors", "investor-relations",
    ]:
        urls.append(_absolute_url(target,path))
    return unique_list(urls)[:limit]


def _download_public_page_text(url, timeout=8, max_bytes=160000):
    try:
        r=http_text_get(url, timeout=timeout, max_bytes=max_bytes)
        return r
    except Exception as exc:
        return {"status_code":None,"headers":{},"body":"","url":url,"error":str(exc)}


def _clean_html_text(body):
    text=re.sub(r"<script[\s\S]*?</script>"," ",body or "",flags=re.I)
    text=re.sub(r"<style[\s\S]*?</style>"," ",text,flags=re.I)
    text=re.sub(r"<[^>]+>"," ",text)
    text=re.sub(r"&nbsp;"," ",text,flags=re.I)
    text=re.sub(r"&amp;","&",text,flags=re.I)
    text=re.sub(r"\s+"," ",text)
    return text.strip()


def _extract_public_contacts_from_text(body):
    text=_clean_html_text(body)
    emails=sorted(set(re.findall(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}",text,re.I)))
    emails=[e for e in emails if not e.lower().endswith(("@example.com","@example.org","@example.net"))]
    # Phone extraction is deliberately conservative: public business/contact strings only.
    phones=sorted(set(re.findall(r"(?<!\d)(?:\+?\d[\d\s().-]{7,}\d)(?!\d)",text)))
    phones=[re.sub(r"\s+"," ",x).strip(" .") for x in phones]
    phones=[x for x in phones if 8 <= len(re.sub(r"\D","",x)) <= 15]
    return emails, unique_list(phones)


def _extract_social_links(body):
    links=[]
    for href in re.findall(r"(?:href\s*=\s*[\"']|https?://)(https?://[^\s\"'<>]+)",body or "",re.I):
        u=href.rstrip("'\"),.;")
        if re.search(r"(linkedin\.com|facebook\.com|instagram\.com|x\.com|twitter\.com|youtube\.com|github\.com|gitlab\.com)",u,re.I):
            links.append(u)
    # Also catch bare URLs in rendered text/source.
    for u in re.findall(r"https?://[^\s\"'<>]+",body or "",re.I):
        if re.search(r"(linkedin\.com|facebook\.com|instagram\.com|x\.com|twitter\.com|youtube\.com|github\.com|gitlab\.com)",u,re.I):
            links.append(u.rstrip("'\"),.;"))
    return unique_list(links)


def _extract_person_role_records(body, source_url):
    # Extract conservative public person/title pairs from visible page text.
    # Only names/titles explicitly published on the target public pages are used.
    text=_clean_html_text(body)
    records=[]
    role_words=(
        "chief executive officer|ceo|chief technology officer|cto|chief operating officer|coo|"
        "chief financial officer|cfo|chief information officer|cio|chief security officer|cso|"
        "chief marketing officer|cmo|chief product officer|cpo|president|vice president|vp|"
        "founder|co-founder|cofounder|director|managing director|general manager|head of|partner|"
        "chairman|chairwoman|chairperson|board member|executive director|manager|lead"
    )
    # Handles common formats: "Name - CEO", "Name | Director", "Name, Chief ..."
    patterns=[
        rf"\b([A-Z][A-Za-z'ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¾Ãƒâ€šÃ‚Â¢.-]+(?:\s+[A-Z][A-Za-z'ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¾Ãƒâ€šÃ‚Â¢.-]+){{1,3}})\s*[,|\-ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã¢â‚¬Å“ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â:]\s*({role_words})\b",
        rf"\b({role_words})\s*[,|:\-ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã¢â‚¬Å“ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â]\s*([A-Z][A-Za-z'ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¾Ãƒâ€šÃ‚Â¢.-]+(?:\s+[A-Z][A-Za-z'ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¾Ãƒâ€šÃ‚Â¢.-]+){{1,3}})\b",
    ]
    for idx,pat in enumerate(patterns):
        for m in re.finditer(pat,text,flags=re.I):
            if idx==0: name,role=m.group(1),m.group(2)
            else: role,name=m.group(1),m.group(2)
            name=" ".join(name.split())
            role=" ".join(role.split())
            if len(name)<4 or len(name)>80: continue
            if name.lower() in {"privacy policy","terms and conditions","contact us","about us"}: continue
            records.append({"name":name,"title":role,"source":source_url})
    # HTML heading/name + nearby title fallback.
    for m in re.finditer(r"<h[1-6][^>]*>(.*?)</h[1-6]>(.{0,350})",body or "",flags=re.I|re.S):
        name=_clean_html_text(m.group(1))
        nearby=_clean_html_text(m.group(2))
        if not re.match(r"^[A-Z][A-Za-z'ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¾Ãƒâ€šÃ‚Â¢.-]+(?:\s+[A-Z][A-Za-z'ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¾Ãƒâ€šÃ‚Â¢.-]+){1,3}$",name): continue
        rm=re.search(rf"\b({role_words})\b",nearby,re.I)
        if rm:
            records.append({"name":name,"title":rm.group(1),"source":source_url})
    seen=set(); out=[]
    for r in records:
        k=(r["name"].lower(),r["title"].lower(),r["source"].lower())
        if k not in seen:
            seen.add(k); out.append(r)
    return out


def collect_people_intelligence(target, crawler=None):
    # Collect only publicly disclosed people/organization intelligence.
    # LinkedIn/social links are discovered from public target pages; authenticated
    # profile scraping is not performed. Document metadata is read from public files.
    urls=_public_site_urls(target,crawler,limit=80)
    pages=[]
    checked=0
    for url in urls:
        r=_download_public_page_text(url,timeout=7,max_bytes=160000)
        checked += 1
        code=r.get("status_code")
        if isinstance(code,int) and code in {200,206,301,302,307,308,401,403} and r.get("body"):
            pages.append({"url":r.get("url",url),"status_code":code,"body":r.get("body","")})

    # Public contacts
    contact_items=[]; contact_evidence=[]
    for page in pages:
        emails,phones=_extract_public_contacts_from_text(page["body"])
        for e in emails:
            contact_items.append({"type":"email","value":e,"source":page["url"]})
        for ph in phones:
            contact_items.append({"type":"phone","value":ph,"source":page["url"]})
        if emails or phones:
            contact_evidence.append({"url":page["url"],"emails_found":len(emails),"phones_found":len(phones)})
    # Deduplicate values while retaining evidence sources.
    uniq={}
    for x in contact_items:
        uniq.setdefault((x["type"],x["value"].lower()),x)
    public_contacts=_feature_contract("Public Contacts","target public webpages",checked,list(uniq.values()),contact_evidence)

    # Executive/public organization records
    people=[]
    for page in pages:
        people.extend(_extract_person_role_records(page["body"],page["url"]))
    ded={}
    for x in people: ded.setdefault((x["name"].lower(),x["title"].lower()),x)
    people=list(ded.values())
    exec_roles=re.compile(r"ceo|chief|president|founder|co-founder|chair|executive director|managing director|vp|vice president",re.I)
    executives=[x for x in people if exec_roles.search(x.get("title", ""))]
    executives=_feature_contract("Executive OSINT","public target webpages",checked,executives,[{"url":x["url"]} for x in []])

    # Organization chart is limited to publicly stated person/title pairs; it does not infer private reporting lines.
    org=_feature_contract("Organization Chart","public target webpages",checked,people,[],
                          "Contains publicly stated names and titles; reporting relationships are not inferred unless published.")

    # Social media / public profiles
    social=[]
    for page in pages:
        for u in _extract_social_links(page["body"]):
            social.append({"url":u,"platform":re.search(r"(?:https?://)?(?:www\.)?([^./]+)",u).group(1).lower() if re.search(r"(?:https?://)?(?:www\.)?([^./]+)",u) else "unknown","source":page["url"]})
    social_d={x["url"].lower():x for x in social}
    social=_feature_contract("Social Media Posture","links published on target webpages",checked,list(social_d.values()),[])

    # LinkedIn: report public links published by the target, without crawling LinkedIn profiles.
    linkedin_items=[x for x in social["items"] if "linkedin.com" in x.get("url","").lower()]
    linkedin=_feature_contract("Employee LinkedIn","LinkedIn URLs publicly published by target pages",checked,linkedin_items,[],
                               "Only links exposed by the target's public pages are collected; authenticated/profile scraping is not performed.")

    # Travel/schedule: public events/calendar/schedule pages and explicit event-like URLs.
    travel=[]
    event_re=re.compile(r"(event|events|calendar|conference|webinar|summit|schedule|speaking|speaker|agenda|travel)",re.I)
    for page in pages:
        if event_re.search(page["url"]):
            travel.append({"url":page["url"],"source":"public target webpage","status_code":page["status_code"]})
        for m in re.finditer(r"\b(?:conference|summit|webinar|speaking|speaker|event|agenda|calendar)\b.{0,100}",_clean_html_text(page["body"]),re.I):
            snippet=" ".join(m.group(0).split())
            if len(snippet)>=10:
                travel.append({"url":page["url"],"snippet":snippet,"source":"public webpage"})
    travel_d={json.dumps(x,sort_keys=True):x for x in travel}
    travel=_feature_contract("Public Travel / Schedule Signals","public target webpages",checked,list(travel_d.values()),[],
                             "Only publicly disclosed event/schedule signals are reported; no private travel data is inferred or collected.")

    # Public document metadata
    document_items=[]; document_evidence=[]
    doc_urls=[]
    for page in pages:
        body=page["body"]
        # href/src URLs plus absolute document URLs in source
        refs=re.findall(r"(?:href|src)\s*=\s*[\"']([^\"']+)[\"']",body,re.I)
        refs += re.findall(r"https?://[^\s\"'<>]+",body,re.I)
        for ref in refs:
            u=_absolute_url(page["url"],ref)
            if re.search(r"\.(pdf|docx|xlsx|pptx)(?:$|[?#])",u,re.I): doc_urls.append(u)
    doc_urls=unique_list(doc_urls)[:40]
    for u in doc_urls:
        r=_download_public_page_text(u,timeout=10,max_bytes=300000)
        code=r.get("status_code")
        if not isinstance(code,int) or code not in {200,206}: continue
        body=r.get("body","")
        # http_text_get decodes binary as text, so fetch bytes directly for metadata parsing.
        try:
            req=urllib.request.Request(u,headers={"User-Agent":"VAPT-Automation-Tool/1.0"},method="GET")
            with urllib.request.urlopen(req,timeout=10) as resp:
                raw=resp.read(300000)
            ext=Path(urllib.parse.urlparse(u).path).suffix.lower()
            meta={"url":u,"type":ext.lstrip("."),"status_code":resp.status}
            if ext==".pdf":
                try:
                    from pypdf import PdfReader
                    import io as _io
                    reader=PdfReader(_io.BytesIO(raw),strict=False)
                    m=reader.metadata
                    if m:
                        for key in ("title","author","subject","creator","producer","creation_date","modification_date"):
                            try:
                                value=getattr(m,key,None)
                            except Exception: value=None
                            if value not in (None,""): meta[key]=str(value)
                except Exception as exc:
                    meta["metadata_error"]=str(exc)
            elif ext in {".docx",".xlsx",".pptx"}:
                import zipfile as _zipfile
                import xml.etree.ElementTree as ET
                with _zipfile.ZipFile(_io.BytesIO(raw)) as z:
                    xml=z.read("docProps/core.xml").decode("utf-8","replace")
                    root=ET.fromstring(xml)
                    ns={"dc":"http://purl.org/dc/elements/1.1/","cp":"http://schemas.openxmlformats.org/package/2006/metadata/core-properties","dcterms":"http://purl.org/dc/terms/"}
                    for key,path in [("title","dc:title"),("creator","dc:creator"),("subject","dc:subject"),("description","dc:description"),("last_modified_by","cp:lastModifiedBy"),("created","dcterms:created"),("modified","dcterms:modified")]:
                        node=root.find(path,ns)
                        if node is not None and node.text: meta[key]=node.text
            document_items.append(meta)
            document_evidence.append({"url":u,"type":ext.lstrip(".")})
        except Exception as exc:
            document_evidence.append({"url":u,"error":str(exc)})
    document_metadata=_feature_contract("Public Document Metadata","public documents linked from target pages",len(doc_urls),document_items,document_evidence,
                                      "Metadata is read only from publicly linked documents; document contents are not indexed into the result.")

    return {
        "executives":executives,
        "linkedin":linkedin,
        "org_chart":org,
        "public_contacts":public_contacts,
        "document_metadata":document_metadata,
        "social_media":social,
        "travel_schedule":travel,
    }



# ============================================================
# CREDENTIAL / CODE / THREAT PUBLIC-SOURCE COLLECTION
# ============================================================

def _feature_not_checked(feature, note, source="not configured"):
    return {
        "status": "not_configured",
        "feature": feature,
        "source": source,
        "checked": 0,
        "found": 0,
        "count": 0,
        "items": [],
        "evidence": [],
        "note": note,
        "authorized_only": True,
    }


def _http_head_or_get(url, timeout=8, max_bytes=4096):
    return http_text_get(url, timeout=timeout, max_bytes=max_bytes)


def collect_archive_snapshots(target, crawler=None):
    """Check the public Internet Archive CDX index for historical snapshots.
    No archived page bodies are downloaded; only snapshot metadata is retained.
    """
    target_url=target.rstrip('/') + '/'
    api='https://web.archive.org/cdx/search/cdx?url=' + urllib.parse.quote(target_url, safe='') + '&output=json&fl=timestamp,original,statuscode,digest&filter=statuscode:200&filter=mimetype:text/html&collapse=digest&limit=200'
    try:
        data=http_json_get(api, timeout=15)
        rows=[]
        if isinstance(data,list) and len(data)>1:
            for row in data[1:]:
                if isinstance(row,list) and len(row)>=4:
                    rows.append({"timestamp":row[0],"url":row[1],"status_code":row[2],"digest":row[3]})
        return _feature_contract("Archive.org Snapshots", "Internet Archive CDX metadata", 1, rows,
            [{"url":api,"snapshot_count":len(rows)}],
            "Only public snapshot metadata is collected; archived page bodies are not downloaded.")
    except Exception as exc:
        return {
            "status":"completed","feature":"Archive.org Snapshots","source":"Internet Archive CDX metadata",
            "checked":1,"found":0,"count":0,"items":[],"evidence":[{"url":api,"error":str(exc)}],
            "note":"Archive metadata check completed but the public CDX service was unavailable."
        }


def _extract_git_orgs_and_repos(target, crawler=None):
    urls=_public_site_urls(target,crawler,limit=100)
    links=[]
    for u in urls:
        r=_download_public_page_text(u,timeout=6,max_bytes=60000)
        body=r.get('body','')
        links.extend(_extract_social_links(body))
        links.extend(re.findall(r'https?://(?:www\\.)?(?:github\\.com|gitlab\\.com)/[^\\s"\'<>]+',body,re.I))
    links=unique_list(links)
    github=[]; gitlab=[]
    for u in links:
        m=re.search(r'https?://(?:www\\.)?github\\.com/([^/?#]+)(?:/([^/?#]+))?',u,re.I)
        if m: github.append({"owner":m.group(1),"repo":m.group(2),"url":u})
        m=re.search(r'https?://(?:www\\.)?gitlab\\.com/([^/?#]+)(?:/([^/?#]+))?',u,re.I)
        if m: gitlab.append({"owner":m.group(1),"repo":m.group(2),"url":u})
    return github,gitlab


def collect_git_org_scan(target,crawler=None):
    github,gitlab=_extract_git_orgs_and_repos(target,crawler)
    items=[]; evidence=[]
    checked=len(github)+len(gitlab)
    for x in github:
        owner=x['owner']; repo=x.get('repo')
        if repo:
            items.append({"provider":"GitHub","owner":owner,"repo":repo,"url":x['url'],"source":"public target page"})
            continue
        api=f'https://api.github.com/orgs/{urllib.parse.quote(owner,safe="")}/repos?per_page=100'
        try:
            data=http_json_get(api,headers={"User-Agent":"VAPT-Automation-Tool/1.0","Accept":"application/vnd.github+json"},timeout=10)
            if isinstance(data,list):
                for r in data:
                    if isinstance(r,dict) and r.get('html_url'):
                        items.append({"provider":"GitHub","owner":owner,"repo":r.get('name'),"url":r.get('html_url'),"visibility":r.get('visibility') or ("public" if not r.get('private') else "private"),"source":"GitHub public API"})
                evidence.append({"provider":"GitHub","owner":owner,"api":api,"repositories_checked":len(data)})
            else: evidence.append({"provider":"GitHub","owner":owner,"api":api,"result":"not an organization or API response unavailable"})
        except Exception as exc: evidence.append({"provider":"GitHub","owner":owner,"api":api,"error":str(exc)})
    for x in gitlab:
        items.append({"provider":"GitLab","owner":x['owner'],"repo":x.get('repo'),"url":x['url'],"source":"public target page"})
    return _feature_contract("GitHub / GitLab Organization Scan","public repository/profile links and public GitHub API",checked,unique_list([json.dumps(x,sort_keys=True) for x in items]),evidence,
        "Only public repository metadata is collected. Repository contents and secrets are not downloaded.") | {"items":[json.loads(x) for x in unique_list([json.dumps(x,sort_keys=True) for x in items])],"found":len(items),"count":len(items)}


def collect_public_repo_secret_indicators(target,crawler=None):
    github,gitlab=_extract_git_orgs_and_repos(target,crawler)
    candidates=[]
    for x in github+gitlab:
        if x.get('repo'):
            candidates.append({"provider":"GitHub" if x in github else "GitLab","url":x['url'],"repo":x.get('repo')})
    # Detect public repository URLs and only metadata/filename indicators. No secret values are fetched.
    indicators=[]
    for x in candidates:
        indicators.append({**x,"checked":True,"secret_scan":"metadata-only","potential_indicators":[]})
    return _feature_contract("Public Repository / Gist Secret Indicators","public repository links exposed by target pages",len(candidates),indicators,[],
        "Metadata-only check. No credentials, tokens, cookies, or secret values are downloaded.")


def collect_paste_links(target,crawler=None):
    urls=_public_site_urls(target,crawler,limit=100)
    found=[]
    paste_re=re.compile(r'https?://(?:www\\.)?(?:pastebin\\.com|paste\\.ee|hastebin\\.com|gist\\.github\\.com)/[^\\s"\'<>]+',re.I)
    for u in urls:
        r=_download_public_page_text(u,timeout=6,max_bytes=70000)
        for purl in paste_re.findall(r.get('body','') or ''):
            found.append({"url":purl.rstrip("'\"),.;"),"source_page":u})
    ded={x['url'].lower():x for x in found}
    return _feature_contract("Paste Leak Indicators","paste URLs publicly referenced by target pages",len(urls),list(ded.values()),[],
        "This checks only public paste references already exposed by the target. It does not search or download unrelated paste dumps.")


def collect_cookie_and_token_surface(target):
    """
    Safe live check of HTTP Set-Cookie security metadata.

    Does NOT harvest browser cookies.
    Does NOT return cookie values.
    Only records cookie name and security attributes.
    """
    try:
        r = http_text_get(
            target,
            timeout=12,
            max_bytes=16384,
        )

        headers = r.get("headers", {}) or {}

        cookie_headers = []

        # urllib response headers may expose Set-Cookie through
        # different casing depending on the server.
        for key, value in headers.items():
            if str(key).lower() == "set-cookie":
                cookie_headers.append(str(value))

        cookie_items = []

        for cookie in cookie_headers:
            name = ""

            if "=" in cookie:
                name = cookie.split("=", 1)[0].strip()

            low = cookie.lower()

            same_site_match = re.search(
                r";\s*samesite=([^;]+)",
                low,
                re.I,
            )

            cookie_items.append({
                "name": name,
                "secure": bool(
                    re.search(
                        r";\s*secure(?:;|$)",
                        low,
                        re.I,
                    )
                ),
                "httponly": bool(
                    re.search(
                        r";\s*httponly(?:;|$)",
                        low,
                        re.I,
                    )
                ),
                "samesite": (
                    same_site_match.group(1).strip()
                    if same_site_match
                    else None
                ),
                "value_exposed": False,
            })

        evidence = [{
            "url": r.get("url") or target,
            "status_code": r.get("status_code"),
            "cookies_seen": len(cookie_items),
        }]

        return _feature_contract(
            "Corporate Cookie Surface",
            "Live HTTP Set-Cookie security metadata",
            1,
            cookie_items,
            evidence,
            "Only cookie security attributes are inspected. Cookie values and browser cookies are never collected.",
        )

    except Exception as exc:
        return {
            "status": "error",
            "feature": "Corporate Cookie Surface",
            "source": "Live HTTP response",
            "checked": 1,
            "found": 0,
            "count": 0,
            "items": [],
            "evidence": [],
            "note": str(exc),
            "error": str(exc),
        }


def collect_session_token_surface(target):
    """
    Safe live check for authentication/session-related HTTP headers.

    Does NOT harvest or return token values.
    """

    try:
        r = http_text_get(
            target,
            timeout=12,
            max_bytes=16384,
        )

        headers = r.get("headers", {}) or {}

        auth_headers = []

        sensitive_header_names = {
            "authorization",
            "x-auth-token",
            "x-access-token",
            "x-api-key",
            "x-session-token",
            "session-token",
            "sessiontoken",
        }

        for key, value in headers.items():

            header_name = str(key).strip()

            if header_name.lower() in sensitive_header_names:

                auth_headers.append({
                    "header": header_name,
                    "present": bool(value),
                    "value_exposed": False,
                })

        evidence = [{
            "url": r.get("url") or target,
            "status_code": r.get("status_code"),
            "response_auth_headers": len(auth_headers),
        }]

        return _feature_contract(
            "Session Token Surface",
            "Live HTTP response header metadata",
            1,
            auth_headers,
            evidence,
            "Authentication header names are checked only. Token values are never harvested or returned.",
        )

    except Exception as exc:
        return {
            "status": "error",
            "feature": "Session Token Surface",
            "source": "Live HTTP response",
            "checked": 1,
            "found": 0,
            "count": 0,
            "items": [],
            "evidence": [],
            "note": str(exc),
            "error": str(exc),
        }

def collect_public_third_party_risk(target,crawler=None):
    host=extract_target_host(target)
    urls=_public_site_urls(target,crawler,limit=100)
    domains=set()
    evidence=[]
    for u in urls:
        r=_download_public_page_text(u,timeout=6,max_bytes=100000)
        body=r.get('body','') or ''
        for ref in re.findall(r'https?://([^/\\s"\'<>]+)',body,re.I):
            d=ref.split(':',1)[0].lower().strip('.')
            if d and d!=host and not d.endswith('.'+host): domains.add(d)
    items=[{"domain":d,"source":"public target page","same_organization":False} for d in sorted(domains)]
    return _feature_contract("Third-party Supplier Risk","external domains referenced by public target pages",len(urls),items,evidence,
        "This is an external-domain inventory, not a vendor-risk verdict. Supplier ownership and risk require separate validation.")


def _dns_resolves(hostname):
    try:
        return socket.gethostbyname_ex(hostname)[2]
    except Exception:
        return []


def _typosquat_variants(host):
    base=host.split('.')[0]
    suffix='.'.join(host.split('.')[1:]) if '.' in host else ''
    variants=set()
    for i in range(len(base)):
        variants.add(base[:i]+base[i+1:])
    for i in range(len(base)):
        for ch in 'abcdefghijklmnopqrstuvwxyz0123456789':
            if ch!=base[i]: variants.add(base[:i]+ch+base[i+1:])
    for i in range(len(base)+1):
        for ch in 'abcdefghijklmnopqrstuvwxyz': variants.add(base[:i]+ch+base[i:])
    for i in range(len(base)-1):
        variants.add(base[:i]+base[i+1]+base[i]+base[i+2:])
    variants.discard(base)
    return unique_list([v+'.'+suffix for v in variants if suffix and 3<=len(v)<=63])[:300]


def collect_typosquats(target):
    host=extract_target_host(target)
    variants=_typosquat_variants(host)
    items=[]; checked=0
    for h in variants:
        checked+=1
        ips=_dns_resolves(h)
        if ips:
            items.append({"hostname":h,"ips":ips,"evidence":"DNS A record resolved"})
    return _feature_contract("Impersonation / Typosquat Indicators","generated edit-distance DNS checks",checked,items,[],
        "Only DNS resolution is checked. A resolving lookalike is an indicator, not proof of malicious ownership or impersonation.")


def collect_phishing_indicators(target,crawler=None):
    urls=_public_site_urls(target,crawler,limit=100)
    items=[]; checked=0
    for u in urls:
        r=_download_public_page_text(u,timeout=6,max_bytes=120000)
        body=r.get('body','') or ''
        forms=re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>',body,re.I)
        auth=re.search(r'(login|signin|sign-in|password|otp|authenticate|verify)',_clean_html_text(body),re.I)
        for action in forms:
            au=_absolute_url(u,action)
            host_u=urllib.parse.urlparse(u).hostname or ''
            host_a=urllib.parse.urlparse(au).hostname or ''
            if auth and host_a and host_a.lower()!=host_u.lower():
                items.append({"page":u,"form_action":au,"indicator":"authentication form posts to different host"})
        checked+=1
    return _feature_contract("Phishing Kit Indicators","public authentication-form structure on target pages",checked,items,[],
        "Only public form structure is inspected. This does not classify a site as a phishing kit by itself.")


def collect_sector_ttp_profile(job):
    nmap=job.get('nmap',{}) or {}; tech=job.get('technologies',[]) or []
    items=[]
    for p in nmap.get('open_ports',[]) or []:
        items.append({"type":"exposed_service","port":p.get('port'),"service":p.get('service'),"product":p.get('product'),"version":p.get('version')})
    for t in tech:
        items.append({"type":"observed_technology","name":t.get('name') or t.get('product') or t.get('technology'),"version":t.get('version')})
    return _feature_contract("Sectoral TTP Matching","observed technology and service profile",1,items,[],
        "This is an exposure profile only. No sector-specific threat attribution or adversary matching is claimed.")


def collect_provider_status_features():
    # These datasets are not safely or truthfully searchable without an explicitly
    # configured/licensed provider. Keep them distinct from live public-source checks.
    return {
        "breach_corpus": run_hibp_breach_test(),
        "combolist": _feature_not_checked("ComboList Appearances", "No authorized threat-intelligence provider configured; no combo lists are queried."),
        "infostealer": _feature_not_checked("Infostealer Exposure", "No authorized provider configured; stolen infostealer logs are never collected."),
        "credential_reuse": _feature_not_checked("Credential Reuse Verification", "Requires explicitly supplied authorized test credentials; none are supplied to this scan."),
        "iab": _feature_not_checked("Initial Access Broker Listings", "No authorized threat-intelligence provider configured."),
        "ransomware": _feature_not_checked("Ransomware Leak-site Hits", "No authorized threat-intelligence provider configured."),
        "adversary_chatter": _feature_not_checked("Targeted Adversary Chatter", "No authorized threat-intelligence provider configured."),
    }


def _run_final_collector(scan_id, name, label, fn):
    """Run one bounded final-stage collector with live dashboard telemetry."""
    try:
        update_job(scan_id, finalization_current=name, finalization_message=f"{label} ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â collecting live evidence...", message=f"{label} ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â collecting live evidence...")
        value = fn()
        return {"name": name, "label": label, "ok": True, "value": value}
    except Exception as exc:
        return {"name": name, "label": label, "ok": False, "value": {"status":"error","feature":label,"checked":0,"found":0,"count":0,"items":[],"evidence":[],"note":str(exc),"error":str(exc)}}


def populate_safe_features(scan_id, target):
    """Populate extended intelligence in parallel so the 99% stage is short and observable."""
    job = get_job(scan_id) or {}
    host = extract_target_host(target)
    dns_result = job.get("dns", {}) or {}
    subdomains_result = job.get("subdomains", {}) or {}
    crawler = job.get("crawler", {}) or {}
    nmap_result = job.get("nmap", {}) or {}
    technologies = job.get("technologies", []) or []

    # Finalization has its own progress budget: 92 -> 99. It never reports 100 here.
    collector_specs = [
        ("dns_ns", "DNS / NS intelligence", lambda: collect_dns_feature(dns_result)),
        ("asn_bgp", "ASN / BGP intelligence", lambda: collect_asn_bgp(host)),
        ("cloud_storage", "Cloud storage exposure", lambda: collect_cloud_storage_indicators(target, crawler)),
        ("service_exposure", "Service exposure discovery", lambda: collect_public_service_exposure(target, crawler=crawler, subdomains=subdomains_result)),
        ("remote_services", "Remote service analysis", lambda: collect_remote_services(nmap_result)),
        ("email_gateway", "Email gateway analysis", lambda: collect_email_gateway(dns_result)),
        ("eol_assets", "EOL asset analysis", lambda: collect_eol_assets(nmap_result, technologies)),
        ("shadow_saas", "Shadow SaaS discovery", lambda: collect_shadow_saas(crawler)),
        ("people", "People / public organization intelligence", lambda: collect_people_intelligence(target, crawler)),
        ("corporate_cookies", "Corporate cookie surface", lambda: collect_cookie_and_token_surface(target)),
        ("session_tokens", "Session-token surface", lambda: collect_session_token_surface(target)),
        ("git_paste", "Public Git / Paste references", lambda: collect_paste_links(target, crawler)),
        ("git_orgs", "GitHub / GitLab public metadata", lambda: collect_git_org_scan(target, crawler)),
        ("repo_secrets", "Public repository metadata indicators", lambda: collect_public_repo_secret_indicators(target, crawler)),
        ("archive", "Archive.org snapshot metadata", lambda: collect_archive_snapshots(target, crawler)),
        ("typosquats", "Typosquat DNS indicators", lambda: collect_typosquats(target)),
        ("phishing", "Public authentication-form indicators", lambda: collect_phishing_indicators(target, crawler)),
        ("supplier_risk", "Public third-party domain inventory", lambda: collect_public_third_party_risk(target, crawler)),
        ("sector_ttps", "Observed service / technology profile", lambda: collect_sector_ttp_profile(job)),
    ]

    total = len(collector_specs)
    results = {}
    running = set()
    completed = 0

    update_job(scan_id,
        phase="Final intelligence collection",
        progress=92,
        message="Starting final live intelligence collectors...",
        finalization={
            "status":"running",
            "completed":0,
            "total":total,
            "current_collector":None,
            "running_collectors":[],
            "message":"Starting final live intelligence collectors...",
        },
    )

    def wrapped(spec):
        name, label, fn = spec
        with scan_jobs_lock:
            job2 = scan_jobs.get(scan_id)
            if job2:
                running2 = set(job2.get("finalization", {}).get("running_collectors", []))
                running2.add(label)
                job2["finalization"] = {
                    **job2.get("finalization", {}),
                    "status":"running",
                    "current_collector":label,
                    "running_collectors":sorted(running2),
                    "message":f"{label} ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â collecting live evidence...",
                    "completed":job2.get("finalization", {}).get("completed",0),
                    "total":total,
                }
                job2["phase"]="Final intelligence collection"
                job2["message"]=f"{label} ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â collecting live evidence..."
        return _run_final_collector(scan_id, name, label, fn)

    # Network-bound final collectors run concurrently. This removes the old
    # serial 99% bottleneck while retaining real source checks and strict errors.
    with ThreadPoolExecutor(max_workers=min(10, total)) as executor:
        futures = {executor.submit(wrapped, spec): spec for spec in collector_specs}
        for future in as_completed(futures):
            spec = futures[future]
            name, label, _ = spec
            try:
                result = future.result()
            except Exception as exc:
                result = {"name":name,"label":label,"ok":False,"value":{"status":"error","feature":label,"checked":0,"found":0,"count":0,"items":[],"evidence":[],"error":str(exc)}}
            results[name] = result.get("value", {})
            completed += 1
            with scan_jobs_lock:
                job2 = scan_jobs.get(scan_id)
                if job2:
                    fin = dict(job2.get("finalization", {}))
                    running2 = set(fin.get("running_collectors", []))
                    running2.discard(label)
                    fin.update({
                        "status":"running",
                        "completed":completed,
                        "total":total,
                        "current_collector":label,
                        "running_collectors":sorted(running2),
                        "message":f"{label} ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â completed ({completed}/{total})",
                    })
                    job2["finalization"] = fin
                    job2["phase"]="Final intelligence collection"
                    job2["message"]=f"{label} ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â completed ({completed}/{total})"
                    # 92..99 only. 100 is reserved for the final atomic completion.
                    job2["progress"] = min(99, 92 + int((completed / total) * 7))

    # Cheap derived values.
    asn_result = results.get("asn_bgp", {})
    dns_feature = results.get("dns_ns", {})
    cloud = results.get("cloud_storage", {})
    service_exposure = results.get("service_exposure", {}) or {}
    remote = results.get("remote_services", {})
    email = results.get("email_gateway", {})
    eol = results.get("eol_assets", {})
    shadow = results.get("shadow_saas", {})
    internal_urls = update_internal_urls_from_crawler(scan_id)
    people = results.get("people", {}) or {}
    provider_features = collect_provider_status_features()

    sd_values = _extract_subdomain_values(subdomains_result)
    ct_values = _extract_subdomain_values((job.get("certificates", {}) or {}).get("subdomains", []))
    all_sd = unique_list(sd_values + ct_values)
    dev_hosts = [x for x in all_sd if re.search(r"(^|[.-])(dev|development|test|testing|staging|stage|uat|qa|beta|sandbox|demo)([.-]|$)", x, re.I)]
    dev_probe = service_exposure.get("dev_staging", {}) or {}
    dev_feature = {
        "status":"completed",
        "feature":"Exposed Dev / Staging",
        "source":"CT + subdomain enumeration + live HTTP probes",
        "checked":len(all_sd) + dev_probe.get("checked", 0),
        "found":len(dev_hosts) + dev_probe.get("found", 0),
        "count":len(dev_hosts) + dev_probe.get("found", 0),
        "items":[{"hostname":x,"source":"CT/subdomain enumeration"} for x in dev_hosts] + dev_probe.get("items", []),
        "evidence":{"discovered_subdomains":all_sd,"http_probes":dev_probe.get("evidence", [])},
    }

    # A failed optional collector must still produce a truthful completed/error result,
    # rather than silently turning the whole scan into NOT_CONFIGURED.
    def feature_or_empty(key, title):
        value = results.get(key)
        if isinstance(value, dict) and value:
            return value
        return {"status":"error","feature":title,"checked":0,"found":0,"count":0,"items":[],"evidence":[],"note":"Collector returned no data."}

    update_job(scan_id,
        asn_bgp=feature_or_empty("asn_bgp", "ASN / BGP intelligence"),
        cloud_storage=feature_or_empty("cloud_storage", "Cloud storage exposure"),
        dns_history_ns_recon=feature_or_empty("dns_ns", "DNS / NS intelligence"),
        dev_staging=dev_feature,
        eol_assets=feature_or_empty("eol_assets", "EOL asset analysis"),
        admin_panels=service_exposure.get("admin_panels", {}),
        public_apis=service_exposure.get("public_apis", {}),
        technical_docs=service_exposure.get("technical_docs", {}),
        remote_services=feature_or_empty("remote_services", "Remote service analysis"),
        email_gateway=feature_or_empty("email_gateway", "Email gateway analysis"),
        cicd_registries=service_exposure.get("cicd_registries", {}),
        shadow_saas=feature_or_empty("shadow_saas", "Shadow SaaS discovery"),
        internal_urls=internal_urls,
        executives=people.get("executives", _feature_not_checked("Executive OSINT", "Collector did not return data.")),
        linkedin=people.get("linkedin", _feature_not_checked("Employee LinkedIn", "Collector did not return data.")),
        org_chart=people.get("org_chart", _feature_not_checked("Organization Chart", "Collector did not return data.")),
        public_contacts=people.get("public_contacts", _feature_not_checked("Public Contacts", "Collector did not return data.")),
        document_metadata=people.get("document_metadata", _feature_not_checked("Public Document Metadata", "Collector did not return data.")),
        social_media=people.get("social_media", _feature_not_checked("Social Media Posture", "Collector did not return data.")),
        travel_schedule=people.get("travel_schedule", _feature_not_checked("Public Travel / Schedule Signals", "Collector did not return data.")),
        breach_corpus=provider_features["breach_corpus"],
        combolist=provider_features["combolist"],
        infostealer=provider_features["infostealer"],
        credential_reuse=provider_features["credential_reuse"],
        corporate_cookies=feature_or_empty("corporate_cookies", "Corporate Cookie Surface"),
        session_tokens=feature_or_empty("session_tokens", "Session Token Surface"),
        git_paste_secrets=feature_or_empty("git_paste", "Public Git / Paste References"),
        git_orgs=feature_or_empty("git_orgs", "GitHub / GitLab Public Metadata"),
        repo_secrets=feature_or_empty("repo_secrets", "Public Repository Metadata Indicators"),
        mobile_keys=_feature_not_checked("Mobile App Extracted Keys", "Provide an authorized APK/IPA artifact for offline analysis"),
        paste_leaks=feature_or_empty("git_paste", "Paste Leak Indicators"),
        archive_snapshots=feature_or_empty("archive", "Archive.org Snapshots"),
        adversary_chatter=provider_features["adversary_chatter"],
        ransomware=provider_features["ransomware"],
        iab=provider_features["iab"],
        typosquats=feature_or_empty("typosquats", "Impersonation / Typosquat Indicators"),
        phishing=feature_or_empty("phishing", "Phishing Kit Indicators"),
        supplier_risk=feature_or_empty("supplier_risk", "Public Third-Party Risk Inventory"),
        sector_ttps=feature_or_empty("sector_ttps", "Observed Service / Technology Profile"),
        intelligence_run={
            "status":"completed",
            "mode":"live_public_source",
            "target":target,
            "checked_at":utc_now(),
            "collector_count":total,
            "collectors_completed":completed,
            "note":"Live public-source collectors ran concurrently. Provider-dependent intelligence remains not_configured until an authorized provider is configured.",
        },
    )

    update_job(scan_id,
        finalization={
            "status":"completed",
            "completed":total,
            "total":total,
            "current_collector":"Final result assembly",
            "running_collectors":[],
            "message":"All live intelligence collectors completed.",
        },
        phase="Finalizing results",
        message="All live intelligence collectors completed. Building final dashboard result...",
        progress=99,
    )

def update_internal_urls_from_crawler(scan_id):
    job = get_job(scan_id) or {}
    crawler = job.get("crawler", {}) or {}
    items = crawler.get("internal_urls", []) or []
    return {
        "status": "completed",
        "feature": "Internal URL enumeration",
        "source": "web crawler",
        "checked": len(items),
        "found": len(items),
        "count": len(items),
        "items": json_safe(items),
        "evidence": {"crawler_statistics": crawler.get("statistics", {})},
    }




# ============================================================
# SUMMARY
# ============================================================

def severity_summary(findings):
    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "total": 0,
    }

    for finding in findings or []:
        severity = str(
            finding.get(
                "severity",
                "info",
            )
        ).lower()

        if severity not in summary:
            severity = "info"

        summary[severity] += 1
        summary["total"] += 1

    return summary


# ============================================================
# MAIN SCAN ENGINE
# ============================================================

def perform_scan(
    scan_id,
    target,
    profile,
):
    try:
        update_job(
            scan_id,
            status="running",
            phase="Running security assessment",
            message=(
                f"{NMAP_PROFILES[profile]['label']} "
                "parallel security assessment started"
            ),
            progress=1,
        )

        update_module(
            scan_id,
            "http",
            "running",
            10,
        )

        http_result = http_assessment(
            target,
            scan_id,
        )

        update_job(
            scan_id,
            http=http_result,
        )

        tasks = {
            "dns": lambda: run_dns(
                scan_id,
                target,
            ),
            "subdomains": lambda: run_subdomains(
                scan_id,
                target,
            ),
            "certificates": lambda: run_certificates(
                scan_id,
                target,
            ),
            "technologies": lambda: run_technologies(
                scan_id,
                target,
            ),
            "web_security": lambda: run_web_security(
                scan_id,
                target,
            ),
            "crawler": lambda: run_crawler(
                scan_id,
                target,
            ),
            "nmap": lambda: nmap_tcp_scan(
                extract_target_host(target),
                scan_id,
                profile,
            ),
        }

        for module in tasks:
            update_module(
                scan_id,
                module,
                "queued",
                0,
            )

        with ThreadPoolExecutor(
            max_workers=7
        ) as executor:

            futures = {
                executor.submit(
                    fn
                ): name
                for name, fn in tasks.items()
            }

            for future in as_completed(
                futures
            ):
                name = futures[future]

                try:
                    value = future.result()

                except Exception as exc:
                    value = {
                        "status": "error",
                        "error": str(exc),
                    }

                if name == "dns":
                    update_job(
                        scan_id,
                        dns=value,
                        dns_history_ns_recon=value,
                    )

                elif name == "subdomains":
                    update_job(
                        scan_id,
                        subdomains=value,
                        subdomain_enumeration=value,
                    )

                elif name == "certificates":
                    update_job(
                        scan_id,
                        certificates=value,
                        certificate_transparency=value,
                    )

                elif name == "technologies":
                    current_http_tech = (
                        http_result.get(
                            "technologies",
                            [],
                        )
                    )

                    update_job(
                        scan_id,
                        technologies=merge_technologies(
                            current_http_tech,
                            value,
                        ),
                    )

                elif name == "web_security":
                    update_job(
                        scan_id,
                        web_security=value,
                        findings=normalize_findings(
                            value
                        ),
                    )

                elif name == "crawler":
                    value = normalize_crawler(value)
                    update_job(
                        scan_id,
                        crawler=value,
                        internal_urls={
                            "status": "completed",
                            "source": "web crawler",
                            "items": value.get(
                                "internal_urls",
                                [],
                            ),
                            "count": len(
                                value.get(
                                    "internal_urls",
                                    [],
                                )
                            ),
                        },
                    )

                elif name == "nmap":
                    current_tech = get_job(scan_id).get("technologies", []) if get_job(scan_id) else []
                    merged_tech = merge_technologies(
                        current_tech,
                        nmap_technology_records(value),
                    )
                    update_job(
                        scan_id,
                        nmap=value,
                        port_technology_fingerprint=value,
                        technologies=merged_tech,
                    )

                update_module(
                    scan_id,
                    name,
                    "completed",
                    100,
                )

                # Keep the live progress below 100 until finalization.
                update_job(
                    scan_id,
                    progress=min(99, calculate_overall_progress(scan_id)),
                )

        # Populate the broader feature matrix.
        populate_safe_features(
            scan_id,
            target,
        )

        with scan_jobs_lock:
            job = scan_jobs.get(scan_id)

            if not job:
                return

            findings = job.get(
                "findings",
                [],
            )

            job["summary"] = {
                "findings": severity_summary(
                    findings
                ),
                "open_ports": (
                    job.get(
                        "nmap",
                        {},
                    ).get(
                        "open_port_count",
                        0,
                    )
                ),
                "subdomains": (
                    job.get(
                        "subdomains",
                        {},
                    ).get(
                        "count",
                        0,
                    )
                ),
                "certificates": (
                    job.get(
                        "certificates",
                        {},
                    ).get(
                        "count",
                        0,
                    )
                ),
                "technologies": len(
                    job.get(
                        "technologies",
                        [],
                    )
                ),
                "crawler_pages": (
                    job.get(
                        "crawler",
                        {},
                    )
                    .get(
                        "statistics",
                        {},
                    )
                    .get(
                        "pages",
                        0,
                    )
                ),
            }

            job["features"] = build_features(
                job
            )

            # Finalization is atomic from the dashboard's point of view:
            # result/features are already present before status becomes
            # completed and progress becomes 100.
            job["phase"] = "Finalizing results"
            job["message"] = "Building final dashboard result..."
            job["progress"] = 99

            # The result is complete only now. Set status/progress last.
            job["status"] = "completed"
            job["phase"] = "Completed"
            job["message"] = "Security assessment completed"
            job["progress"] = 100
            job["completed_at"] = utc_now()

            result = json_safe(job)

        save_scan_to_database(
            scan_id,
            target,
            result,
        )

    except Exception as exc:
        update_job(
            scan_id,
            status="failed",
            phase="Error",
            message="Scan failed",
            error=str(exc),
            completed_at=utc_now(),
        )


# ============================================================
# DATABASE HELPERS
# ============================================================

def save_scan_to_database(
    scan_id,
    target,
    result,
):
    if not db_create_scan or not db_complete_scan:
        return

    try:
        try:
            db_create_scan(
                scan_id,
                target,
            )
        except TypeError:
            try:
                db_create_scan(
                    scan_id=scan_id,
                    target=target,
                )
            except Exception:
                pass

        payload = json.dumps(
            json_safe(result)
        )

        try:
            db_complete_scan(
                scan_id,
                payload,
            )
        except TypeError:
            try:
                db_complete_scan(
                    scan_id=scan_id,
                    result=payload,
                )
            except Exception:
                pass

    except Exception:
        pass


# ============================================================
# DASHBOARD RESULT
# ============================================================

def build_dashboard_result(job):
    return {
        "scan_id": job.get("scan_id"),
        "target": job.get("target"),
        "profile": job.get("profile"),
        "profile_label": job.get(
            "profile_label"
        ),

        "status": job.get("status"),
        "progress": job.get("progress"),
        "phase": job.get("phase"),
        "message": job.get("message"),

        "started_at": job.get("started_at"),
        "completed_at": job.get(
            "completed_at"
        ),

        "http": job.get("http", {}),
        "dns": job.get("dns", {}),
        "subdomains": job.get(
            "subdomains",
            {},
        ),
        "certificates": job.get(
            "certificates",
            {},
        ),
        "technologies": job.get(
            "technologies",
            [],
        ),
        "web_security": job.get(
            "web_security",
            {},
        ),
        "crawler": job.get(
            "crawler",
            {},
        ),
        "nmap": job.get(
            "nmap",
            {},
        ),

        # Full feature data
        "subdomain_enumeration": job.get(
            "subdomain_enumeration",
            {},
        ),
        "certificate_transparency": job.get(
            "certificate_transparency",
            {},
        ),
        "dns_history_ns_recon": job.get(
            "dns_history_ns_recon",
            {},
        ),
        "asn_bgp": job.get(
            "asn_bgp",
            {},
        ),
        "dev_staging": job.get(
            "dev_staging",
            {},
        ),
        "eol_assets": job.get(
            "eol_assets",
            {},
        ),
        "cloud_storage": job.get(
            "cloud_storage",
            {},
        ),

        "port_technology_fingerprint": job.get(
            "port_technology_fingerprint",
            {},
        ),
        "admin_panels": job.get(
            "admin_panels",
            {},
        ),
        "remote_services": job.get(
            "remote_services",
            {},
        ),
        "email_gateway": job.get(
            "email_gateway",
            {},
        ),
        "public_apis": job.get(
            "public_apis",
            {},
        ),
        "cicd_registries": job.get(
            "cicd_registries",
            {},
        ),
        "shadow_saas": job.get(
            "shadow_saas",
            {},
        ),

        "executives": job.get(
            "executives",
            {},
        ),
        "linkedin": job.get(
            "linkedin",
            {},
        ),
        "org_chart": job.get(
            "org_chart",
            {},
        ),
        "public_contacts": job.get(
            "public_contacts",
            {},
        ),
        "document_metadata": job.get(
            "document_metadata",
            {},
        ),
        "social_media": job.get(
            "social_media",
            {},
        ),
        "travel_schedule": job.get(
            "travel_schedule",
            {},
        ),

        "breach_corpus": job.get(
            "breach_corpus",
            {},
        ),
        "combolist": job.get(
            "combolist",
            {},
        ),
        "infostealer": job.get(
            "infostealer",
            {},
        ),
        "credential_reuse": job.get(
            "credential_reuse",
            {},
        ),
        "corporate_cookies": job.get(
            "corporate_cookies",
            {},
        ),
        "session_tokens": job.get(
            "session_tokens",
            {},
        ),
        "git_paste_secrets": job.get(
            "git_paste_secrets",
            {},
        ),

        "git_orgs": job.get(
            "git_orgs",
            {},
        ),
        "repo_secrets": job.get(
            "repo_secrets",
            {},
        ),
        "mobile_keys": job.get(
            "mobile_keys",
            {},
        ),
        "paste_leaks": job.get(
            "paste_leaks",
            {},
        ),
        "archive_snapshots": job.get(
            "archive_snapshots",
            {},
        ),
        "technical_docs": job.get(
            "technical_docs",
            {},
        ),
        "internal_urls": job.get(
            "internal_urls",
            {},
        ),

        "adversary_chatter": job.get(
            "adversary_chatter",
            {},
        ),
        "ransomware": job.get(
            "ransomware",
            {},
        ),
        "iab": job.get(
            "iab",
            {},
        ),
        "typosquats": job.get(
            "typosquats",
            {},
        ),
        "phishing": job.get(
            "phishing",
            {},
        ),
        "supplier_risk": job.get(
            "supplier_risk",
            {},
        ),
        "sector_ttps": job.get(
            "sector_ttps",
            {},
        ),

        "findings": job.get(
            "findings",
            [],
        ),
        "summary": job.get(
            "summary",
            {},
        ),
        "features": job.get(
            "features",
            {},
        ),

        "module_status": job.get(
            "module_status",
            {},
        ),
        "module_progress": job.get(
            "module_progress",
            {},
        ),

        "error": job.get("error"),
    }



# ============================================================
# AUTHENTICATION
# ============================================================

AUTH_EXEMPT_ENDPOINTS = {
    "login",
    "health",
    "static",
}

def get_auth_config():
    username = os.environ.get("VAPT_ADMIN_USERNAME", "").strip()
    password_hash = os.environ.get("VAPT_ADMIN_PASSWORD_HASH", "").strip()
    secret_key = os.environ.get("VAPT_SECRET_KEY", "").strip()

    return username, password_hash, secret_key


@app.before_request
def require_login():
    endpoint = request.endpoint

    if endpoint in AUTH_EXEMPT_ENDPOINTS:
        return None

    if endpoint is None:
        return None

    if session.get("authenticated") is True:
        return None

    if request.path.startswith("/login"):
        return None

    if request.path.startswith("/static/"):
        return None

    if request.path.startswith("/health"):
        return None

    if request.path.startswith("/scan/") or request.path == "/":
        if request.path.startswith("/scan/") and request.method != "GET":
            return jsonify({
                "success": False,
                "error": "Authentication required",
            }), 401

        return redirect(url_for("login", next=request.path))

    return redirect(url_for("login", next=request.path))


@app.route("/login", methods=["GET", "POST"])
def login():
    username, password_hash, secret_key = get_auth_config()

    if not secret_key:
        return """
        <h2>Authentication is not configured</h2>
        <p>The administrator must configure VAPT_SECRET_KEY in the server environment.</p>
        """, 503

    if request.method == "POST":
        submitted_username = (
            request.form.get("username", "").strip()
        )
        submitted_password = request.form.get(
            "password", ""
        )

        valid = (
            bool(username)
            and bool(password_hash)
            and submitted_username == username
            and check_password_hash(
                password_hash,
                submitted_password,
            )
        )

        if valid:
            session.clear()
            session["authenticated"] = True
            session["username"] = username

            next_url = request.args.get("next", "/")

            if not next_url.startswith("/"):
                next_url = "/"

            return redirect(next_url)

        return render_template(
            "login.html",
            error="Invalid username or password.",
        ), 401

    return render_template(
        "login.html",
        error=None,
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ============================================================
# ROUTES
# ============================================================

@app.route("/")
def index():
    return render_template(
        "index.html",
        profiles=NMAP_PROFILES,
        default_profile=DEFAULT_SCAN_PROFILE,
    )


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "tool": "VAPT Automation Tool",
        "default_profile": DEFAULT_SCAN_PROFILE,
        "profiles": NMAP_PROFILES,
        "nmap_available": bool(
            shutil_which("nmap")
        ),
        "modules": {
            "dns": bool(
                scan_dns
                or True
            ),
            "subdomains": bool(
                enumerate_subdomains
            ),
            "certificates": bool(
                enumerate_certificates
                or True
            ),
            "web_security": bool(
                scan_web_security
            ),
            "crawler": bool(
                crawl_site
            ),
        },
    })


@app.route(
    "/scan/start",
    methods=["POST"],
)
def start_scan():
    try:
        data = request.get_json(
            silent=True
        ) or {}

        target = normalize_target(
            data.get("target")
        )

        profile = normalize_profile(
            data.get(
                "profile",
                DEFAULT_SCAN_PROFILE,
            )
        )

        scan_id = str(uuid.uuid4())

        create_job(
            scan_id,
            target,
            profile,
        )

        if db_create_scan:
            try:
                db_create_scan(
                    scan_id,
                    target,
                )
            except Exception:
                pass

        thread = threading.Thread(
            target=perform_scan,
            args=(
                scan_id,
                target,
                profile,
            ),
            daemon=True,
        )

        thread.start()

        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "target": target,
            "profile": profile,
            "profile_label": NMAP_PROFILES[
                profile
            ]["label"],
            "message": "Scan started",
        })

    except Exception as exc:
        return jsonify({
            "success": False,
            "error": str(exc),
        }), 400


@app.route(
    "/scan-status/<scan_id>"
)
def scan_status(scan_id):
    job = get_job(scan_id)

    if not job:
        return jsonify({
            "success": False,
            "error": "Scan not found",
        }), 404

    return jsonify({
        "success": True,
        "scan": build_dashboard_result(
            job
        ),
    })


@app.route(
    "/scan/<scan_id>/result"
)
def scan_result(scan_id):
    job = get_job(scan_id)

    if not job:
        return jsonify({
            "success": False,
            "error": "Scan not found",
        }), 404

    return jsonify({
        "success": True,
        "result": build_dashboard_result(
            job
        ),
    })


# ============================================================
# DETAIL ENDPOINTS
# ============================================================

@app.route(
    "/scan/<scan_id>/crawler/<category>"
)
def crawler_detail(
    scan_id,
    category,
):
    job = get_job(scan_id)

    if not job:
        return jsonify({
            "error": "Scan not found",
        }), 404

    allowed = {
        "pages",
        "internal_urls",
        "external_urls",
        "parameters",
        "api_endpoints",
        "forms",
        "js_files",
        "css_files",
        "robots",
        "sitemap",
    }

    if category not in allowed:
        return jsonify({
            "error": "Invalid crawler category",
        }), 400

    crawler = job.get(
        "crawler",
        {},
    )

    return jsonify({
        "success": True,
        "category": category,
        "items": crawler.get(
            category,
            [],
        ),
    })


@app.route(
    "/scan/<scan_id>/security-findings"
)
def security_findings(scan_id):
    job = get_job(scan_id)

    if not job:
        return jsonify({
            "error": "Scan not found",
        }), 404

    return jsonify({
        "success": True,
        "findings": job.get(
            "findings",
            [],
        ),
    })


@app.route(
    "/scan/<scan_id>/security-finding/<int:index>"
)
def security_finding(
    scan_id,
    index,
):
    job = get_job(scan_id)

    if not job:
        return jsonify({
            "error": "Scan not found",
        }), 404

    findings = job.get(
        "findings",
        [],
    )

    if (
        index < 0
        or index >= len(findings)
    ):
        return jsonify({
            "error": "Finding not found",
        }), 404

    return jsonify({
        "success": True,
        "finding": findings[index],
    })


@app.route(
    "/scan/<scan_id>/web-security"
)
def web_security_detail(scan_id):
    job = get_job(scan_id)

    if not job:
        return jsonify({
            "error": "Scan not found",
        }), 404

    return jsonify({
        "success": True,
        "web_security": job.get(
            "web_security",
            {},
        ),
        "findings": job.get(
            "findings",
            [],
        ),
    })


@app.route(
    "/scan/<scan_id>/technologies"
)
def technology_detail(scan_id):
    job = get_job(scan_id)

    if not job:
        return jsonify({
            "error": "Scan not found",
        }), 404

    return jsonify({
        "success": True,
        "technologies": job.get(
            "technologies",
            [],
        ),
    })


@app.route(
    "/scan/<scan_id>/ports"
)
def ports_detail(scan_id):
    job = get_job(scan_id)

    if not job:
        return jsonify({
            "error": "Scan not found",
        }), 404

    return jsonify({
        "success": True,
        "nmap": job.get(
            "nmap",
            {},
        ),
        "ports": job.get(
            "nmap",
            {},
        ).get(
            "open_ports",
            [],
        ),
    })


@app.route(
    "/scan/<scan_id>/certificates"
)
def certificates_detail(scan_id):
    job = get_job(scan_id)

    if not job:
        return jsonify({
            "error": "Scan not found",
        }), 404

    return jsonify({
        "success": True,
        "certificates": job.get(
            "certificates",
            {},
        ),
    })


@app.route(
    "/scan/<scan_id>/dns"
)
def dns_detail(scan_id):
    job = get_job(scan_id)

    if not job:
        return jsonify({
            "error": "Scan not found",
        }), 404

    return jsonify({
        "success": True,
        "dns": job.get(
            "dns",
            {},
        ),
    })


@app.route(
    "/scan/<scan_id>/subdomains"
)
def subdomains_detail(scan_id):
    job = get_job(scan_id)

    if not job:
        return jsonify({
            "error": "Scan not found",
        }), 404

    return jsonify({
        "success": True,
        "subdomains": job.get(
            "subdomains",
            {},
        ),
    })


@app.route(
    "/scan/<scan_id>/features/<group>/<name>"
)
def feature_detail(
    scan_id,
    group,
    name,
):
    job = get_job(scan_id)

    if not job:
        return jsonify({
            "error": "Scan not found",
        }), 404

    features = job.get(
        "features",
        {},
    )

    group_data = features.get(
        group,
        {},
    )

    if name not in group_data:
        return jsonify({
            "error": "Feature not found",
        }), 404

    return jsonify({
        "success": True,
        "group": group,
        "name": name,
        "data": group_data[name],
    })


# ============================================================
# EXPORT
# ============================================================

def make_csv(result):
    output = io.StringIO()

    writer = csv.writer(output)

    writer.writerow([
        "Category",
        "Item",
        "Value",
    ])

    summary = result.get(
        "summary",
        {},
    )

    for key, value in summary.items():
        writer.writerow([
            "Summary",
            key,
            json.dumps(
                value,
                ensure_ascii=False,
            ),
        ])

    for port in (
        result.get(
            "nmap",
            {},
        ).get(
            "open_ports",
            [],
        )
    ):
        writer.writerow([
            "Open Port",
            port.get("port"),
            json.dumps(
                port,
                ensure_ascii=False,
            ),
        ])

    for technology in result.get(
        "technologies",
        [],
    ):
        writer.writerow([
            "Technology",
            technology.get(
                "name",
                "",
            ),
            json.dumps(
                technology,
                ensure_ascii=False,
            ),
        ])

    for finding in result.get(
        "findings",
        [],
    ):
        writer.writerow([
            "Finding",
            finding.get(
                "title",
                "",
            ),
            json.dumps(
                finding,
                ensure_ascii=False,
            ),
        ])

    for name, group in (
        result.get(
            "features",
            {},
        ).items()
    ):
        for feature_name, value in (
            group.items()
        ):
            writer.writerow([
                name,
                feature_name,
                json.dumps(
                    value,
                    ensure_ascii=False,
                ),
            ])

    return output.getvalue()


def make_html_report(result):
    target = html_lib.escape(
        str(result.get("target", ""))
    )

    profile = html_lib.escape(
        str(
            result.get(
                "profile_label",
                "",
            )
        )
    )

    summary = result.get(
        "summary",
        {},
    )

    findings = result.get(
        "findings",
        [],
    )

    ports = result.get(
        "nmap",
        {},
    ).get(
        "open_ports",
        [],
    )

    technologies = result.get(
        "technologies",
        [],
    )

    rows = ""

    for port in ports:
        rows += f"""
        <tr>
            <td>{html_lib.escape(str(port.get("port", "")))}</td>
            <td>{html_lib.escape(str(port.get("protocol", "")))}</td>
            <td>{html_lib.escape(str(port.get("service", "")))}</td>
            <td>{html_lib.escape(str(port.get("product", "")))}</td>
            <td>{html_lib.escape(str(port.get("version", "")))}</td>
        </tr>
        """

    tech_rows = ""

    for tech in technologies:
        tech_rows += f"""
        <tr>
            <td>{html_lib.escape(str(tech.get("name", "")))}</td>
            <td>{html_lib.escape(str(tech.get("technology", "")))}</td>
            <td>{html_lib.escape(str(tech.get("source", "")))}</td>
        </tr>
        """

    finding_rows = ""

    for finding in findings:
        finding_rows += f"""
        <tr>
            <td>{html_lib.escape(str(finding.get("severity", "")))}</td>
            <td>{html_lib.escape(str(finding.get("title", "")))}</td>
            <td>{html_lib.escape(str(finding.get("description", "")))}</td>
        </tr>
        """

    feature_rows = ""

    for group_name, group_data in (
        result.get(
            "features",
            {},
        ).items()
    ):
        for feature_name, value in group_data.items():
            feature_rows += f"""
            <tr>
                <td>{html_lib.escape(str(group_name))}</td>
                <td>{html_lib.escape(str(feature_name))}</td>
                <td><pre>{html_lib.escape(json.dumps(value, indent=2, default=str))}</pre></td>
            </tr>
            """

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>VAPT Report - {target}</title>
<style>
body {{
    font-family: Arial, sans-serif;
    margin: 30px;
    color: #222;
}}
h1, h2 {{
    margin-top: 30px;
}}
table {{
    border-collapse: collapse;
    width: 100%;
    margin-top: 10px;
}}
th, td {{
    border: 1px solid #ccc;
    padding: 8px;
    text-align: left;
    vertical-align: top;
}}
th {{
    background: #eee;
}}
.card {{
    display: inline-block;
    border: 1px solid #ddd;
    padding: 15px;
    margin: 5px;
    min-width: 130px;
}}
pre {{
    white-space: pre-wrap;
    word-break: break-word;
}}
</style>
</head>
<body>

<h1>VAPT Automation Report</h1>

<p><b>Target:</b> {target}</p>
<p><b>Scan Profile:</b> {profile}</p>
<p><b>Generated:</b> {html_lib.escape(utc_now())}</p>

<h2>Summary</h2>

<div class="card">
<b>Critical</b><br>
{summary.get("findings", {}).get("critical", 0)}
</div>

<div class="card">
<b>High</b><br>
{summary.get("findings", {}).get("high", 0)}
</div>

<div class="card">
<b>Medium</b><br>
{summary.get("findings", {}).get("medium", 0)}
</div>

<div class="card">
<b>Low</b><br>
{summary.get("findings", {}).get("low", 0)}
</div>

<div class="card">
<b>Open Ports</b><br>
{summary.get("open_ports", 0)}
</div>

<div class="card">
<b>Subdomains</b><br>
{summary.get("subdomains", 0)}
</div>

<div class="card">
<b>Certificates</b><br>
{summary.get("certificates", 0)}
</div>

<div class="card">
<b>Technologies</b><br>
{summary.get("technologies", 0)}
</div>

<h2>Open Ports</h2>

<table>
<tr>
<th>Port</th>
<th>Protocol</th>
<th>Service</th>
<th>Product</th>
<th>Version</th>
</tr>
{rows}
</table>

<h2>Technologies</h2>

<table>
<tr>
<th>Name</th>
<th>Technology</th>
<th>Source</th>
</tr>
{tech_rows}
</table>

<h2>Security Findings</h2>

<table>
<tr>
<th>Severity</th>
<th>Title</th>
<th>Description</th>
</tr>
{finding_rows}
</table>

<h2>Full Feature Matrix</h2>

<table>
<tr>
<th>Group</th>
<th>Feature</th>
<th>Data</th>
</tr>
{feature_rows}
</table>

</body>
</html>"""


@app.route(
    "/scan/<scan_id>/export/<fmt>"
)
def export_scan(
    scan_id,
    fmt,
):
    job = get_job(scan_id)

    if not job:
        return jsonify({
            "error": "Scan not found",
        }), 404

    result = build_dashboard_result(
        job
    )

    fmt = fmt.lower()

    if fmt == "json":
        data = json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        ).encode("utf-8")

        return send_file(
            io.BytesIO(data),
            mimetype="application/json",
            as_attachment=True,
            download_name=(
                f"vapt_{scan_id}.json"
            ),
        )

    if fmt == "csv":
        data = make_csv(
            result
        ).encode("utf-8")

        return send_file(
            io.BytesIO(data),
            mimetype="text/csv",
            as_attachment=True,
            download_name=(
                f"vapt_{scan_id}.csv"
            ),
        )

    if fmt == "html":
        data = make_html_report(
            result
        ).encode("utf-8")

        return send_file(
            io.BytesIO(data),
            mimetype="text/html",
            as_attachment=True,
            download_name=(
                f"vapt_{scan_id}.html"
            ),
        )

    if fmt == "zip":
        memory = io.BytesIO()

        with zipfile.ZipFile(
            memory,
            "w",
            zipfile.ZIP_DEFLATED,
        ) as z:
            z.writestr(
                f"vapt_{scan_id}.json",
                json.dumps(
                    result,
                    indent=2,
                    ensure_ascii=False,
                ),
            )

            z.writestr(
                f"vapt_{scan_id}.csv",
                make_csv(result),
            )

            z.writestr(
                f"vapt_{scan_id}.html",
                make_html_report(result),
            )

        memory.seek(0)

        return send_file(
            memory,
            mimetype="application/zip",
            as_attachment=True,
            download_name=(
                f"vapt_{scan_id}_report.zip"
            ),
        )

    return jsonify({
        "error": "Unsupported export format",
        "supported": [
            "json",
            "csv",
            "html",
            "zip",
        ],
    }), 400


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("VAPT Automation Tool")
    print("=" * 60)
    print(
        f"Default scan profile : "
        f"{DEFAULT_SCAN_PROFILE}"
    )
    print(
        "Fast     : Top 1000 TCP ports"
    )
    print(
        "Standard : Top 5000 TCP ports"
    )
    print(
        "Full     : 1-65535 TCP ports"
    )
    print(
        "Nmap available       : "
        f"{bool(shutil_which('nmap'))}"
    )
    print("=" * 60)

    app.run(
        host="127.0.0.1",
        port=5000,
        threaded=True,
        debug=False,
        use_reloader=False,
    )

