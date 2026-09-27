from flask import Flask, render_template, request, jsonify

import requests
import time
import threading
import uuid
import inspect
import re
import json
import csv
import io
import zipfile
from datetime import datetime

from urllib.parse import urlparse

from modules.infrastructure.dns import scan_dns
from modules.infrastructure.subdomains import enumerate_subdomains
from modules.infrastructure.cert_transparency import enumerate_certificates

from modules.services_port_scan import scan_ports
from modules.web_security import scan_web_security
from modules.web_crawler import crawl_site

from core.scanner import create_scan, complete_scan


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)


# ============================================================
# LIVE SCAN STATE
# ============================================================

scan_jobs = {}

scan_jobs_lock = threading.Lock()

nmap_lock = threading.Lock()


# ============================================================
# GENERAL HELPERS
# ============================================================

def now():
    return time.time()


def update_job(scan_id, **updates):
    """
    Thread-safe update of live scan state.
    """

    with scan_jobs_lock:

        job = scan_jobs.get(scan_id)

        if job is None:
            return

        job.update(updates)

        job["updated_at"] = now()


def get_job(scan_id):

    with scan_jobs_lock:

        job = scan_jobs.get(scan_id)

        if job is None:
            return None

        return dict(job)


def safe_dict(value):

    if value is None:
        return {}

    if isinstance(value, dict):
        return value

    try:
        return dict(value)

    except Exception:

        return {
            "result": value
        }


def safe_list(value):

    if value is None:
        return []

    if isinstance(value, list):
        return value

    if isinstance(value, tuple):
        return list(value)

    return [value]


def extract_target_host(target):

    parsed = urlparse(target)

    if parsed.hostname:
        return parsed.hostname

    return target


def normalize_target(target):

    target = (target or "").strip()

    if not target:

        raise ValueError(
            "Target is required."
        )

    if not target.startswith(
        (
            "http://",
            "https://"
        )
    ):

        target = "https://" + target

    parsed = urlparse(target)

    if not parsed.hostname:

        raise ValueError(
            "Invalid target."
        )

    return target.rstrip("/")


# ============================================================
# HTTP ASSESSMENT
# ============================================================

def http_assessment(target):

    result = {

        "target":
            target,

        "status_code":
            None,

        "final_url":
            None,

        "response_time_ms":
            None,

        "server":
            "",

        "content_type":
            "",

        "content_length":
            0,

        "headers":
            {},

        "error":
            None
    }

    try:

        start = time.time()

        response = requests.get(

            target,

            timeout=15,

            allow_redirects=True,

            verify=True,

            headers={
                "User-Agent":
                    "VAPT-Automation-Tool/1.0"
            }
        )

        elapsed = (
            time.time() - start
        ) * 1000

        result.update({

            "status_code":
                response.status_code,

            "final_url":
                response.url,

            "response_time_ms":
                round(
                    elapsed,
                    2
                ),

            "server":
                response.headers.get(
                    "Server",
                    ""
                ),

            "content_type":
                response.headers.get(
                    "Content-Type",
                    ""
                ),

            "content_length":
                len(
                    response.content
                ),

            "headers":
                dict(
                    response.headers
                )
        })

    except requests.exceptions.SSLError as exc:

        result["error"] = (
            f"TLS/SSL error: {exc}"
        )

    except requests.exceptions.RequestException as exc:

        result["error"] = str(exc)

    except Exception as exc:

        result["error"] = str(exc)

    return result


# ============================================================
# TECHNOLOGY DETECTION
# ============================================================

def detect_technologies(
    target,
    http_result=None
):
    """
    Passive technology detection.

    This returns the technologies detected directly here.
    Additional technologies returned by web_security are
    merged later.
    """

    technologies = []

    try:

        response = requests.get(

            target,

            timeout=12,

            allow_redirects=True,

            verify=True,

            headers={
                "User-Agent":
                    "VAPT-Automation-Tool/1.0"
            }
        )

        headers = {

            str(k).lower():
                str(v)

            for k, v
            in response.headers.items()
        }

        body = response.text[
            :500000
        ]

        body_lower = body.lower()

        server = headers.get(
            "server",
            ""
        )

        powered = headers.get(
            "x-powered-by",
            ""
        )

        # ----------------------------------------------------
        # Server
        # ----------------------------------------------------

        if server:

            technologies.append({

                "name":
                    server,

                "source":
                    "Server header",

                "confidence":
                    "High"
            })

        # ----------------------------------------------------
        # X-Powered-By
        # ----------------------------------------------------

        if powered:

            technologies.append({

                "name":
                    powered,

                "source":
                    "X-Powered-By header",

                "confidence":
                    "High"
            })

        # ----------------------------------------------------
        # WordPress
        # ----------------------------------------------------

        if (

            "wp-content/" in body_lower

            or

            "wp-includes/" in body_lower

            or

            "wordpress" in body_lower
        ):

            technologies.append({

                "name":
                    "WordPress",

                "source":
                    "HTML fingerprint",

                "confidence":
                    "High"
            })

        # ----------------------------------------------------
        # Elementor
        # ----------------------------------------------------

        if (

            "elementor" in body_lower

            or

            "elementor-pro" in body_lower
        ):

            technologies.append({

                "name":
                    "Elementor",

                "source":
                    "HTML fingerprint",

                "confidence":
                    "Medium"
            })

        # ----------------------------------------------------
        # jQuery
        # ----------------------------------------------------

        jquery_match = re.search(

            r"jquery(?:\.min)?\.js[^\"']*",

            body,

            re.I
        )

        if jquery_match:

            technologies.append({

                "name":
                    "jQuery",

                "source":
                    "JavaScript reference",

                "confidence":
                    "Medium"
            })

        # ----------------------------------------------------
        # Bootstrap
        # ----------------------------------------------------

        if "bootstrap" in body_lower:

            technologies.append({

                "name":
                    "Bootstrap",

                "source":
                    "HTML fingerprint",

                "confidence":
                    "Medium"
            })

        # ----------------------------------------------------
        # React
        # ----------------------------------------------------

        if (

            "react" in body_lower

            or

            "__next_data__" in body_lower
        ):

            technologies.append({

                "name":
                    "React",

                "source":
                    "HTML fingerprint",

                "confidence":
                    "Low"
            })

        # ----------------------------------------------------
        # Next.js
        # ----------------------------------------------------

        if (

            "_next/static/" in body

            or

            "__next_data__" in body_lower
        ):

            technologies.append({

                "name":
                    "Next.js",

                "source":
                    "HTML fingerprint",

                "confidence":
                    "High"
            })

        # ----------------------------------------------------
        # PHP
        # ----------------------------------------------------

        if (

            "php" in powered.lower()

            or

            ".php" in response.url.lower()
        ):

            technologies.append({

                "name":
                    "PHP",

                "source":
                    "Response fingerprint",

                "confidence":
                    "Medium"
            })

        # ----------------------------------------------------
        # Cloudflare
        # ----------------------------------------------------

        if (

            "cf-ray" in headers

            or

            "cloudflare" in server.lower()
        ):

            technologies.append({

                "name":
                    "Cloudflare",

                "source":
                    "HTTP headers",

                "confidence":
                    "High"
            })

        # ----------------------------------------------------
        # LiteSpeed
        # ----------------------------------------------------

        if "litespeed" in server.lower():

            technologies.append({

                "name":
                    "LiteSpeed",

                "source":
                    "Server header",

                "confidence":
                    "High"
            })

        # ----------------------------------------------------
        # Apache
        # ----------------------------------------------------

        if "apache" in server.lower():

            technologies.append({

                "name":
                    "Apache",

                "source":
                    "Server header",

                "confidence":
                    "High"
            })

        # ----------------------------------------------------
        # Nginx
        # ----------------------------------------------------

        if "nginx" in server.lower():

            technologies.append({

                "name":
                    "Nginx",

                "source":
                    "Server header",

                "confidence":
                    "High"
            })

        # ----------------------------------------------------
        # Google Analytics
        # ----------------------------------------------------

        if (

            "google-analytics" in body_lower

            or

            "googletagmanager.com" in body_lower

            or

            "gtag(" in body_lower
        ):

            technologies.append({

                "name":
                    "Google Analytics",

                "source":
                    "HTML/JavaScript fingerprint",

                "confidence":
                    "Medium"
            })

        # ----------------------------------------------------
        # Google Tag Manager
        # ----------------------------------------------------

        if "googletagmanager" in body_lower:

            technologies.append({

                "name":
                    "Google Tag Manager",

                "source":
                    "HTML/JavaScript fingerprint",

                "confidence":
                    "High"
            })

        # ----------------------------------------------------
        # Google Fonts
        # ----------------------------------------------------

        if (

            "fonts.googleapis.com" in body_lower

            or

            "fonts.gstatic.com" in body_lower
        ):

            technologies.append({

                "name":
                    "Google Fonts",

                "source":
                    "External resource",

                "confidence":
                    "High"
            })

        # ----------------------------------------------------
        # Deduplicate
        # ----------------------------------------------------

        unique = []

        seen = set()

        for item in technologies:

            if not isinstance(
                item,
                dict
            ):

                continue

            name = str(
                item.get(
                    "name",
                    ""
                )
            ).strip()

            key = name.lower()

            if key and key not in seen:

                seen.add(key)

                unique.append(item)

        return {

            "technologies":
                unique,

            "count":
                len(unique),

            "status":
                response.status_code
        }

    except Exception as exc:

        return {

            "technologies":
                technologies,

            "count":
                len(technologies),

            "error":
                str(exc)
        }


# ============================================================
# MERGE TECHNOLOGIES
# ============================================================

def merge_technologies(
    primary,
    secondary
):
    """
    Merge technologies from multiple scanners.

    Prevents the dashboard from showing only the first
    scanner's small list.
    """

    merged = []

    seen = set()

    def add_items(value, source_name=""):

        if isinstance(
            value,
            dict
        ):

            items = value.get(
                "technologies",
                []
            )

        elif isinstance(
            value,
            list
        ):

            items = value

        else:

            items = []

        for item in items:

            if isinstance(
                item,
                str
            ):

                item = {

                    "name":
                        item,

                    "source":
                        source_name,

                    "confidence":
                        ""
                }

            if not isinstance(
                item,
                dict
            ):

                continue

            name = str(
                item.get(
                    "name",
                    item.get(
                        "technology",
                        ""
                    )
                )
            ).strip()

            if not name:

                continue

            key = name.lower()

            if key in seen:

                continue

            seen.add(key)

            normalized = dict(
                item
            )

            normalized[
                "name"
            ] = name

            if not normalized.get(
                "source"
            ):

                normalized[
                    "source"
                ] = source_name

            merged.append(
                normalized
            )

    add_items(
        primary,
        "Technology detector"
    )

    add_items(
        secondary,
        "Web security scanner"
    )

    return {

        "technologies":
            merged,

        "count":
            len(merged)
    }


# ============================================================
# CERTIFICATE NORMALIZATION
# ============================================================

def normalize_certificates(
    certificate_result
):
    """
    Keep all certificate fields while exposing a consistent
    list for the dashboard.
    """

    result = certificate_result

    certificates = []

    if isinstance(
        result,
        dict
    ):

        for key in (
            "certificates",
            "results",
            "domains",
            "records",
            "items"
        ):

            value = result.get(
                key
            )

            if isinstance(
                value,
                list
            ):

                certificates = value

                break

        if not certificates:

            # Some certificate modules return one
            # certificate dictionary directly.
            if any(
                key in result
                for key in (
                    "domain",
                    "issuer",
                    "valid_from",
                    "valid_to",
                    "not_before",
                    "not_after"
                )
            ):

                certificates = [
                    result
                ]

    elif isinstance(
        result,
        list
    ):

        certificates = result

    normalized = []

    for cert in certificates:

        if not isinstance(
            cert,
            dict
        ):

            continue

        item = dict(
            cert
        )

        item["domain"] = (
            item.get("domain")
            or
            item.get("name")
            or
            item.get("common_name")
            or
            item.get("subject")
            or
            ""
        )

        item["issuer"] = (
            item.get("issuer")
            or
            item.get("issuer_name")
            or
            item.get("issuer_cn")
            or
            ""
        )

        item["valid_from"] = (
            item.get("valid_from")
            or
            item.get("not_before")
            or
            item.get("validFrom")
            or
            ""
        )

        item["valid_to"] = (
            item.get("valid_to")
            or
            item.get("not_after")
            or
            item.get("validTo")
            or
            ""
        )

        normalized.append(
            item
        )

    return {

        "certificates":
            normalized,

        "count":
            len(normalized),

        "raw":
            result
    }


# ============================================================
# CORS NORMALIZATION
# ============================================================

def normalize_cors(
    web_security_result
):
    """
    Normalize CORS values for dashboard rendering.
    """

    data = safe_dict(
        web_security_result
    )

    cors = (
        data.get(
            "cors"
        )
        or
        data.get(
            "CORS"
        )
        or
        {}
    )

    if not isinstance(
        cors,
        dict
    ):

        cors = {}

    headers = (
        data.get(
            "headers"
        )
        or
        {}
    )

    if not isinstance(
        headers,
        dict
    ):

        headers = {}

    lower_headers = {

        str(k).lower():
            str(v)

        for k, v
        in headers.items()
    }

    origin = (
        cors.get(
            "access_control_allow_origin"
        )
        or
        cors.get(
            "Access-Control-Allow-Origin"
        )
        or
        cors.get(
            "allow_origin"
        )
        or
        lower_headers.get(
            "access-control-allow-origin",
            ""
        )
    )

    credentials = (
        cors.get(
            "access_control_allow_credentials"
        )
        or
        cors.get(
            "Access-Control-Allow-Credentials"
        )
        or
        cors.get(
            "allow_credentials"
        )
        or
        lower_headers.get(
            "access-control-allow-credentials",
            ""
        )
    )

    enabled = cors.get(
        "enabled"
    )

    if enabled is None:

        enabled = bool(
            origin
            or
            credentials
        )

    return {

        "enabled":
            bool(enabled),

        "access_control_allow_origin":
            origin if origin else "-",

        "access_control_allow_credentials":
            credentials if credentials else "-",

        "raw":
            cors
    }


# ============================================================
# HTTP METHODS NORMALIZATION
# ============================================================

def normalize_http_methods(
    web_security_result
):
    """
    Normalize HTTP method testing results.
    """

    data = safe_dict(
        web_security_result
    )

    methods = (
        data.get(
            "http_methods"
        )
        or
        data.get(
            "methods"
        )
        or
        data.get(
            "allowed_methods"
        )
        or
        {}
    )

    status_code = (
        data.get(
            "status_code"
        )
        or
        data.get(
            "status"
        )
        or
        "-"
    )

    allowed = []

    if isinstance(
        methods,
        dict
    ):

        status_code = (
            methods.get(
                "status_code"
            )
            or
            methods.get(
                "status"
            )
            or
            status_code
        )

        allowed = (
            methods.get(
                "allowed_methods"
            )
            or
            methods.get(
                "allowed"
            )
            or
            methods.get(
                "methods"
            )
            or
            []
        )

    elif isinstance(
        methods,
        list
    ):

        allowed = methods

    elif isinstance(
        methods,
        str
    ):

        allowed = [
            x.strip()
            for x in methods.split(",")
            if x.strip()
        ]

    if isinstance(
        allowed,
        str
    ):

        allowed = [
            x.strip()
            for x in allowed.split(",")
            if x.strip()
        ]

    return {

        "status_code":
            status_code,

        "allowed_methods":
            safe_list(
                allowed
            ),

        "raw":
            methods
    }


# ============================================================
# NMAP CALLBACK
# ============================================================

def make_nmap_callback(scan_id):

    def nmap_progress_callback(info):

        if not isinstance(
            info,
            dict
        ):

            info = {
                "message":
                    str(info)
            }

        percent = info.get(

            "percent",

            info.get(

                "progress",

                info.get(

                    "percentage",

                    0
                )
            )
        )

        try:

            percent = float(
                percent
            )

        except Exception:

            percent = 0

        percent = max(
            0,
            min(
                100,
                percent
            )
        )

        global_progress = (

            68

            +

            (
                percent
                *
                24
                /
                100
            )
        )

        update_job(

            scan_id,

            phase=
                "Full TCP port scan",

            progress=
                round(
                    global_progress,
                    1
                ),

            nmap_progress={

                **info,

                "percent":
                    round(
                        percent,
                        1
                    )
            },

            message=info.get(

                "message",

                (
                    "Nmap TCP scan: "
                    f"{percent:.1f}%"
                )
            )
        )

    return nmap_progress_callback


# ============================================================
# NMAP RUNNER
# ============================================================


def run_nmap(
    scan_id,
    target
):
    """
    Bounded TCP service scan: ports 1-3000.
    Uses Nmap directly so the port range is deterministic.
    """
    import subprocess
    import xml.etree.ElementTree as ET

    host = extract_target_host(target)
    total_ports = 3000

    update_job(
        scan_id,
        phase="TCP Service Scan",
        progress=68,
        nmap_progress={
            "event": "starting",
            "percent": 0,
            "ports_scanned": 0,
            "total_ports": total_ports,
            "open_ports": 0,
            "ports": [],
            "message": "Starting TCP scan of ports 1-3000..."
        },
        message="Starting Nmap TCP scan (ports 1-3000)..."
    )

    with nmap_lock:
        try:
            command = [
                "nmap",
                "-Pn",
                "-sT",
                "-sV",
                "--version-light",
                "--open",
                "--stats-every", "2s",
                "-p", "1-3000",
                "-oX", "-",
                host
            ]

            creationflags = getattr(
                subprocess,
                "CREATE_NO_WINDOW",
                0
            )

            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=creationflags
            )

            output_lines = []
            last_percent = 0.0

            for line in process.stdout:
                output_lines.append(line)

                match = re.search(
                    r"About\s+(\d+(?:\.\d+)?)%\s+done",
                    line,
                    re.I
                )

                if match:
                    last_percent = max(
                        0.0,
                        min(100.0, float(match.group(1)))
                    )

                    update_job(
                        scan_id,
                        phase="TCP Service Scan",
                        progress=round(
                            68 + last_percent * 0.24,
                            1
                        ),
                        nmap_progress={
                            "event": "scanning",
                            "percent": round(last_percent, 1),
                            "ports_scanned": int(
                                total_ports *
                                last_percent / 100
                            ),
                            "total_ports": total_ports,
                            "open_ports": 0,
                            "ports": [],
                            "message": line.strip()
                        },
                        message=(
                            line.strip()
                            or
                            f"Nmap TCP scan: {last_percent:.1f}%"
                        )
                    )

            return_code = process.wait()
            raw_output = "".join(output_lines)

            if return_code != 0:
                raise RuntimeError(
                    raw_output.strip()
                    or
                    f"Nmap exited with code {return_code}"
                )

            ports = []

            try:
                root = ET.fromstring(raw_output)

                for port_node in root.findall(
                    ".//host/ports/port"
                ):
                    state_node = port_node.find("state")
                    service_node = port_node.find("service")

                    state = (
                        state_node.get("state", "")
                        if state_node is not None
                        else ""
                    )

                    if state != "open":
                        continue

                    service = (
                        dict(service_node.attrib)
                        if service_node is not None
                        else {}
                    )

                    ports.append({
                        "port": int(
                            port_node.get(
                                "portid",
                                "0"
                            )
                        ),
                        "protocol": (
                            port_node.get(
                                "protocol",
                                "tcp"
                            )
                            or
                            "tcp"
                        ),
                        "state": "open",
                        "service": service.get(
                            "name",
                            ""
                        ),
                        "product": service.get(
                            "product",
                            ""
                        ),
                        "version": service.get(
                            "version",
                            ""
                        ),
                        "extrainfo": service.get(
                            "extrainfo",
                            ""
                        )
                    })

            except ET.ParseError:
                ports = []

            result = {
                "ports": ports,
                "open_ports": ports,
                "open_port_count": len(ports),
                "scanned_ports": total_ports,
                "total_ports": total_ports,
                "port_range": "1-3000",
                "raw_output": raw_output,
                "error": None
            }

            update_job(
                scan_id,
                ports=ports,
                nmap_progress={
                    "event": "completed",
                    "percent": 100,
                    "ports_scanned": total_ports,
                    "total_ports": total_ports,
                    "open_ports": len(ports),
                    "ports": ports,
                    "port_range": "1-3000",
                    "message": (
                        f"TCP scan completed: "
                        f"{len(ports)} open ports found "
                        f"from ports 1-3000."
                    )
                },
                progress=92,
                message=(
                    f"TCP scan completed. {len(ports)} "
                    f"open ports discovered from 3,000 ports."
                )
            )

            return result

        except FileNotFoundError:
            error_message = (
                "Nmap was not found in PATH. "
                "Verify Nmap is installed."
            )

        except Exception as exc:
            error_message = str(exc)

        update_job(
            scan_id,
            progress=92,
            ports=[],
            nmap_progress={
                "event": "error",
                "percent": 100,
                "ports_scanned": total_ports,
                "total_ports": total_ports,
                "open_ports": 0,
                "ports": [],
                "port_range": "1-3000",
                "error": error_message,
                "message": "TCP scan completed with an error."
            },
            message=f"TCP scan error: {error_message}"
        )

        return {
            "ports": [],
            "open_ports": [],
            "open_port_count": 0,
            "scanned_ports": total_ports,
            "total_ports": total_ports,
            "port_range": "1-3000",
            "raw_output": "",
            "error": error_message
        }


# ============================================================
# CRAWLER CALLBACK
# ============================================================

def make_crawler_callback(
    scan_id
):

    def crawler_progress_callback(
        info
    ):

        if not isinstance(
            info,
            dict
        ):

            info = {

                "message":
                    str(info)
            }

        pages = info.get(

            "pages",

            info.get(
                "pages_crawled",
                0
            )
        )

        max_pages = info.get(
            "max_pages",
            30
        )

        try:

            pages = float(
                pages
            )

        except Exception:

            pages = 0

        try:

            max_pages = float(
                max_pages
            )

        except Exception:

            max_pages = 30

        if max_pages <= 0:

            max_pages = 30

        crawler_percent = min(

            100,

            (
                pages
                /
                max_pages
                *
                100
            )
        )

        global_progress = (

            56

            +

            (
                crawler_percent
                *
                12
                /
                100
            )
        )

        # Preserve all information supplied by crawler.
        crawl_live = dict(
            info
        )

        crawl_live[
            "pages"
        ] = int(
            pages
        )

        crawl_live[
            "max_pages"
        ] = int(
            max_pages
        )

        update_job(

            scan_id,

            phase=
                "Attack Surface Discovery",

            progress=
                round(
                    global_progress,
                    1
                ),

            crawl_progress=
                crawl_live,

            message=info.get(

                "message",

                (
                    "Crawling application: "
                    f"{int(pages)} pages"
                )
            )
        )

    return crawler_progress_callback


# ============================================================
# CRAWLER DATA NORMALIZATION
# ============================================================

def normalize_crawl_result(
    crawl_result
):

    if not isinstance(
        crawl_result,
        dict
    ):

        return {

            "statistics": {},

            "pages": [],

            "internal_urls": [],

            "external_urls": [],

            "parameters": [],

            "api_endpoints": [],

            "forms": [],

            "javascript_files": [],

            "css_files": [],

            "js_endpoints": [],

            "raw": crawl_result
        }

    result = dict(
        crawl_result
    )

    statistics = result.get(
        "statistics",
        {}
    )

    if not isinstance(
        statistics,
        dict
    ):

        statistics = {}

    # --------------------------------------------------------
    # Preserve common alternate field names.
    # --------------------------------------------------------

    aliases = {

        "pages":
            (
                "pages",
                "crawled_pages",
                "page_urls"
            ),

        "internal_urls":
            (
                "internal_urls",
                "internal",
                "internal_links"
            ),

        "external_urls":
            (
                "external_urls",
                "external",
                "external_links"
            ),

        "parameters":
            (
                "parameters",
                "parameter_names",
                "query_parameters"
            ),

        "api_endpoints":
            (
                "api_endpoints",
                "api",
                "apis"
            ),

        "forms":
            (
                "forms",
                "form_details"
            ),

        "javascript_files":
            (
                "javascript_files",
                "js_files",
                "javascript"
            ),

        "css_files":
            (
                "css_files",
                "stylesheets",
                "css"
            ),

        "js_endpoints":
            (
                "js_endpoints",
                "javascript_endpoints"
            )
    }

    normalized = {}

    for canonical, keys in aliases.items():

        value = None

        for key in keys:

            if key in result:

                value = result.get(
                    key
                )

                if value is not None:
                    break

        if value is None:

            value = []

        normalized[
            canonical
        ] = safe_list(
            value
        )

    # --------------------------------------------------------
    # Calculate accurate statistics from actual arrays
    # where possible.
    # --------------------------------------------------------

    for key in (
        "pages",
        "internal_urls",
        "external_urls",
        "parameters",
        "api_endpoints",
        "forms",
        "javascript_files",
        "css_files",
        "js_endpoints"
    ):

        if normalized[key]:

            statistics[key] = len(
                normalized[key]
            )

    # Preserve original statistics.
    normalized_statistics = dict(
        statistics
    )

    # Ensure all dashboard counters exist.
    for key in (
        "pages",
        "internal_urls",
        "external_urls",
        "parameters",
        "api_endpoints",
        "forms",
        "javascript_files",
        "css_files",
        "js_endpoints"
    ):

        normalized_statistics.setdefault(
            key,
            len(
                normalized[key]
            )
        )

    result[
        "statistics"
    ] = normalized_statistics

    # --------------------------------------------------------
    # Put normalized arrays at top level.
    # --------------------------------------------------------

    for key, value in normalized.items():

        result[
            key
        ] = value

    return result

# ============================================================
# LIVE DASHBOARD FEATURE ENRICHMENT
# ============================================================

def unique_items(items):
    seen = set()
    result = []

    for item in items:
        if isinstance(item, dict):
            key = json.dumps(
                item,
                sort_keys=True,
                default=str
            )
        else:
            key = str(item).strip().lower()

        if not key or key in seen:
            continue

        seen.add(key)
        result.append(item)

    return result


def flatten_strings(value):
    if isinstance(value, str):
        return [value] if value.strip() else []

    if isinstance(value, dict):
        out = []
        for v in value.values():
            out.extend(flatten_strings(v))
        return out

    if isinstance(value, (list, tuple, set)):
        out = []
        for v in value:
            out.extend(flatten_strings(v))
        return out

    return []


def normalize_subdomain_items(value):
    data = safe_dict(value)

    candidates = (
        data.get("subdomains")
        or
        data.get("items")
        or
        data.get("hosts")
        or
        []
    )

    if isinstance(candidates, dict):
        candidates = flatten_strings(candidates)

    return unique_items(
        [
            str(x).strip()
            for x in safe_list(candidates)
            if str(x).strip()
        ]
    )


def collect_js_endpoints(
    target,
    javascript_files
):
    """
    Fetch only discovered JavaScript files and extract URL/path
    references. Same-target references are preferred. No auth
    tokens, cookies, or secrets are collected.
    """
    base = urlparse(target)
    base_host = (base.hostname or "").lower()

    results = []
    js_urls = []

    for item in javascript_files:
        if isinstance(item, str):
            js_urls.append(item)
        elif isinstance(item, dict):
            for key in (
                "url",
                "src",
                "href",
                "location"
            ):
                value = item.get(key)
                if value:
                    js_urls.append(str(value))
                    break

    for js_url in unique_items(js_urls)[:100]:
        try:
            absolute = requests.compat.urljoin(
                target.rstrip("/") + "/",
                js_url
            )

            parsed = urlparse(absolute)

            if (
                parsed.scheme not in (
                    "http",
                    "https"
                )
                or
                (parsed.hostname or "").lower()
                != base_host
            ):
                continue

            response = requests.get(
                absolute,
                timeout=8,
                allow_redirects=True,
                verify=True,
                headers={
                    "User-Agent":
                        "VAPT-Automation-Tool/1.0"
                }
            )

            if response.status_code >= 400:
                continue

            body = response.text[:1000000]

            # Absolute same-origin URLs.
            for match in re.findall(
                r"""https?://[^\s"'`<>\\]+""",
                body
            ):
                parsed_ref = urlparse(match)

                if (
                    (parsed_ref.hostname or "").lower()
                    == base_host
                ):
                    results.append({
                        "url": match.rstrip(");,]"),
                        "source": absolute,
                        "type": "absolute_url"
                    })

            # API-like paths.
            for match in re.findall(
                r"""['"`]((?:/|\.\.?/)[A-Za-z0-9_./?=&:%{}-]*(?:api|graphql|swagger|openapi|v[0-9]+)[A-Za-z0-9_./?=&:%{}-]*)['"`]""",
                body,
                re.I
            ):
                path = match.replace(
                    "\\/",
                    "/"
                )

                full = requests.compat.urljoin(
                    target.rstrip("/") + "/",
                    path.lstrip("/")
                )

                results.append({
                    "url": full,
                    "source": absolute,
                    "type": "api_path"
                })

        except Exception:
            continue
    return unique_items(results)


def build_feature_modules(
    target,
    dns_result,
    subdomain_result,
    crawl_result,
    ports_result
):
    dns = safe_dict(dns_result)
    crawl = safe_dict(crawl_result)
    ports = safe_dict(ports_result)

    stats = safe_dict(
        crawl.get("statistics")
    )

    categories = (
        "pages",
        "internal_urls",
        "external_urls",
        "parameters",
        "api_endpoints",
        "forms",
        "javascript_files",
        "css_files",
        "js_endpoints"
    )

    lists = {
        key: safe_list(
            crawl.get(key, [])
        )
        for key in categories
    }

    all_urls = unique_items(
        flatten_strings(
            lists["pages"]
        )
        +
        flatten_strings(
            lists["internal_urls"]
        )
        +
        flatten_strings(
            lists["external_urls"]
        )
    )

    subdomains = normalize_subdomain_items(
        subdomain_result
    )

    open_ports = safe_list(
        ports.get(
            "ports",
            ports.get(
                "open_ports",
                []
            )
        )
    )

    # JS endpoint extraction fixes the missing JS Endpoints card.
    js_endpoints = collect_js_endpoints(
        target,
        lists["javascript_files"]
    )

    if js_endpoints:
        lists["js_endpoints"] = js_endpoints
        crawl["js_endpoints"] = js_endpoints

    stats["js_endpoints"] = len(
        lists["js_endpoints"]
    )

    # API docs / public API references.
    api_doc_patterns = (
        "swagger",
        "openapi",
        "api-docs",
        "apidocs",
        "redoc",
        "graphql",
        "/api/"
    )

    api_docs = unique_items(
        [
            u for u in all_urls
            if any(
                p in str(u).lower()
                for p in api_doc_patterns
            )
        ]
        +
        [
            x for x in lists["js_endpoints"]
            if any(
                p in str(x).lower()
                for p in api_doc_patterns
            )
        ]
    )

    # Admin/login panels are exposure indicators, not proof of
    # a vulnerable admin interface.
    admin_patterns = (
        "/admin",
        "/administrator",
        "/wp-admin",
        "/dashboard",
        "/manage",
        "/control-panel",
        "/backend",
        "/login"
    )

    admin_panels = unique_items(
        [
            u for u in all_urls
            if any(
                p in str(u).lower()
                for p in admin_patterns
            )
        ]
    )

    # Remote-service exposure from actual Nmap results.
    remote_services = []

    for item in open_ports:
        if not isinstance(item, dict):
            continue

        port = str(
            item.get("port", "")
        )

        service = str(
            item.get("service", "")
        ).lower()

        if (
            port in {
                "22",
                "23",
                "3389",
                "5900",
                "5901",
                "1723",
                "500",
                "4500",
                "1701"
            }
            or
            any(
                word in service
                for word in (
                    "ssh",
                    "rdp",
                    "telnet",
                    "vnc",
                    "vpn",
                    "l2tp"
                )
            )
        ):
            remote_services.append(item)

    # Mail infrastructure from DNS MX.
    mx_values = []

    for key in (
        "MX",
        "mx",
        "mail",
        "mail_servers"
    ):
        value = dns.get(key)
        if value:
            mx_values.extend(
                flatten_strings(value)
            )

    # Environment / legacy hostname indicators.
    environment_patterns = (
        "dev.",
        "dev-",
        "-dev.",
        "test.",
        "test-",
        "qa.",
        "qa-",
        "stage.",
        "staging.",
        "uat.",
        "preprod.",
        "sandbox.",
        "beta."
    )

    legacy_patterns = (
        "old.",
        "legacy.",
        "backup.",
        "bak.",
        "archive."
    )

    environment_assets = unique_items(
        [
            x for x in subdomains
            if any(
                p in x.lower()
                for p in environment_patterns
            )
        ]
        +
        [
            x for x in all_urls
            if any(
                p in str(x).lower()
                for p in environment_patterns
            )
        ]
    )

    legacy_assets = unique_items(
        [
            x for x in subdomains
            if any(
                p in x.lower()
                for p in legacy_patterns
            )
        ]
    )

    # Public cloud-storage references visible in crawled URLs.
    cloud_patterns = (
        "amazonaws.com",
        "s3.",
        ".s3.",
        "storage.googleapis.com",
        "blob.core.windows.net",
        "azurewebsites.net",
        "cloudfront.net"
    )

    cloud_refs = unique_items(
        [
            u for u in all_urls
            if any(
                p in str(u).lower()
                for p in cloud_patterns
            )
        ]
    )

    # Public CI/CD/registry references visible in discovered
    # URLs only.
    cicd_patterns = (
        "jenkins",
        "gitlab",
        "github",
        "bitbucket",
        "teamcity",
        "bamboo",
        "azure-pipelines",
        "docker.io",
        "registry.",
        "ci/",
        "cd/"
    )

    cicd = unique_items(
        [
            u for u in all_urls
            if any(
                p in str(u).lower()
                for p in cicd_patterns
            )
        ]
    )

    technical_docs = unique_items(
        [
            u for u in all_urls
            if any(
                p in str(u).lower()
                for p in (
                    "docs",
                    "documentation",
                    "developer",
                    "swagger",
                    "openapi",
                    "api-docs"
                )
            )
        ]
    )

    # Public source/repository references in already fetched URLs.
    repo_refs = unique_items(
        [
            u for u in all_urls
            if any(
                p in str(u).lower()
                for p in (
                    "github.com/",
                    "gitlab.com/",
                    "bitbucket.org/"
                )
            )
        ]
    )

    return {
        "services": {
            "admin_panels": {
                "items": admin_panels,
                "count": len(admin_panels)
            },
            "remote_endpoints": {
                "items": remote_services,
                "count": len(remote_services)
            },
            "mail_gateways": {
                "items": unique_items(mx_values),
                "count": len(
                    unique_items(mx_values)
                )
            },
            "api_docs": {
                "items": api_docs,
                "count": len(api_docs)
            },
            "cicd_indicators": {
                "items": cicd,
                "count": len(cicd)
            },
            "shadow_saas_indicators": {
                "status": "indicator_only",
                "items": [],
                "count": 0
            }
        },

        "infrastructure": {
            "dns_history": {
                "status": "current_dns_only",
                "items": [],
                "count": 0,
                "message":
                    "Historical passive-DNS provider not configured."
            },
            "asn_bgp": {
                "status": "not_collected",
                "items": [],
                "count": 0
            },
            "environment_assets": {
                "items": environment_assets,
                "count": len(environment_assets)
            },
            "legacy_assets": {
                "items": legacy_assets,
                "count": len(legacy_assets)
            },
            "cloud_references": {
                "items": cloud_refs,
                "count": len(cloud_refs)
            }
        },

        # These are deliberately not populated from private or
        # sensitive sources. No personal profiling is performed.
        "people": {
            "executives": {
                "status": "not_collected",
                "items": [],
                "count": 0
            },
            "linkedin_profiles": {
                "status": "not_collected",
                "items": [],
                "count": 0
            },
            "org_chart_reconstruction": {
                "status": "not_collected",
                "items": [],
                "count": 0
            },
            "public_contacts": {
                "status": "not_collected",
                "items": [],
                "count": 0
            },
            "public_doc_metadata": {
                "status": "not_collected",
                "items": [],
                "count": 0
            },
            "social_media": {
                "status": "not_collected",
                "items": [],
                "count": 0
            },
            "schedule_leaks": {
                "status": "not_collected",
                "items": [],
                "count": 0
            }
        },

        # Credential modules expose only status/indicators.
        # No credential replay, cookie theft, or infostealer
        # collection is performed.
        "credentials": {
            "breach_crosscheck": {
                "status": "not_configured",
                "items": [],
                "count": 0
            },
            "combolist": {
                "status": "not_authenticated",
                "items": [],
                "count": 0
            },
            "infostealer_logs": {
                "status": "not_collected",
                "items": [],
                "count": 0
            },
            "reuse_verification": {
                "status": "not_performed",
                "items": [],
                "count": 0
            },
            "corporate_cookies": {
                "status": "not_collected",
                "items": [],
                "count": 0
            },
            "session_token_leaks": {
                "status": "exposure_indicators_only",
                "items": [],
                "count": 0
            },
            "git_paste_secrets": {
                "status": "redacted_indicators_only",
                "items": [],
                "count": 0
            }
        },

        "code_docs": {
            "github_gitlab": {
                "items": repo_refs,
                "count": len(repo_refs)
            },
            "repo_gist_secrets": {
                "status": "redacted_indicators_only",
                "items": [],
                "count": 0
            },
            "mobile_app_keys": {
                "status": "static_extraction_not_configured",
                "items": [],
                "count": 0
            },
            "paste_leaks": {
                "status": "public_source_not_configured",
                "items": [],
                "count": 0
            },
            "archive_snapshots": {
                "status": "archive_provider_not_configured",
                "items": [],
                "count": 0
            },
            "technical_docs": {
                "items": technical_docs,
                "count": len(technical_docs)
            },
            "internal_url_indicators": {
                "items": unique_items(
                    lists["internal_urls"]
                ),
                "count": len(
                    lists["internal_urls"]
                )
            }
        },

        "threat_landscape": {
            "adversary_chatter": {
                "status": "public_source_not_configured",
                "items": [],
                "count": 0
            },
            "ransomware_hits": {
                "status": "public_source_not_configured",
                "items": [],
                "count": 0
            },
            "iab_listings": {
                "status": "public_source_not_configured",
                "items": [],
                "count": 0
            },
            "typosquat": {
                "status": "domain_indicator_not_configured",
                "items": [],
                "count": 0
            },
            "phishing_kits": {
                "status": "public_source_not_configured",
                "items": [],
                "count": 0
            },
            "supplier_risk": {
                "status": "dependency_indicator_not_configured",
                "items": [],
                "count": 0
            },
            "sector_ttp": {
                "status": "technique_indicator_not_configured",
                "items": [],
                "count": 0
            }
        },

        "crawler": {
            "statistics": stats,
            "js_endpoints": lists["js_endpoints"]
        }
    }


def apply_feature_modules(
    scan_result
):
    """
    Build feature modules from the final scan data.
    """
    features = build_feature_modules(
        scan_result.get("target", ""),
        scan_result.get("dns"),
        scan_result.get("subdomains"),
        scan_result.get("crawl"),
        scan_result.get("ports")
    )

    scan_result.update(features)

    return features


# ============================================================
# LIVE FEATURE MODULE REFRESH
# ============================================================

def update_live_feature_modules(scan_id, scan_result):
    """Rebuild and publish feature modules from data collected so far."""
    try:
        features = apply_feature_modules(scan_result)

        update_job(
            scan_id,
            services=features.get("services", {}),
            infrastructure=features.get("infrastructure", {}),
            people=features.get("people", {}),
            credentials=features.get("credentials", {}),
            code_docs=features.get("code_docs", {}),
            threat_landscape=features.get("threat_landscape", {}),
        )
        return features
    except Exception as exc:
        # Dashboard enrichment must never abort the main scan.
        update_job(scan_id, feature_module_error=str(exc))
        return {}


# ============================================================
# FULL LIVE SCAN
# ============================================================

def run_full_scan(
    scan_id,
    target
):

    scan_result = {

        "target":
            target,

        "hostname":
            extract_target_host(target),

        "started_at":
            time.time(),

        "http":
            None,

        "dns":
            None,

        "subdomains":
            None,

        "certificates":
            None,

        "technologies":
            None,

        "web_security":
            None,

        "cors":
            None,

        "http_methods":
            None,

        "crawl":
            None,

        "ports":
            None,

        "findings":
            [],

        "services":
            None,

        "infrastructure":
            None,

        "people":
            None,

        "credentials":
            None,

        "code_docs":
            None,

        "threat_landscape":
            None,

        "summary": {

            "critical":
                0,

            "high":
                0,

            "medium":
                0,

            "low":
                0,

            "info":
                0
        }
    }

    try:

        host = (
            extract_target_host(
                target
            )
        )

        # ====================================================
        # PHASE 1 - HTTP
        # ====================================================

        update_job(

            scan_id,

            phase=
                "HTTP Assessment",

            progress=2,

            message=
                "Performing HTTP assessment..."
        )

        http_result = (
            http_assessment(
                target
            )
        )

        scan_result[
            "http"
        ] = http_result

        update_job(

            scan_id,

            http=
                http_result,

            phase=
                "HTTP Assessment",

            progress=8,

            message=
                "HTTP assessment completed."
        )

        # ====================================================
        # PHASE 2 - DNS
        # ====================================================

        update_job(

            scan_id,

            phase=
                "DNS Records",

            progress=8,

            message=(
                f"Resolving DNS records for {host}..."
            )
        )

        try:

            dns_result = scan_dns(
                host
            )

        except TypeError:

            dns_result = scan_dns(
                target
            )

        scan_result[
            "dns"
        ] = safe_dict(
            dns_result
        )

        update_job(

            scan_id,

            dns=
                scan_result[
                    "dns"
                ],

            phase=
                "DNS Records",

            progress=17,

            message=
                "DNS reconnaissance completed."
        )

        update_live_feature_modules(
            scan_id,
            scan_result
        )

        # ====================================================
        # PHASE 3 - SUBDOMAINS
        # ====================================================

        update_job(

            scan_id,

            phase=
                "Subdomain Enumeration",

            progress=17,

            message=(
                f"Enumerating subdomains for {host}..."
            )
        )

        try:

            subdomain_result = (
                enumerate_subdomains(
                    host
                )
            )

        except TypeError:

            subdomain_result = (
                enumerate_subdomains(
                    target
                )
            )

        scan_result[
            "subdomains"
        ] = subdomain_result

        update_job(

            scan_id,

            subdomains=
                subdomain_result,

            phase=
                "Subdomain Enumeration",

            progress=27,

            message=
                "Subdomain enumeration completed."
        )

        update_live_feature_modules(
            scan_id,
            scan_result
        )

        # ====================================================
        # PHASE 4 - CERTIFICATE TRANSPARENCY
        # ====================================================

        update_job(

            scan_id,

            phase=
                "Certificate Transparency",

            progress=27,

            message=
                "Querying Certificate Transparency data..."
        )

        try:

            certificate_result = (
                enumerate_certificates(
                    host
                )
            )

        except TypeError:

            certificate_result = (
                enumerate_certificates(
                    target
                )
            )

        normalized_certificates = (
            normalize_certificates(
                certificate_result
            )
        )

        scan_result[
            "certificates"
        ] = normalized_certificates

        update_job(

            scan_id,

            certificates=
                normalized_certificates,

            phase=
                "Certificate Transparency",

            progress=36,

            message=(
                "Certificate Transparency "
                "enumeration completed."
            )
        )

        update_live_feature_modules(
            scan_id,
            scan_result
        )

        # ====================================================
        # PHASE 5 - TECHNOLOGY
        # ====================================================

        update_job(

            scan_id,

            phase=
                "Technology Detection",

            progress=36,

            message=
                "Detecting web technologies..."
        )

        technology_result = (
            detect_technologies(
                target,
                http_result
            )
        )

        scan_result[
            "technologies"
        ] = technology_result

        update_job(

            scan_id,

            technologies=
                technology_result,

            phase=
                "Technology Detection",

            progress=44,

            message=(

                "Technology detection completed: "

                f"{technology_result.get('count', 0)} "

                "technologies identified."
            )
        )

        # ====================================================
        # PHASE 6 - WEB SECURITY
        # ====================================================

        update_job(

            scan_id,

            phase=
                "Web Security Checks",

            progress=44,

            message=(
                "Checking security headers, CORS, "
                "HTTP methods and web configuration..."
            )
        )

        try:

            web_security_result = (
                scan_web_security(
                    target
                )
            )

        except TypeError:

            web_security_result = (
                scan_web_security(
                    target,
                    None
                )
            )

        web_security_result = safe_dict(
            web_security_result
        )

        scan_result[
            "web_security"
        ] = web_security_result

        # ----------------------------------------------------
        # Merge technologies.
        # ----------------------------------------------------

        merged_technologies = (
            merge_technologies(

                technology_result,

                web_security_result
            )
        )

        scan_result[
            "technologies"
        ] = merged_technologies

        # ----------------------------------------------------
        # Normalize CORS.
        # ----------------------------------------------------

        cors_result = (
            normalize_cors(
                web_security_result
            )
        )

        scan_result[
            "cors"
        ] = cors_result

        # ----------------------------------------------------
        # Normalize HTTP methods.
        # ----------------------------------------------------

        methods_result = (
            normalize_http_methods(
                web_security_result
            )
        )

        scan_result[
            "http_methods"
        ] = methods_result

        # ----------------------------------------------------
        # Findings.
        # ----------------------------------------------------

        web_findings = (
            web_security_result.get(
                "findings",
                []
            )
        )

        if isinstance(
            web_findings,
            list
        ):

            scan_result[
                "findings"
            ].extend(
                web_findings
            )

        live_summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }

        for finding in scan_result["findings"]:
            if not isinstance(finding, dict):
                continue
            severity = str(
                finding.get("severity", "Info")
            ).lower().strip()
            if severity in live_summary:
                live_summary[severity] += 1

        scan_result["summary"] = live_summary

        update_job(

            scan_id,

            web_security=
                web_security_result,

            technologies=
                merged_technologies,

            cors=
                cors_result,

            http_methods=
                methods_result,

            findings=
                scan_result[
                    "findings"
                ],

            summary=
                live_summary,

            phase=
                "Web Security Checks",

            progress=56,

            message=
                "Web security checks completed."
        )

        # ====================================================
        # PHASE 7 - CRAWLER
        # ====================================================

        update_job(

            scan_id,

            phase=
                "Attack Surface Discovery",

            progress=56,

            crawl_progress={

                "event":
                    "starting",

                "pages":
                    0,

                "max_pages":
                    30,

                "internal_urls":
                    0,

                "external_urls":
                    0,

                "forms":
                    0,

                "parameters":
                    0,

                "api_endpoints":
                    0,

                "javascript_files":
                    0,

                "css_files":
                    0,

                "js_endpoints":
                    0,

                "message":
                    "Starting application crawl..."
            },

            message=(
                "Crawling application pages and "
                "discovering endpoints..."
            )
        )

        crawler_callback = (
            make_crawler_callback(
                scan_id
            )
        )

        try:

            crawl_result = crawl_site(

                target,

                max_pages=30,

                progress_callback=
                    crawler_callback
            )

        except TypeError as exc:

            if (

                "progress_callback"
                not in str(exc)

                and

                "unexpected keyword argument"
                not in str(exc)
            ):

                raise

            update_job(

                scan_id,

                phase=
                    "Attack Surface Discovery",

                progress=57,

                crawl_progress={

                    "event":
                        "running",

                    "pages":
                        0,

                    "max_pages":
                        30,

                    "message":
                        "Crawler is running..."
                },

                message=
                    "Crawler is running..."
            )

            crawl_result = crawl_site(

                target,

                max_pages=30
            )

        normalized_crawl = (
            normalize_crawl_result(
                crawl_result
            )
        )

        scan_result[
            "crawl"
        ] = normalized_crawl

        crawl_stats = (
            normalized_crawl.get(
                "statistics",
                {}
            )
        )

        update_job(

            scan_id,

            crawl=
                normalized_crawl,

            progress=68,

            crawl_progress={

                "event":
                    "complete",

                "pages":
                    crawl_stats.get(
                        "pages",
                        0
                    ),

                "max_pages":
                    30,

                "internal_urls":
                    crawl_stats.get(
                        "internal_urls",
                        0
                    ),

                "external_urls":
                    crawl_stats.get(
                        "external_urls",
                        0
                    ),

                "forms":
                    crawl_stats.get(
                        "forms",
                        0
                    ),

                "parameters":
                    crawl_stats.get(
                        "parameters",
                        0
                    ),

                "api_endpoints":
                    crawl_stats.get(
                        "api_endpoints",
                        0
                    ),

                "javascript_files":
                    crawl_stats.get(
                        "javascript_files",
                        0
                    ),

                "css_files":
                    crawl_stats.get(
                        "css_files",
                        0
                    ),

                "js_endpoints":
                    crawl_stats.get(
                        "js_endpoints",
                        0
                    ),

                "message":
                    "Attack surface discovery completed."
            },

            message=(

                "Attack surface discovery completed: "

                f"{crawl_stats.get('pages', 0)} pages, "

                f"{crawl_stats.get('api_endpoints', 0)} "
                "API endpoints, "

                f"{crawl_stats.get('forms', 0)} forms."
            )
        )
        # Build service/infrastructure/code indicators immediately
        # from crawler output; do not wait for Nmap.
        update_live_feature_modules(
            scan_id,
            scan_result
        )

        # ====================================================
        # PHASE 8 - NMAP
        # ====================================================

        nmap_result = run_nmap(
            scan_id,
            target
        )

        scan_result[
            "ports"
        ] = nmap_result

        # Rebuild modules with newly discovered open ports.
        feature_modules = update_live_feature_modules(
            scan_id,
            scan_result
        )

        # Persist the normalized crawler including JS endpoints.
        update_job(
            scan_id,
            crawl=scan_result.get("crawl"),
            services=feature_modules.get("services"),
            infrastructure=feature_modules.get("infrastructure"),
            people=feature_modules.get("people"),
            credentials=feature_modules.get("credentials"),
            code_docs=feature_modules.get("code_docs"),
            threat_landscape=feature_modules.get(
                "threat_landscape"
            )
        )

        # ====================================================
        # FINAL RESULT
        # ====================================================

        scan_result[
            "finished_at"
        ] = time.time()

        scan_result[
            "hostname"
        ] = extract_target_host(target)

        severity_summary = {

            "critical":
                0,

            "high":
                0,

            "medium":
                0,

            "low":
                0,

            "info":
                0
        }

        for item in scan_result[
            "findings"
        ]:

            if not isinstance(
                item,
                dict
            ):

                continue

            severity = str(

                item.get(
                    "severity",
                    "Info"
                )
            ).lower().strip()

            if severity in severity_summary:

                severity_summary[
                    severity
                ] += 1

        scan_result[
            "summary"
        ] = severity_summary

        # ----------------------------------------------------
        # Persist.
        # ----------------------------------------------------

        try:

            complete_scan(

                scan_id,

                scan_result
            )

        except TypeError:

            try:

                complete_scan(
                    scan_id
                )

            except Exception:

                pass

        # ----------------------------------------------------
        # Final live state.
        # ----------------------------------------------------

        update_job(

            scan_id,

            status=
                "completed",

            phase=
                "Completed",

            progress=
                100,

            message=
                "Full VAPT scan completed successfully.",

            result=
                scan_result,

            http=
                http_result,

            dns=
                scan_result[
                    "dns"
                ],

            subdomains=
                scan_result[
                    "subdomains"
                ],

            certificates=
                scan_result[
                    "certificates"
                ],

            technologies=
                scan_result[
                    "technologies"
                ],

            web_security=
                scan_result[
                    "web_security"
                ],

            cors=
                scan_result[
                    "cors"
                ],

            http_methods=
                scan_result[
                    "http_methods"
                ],

            crawl=
                scan_result[
                    "crawl"
                ],

            ports=
                scan_result[
                    "ports"
                ],

            findings=
                scan_result[
                    "findings"
                ],

            services=
                scan_result.get(
                    "services"
                ),

            infrastructure=
                scan_result.get(
                    "infrastructure"
                ),

            people=
                scan_result.get(
                    "people"
                ),

            credentials=
                scan_result.get(
                    "credentials"
                ),

            code_docs=
                scan_result.get(
                    "code_docs"
                ),

            threat_landscape=
                scan_result.get(
                    "threat_landscape"
                ),

            summary=
                severity_summary
        )

    except Exception as exc:

        error_message = str(
            exc
        )

        scan_result[
            "error"
        ] = error_message

        scan_result[
            "finished_at"
        ] = time.time()

        update_job(

            scan_id,

            status=
                "failed",

            phase=
                "Failed",

            progress=
                100,

            message=(
                "Scan failed: "
                + error_message
            ),

            error=
                error_message,

            result=
                scan_result
        )


# ============================================================
# START LIVE SCAN
# ============================================================

@app.post("/scan/start")
def start_live_scan():

    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    target = data.get(
        "target",
        ""
    )

    try:

        target = normalize_target(
            target
        )

    except ValueError as exc:

        return jsonify({

            "error":
                str(exc)
        }), 400

    scan_id = str(
        uuid.uuid4()
    )

    job = {

        "scan_id":
            scan_id,

        "target":
            target,

        "hostname":
            extract_target_host(target),

        "status":
            "running",

        "phase":
            "Starting",

        "progress":
            0,

        "message":
            "Initializing full VAPT scan...",

        "started_at":
            now(),

        "updated_at":
            now(),

        "http":
            None,

        "dns":
            None,

        "subdomains":
            None,

        "certificates":
            None,

        "technologies":
            None,

        "web_security":
            None,

        "cors":
            None,

        "http_methods":
            None,

        "crawl":
            None,

        "ports":
            None,

        "crawl_progress":
            None,

        "nmap_progress":
            None,

        "findings":
            [],

        "services":
            None,

        "infrastructure":
            None,

        "people":
            None,

        "credentials":
            None,

        "code_docs":
            None,

        "threat_landscape":
            None,

        "summary": {

            "critical":
                0,

            "high":
                0,

            "medium":
                0,

            "low":
                0,

            "info":
                0
        },

        "result":
            None,

        "error":
            None
    }

    with scan_jobs_lock:

        scan_jobs[
            scan_id
        ] = job

    try:

        create_scan(

            scan_id,

            target
        )

    except TypeError:

        try:

            create_scan(

                scan_id=
                    scan_id,

                target=
                    target
            )

        except Exception:

            pass

    except Exception:

        pass

    thread = threading.Thread(

        target=
            run_full_scan,

        args=(

            scan_id,

            target
        ),

        daemon=True,

        name=
            f"vapt-scan-{scan_id[:8]}"
    )

    thread.start()

    return jsonify({

        "scan_id":
            scan_id,

        "status":
            "running",

        "phase":
            "Starting",

        "progress":
            0,

        "message":
            "Full VAPT scan started."
    }), 202

# ============================================================
# CRAWLER DETAIL API
# ============================================================

@app.get("/scan/<scan_id>/crawler/<category>")
def crawler_detail(scan_id, category):
    job = get_job(scan_id)

    if job is None:
        return jsonify({
            "error": "Scan not found.",
            "scan_id": scan_id
        }), 404

    result = safe_dict(
        job.get("result")
    )

    crawl = safe_dict(
        result.get(
            "crawl",
            job.get("crawl")
        )
    )

    allowed = {
        "pages",
        "internal_urls",
        "external_urls",
        "parameters",
        "api_endpoints",
        "forms",
        "javascript_files",
        "css_files",
        "js_endpoints"
    }

    if category not in allowed:
        return jsonify({
            "error": "Unknown crawler category.",
            "allowed": sorted(allowed)
        }), 400

    items = safe_list(
        crawl.get(category, [])
    )

    return jsonify({
        "scan_id": scan_id,
        "category": category,
        "count": len(items),
        "items": items,
        "data": items
    })


# ============================================================
# FEATURE DETAIL API
# ============================================================

@app.get("/scan/<scan_id>/features/<group>/<name>")
def feature_detail(
    scan_id,
    group,
    name
):
    job = get_job(scan_id)

    if job is None:
        return jsonify({
            "error": "Scan not found.",
            "scan_id": scan_id
        }), 404

    result = safe_dict(
        job.get("result")
    )

    group_data = safe_dict(
        result.get(group)
    )

    value = group_data.get(name)

    if value is None:
        return jsonify({
            "error": "Feature not found.",
            "group": group,
            "name": name
        }), 404

    return jsonify({
        "scan_id": scan_id,
        "group": group,
        "name": name,
        "data": value
    })



# ============================================================
# LIVE SCAN STATUS
# ============================================================

@app.get("/scan-status/<scan_id>")
def scan_status(scan_id):

    job = get_job(
        scan_id
    )

    if job is None:

        return jsonify({

            "error":
                "Scan not found.",

            "scan_id":
                scan_id
        }), 404

    return jsonify(
        job
    )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():

    with scan_jobs_lock:

        active_scans = sum(

            1

            for job
            in scan_jobs.values()

            if job.get(
                "status"
            ) == "running"
        )

    return jsonify({

        "status":
            "ok",

        "service":
            "VAPT Automation Tool",

        "active_scans":
            active_scans,

        "total_scans":
            len(scan_jobs),

        "time":
            time.time()
    })


# ============================================================
# RESULT EXPORTS
# ============================================================

def _current_scan_result(scan_id):
    job = get_job(scan_id)
    if job is None:
        return None, None
    result = safe_dict(job.get("result"))
    if not result:
        # During a live scan, build the best available result from job state.
        result = {
            k: v for k, v in job.items()
            if k not in {"result"}
        }
    return job, result


def _flatten_rows(value, prefix=""):
    rows = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(child, (dict, list, tuple)):
                rows.extend(_flatten_rows(child, path))
            else:
                rows.append((path, "" if child is None else str(child)))
    elif isinstance(value, (list, tuple)):
        for i, child in enumerate(value):
            path = f"{prefix}[{i}]"
            if isinstance(child, (dict, list, tuple)):
                rows.extend(_flatten_rows(child, path))
            else:
                rows.append((path, "" if child is None else str(child)))
    else:
        rows.append((prefix, "" if value is None else str(value)))
    return rows


def _result_csv(result):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Path", "Value"])
    for path, value in _flatten_rows(result):
        writer.writerow([path, value])
    return output.getvalue()


def _result_html(job, result):
    target = html.escape(str(job.get("target", "")))
    status = html.escape(str(job.get("status", "")))
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sections = []
    for key, value in result.items():
        if key in {"raw_output"}:
            continue
        pretty = html.escape(json.dumps(value, indent=2, ensure_ascii=False, default=str))
        sections.append(
            f"<section><h2>{html.escape(str(key))}</h2>"
            f"<pre>{pretty}</pre></section>"
        )

    return f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>VAPT Report - {target}</title>
<style>
body{{font-family:Arial,sans-serif;background:#0b1220;color:#e5e7eb;margin:0;padding:30px}}
main{{max-width:1400px;margin:auto}}
header,section{{background:#111827;border:1px solid #263244;border-radius:12px;padding:20px;margin-bottom:18px}}
h1{{margin-top:0}} h2{{color:#93c5fd}}
pre{{white-space:pre-wrap;overflow:auto;background:#080d17;padding:15px;border-radius:8px;color:#d1d5db}}
.meta{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}}
</style></head><body><main>
<header><h1>VAPT Automation Tool</h1>
<div class="meta">
<div><b>Target</b><br>{target}</div>
<div><b>Status</b><br>{status}</div>
<div><b>Generated</b><br>{generated}</div>
</div></header>
{''.join(sections)}
</main></body></html>"""


@app.get("/scan/<scan_id>/export/<fmt>")
def export_scan(scan_id, fmt):
    job, result = _current_scan_result(scan_id)

    if job is None:
        return jsonify({"error": "Scan not found.", "scan_id": scan_id}), 404

    fmt = fmt.lower().strip()

    if fmt == "json":
        return app.response_class(
            json.dumps(result, indent=2, ensure_ascii=False, default=str),
            mimetype="application/json",
            headers={
                "Content-Disposition":
                    f'attachment; filename="vapt-{scan_id}.json"'
            }
        )

    if fmt == "csv":
        return app.response_class(
            _result_csv(result),
            mimetype="text/csv",
            headers={
                "Content-Disposition":
                    f'attachment; filename="vapt-{scan_id}.csv"'
            }
        )

    if fmt == "html":
        return app.response_class(
            _result_html(job, result),
            mimetype="text/html",
            headers={
                "Content-Disposition":
                    f'attachment; filename="vapt-{scan_id}.html"'
            }
        )

    if fmt == "pdf":
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Preformatted
            )
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib.units import mm

            buffer = io.BytesIO()
            doc = SimpleDocTemplate(
                buffer, pagesize=A4,
                rightMargin=12*mm, leftMargin=12*mm,
                topMargin=12*mm, bottomMargin=12*mm
            )
            styles = getSampleStyleSheet()
            story = [
                Paragraph("VAPT Automation Tool - Assessment Report",
                          styles["Title"]),
                Spacer(1, 8),
                Paragraph(
                    f"Target: {html.escape(str(job.get('target', '')))}",
                    styles["Normal"]
                ),
                Paragraph(
                    f"Status: {html.escape(str(job.get('status', '')))}",
                    styles["Normal"]
                ),
                Spacer(1, 12)
            ]

            for key, value in result.items():
                if key == "raw_output":
                    continue
                story.append(Paragraph(str(key), styles["Heading2"]))
                text = json.dumps(
                    value, indent=2, ensure_ascii=False, default=str
                )
                story.append(
                    Preformatted(
                        text[:250000],
                        styles["Code"]
                    )
                )
                story.append(Spacer(1, 8))

            doc.build(story)
            buffer.seek(0)
            return app.response_class(
                buffer.getvalue(),
                mimetype="application/pdf",
                headers={
                    "Content-Disposition":
                        f'attachment; filename="vapt-{scan_id}.pdf"'
                }
            )
        except ImportError:
            return jsonify({
                "error": "PDF export requires reportlab.",
                "install": "pip install reportlab"
            }), 501
        except Exception as exc:
            return jsonify({"error": f"PDF export failed: {exc}"}), 500

    if fmt == "zip":
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr(
                f"vapt-{scan_id}/scan.json",
                json.dumps(result, indent=2, ensure_ascii=False, default=str)
            )
            z.writestr(
                f"vapt-{scan_id}/scan.csv",
                _result_csv(result)
            )
            z.writestr(
                f"vapt-{scan_id}/report.html",
                _result_html(job, result)
            )

            # Convenient module-level CSV files.
            for group in (
                "infrastructure", "services", "people",
                "credentials", "code_docs", "threat_landscape", "crawler"
            ):
                value = result.get(group)
                if value is not None:
                    z.writestr(
                        f"vapt-{scan_id}/{group}.csv",
                        _result_csv({group: value})
                    )

        buffer.seek(0)
        return app.response_class(
            buffer.getvalue(),
            mimetype="application/zip",
            headers={
                "Content-Disposition":
                    f'attachment; filename="vapt-{scan_id}.zip"'
            }
        )

    return jsonify({
        "error": "Unsupported export format.",
        "allowed": ["json", "csv", "html", "pdf", "zip"]
    }), 400


@app.get("/scan/<scan_id>/result")
def scan_result_api(scan_id):
    job, result = _current_scan_result(scan_id)
    if job is None:
        return jsonify({"error": "Scan not found.", "scan_id": scan_id}), 404
    return jsonify({
        "scan_id": scan_id,
        "status": job.get("status"),
        "progress": job.get("progress", 0),
        "phase": job.get("phase"),
        "result": result
    })



# ============================================================
# HOME PAGE
# ============================================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    app.run(

        host=
            "127.0.0.1",

        port=
            5000,

        debug=
            False,

        threaded=
            True,

        use_reloader=
            False
    )
