import socket
import ssl
import urllib.request
import urllib.error
import urllib.parse
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone


DEFAULT_SUBDOMAINS = [
    "www",
    "mail",
    "webmail",
    "smtp",
    "imap",
    "pop",
    "ftp",
    "sftp",
    "api",
    "api-dev",
    "api-test",
    "api-staging",
    "dev",
    "development",
    "test",
    "testing",
    "stage",
    "staging",
    "uat",
    "qa",
    "demo",
    "preview",
    "portal",
    "admin",
    "dashboard",
    "app",
    "mobile",
    "m",
    "beta",
    "internal",
    "vpn",
    "remote",
    "git",
    "gitlab",
    "github",
    "jenkins",
    "ci",
    "cd",
    "docker",
    "registry",
    "docs",
    "documentation",
    "support",
    "help",
    "status",
    "blog",
    "shop",
    "store",
    "cdn",
    "static",
    "assets",
    "img",
    "images",
    "files",
    "download",
    "uploads",
    "auth",
    "login",
    "sso",
    "oauth",
    "accounts",
    "secure",
    "payments",
    "payment",
]


def _now():
    return datetime.now(timezone.utc).isoformat()


def _clean_host(target):
    if not target:
        return ""

    value = str(target).strip()

    value = re.sub(
        r"^https?://",
        "",
        value,
        flags=re.I
    )

    value = value.split("/")[0]
    value = value.split(":")[0]

    return value.strip().lower().rstrip(".")


def _valid_domain(domain):
    if not domain:
        return False

    if len(domain) > 253:
        return False

    if not re.match(
        r"^[a-zA-Z0-9.-]+$",
        domain
    ):
        return False

    if ".." in domain:
        return False

    return True


def _resolve(host):
    """
    Resolve A and AAAA records using the local
    Windows resolver / socket API.

    No HTTP request is performed here.
    """

    result = {
        "resolved": False,
        "ipv4": [],
        "ipv6": [],
        "aliases": [],
        "hostname": host,
        "error": ""
    }

    try:
        infos = socket.getaddrinfo(
            host,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM
        )

        for info in infos:
            family = info[0]
            sockaddr = info[4]

            if not sockaddr:
                continue

            address = sockaddr[0]

            if family == socket.AF_INET:

                if address not in result["ipv4"]:
                    result["ipv4"].append(
                        address
                    )

            elif family == socket.AF_INET6:

                if address not in result["ipv6"]:
                    result["ipv6"].append(
                        address
                    )

        result["resolved"] = bool(
            result["ipv4"] or
            result["ipv6"]
        )

    except Exception as exc:
        result["error"] = str(exc)

    return result


def _certificate_info(host):
    """
    Read public TLS certificate metadata.

    This is only attempted after DNS resolution
    and only on TCP/443.
    """

    result = {
        "available": False,
        "subject": "",
        "issuer": "",
        "not_before": "",
        "not_after": "",
        "san": [],
        "error": ""
    }

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (host, 443),
            timeout=3
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=host
            ) as tls:

                cert = tls.getpeercert()

                if not cert:
                    return result

                result["available"] = True

                subject = []

                for item in cert.get(
                    "subject",
                    []
                ):
                    for key, value in item:
                        subject.append(
                            f"{key}={value}"
                        )

                result["subject"] = ", ".join(
                    subject
                )

                issuer = []

                for item in cert.get(
                    "issuer",
                    []
                ):
                    for key, value in item:
                        issuer.append(
                            f"{key}={value}"
                        )

                result["issuer"] = ", ".join(
                    issuer
                )

                result["not_before"] = cert.get(
                    "notBefore",
                    ""
                )

                result["not_after"] = cert.get(
                    "notAfter",
                    ""
                )

                for entry in cert.get(
                    "subjectAltName",
                    []
                ):
                    if len(entry) == 2:
                        result["san"].append(
                            entry[1]
                        )

    except Exception as exc:
        result["error"] = str(exc)

    return result


def _probe_web(host):
    """
    Lightweight HTTPS/HTTP reachability check.

    DNS discovery does not depend on this function.
    """

    result = {
        "reachable": False,
        "https": False,
        "url": "",
        "status_code": None,
        "server": "",
        "content_type": "",
        "title": "",
        "redirect": "",
        "error": ""
    }

    for scheme in (
        "https",
        "http"
    ):

        url = f"{scheme}://{host}/"

        try:

            request = urllib.request.Request(
                url,
                headers={
                    "User-Agent":
                        "VAPT-Automation-Scanner/1.0"
                },
                method="GET"
            )

            if scheme == "https":
                context = ssl.create_default_context()

                response = urllib.request.urlopen(
                    request,
                    timeout=4,
                    context=context
                )

            else:

                response = urllib.request.urlopen(
                    request,
                    timeout=4
                )

            with response:

                result["reachable"] = True
                result["https"] = (
                    scheme == "https"
                )

                result["url"] = response.geturl()

                result["status_code"] = (
                    response.status
                )

                result["server"] = (
                    response.headers.get(
                        "Server",
                        ""
                    )
                )

                result["content_type"] = (
                    response.headers.get(
                        "Content-Type",
                        ""
                    )
                )

                if (
                    response.geturl()
                    != url
                ):
                    result["redirect"] = (
                        response.geturl()
                    )

                try:
                    body = response.read(
                        32768
                    )

                    text = body.decode(
                        "utf-8",
                        errors="ignore"
                    )

                    match = re.search(
                        r"<title[^>]*>"
                        r"(.*?)"
                        r"</title>",
                        text,
                        flags=re.I | re.S
                    )

                    if match:
                        result["title"] = re.sub(
                            r"\s+",
                            " ",
                            match.group(1)
                        ).strip()[:250]

                except Exception:
                    pass

                return result

        except urllib.error.HTTPError as exc:

            result["reachable"] = True
            result["https"] = (
                scheme == "https"
            )
            result["url"] = url
            result["status_code"] = (
                exc.code
            )

            try:
                result["server"] = (
                    exc.headers.get(
                        "Server",
                        ""
                    )
                )
            except Exception:
                pass

            return result

        except Exception as exc:

            result["error"] = str(exc)

    return result


def _scan_candidate(host):
    """
    DNS-first candidate scan.

    Important:
    A subdomain is considered discovered when DNS
    resolves it. HTTP availability is separate.
    """

    resolution = _resolve(host)

    item = {
        "subdomain": host,
        "hostname": host,

        "resolved": resolution[
            "resolved"
        ],

        "ipv4": resolution[
            "ipv4"
        ],

        "ipv6": resolution[
            "ipv6"
        ],

        "aliases": resolution[
            "aliases"
        ],

        "dns_error": resolution[
            "error"
        ],

        "web": {
            "reachable": False,
            "https": False,
            "url": "",
            "status_code": None,
            "server": "",
            "content_type": "",
            "title": "",
            "redirect": "",
            "error": ""
        },

        "certificate": {},

        "status": (
            "resolved"
            if resolution["resolved"]
            else "not_resolved"
        )
    }

    if not resolution["resolved"]:
        return item

    # Web probing is performed only after DNS resolution.
    web = _probe_web(host)

    item["web"] = web

    if web.get("reachable"):
        item["status"] = "web_reachable"

    # Keep compatibility with older dashboard
    # structures.
    item["https"] = web

    if web.get("https"):
        item["certificate"] = (
            _certificate_info(host)
        )

    return item


def _crtsh_discovery(domain):
    """
    Passive Certificate Transparency discovery.

    Only public CT records are queried.
    """

    result = {
        "available": False,
        "names": [],
        "certificates": [],
        "error": ""
    }

    try:

        encoded_domain = urllib.parse.quote(
            f"%.{domain}",
            safe=""
        )

        url = (
            "https://crt.sh/"
            f"?q={encoded_domain}"
            "&output=json"
        )

        request = urllib.request.Request(
            url,
            headers={
                "User-Agent":
                    "VAPT-Automation-Scanner/1.0"
            }
        )

        with urllib.request.urlopen(
            request,
            timeout=12
        ) as response:

            raw = response.read(
                4 * 1024 * 1024
            )

        rows = json.loads(
            raw.decode(
                "utf-8",
                errors="ignore"
            )
        )

        names = []
        certificates = []

        if isinstance(rows, list):

            for row in rows:

                name_value = str(
                    row.get(
                        "name_value",
                        ""
                    )
                )

                row_names = []

                for name in name_value.splitlines():

                    name = (
                        name
                        .strip()
                        .lower()
                        .rstrip(".")
                    )

                    if name.startswith("*."):
                        name = name[2:]

                    if not name:
                        continue

                    if (
                        name == domain
                        or name.endswith(
                            "." + domain
                        )
                    ):
                        if name not in names:
                            names.append(name)

                            row_names.append(
                                name
                            )

                if row_names:

                    certificates.append({
                        "id": row.get(
                            "id"
                        ),
                        "issuer_name": row.get(
                            "issuer_name",
                            ""
                        ),
                        "common_name": row.get(
                            "common_name",
                            ""
                        ),
                        "name_value": name_value,
                        "not_before": row.get(
                            "not_before",
                            ""
                        ),
                        "not_after": row.get(
                            "not_after",
                            ""
                        ),
                        "names": row_names
                    })

        result["available"] = True
        result["names"] = names
        result["certificates"] = certificates

    except Exception as exc:
        result["error"] = str(exc)

    return result


def _build_candidates(domain, ct_names):
    candidates = set()

    # Common names.
    for prefix in DEFAULT_SUBDOMAINS:
        candidates.add(
            f"{prefix}.{domain}"
        )

    # CT-discovered names.
    for name in ct_names:

        name = (
            str(name)
            .strip()
            .lower()
            .rstrip(".")
        )

        if name.startswith("*."):
            name = name[2:]

        if (
            name.endswith(
                "." + domain
            )
        ):
            candidates.add(name)

    return sorted(candidates)


def enumerate_subdomains(target):
    """
    Main public subdomain enumeration function.
    """

    started = _now()

    domain = _clean_host(target)

    result = {
        "status": "completed",
        "target": target,
        "domain": domain,

        "started_at": started,
        "completed_at": None,

        "subdomains": [],
        "resolved": [],
        "reachable": [],

        "count": 0,
        "resolved_count": 0,
        "reachable_count": 0,

        "sources": {
            "common_names": True,
            "certificate_transparency": False
        },

        "certificate_transparency": {
            "available": False,
            "names": [],
            "certificates": [],
            "error": ""
        },

        "errors": []
    }

    if not _valid_domain(domain):

        result["status"] = "error"

        result["errors"].append(
            "Invalid domain"
        )

        result["completed_at"] = _now()

        return result

    # ---------------------------------------------------------
    # Certificate Transparency
    # ---------------------------------------------------------

    ct = _crtsh_discovery(
        domain
    )

    result[
        "certificate_transparency"
    ] = ct

    if ct.get("available"):
        result[
            "sources"
        ][
            "certificate_transparency"
        ] = True

    # ---------------------------------------------------------
    # Build candidates
    # ---------------------------------------------------------

    candidates = _build_candidates(
        domain,
        ct.get(
            "names",
            []
        )
    )

    # ---------------------------------------------------------
    # DNS enumeration
    # ---------------------------------------------------------

    discovered = []

    max_workers = min(
        20,
        max(
            4,
            len(candidates)
        )
    )

    with ThreadPoolExecutor(
        max_workers=max_workers
    ) as executor:

        futures = {
            executor.submit(
                _scan_candidate,
                candidate
            ): candidate

            for candidate in candidates
        }

        for future in as_completed(
            futures
        ):

            candidate = futures[
                future
            ]

            try:

                item = future.result()

                if item.get(
                    "resolved"
                ):
                    discovered.append(
                        item
                    )

            except Exception as exc:

                result["errors"].append(
                    f"{candidate}: {exc}"
                )

    # ---------------------------------------------------------
    # Sort
    # ---------------------------------------------------------

    discovered.sort(
        key=lambda x: x.get(
            "subdomain",
            ""
        )
    )

    # ---------------------------------------------------------
    # Build dashboard lists
    # ---------------------------------------------------------

    for item in discovered:

        host = item.get(
            "subdomain",
            ""
        )

        if not host:
            continue

        result[
            "subdomains"
        ].append(item)

        result[
            "resolved"
        ].append(host)

        if item.get(
            "web",
            {}
        ).get(
            "reachable"
        ):
            result[
                "reachable"
            ].append(host)

    # ---------------------------------------------------------
    # Root domain
    # ---------------------------------------------------------

    root_resolution = _resolve(
        domain
    )

    root = {
        "subdomain": domain,
        "hostname": domain,
        "root_domain": True,

        "resolved": root_resolution[
            "resolved"
        ],

        "ipv4": root_resolution[
            "ipv4"
        ],

        "ipv6": root_resolution[
            "ipv6"
        ],

        "dns_error": root_resolution[
            "error"
        ]
    }

    result["root"] = root

    # ---------------------------------------------------------
    # Counts
    # ---------------------------------------------------------

    result[
        "count"
    ] = len(
        result["subdomains"]
    )

    result[
        "resolved_count"
    ] = len(
        result["resolved"]
    )

    result[
        "reachable_count"
    ] = len(
        result["reachable"]
    )

    # ---------------------------------------------------------
    # Summary
    # ---------------------------------------------------------

    result["summary"] = {
        "candidate_count": len(
            candidates
        ),

        "subdomain_count": result[
            "count"
        ],

        "resolved_count": result[
            "resolved_count"
        ],

        "reachable_count": result[
            "reachable_count"
        ],

        "ct_discovery": result[
            "sources"
        ][
            "certificate_transparency"
        ],

        "ct_names": len(
            ct.get(
                "names",
                []
            )
        ),

        "ct_certificates": len(
            ct.get(
                "certificates",
                []
            )
        )
    }

    result["completed_at"] = _now()

    return result


# Compatibility aliases
scan_subdomains = enumerate_subdomains
subdomain_enum = enumerate_subdomains


if __name__ == "__main__":

    import sys

    target = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "example.com"
    )

    output = enumerate_subdomains(
        target
    )

    print(
        json.dumps(
            output,
            indent=2,
            default=str
        )
    )