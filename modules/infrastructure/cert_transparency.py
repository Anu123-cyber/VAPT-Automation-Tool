import json
import re
import urllib.request
import urllib.parse
from datetime import datetime, timezone


def _now():
    return datetime.now(timezone.utc).isoformat()


def _clean_domain(target):
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


def _request_json(url, timeout=15):
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent":
                "VAPT-Automation-Scanner/1.0"
        }
    )

    with urllib.request.urlopen(
        request,
        timeout=timeout
    ) as response:

        raw = response.read(
            8 * 1024 * 1024
        )

    return json.loads(
        raw.decode(
            "utf-8",
            errors="ignore"
        )
    )


def _normalize_names(value, domain):
    names = []

    if not value:
        return names

    for name in str(value).splitlines():

        name = (
            name
            .strip()
            .lower()
            .rstrip(".")
        )

        if not name:
            continue

        if name.startswith("*."):
            name = name[2:]

        if (
            name == domain
            or name.endswith(
                "." + domain
            )
        ):
            if name not in names:
                names.append(name)

    return names


def _normalize_certificate(row, domain):
    name_value = row.get(
        "name_value",
        ""
    )

    matched_names = _normalize_names(
        name_value,
        domain
    )

    return {
        "id": row.get("id"),

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

        "serial_number": row.get(
            "serial_number",
            ""
        ),

        "entry_timestamp": row.get(
            "entry_timestamp",
            ""
        ),

        "matched_names": matched_names,

        "name_count": len(
            matched_names
        )
    }


def enumerate_certificates(target):
    """
    Passive Certificate Transparency enumeration.

    Uses crt.sh public CT records.

    No authentication, exploitation, certificate
    manipulation, or active scanning is performed.
    """

    started = _now()

    domain = _clean_domain(
        target
    )

    result = {
        "status": "completed",
        "target": target,
        "domain": domain,

        "started_at": started,
        "completed_at": None,

        "certificates": [],
        "subdomains": [],

        "count": 0,
        "certificate_count": 0,
        "subdomain_count": 0,

        "unique_issuers": [],
        "unique_common_names": [],

        "sources": {
            "crt_sh": True
        },

        "errors": []
    }

    if not domain:

        result["status"] = "error"

        result["errors"].append(
            "Invalid or empty domain"
        )

        result["completed_at"] = _now()

        return result

    try:

        encoded = urllib.parse.quote(
            f"%.{domain}",
            safe=""
        )

        url = (
            "https://crt.sh/"
            f"?q={encoded}"
            "&output=json"
        )

        rows = _request_json(
            url,
            timeout=15
        )

        if not isinstance(
            rows,
            list
        ):
            rows = []

        certificates = []

        subdomains = []

        issuers = []

        common_names = []

        for row in rows:

            if not isinstance(
                row,
                dict
            ):
                continue

            certificate = (
                _normalize_certificate(
                    row,
                    domain
                )
            )

            matched_names = (
                certificate[
                    "matched_names"
                ]
            )

            # Ignore records that do not
            # belong to the target domain.
            if not matched_names:
                continue

            certificates.append(
                certificate
            )

            for name in matched_names:

                if name not in subdomains:
                    subdomains.append(
                        name
                    )

            issuer = certificate[
                "issuer_name"
            ]

            if (
                issuer
                and issuer not in issuers
            ):
                issuers.append(
                    issuer
                )

            common_name = certificate[
                "common_name"
            ]

            if (
                common_name
                and common_name
                not in common_names
            ):
                common_names.append(
                    common_name
                )

        # -----------------------------------------------------
        # Remove duplicate certificate rows
        # -----------------------------------------------------

        unique_certificates = []
        seen = set()

        for cert in certificates:

            key = (
                cert.get("id"),
                cert.get(
                    "serial_number"
                ),
                cert.get(
                    "not_before"
                ),
                cert.get(
                    "not_after"
                ),
                cert.get(
                    "name_value"
                )
            )

            if key in seen:
                continue

            seen.add(key)

            unique_certificates.append(
                cert
            )

        certificates = (
            unique_certificates
        )

        # -----------------------------------------------------
        # Sort newest certificates first
        # -----------------------------------------------------

        certificates.sort(
            key=lambda x: (
                x.get(
                    "not_before",
                    ""
                ) or ""
            ),
            reverse=True
        )

        subdomains.sort()

        issuers.sort()

        common_names.sort()

        result["certificates"] = (
            certificates
        )

        result["subdomains"] = (
            subdomains
        )

        result["count"] = len(
            certificates
        )

        result[
            "certificate_count"
        ] = len(
            certificates
        )

        result[
            "subdomain_count"
        ] = len(
            subdomains
        )

        result[
            "unique_issuers"
        ] = issuers

        result[
            "unique_common_names"
        ] = common_names

        result["summary"] = {
            "certificate_count": len(
                certificates
            ),

            "unique_subdomains": len(
                subdomains
            ),

            "unique_issuers": len(
                issuers
            ),

            "unique_common_names": len(
                common_names
            )
        }

    except Exception as exc:

        result["status"] = "error"

        result["errors"].append(
            str(exc)
        )

        result["summary"] = {
            "certificate_count": 0,
            "unique_subdomains": 0,
            "unique_issuers": 0,
            "unique_common_names": 0
        }

    result["completed_at"] = _now()

    return result


# Compatibility aliases
scan_certificates = enumerate_certificates
certificate_transparency = enumerate_certificates
ct_enum = enumerate_certificates


if __name__ == "__main__":

    import sys

    target = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "example.com"
    )

    print(
        json.dumps(
            enumerate_certificates(
                target
            ),
            indent=2,
            default=str
        )
    )