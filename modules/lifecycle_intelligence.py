import re


# ============================================================
# SAFE LOCAL TECHNOLOGY LIFECYCLE KNOWLEDGE
# ============================================================

# This is intentionally conservative.
#
# The scanner reports:
#   potentially outdated
#   lifecycle review required
#
# It does NOT automatically claim that an arbitrary version
# is vulnerable.

KNOWN_EOL = {
    "php": {
        7: "PHP 7.x is EOL; verify the exact supported branch.",
        5: "PHP 5.x is EOL.",
    },

    "python": {
        2: "Python 2.x is EOL.",
    },

    "node": {
        10: "Node.js 10.x is EOL.",
        12: "Node.js 12.x is EOL.",
        14: "Node.js 14.x is EOL.",
        16: "Node.js 16.x is EOL.",
        18: "Node.js 18.x is EOL.",
    },

    "ubuntu": {
        16: "Ubuntu 16.04 standard support ended.",
        18: "Ubuntu 18.04 standard support ended.",
    },

    "centos": {
        6: "CentOS 6 is EOL.",
        7: "CentOS 7 is EOL.",
        8: "CentOS 8 is EOL.",
    },

    "debian": {
        8: "Debian 8 is EOL.",
        9: "Debian 9 is EOL.",
        10: "Debian 10 has reached the end of regular support.",
    },

    "windows server": {
        2008: "Windows Server 2008 is EOL.",
        2012: "Windows Server 2012 regular support ended.",
    },
}


def extract_version(
    text,
):
    if not text:
        return None

    match = re.search(
        r"\b(\d+)(?:\.(\d+))?(?:\.(\d+))?",
        str(text),
    )

    if not match:
        return None

    major = int(
        match.group(1)
    )

    minor = (
        int(match.group(2))
        if match.group(2)
        else 0
    )

    patch = (
        int(match.group(3))
        if match.group(3)
        else 0
    )

    return (
        major,
        minor,
        patch,
    )


def normalize_technology_name(
    item,
):
    if isinstance(
        item,
        str,
    ):
        return item

    if isinstance(
        item,
        dict,
    ):
        return str(
            item.get("name")
            or item.get("technology")
            or item.get("product")
            or ""
        )

    return ""


def lifecycle_match(
    name,
    version,
):
    low = name.lower()

    parsed = extract_version(
        version
    )

    if parsed is None:
        return None

    major = parsed[0]

    for technology, versions in KNOWN_EOL.items():

        if technology not in low:
            continue

        for eol_major, message in versions.items():

            if major == eol_major:
                return {
                    "technology": name,
                    "version": version,
                    "status": "EOL_REVIEW_REQUIRED",
                    "reason": message,
                }

    return None


def analyze_lifecycle_assets(
    target,
    technologies=None,
    subdomains=None,
    ports=None,
):
    items = []

    technologies = technologies or []
    subdomains = subdomains or []
    ports = ports or []

    # --------------------------------------------------------
    # Technology versions
    # --------------------------------------------------------

    for technology in technologies:

        name = normalize_technology_name(
            technology
        )

        if isinstance(
            technology,
            dict,
        ):
            version = (
                technology.get("version")
                or ""
            )

            if not version:
                combined = str(
                    technology.get("name")
                    or ""
                )

                parsed = extract_version(
                    combined
                )

                version = (
                    ".".join(
                        str(x)
                        for x in parsed
                    )
                    if parsed
                    else ""
                )

        else:
            parsed = extract_version(
                name
            )

            version = (
                ".".join(
                    str(x)
                    for x in parsed
                )
                if parsed
                else ""
            )

        match = lifecycle_match(
            name,
            version,
        )

        if match:
            match["asset"] = target
            match["source"] = (
                technology.get(
                    "source",
                    "technology fingerprint",
                )
                if isinstance(
                    technology,
                    dict,
                )
                else "technology fingerprint"
            )

            items.append(
                match
            )

    # --------------------------------------------------------
    # Service products
    # --------------------------------------------------------

    for port in ports:

        if not isinstance(
            port,
            dict,
        ):
            continue

        product = (
            port.get("product")
            or ""
        )

        version = (
            port.get("version")
            or ""
        )

        if not product:
            continue

        match = lifecycle_match(
            product,
            version,
        )

        if match:

            match.update({
                "asset": target,
                "port": port.get(
                    "port"
                ),
                "service": port.get(
                    "service"
                ),
                "source": "Nmap service detection",
            })

            items.append(
                match
            )

    # --------------------------------------------------------
    # Potential forgotten subdomains
    # --------------------------------------------------------

    forgotten_markers = (
        "old",
        "legacy",
        "dev",
        "development",
        "test",
        "testing",
        "qa",
        "uat",
        "stage",
        "staging",
        "beta",
        "demo",
    )

    for item in subdomains:

        if isinstance(
            item,
            dict,
        ):
            hostname = str(
                item.get(
                    "subdomain",
                    "",
                )
            )
        else:
            hostname = str(
                item
            )

        low = hostname.lower()

        matched_marker = next(
            (
                marker
                for marker in forgotten_markers
                if (
                    low.startswith(
                        marker + "."
                    )
                    or (
                        "." + marker + "."
                    ) in low
                )
            ),
            None,
        )

        if matched_marker:

            items.append({
                "asset": hostname,
                "status": "LIFECYCLE_REVIEW_REQUIRED",
                "reason": (
                    "Hostname contains a "
                    "development/test/legacy marker."
                ),
                "indicator": matched_marker,
                "source": "Subdomain naming analysis",
            })

    # Deduplicate
    unique = []
    seen = set()

    for item in items:

        key = (
            item.get("asset"),
            item.get("technology"),
            item.get("version"),
            item.get("status"),
            item.get("port"),
        )

        if key not in seen:
            seen.add(key)
            unique.append(item)

    return {
        "status": "COMPLETED",
        "items": unique,
        "count": len(unique),
        "target": target,
        "message": (
            "Technology lifecycle and forgotten-asset "
            "indicators analyzed."
        ),
    }