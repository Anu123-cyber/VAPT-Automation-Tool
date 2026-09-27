import socket
import subprocess
import shutil
import re
from datetime import datetime, timezone


def _now():
    return datetime.now(timezone.utc).isoformat()


def _clean_host(target):
    if not target:
        return ""

    target = str(target).strip()

    target = re.sub(r"^https?://", "", target, flags=re.I)
    target = target.split("/")[0]
    target = target.split(":")[0]

    return target.strip().lower()


def _run_nslookup(host, record_type=None):
    """
    Windows/Linux compatible nslookup helper.
    Returns raw output and parsed values.
    """

    if not shutil.which("nslookup"):
        return {
            "available": False,
            "raw": "",
            "records": []
        }

    try:
        command = ["nslookup"]

        if record_type:
            command.extend(["-type=" + record_type])

        command.append(host)

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15
        )

        raw = (process.stdout or "") + "\n" + (process.stderr or "")

        return {
            "available": True,
            "raw": raw.strip(),
            "records": _parse_nslookup(raw, record_type)
        }

    except Exception as exc:
        return {
            "available": False,
            "raw": "",
            "records": [],
            "error": str(exc)
        }


def _parse_nslookup(raw, record_type=None):
    """
    Basic parser for nslookup output.
    Designed to work with Windows nslookup output.
    """

    if not raw:
        return []

    records = []

    lines = raw.splitlines()

    for line in lines:
        line = line.strip()

        if not line:
            continue

        lower = line.lower()

        if record_type == "A":
            match = re.search(
                r"(?:Address|Addresses):\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)",
                line,
                re.I
            )

            if match:
                records.append(match.group(1))
                continue

            match = re.search(
                r"^\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s*$",
                line
            )

            if match:
                records.append(match.group(1))
                continue

        elif record_type == "AAAA":
            match = re.search(
                r"(?:Address|Addresses):\s*([0-9a-fA-F:]+)",
                line,
                re.I
            )

            if match and ":" in match.group(1):
                records.append(match.group(1))
                continue

        elif record_type == "MX":
            match = re.search(
                r"mail exchanger\s*=\s*(.+)$",
                line,
                re.I
            )

            if match:
                records.append(match.group(1).strip().rstrip("."))

        elif record_type == "NS":
            match = re.search(
                r"nameserver\s*=\s*(.+)$",
                line,
                re.I
            )

            if match:
                records.append(match.group(1).strip().rstrip("."))

        elif record_type == "TXT":
            match = re.search(
                r"text\s*=\s*(.*)$",
                line,
                re.I
            )

            if match:
                records.append(match.group(1).strip())

        elif record_type == "CNAME":
            match = re.search(
                r"canonical name\s*=\s*(.+)$",
                line,
                re.I
            )

            if match:
                records.append(match.group(1).strip().rstrip("."))

    # Generic fallback parsing
    if not records:
        for line in lines:
            line = line.strip()

            if record_type == "A":
                if re.fullmatch(
                    r"(?:\d{1,3}\.){3}\d{1,3}",
                    line
                ):
                    records.append(line)

    # Preserve order and remove duplicates
    result = []

    for item in records:
        item = str(item).strip()

        if item and item not in result:
            result.append(item)

    return result


def _socket_records(host):
    """
    Resolve host using Python socket as a fallback.
    """

    result = {
        "ipv4": [],
        "ipv6": [],
        "canonical_name": ""
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
                    result["ipv4"].append(address)

            elif family == socket.AF_INET6:
                if address not in result["ipv6"]:
                    result["ipv6"].append(address)

        try:
            canonical = socket.getfqdn(host)

            if canonical and canonical.lower() != host.lower():
                result["canonical_name"] = canonical
        except Exception:
            pass

    except Exception as exc:
        result["error"] = str(exc)

    return result


def _reverse_dns(ip):
    try:
        hostname, aliases, addresses = socket.gethostbyaddr(ip)

        return {
            "ip": ip,
            "hostname": hostname,
            "aliases": aliases or [],
            "addresses": addresses or []
        }

    except Exception:
        return {
            "ip": ip,
            "hostname": "",
            "aliases": [],
            "addresses": []
        }


def _collect_dns_records(host):
    records = {}

    for record_type in [
        "A",
        "AAAA",
        "MX",
        "NS",
        "TXT",
        "CNAME"
    ]:
        result = _run_nslookup(host, record_type)

        records[record_type] = {
            "records": result.get("records", []),
            "raw": result.get("raw", ""),
            "available": result.get("available", False)
        }

    return records


def scan_dns(target):
    """
    Main DNS reconnaissance function used by app.py.

    Returns a normalized dictionary containing:
      - A
      - AAAA
      - MX
      - NS
      - TXT
      - CNAME
      - reverse DNS
      - resolver information
      - raw nslookup data
    """

    started = _now()

    host = _clean_host(target)

    if not host:
        return {
            "status": "error",
            "target": target,
            "host": "",
            "started_at": started,
            "completed_at": _now(),
            "error": "Invalid or empty target"
        }

    result = {
        "status": "completed",
        "target": target,
        "host": host,
        "started_at": started,
        "completed_at": None,

        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "CNAME": [],

        "ipv4": [],
        "ipv6": [],
        "canonical_name": "",

        "reverse_dns": [],

        "records": {},

        "resolver": {
            "nslookup_available": bool(shutil.which("nslookup")),
            "python_socket": True
        },

        "errors": []
    }

    try:
        # ---------------------------------------------------------
        # 1. Python socket resolution
        # ---------------------------------------------------------

        socket_result = _socket_records(host)

        result["ipv4"] = socket_result.get("ipv4", [])
        result["ipv6"] = socket_result.get("ipv6", [])
        result["canonical_name"] = socket_result.get(
            "canonical_name",
            ""
        )

        if socket_result.get("error"):
            result["errors"].append(
                "Socket resolution: " +
                str(socket_result["error"])
            )

        # ---------------------------------------------------------
        # 2. nslookup DNS records
        # ---------------------------------------------------------

        dns_records = _collect_dns_records(host)

        result["records"] = dns_records

        for record_type in [
            "A",
            "AAAA",
            "MX",
            "NS",
            "TXT",
            "CNAME"
        ]:
            values = (
                dns_records
                .get(record_type, {})
                .get("records", [])
            )

            result[record_type] = values

        # ---------------------------------------------------------
        # 3. Merge socket A/AAAA results
        # ---------------------------------------------------------

        for ip in result["ipv4"]:
            if ip not in result["A"]:
                result["A"].append(ip)

        for ip in result["ipv6"]:
            if ip not in result["AAAA"]:
                result["AAAA"].append(ip)

        # ---------------------------------------------------------
        # 4. Reverse DNS
        # ---------------------------------------------------------

        reverse_ips = []

        for ip in result["A"] + result["AAAA"]:
            if ip not in reverse_ips:
                reverse_ips.append(ip)

        for ip in reverse_ips[:20]:
            result["reverse_dns"].append(
                _reverse_dns(ip)
            )

        # ---------------------------------------------------------
        # 5. Resolver summary
        # ---------------------------------------------------------

        result["resolver"]["successful_records"] = sum(
            1
            for record_type in dns_records.values()
            if record_type.get("records")
        )

        result["resolver"]["record_types_checked"] = 6

        # ---------------------------------------------------------
        # 6. Basic DNS summary
        # ---------------------------------------------------------

        result["summary"] = {
            "resolved": bool(
                result["A"] or
                result["AAAA"]
            ),

            "ipv4_count": len(result["A"]),
            "ipv6_count": len(result["AAAA"]),
            "mx_count": len(result["MX"]),
            "ns_count": len(result["NS"]),
            "txt_count": len(result["TXT"]),
            "cname_count": len(result["CNAME"]),
            "reverse_dns_count": len(result["reverse_dns"])
        }

    except Exception as exc:
        result["status"] = "error"
        result["errors"].append(str(exc))

    result["completed_at"] = _now()

    return result


def collect_dns_ns_recon(host):
    """
    Additional DNS/NS reconnaissance helper used by the dashboard.
    """

    host = _clean_host(host)

    if not host:
        return {
            "status": "error",
            "host": "",
            "error": "Invalid target"
        }

    result = scan_dns(host)

    return {
        "status": result.get("status"),
        "host": host,

        "nameservers": result.get("NS", []),
        "mail_servers": result.get("MX", []),
        "txt_records": result.get("TXT", []),
        "cname_records": result.get("CNAME", []),

        "a_records": result.get("A", []),
        "aaaa_records": result.get("AAAA", []),

        "reverse_dns": result.get(
            "reverse_dns",
            []
        ),

        "summary": result.get(
            "summary",
            {}
        ),

        "records": result.get(
            "records",
            {}
        ),

        "errors": result.get(
            "errors",
            []
        )
    }


# Compatibility aliases
enumerate_dns = scan_dns
dns_recon = scan_dns


if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"

    print(
        json.dumps(
            scan_dns(target),
            indent=2,
            default=str
        )
    )