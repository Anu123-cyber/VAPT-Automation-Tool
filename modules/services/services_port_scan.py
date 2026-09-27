# modules/services/services_port_scan.py

import os
import re
import shutil
import socket
import subprocess
from datetime import datetime, timezone
from urllib.parse import urlparse


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def normalize_target(target):
    if not target:
        return ""

    target = str(target).strip()

    if "://" not in target:
        target = "http://" + target

    try:
        parsed = urlparse(target)

        if parsed.hostname:
            return parsed.hostname.lower().strip()
    except Exception:
        pass

    target = re.sub(
        r"^https?://",
        "",
        target,
        flags=re.IGNORECASE,
    )

    target = target.split("/")[0]
    target = target.split("?")[0]
    target = target.split("#")[0]

    if target.count(":") == 1:
        target = target.rsplit(":", 1)[0]

    return target.lower().strip()


def find_nmap():
    """
    Locate Nmap on Windows or PATH.
    """

    path = shutil.which("nmap")

    if path:
        return path

    candidates = [
        r"C:\Program Files\Nmap\nmap.exe",
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        os.path.expandvars(
            r"%ProgramFiles%\Nmap\nmap.exe"
        ),
        os.path.expandvars(
            r"%ProgramFiles(x86)%\Nmap\nmap.exe"
        ),
    ]

    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate

    return None


def normalize_profile(profile):
    profile = str(profile or "fast").lower().strip()

    aliases = {
        "quick": "fast",
        "top1000": "fast",
        "top-1000": "fast",
        "normal": "standard",
        "medium": "standard",
        "top5000": "standard",
        "top-5000": "standard",
        "all": "full",
        "fulltcp": "full",
        "full-tcp": "full",
    }

    profile = aliases.get(profile, profile)

    if profile not in {
        "fast",
        "standard",
        "full",
    }:
        profile = "fast"

    return profile


def get_port_spec(profile):
    profile = normalize_profile(profile)

    if profile == "fast":
        return "--top-ports", "1000"

    if profile == "standard":
        return "--top-ports", "5000"

    return "-p", "1-65535"


def resolve_host(host):
    result = {
        "hostname": host,
        "ipv4": [],
        "ipv6": [],
        "errors": [],
    }

    try:
        addresses = socket.getaddrinfo(
            host,
            None,
        )

        for family, _, _, _, sockaddr in addresses:
            address = sockaddr[0]

            if family == socket.AF_INET:
                if address not in result["ipv4"]:
                    result["ipv4"].append(address)

            elif family == socket.AF_INET6:
                if address not in result["ipv6"]:
                    result["ipv6"].append(address)

    except Exception as exc:
        result["errors"].append(str(exc))

    return result


def parse_port_line(line):
    """
    Parse an Nmap service table line.

    Example:

    80/tcp   open  http     syn-ack ttl 56 Cloudflare http proxy

    Returns:

    port
    protocol
    state
    service
    reason
    product
    version
    raw
    """

    if not line:
        return None

    line = line.strip()

    match = re.match(
        r"^(\d+)/(tcp|udp)\s+"
        r"(\S+)\s+"
        r"(\S+)\s+"
        r"(.*)$",
        line,
        re.IGNORECASE,
    )

    if not match:
        return None

    port = int(match.group(1))
    protocol = match.group(2).lower()
    state = match.group(3).lower()
    service = match.group(4).strip()
    remaining = match.group(5).strip()

    reason = ""
    version_text = remaining

    # ---------------------------------------------
    # Extract Nmap REASON
    # ---------------------------------------------

    reason_match = re.match(
        r"^(syn-ack|reset|conn-refused|"
        r"echo-reply|no-response)"
        r"(?:\s+ttl\s+\d+)?"
        r"(?:\s+|$)",
        remaining,
        re.IGNORECASE,
    )

    if reason_match:
        reason = reason_match.group(0).strip()

        version_text = remaining[
            reason_match.end():
        ].strip()

    # ---------------------------------------------
    # Product / Version
    # ---------------------------------------------

    product = ""
    version = ""

    if version_text:

        version_match = re.search(
            r"^(.*?)\s+"
            r"(\d+(?:\.\d+)+(?:[-._A-Za-z0-9]*)?)"
            r"(?:\s+(.*))?$",
            version_text,
        )

        if version_match:

            product = (
                version_match.group(1) or ""
            ).strip()

            version = (
                version_match.group(2) or ""
            ).strip()

            trailing = (
                version_match.group(3) or ""
            ).strip()

            if trailing:
                product = (
                    f"{product} {trailing}"
                ).strip()

        else:
            product = version_text.strip()

    return {
        "port": port,
        "protocol": protocol,
        "state": state,
        "service": service,
        "reason": reason,
        "product": product,
        "version": version,
        "raw": line,
    }


def parse_nmap_output(output):
    """
    Parse complete Nmap stdout.
    """

    ports = []

    if not output:
        return ports

    for line in output.splitlines():

        parsed = parse_port_line(line)

        if parsed:
            ports.append(parsed)

    # ---------------------------------------------
    # Remove duplicate port/protocol entries
    # ---------------------------------------------

    unique = {}

    for item in ports:

        key = (
            item.get("port"),
            item.get("protocol"),
        )

        existing = unique.get(key)

        if existing is None:
            unique[key] = item
            continue

        existing_score = sum(
            1
            for field in (
                "reason",
                "service",
                "product",
                "version",
            )
            if existing.get(field)
        )

        new_score = sum(
            1
            for field in (
                "reason",
                "service",
                "product",
                "version",
            )
            if item.get(field)
        )

        if new_score >= existing_score:
            unique[key] = item

    return sorted(
        unique.values(),
        key=lambda item: (
            int(item.get("port", 0)),
            str(item.get("protocol", "")),
        ),
    )


def extract_open_ports(ports):
    """
    Return only open ports.
    """

    if not ports:
        return []

    result = []

    for item in ports:

        if not isinstance(item, dict):
            continue

        if (
            str(item.get("state", ""))
            .lower()
            .strip()
            == "open"
        ):
            result.append(item)

    return sorted(
        result,
        key=lambda item: (
            int(item.get("port", 0)),
            str(item.get("protocol", "")),
        ),
    )


def send_progress(
    callback,
    progress,
    message,
    line="",
    ports=None,
    open_ports=None,
):
    """
    Send live scan progress to app.py.
    """

    if not callback:
        return

    payload = {
        "phase": "nmap",
        "progress": int(
            max(
                0,
                min(100, progress),
            )
        ),
        "message": str(message),
        "line": str(line or ""),
        "ports": ports or [],
        "open_ports": open_ports or [],
        "timestamp": utc_now(),
    }

    try:
        callback(payload)
        return
    except TypeError:
        pass
    except Exception:
        return

    try:
        callback(
            payload["progress"],
            payload["message"],
            payload,
        )
        return
    except TypeError:
        pass
    except Exception:
        return

    try:
        callback(
            payload["progress"],
            payload["message"],
        )
    except Exception:
        pass


def scan_ports(
    target,
    profile="fast",
    progress_callback=None,
    callback=None,
    progress_cb=None,
):
    """
    TCP Nmap scanner.

    Profiles:

    fast
        Top 1000 TCP ports

    standard
        Top 5000 TCP ports

    full
        TCP ports 1-65535
    """

    started_at = utc_now()

    host = normalize_target(target)

    profile = normalize_profile(profile)

    progress_callback = (
        progress_callback
        or callback
        or progress_cb
    )

    result = {
        "status": "starting",
        "target": target,
        "host": host,
        "profile": profile,

        "nmap_available": False,
        "nmap_path": None,

        "command": [],
        "command_string": "",

        "started_at": started_at,
        "completed_at": None,

        "scan_duration_seconds": None,

        "resolved": {
            "hostname": host,
            "ipv4": [],
            "ipv6": [],
            "errors": [],
        },

        "ports": [],
        "open_ports": [],
        "open_port_count": 0,

        "stdout": "",
        "stderr": "",

        "errors": [],

        "summary": {},
    }

    # ---------------------------------------------
    # Validate target
    # ---------------------------------------------

    if not host:

        result["status"] = "failed"

        result["errors"].append(
            "Target hostname is empty."
        )

        result["completed_at"] = utc_now()

        return result

    # ---------------------------------------------
    # Find Nmap
    # ---------------------------------------------

    nmap_path = find_nmap()

    if not nmap_path:

        result["status"] = "not_available"

        result["errors"].append(
            "Nmap executable was not found."
        )

        result["completed_at"] = utc_now()

        return result

    result["nmap_available"] = True
    result["nmap_path"] = nmap_path

    # ---------------------------------------------
    # Resolve
    # ---------------------------------------------

    resolved = resolve_host(host)

    result["resolved"] = resolved

    if (
        not resolved["ipv4"]
        and not resolved["ipv6"]
    ):

        result["status"] = "failed"

        result["errors"].append(
            f"Unable to resolve target: {host}"
        )

        result["completed_at"] = utc_now()

        return result

    # ---------------------------------------------
    # Build Nmap command
    # ---------------------------------------------

    port_option, port_value = get_port_spec(
        profile
    )

    command = [
        nmap_path,
        "-Pn",
        "-sV",
        "--reason",
        "--open",
        "-T4",
        port_option,
        port_value,
        host,
    ]

    result["command"] = command

    result["command_string"] = (
        subprocess.list2cmdline(command)
    )

    send_progress(
        progress_callback,
        0,
        (
            f"Starting {profile} TCP scan "
            f"against {host}"
        ),
    )

    stdout_lines = []

    process = None

    try:

        creationflags = 0

        if os.name == "nt":
            creationflags = getattr(
                subprocess,
                "CREATE_NO_WINDOW",
                0,
            )

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            universal_newlines=True,
            creationflags=creationflags,
        )

        result["status"] = "running"

        live_ports = []

        # -----------------------------------------
        # Read output live
        # -----------------------------------------

        while True:

            line = process.stdout.readline()

            if line == "":

                if process.poll() is not None:
                    break

                continue

            line = line.rstrip(
                "\r\n"
            )

            if line:
                stdout_lines.append(line)

            parsed = parse_port_line(line)

            if parsed:

                # Replace duplicate entry.
                found = False

                for index, existing in enumerate(
                    live_ports
                ):

                    if (
                        existing.get("port")
                        == parsed.get("port")
                        and
                        existing.get("protocol")
                        == parsed.get("protocol")
                    ):
                        live_ports[index] = parsed
                        found = True
                        break

                if not found:
                    live_ports.append(parsed)

                open_ports = extract_open_ports(
                    live_ports
                )

                send_progress(
                    progress_callback,
                    90,
                    (
                        f"Discovered "
                        f"{parsed['port']}/"
                        f"{parsed['protocol']} "
                        f"{parsed['service']}"
                    ),
                    line=line,
                    ports=list(live_ports),
                    open_ports=open_ports,
                )

            else:

                percent_match = re.search(
                    r"(\d+(?:\.\d+)?)%\s+done",
                    line,
                    re.IGNORECASE,
                )

                if percent_match:

                    try:

                        pct = float(
                            percent_match.group(1)
                        )

                        mapped = int(
                            min(
                                99,
                                max(
                                    1,
                                    pct,
                                ),
                            )
                        )

                        send_progress(
                            progress_callback,
                            mapped,
                            line,
                            line=line,
                            ports=live_ports,
                            open_ports=extract_open_ports(
                                live_ports
                            ),
                        )

                    except Exception:
                        pass

                elif line:

                    send_progress(
                        progress_callback,
                        10,
                        line,
                        line=line,
                        ports=live_ports,
                        open_ports=extract_open_ports(
                            live_ports
                        ),
                    )

        return_code = process.wait()

        result["stdout"] = "\n".join(
            stdout_lines
        )

        # -----------------------------------------
        # Parse complete output
        # -----------------------------------------

        parsed_ports = parse_nmap_output(
            result["stdout"]
        )

        result["ports"] = parsed_ports

        result["open_ports"] = (
            extract_open_ports(
                parsed_ports
            )
        )

        result["open_port_count"] = len(
            result["open_ports"]
        )

        # -----------------------------------------
        # Status
        # -----------------------------------------

        if return_code == 0:

            result["status"] = "completed"

        else:

            result["status"] = (
                "completed_with_errors"
            )

            result["errors"].append(
                f"Nmap exited with code "
                f"{return_code}."
            )

        send_progress(
            progress_callback,
            100,
            (
                "Nmap scan completed: "
                f"{result['open_port_count']} "
                "open TCP port(s)"
            ),
            ports=result["ports"],
            open_ports=result["open_ports"],
        )

    except FileNotFoundError:

        result["status"] = "not_available"

        result["errors"].append(
            "Nmap executable could not be started."
        )

    except PermissionError as exc:

        result["status"] = "failed"

        result["errors"].append(
            f"Permission error: {exc}"
        )

    except Exception as exc:

        result["status"] = "failed"

        result["errors"].append(
            f"Nmap scan error: {exc}"
        )

    finally:

        if process is not None:

            try:

                if process.poll() is None:

                    process.kill()

                    process.wait(
                        timeout=5
                    )

            except Exception:
                pass

        result["completed_at"] = utc_now()

        result["stdout"] = (
            result.get("stdout")
            or "\n".join(stdout_lines)
        )

        # Always ensure ports are normalized.
        if result.get("stdout"):

            final_ports = (
                parse_nmap_output(
                    result["stdout"]
                )
            )

            result["ports"] = final_ports

            result["open_ports"] = (
                extract_open_ports(
                    final_ports
                )
            )

            result["open_port_count"] = len(
                result["open_ports"]
            )

        try:

            start = datetime.fromisoformat(
                result["started_at"]
            )

            end = datetime.fromisoformat(
                result["completed_at"]
            )

            result[
                "scan_duration_seconds"
            ] = round(
                (
                    end - start
                ).total_seconds(),
                2,
            )

        except Exception:

            result[
                "scan_duration_seconds"
            ] = None

        result["summary"] = {
            "profile": profile,
            "host": host,
            "status": result["status"],
            "nmap_available": (
                result["nmap_available"]
            ),
            "open_port_count": (
                result["open_port_count"]
            ),
            "total_detected_ports": len(
                result["ports"]
            ),
            "ipv4_count": len(
                result["resolved"]
                .get("ipv4", [])
            ),
            "ipv6_count": len(
                result["resolved"]
                .get("ipv6", [])
            ),
            "scan_duration_seconds": (
                result[
                    "scan_duration_seconds"
                ]
            ),
        }

    return result


def nmap_scan(
    target,
    profile="fast",
    progress_callback=None,
    callback=None,
    progress_cb=None,
):
    return scan_ports(
        target,
        profile=profile,
        progress_callback=progress_callback,
        callback=callback,
        progress_cb=progress_cb,
    )


def run_nmap(
    target,
    profile="fast",
    progress_callback=None,
    callback=None,
    progress_cb=None,
):
    return scan_ports(
        target,
        profile=profile,
        progress_callback=progress_callback,
        callback=callback,
        progress_cb=progress_cb,
    )


if __name__ == "__main__":

    import json
    import sys

    target = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "example.com"
    )

    profile = (
        sys.argv[2]
        if len(sys.argv) > 2
        else "fast"
    )

    def progress(data):
        print(
            f"[NMAP] "
            f"{data.get('progress', 0)}% "
            f"{data.get('message', '')}"
        )

    result = scan_ports(
        target,
        profile=profile,
        progress_callback=progress,
    )

    print(
        json.dumps(
            result,
            indent=2,
            default=str,
        )
    )