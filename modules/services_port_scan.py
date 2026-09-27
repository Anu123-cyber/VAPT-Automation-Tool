import subprocess
import re
import time


# ============================================================
# NMAP PORT LINE PARSER
# ============================================================

def parse_port_line(line):
    """
    Parse Nmap open-port output.

    Examples:
        22/tcp open ssh OpenSSH 9.6
        443/tcp open https nginx 1.24.0
        3306/tcp open mysql MySQL 8.0
    """

    line = line.strip()

    match = re.match(
        r"^(\d+)\/(\w+)\s+open\s+(.+)$",
        line,
        re.IGNORECASE
    )

    if not match:
        return None

    port = int(match.group(1))
    protocol = match.group(2).lower()
    service_data = match.group(3).strip()

    parts = service_data.split()

    service = parts[0] if parts else "unknown"

    product = parts[1] if len(parts) > 1 else ""

    version = (
        " ".join(parts[2:])
        if len(parts) > 2
        else ""
    )

    return {
        "port": port,
        "protocol": protocol,
        "state": "open",
        "service": service,
        "product": product,
        "version": version
    }


# ============================================================
# TARGET CLEANING
# ============================================================

def clean_target(target):
    """
    Convert URL/domain/IP into an Nmap-compatible target.

    Examples:

        https://example.com
            -> example.com

        https://example.com/login
            -> example.com

        example.com:443
            -> example.com

        192.168.1.10
            -> 192.168.1.10
    """

    target = str(target or "").strip()

    target = re.sub(
        r"^https?://",
        "",
        target,
        flags=re.IGNORECASE
    )

    # Remove path/query/fragment.
    target = target.split("/")[0]

    # Remove hostname:port.
    #
    # Do NOT modify IPv6 addresses.
    if target.count(":") == 1:

        host, possible_port = target.rsplit(":", 1)

        if possible_port.isdigit():
            target = host

    return target


# ============================================================
# LIVE PROGRESS
# ============================================================

def send_progress(
    callback,
    start_time,
    percent,
    ports,
    message,
    event="running",
    ports_scanned=0,
    total_ports=65535
):
    """
    Send normalized live progress information to app.py.
    """

    if not callback:
        return

    elapsed_seconds = int(
        time.time() - start_time
    )

    hours = elapsed_seconds // 3600
    minutes = (elapsed_seconds % 3600) // 60
    seconds = elapsed_seconds % 60

    elapsed = (
        f"{hours:02d}:"
        f"{minutes:02d}:"
        f"{seconds:02d}"
    )

    callback({
        "event": event,

        "elapsed": elapsed,

        "percent": round(
            max(0, min(100, percent)),
            2
        ),

        "ports_scanned": ports_scanned,

        "total_ports": total_ports,

        "ports_discovered": len(ports),

        "open_ports": len(ports),

        "ports": list(ports),

        "message": message
    })


# ============================================================
# NMAP PROGRESS PARSER
# ============================================================

def parse_nmap_percent(line):
    """
    Extract Nmap progress percentage.

    Supports output such as:

        About 12.34% done
        Approximately 45.67% done
    """

    match = re.search(
        r"(?:About|Approximately)\s+"
        r"([\d.]+)%\s+done",
        line,
        re.IGNORECASE
    )

    if not match:
        return None

    try:
        return float(match.group(1))
    except ValueError:
        return None


# ============================================================
# ADD / UPDATE PORT
# ============================================================

def add_or_update_port(
    ports,
    parsed
):
    """
    Add a newly discovered port or update
    an existing port with service information.
    """

    if not parsed:
        return

    key = (
        parsed["port"],
        parsed["protocol"]
    )

    for index, existing in enumerate(ports):

        existing_key = (
            existing.get("port"),
            existing.get("protocol")
        )

        if existing_key == key:

            ports[index] = {
                **existing,
                **parsed
            }

            return

    ports.append(parsed)


# ============================================================
# FULL PORT DISCOVERY
# ============================================================

def discovery_scan(
    target,
    progress_callback,
    start_time,
    discovered_ports,
    output_lines
):
    """
    Stage 1:
    Full TCP 1-65535 discovery.
    """

    command = [
        "nmap",

        "-Pn",

        "-p-",

        "-sS",

        "--open",

        "-T4",

        "--max-retries",
        "2",

        "--host-timeout",
        "10m",

        "--stats-every",
        "2s",

        target
    ]

    send_progress(
        progress_callback,
        start_time,
        0,
        discovered_ports,
        "Starting full TCP port discovery (1-65535)...",
        event="starting",
        ports_scanned=0,
        total_ports=65535
    )

    try:

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1
        )

    except FileNotFoundError:

        send_progress(
            progress_callback,
            start_time,
            100,
            discovered_ports,
            "Nmap was not found in PATH.",
            event="error",
            ports_scanned=0,
            total_ports=65535
        )

        return None, "Nmap was not found in PATH."

    except Exception as error:

        return None, str(error)

    last_percent = 0

    for raw_line in process.stdout:

        line = raw_line.rstrip()

        if line:
            output_lines.append(line)

        # ----------------------------------------------------
        # Open port
        # ----------------------------------------------------

        parsed = parse_port_line(line)

        if parsed:

            add_or_update_port(
                discovered_ports,
                parsed
            )

        # ----------------------------------------------------
        # Nmap progress
        # ----------------------------------------------------

        nmap_percent = parse_nmap_percent(line)

        if nmap_percent is not None:

            last_percent = max(
                0,
                min(
                    100,
                    nmap_percent
                )
            )

        # Discovery occupies 0-75%.
        global_percent = (
            last_percent * 0.75
        )

        ports_scanned = int(
            65535 * last_percent / 100
        )

        send_progress(
            progress_callback,
            start_time,
            global_percent,
            discovered_ports,
            line or "Scanning TCP ports...",
            event="discovery",
            ports_scanned=ports_scanned,
            total_ports=65535
        )

    process.wait()

    return process, None


# ============================================================
# SERVICE / VERSION DETECTION
# ============================================================

def service_detection(
    target,
    discovered_ports,
    progress_callback,
    start_time,
    output_lines
):
    """
    Stage 2:
    Service/version detection against only
    discovered open TCP ports.
    """

    open_ports = sorted({
        p["port"]
        for p in discovered_ports
        if p.get("protocol") == "tcp"
    })

    if not open_ports:

        return None

    port_string = ",".join(
        str(port)
        for port in open_ports
    )

    send_progress(
        progress_callback,
        start_time,
        75,
        discovered_ports,
        (
            f"Found {len(open_ports)} open TCP port(s). "
            "Starting service detection..."
        ),
        event="service_detection",
        ports_scanned=65535,
        total_ports=65535
    )

    command = [
        "nmap",

        "-Pn",

        "-sV",

        "--version-light",

        "--open",

        "-T4",

        "--max-retries",
        "2",

        "-p",
        port_string,

        target
    ]

    service_output = []

    try:

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1
        )

    except Exception as error:

        service_output.append(
            f"Service detection error: {error}"
        )

        return None

    last_percent = 0

    for raw_line in process.stdout:

        line = raw_line.rstrip()

        if line:
            service_output.append(line)

        parsed = parse_port_line(line)

        if parsed:

            add_or_update_port(
                discovered_ports,
                parsed
            )

        nmap_percent = parse_nmap_percent(line)

        if nmap_percent is not None:

            last_percent = max(
                0,
                min(
                    100,
                    nmap_percent
                )
            )

        # Service detection = 75-100%.
        global_percent = (
            75
            +
            (
                last_percent
                * 0.25
            )
        )

        send_progress(
            progress_callback,
            start_time,
            global_percent,
            discovered_ports,
            line or "Detecting services and versions...",
            event="service_detection",
            ports_scanned=65535,
            total_ports=65535
        )

    process.wait()

    return process


# ============================================================
# MAIN PORT SCANNER
# ============================================================

def scan_ports(
    target,
    progress_callback=None
):
    """
    FULL TCP PORT SCAN

    Stage 1:
        Full TCP 1-65535 discovery.

    Stage 2:
        Service/version detection on discovered
        open TCP ports only.

    Live progress is sent through progress_callback.
    """

    target = clean_target(target)

    start_time = time.time()

    discovered_ports = []

    output_lines = []

    # ========================================================
    # STAGE 1
    # ========================================================

    discovery_process, discovery_error = discovery_scan(
        target,
        progress_callback,
        start_time,
        discovered_ports,
        output_lines
    )

    if discovery_error:

        return {
            "target": target,

            "scan_type":
                "Full TCP 1-65535",

            "ports":
                discovered_ports,

            "open_ports":
                discovered_ports,

            "open_port_count":
                len(discovered_ports),

            "raw_output":
                "\n".join(output_lines),

            "error":
                discovery_error,

            "return_code":
                None
        }

    # ========================================================
    # NO OPEN PORTS
    # ========================================================

    if not discovered_ports:

        send_progress(
            progress_callback,
            start_time,
            100,
            discovered_ports,
            (
                "Full TCP port scan completed. "
                "No open TCP ports found."
            ),
            event="completed",
            ports_scanned=65535,
            total_ports=65535
        )

        return {
            "target": target,

            "scan_type":
                "Full TCP 1-65535",

            "ports": [],

            "open_ports": [],

            "open_port_count":
                0,

            "raw_output":
                "\n".join(output_lines),

            "error":
                None,

            "return_code":
                discovery_process.returncode
        }

    # ========================================================
    # STAGE 2
    # ========================================================

    service_process = service_detection(
        target,
        discovered_ports,
        progress_callback,
        start_time,
        output_lines
    )

    # ========================================================
    # FINAL OUTPUT
    # ========================================================

    discovered_ports = sorted(
        discovered_ports,
        key=lambda item: (
            item.get("port", 0),
            item.get("protocol", "")
        )
    )

    send_progress(
        progress_callback,
        start_time,
        100,
        discovered_ports,
        (
            "Full TCP port scan and "
            "service detection completed."
        ),
        event="completed",
        ports_scanned=65535,
        total_ports=65535
    )

    return {
        "target":
            target,

        "scan_type":
            "Full TCP 1-65535 + Service Detection",

        "ports":
            discovered_ports,

        "open_ports":
            discovered_ports,

        "open_port_count":
            len(discovered_ports),

        "raw_output":
            "\n".join(output_lines),

        "error":
            None,

        "return_code":
            (
                service_process.returncode
                if service_process is not None
                else discovery_process.returncode
            )
    }