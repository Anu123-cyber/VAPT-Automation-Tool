import re
import sys
import json
from collections import deque
from urllib.parse import urljoin, urlparse, urldefrag

import requests


# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_TIMEOUT = 12
DEFAULT_MAX_PAGES = 30

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/140.0 Safari/537.36"
)


# ============================================================
# LIVE PROGRESS HELPER
# ============================================================

def report_progress(callback, **data):
    """
    Safely send live crawler progress information.
    """

    if not callback:
        return

    try:
        callback(data)
    except Exception:
        pass


# ============================================================
# URL HELPERS
# ============================================================

def normalize_url(url):
    """
    Normalize a URL while preserving its host and path.
    """

    if not url:
        return ""

    url = str(url).strip()

    if not url:
        return ""

    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url

    url, _ = urldefrag(url)

    parsed = urlparse(url)

    scheme = parsed.scheme.lower()

    hostname = parsed.hostname

    if not hostname:
        return ""

    hostname = hostname.lower()

    # Keep non-standard port if present
    port = parsed.port

    if port:
        host = f"{hostname}:{port}"
    else:
        host = hostname

    path = parsed.path or "/"

    # Preserve query parameters
    query = parsed.query

    normalized = f"{scheme}://{host}{path}"

    if query:
        normalized += f"?{query}"

    # Remove trailing slash only for root
    if path == "/" and not query:
        normalized = normalized.rstrip("/")

    return normalized


def get_hostname(url):
    """
    Return hostname without port.
    """

    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def get_registered_domain(hostname):
    """
    Basic registered-domain extraction.

    This intentionally avoids third-party dependencies.

    Example:
        www.example.com -> example.com
        api.example.com -> example.com
        example.com -> example.com
    """

    if not hostname:
        return ""

    hostname = hostname.lower().strip(".")

    # IPv4 / IPv6
    if re.match(
        r"^\d{1,3}(?:\.\d{1,3}){3}$",
        hostname
    ):
        return hostname

    if ":" in hostname:
        return hostname

    parts = hostname.split(".")

    if len(parts) <= 2:
        return hostname

    # Common multi-part public suffixes
    common_two_part_suffixes = {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.in",
        "firm.in",
        "net.in",
        "org.in",
        "gen.in",
        "ind.in",
        "co.nz",
        "com.sg",
        "com.my",
        "co.za",
        "com.br",
    }

    suffix = ".".join(parts[-2:])

    if suffix in common_two_part_suffixes and len(parts) >= 3:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


def same_host(url, base_host):
    """
    Determine whether a URL belongs to the target website.

    Improvements:
    - ignores www difference
    - ignores hostname case
    - handles ports
    - prevents unrelated domains from being classified internal
    """

    try:

        url_hostname = get_hostname(url)

        if not url_hostname:
            return False

        if not base_host:
            return False

        # base_host may be:
        # example.com
        # www.example.com
        # example.com:443
        base_hostname = get_hostname(
            "https://" + base_host
        )

        if not base_hostname:
            base_hostname = (
                str(base_host)
                .split(":")[0]
                .lower()
            )

        # Exact hostname match
        if url_hostname == base_hostname:
            return True

        # Treat www and non-www as the same target
        url_registered = get_registered_domain(
            url_hostname
        )

        base_registered = get_registered_domain(
            base_hostname
        )

        if (
            url_registered
            and base_registered
            and url_registered == base_registered
        ):
            return True

        return False

    except Exception:
        return False


def is_http_url(url):
    if not url:
        return False

    return url.lower().startswith(
        ("http://", "https://")
    )


def canonicalize_url(url):
    """
    Produce a consistent URL representation for
    deduplication.
    """

    if not url:
        return ""

    url = normalize_url(url)

    if not url:
        return ""

    parsed = urlparse(url)

    hostname = (
        parsed.hostname or ""
    ).lower()

    scheme = (
        parsed.scheme or "https"
    ).lower()

    port = parsed.port

    # Remove default ports
    if (
        (scheme == "https" and port == 443)
        or
        (scheme == "http" and port == 80)
    ):
        port = None

    host = hostname

    if port:
        host = f"{hostname}:{port}"

    path = parsed.path or "/"

    # Normalize duplicate slashes
    path = re.sub(
        r"/{2,}",
        "/",
        path
    )

    # Root normalization
    if path != "/":
        path = path.rstrip("/")

    result = f"{scheme}://{host}{path}"

    if parsed.query:
        result += "?" + parsed.query

    return result


# ============================================================
# REQUEST HELPERS
# ============================================================

def create_session():
    """
    Create requests session.
    """

    session = requests.Session()

    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": (
            "text/html,application/xhtml+xml,"
            "application/xml;q=0.9,*/*;q=0.8"
        ),
        "Accept-Language": "en-US,en;q=0.9",
    })

    return session


def request_url(
    session,
    url,
    timeout=DEFAULT_TIMEOUT
):
    """
    Safely request a URL.
    """

    try:

        return session.get(
            url,
            timeout=timeout,
            allow_redirects=True
        )

    except requests.RequestException:

        return None


# ============================================================
# RESPONSE HELPERS
# ============================================================

def get_content_type(response):

    if not response:
        return ""

    return response.headers.get(
        "Content-Type",
        ""
    ).lower()


def is_html_response(response):
    """
    Determine whether response should be parsed as HTML.
    """

    if not response:
        return False

    content_type = get_content_type(
        response
    )

    if (
        "text/html" in content_type
        or
        "application/xhtml" in content_type
    ):
        return True

    return not content_type


# ============================================================
# LINK EXTRACTION
# ============================================================

def extract_links(html, base_url):
    """
    Extract HTTP/HTTPS links from href attributes.
    """

    links = set()

    if not html:
        return []

    pattern = re.compile(
        r"<a\b[^>]*?\bhref\s*=\s*"
        r"[\"']([^\"']+)[\"']",
        re.I
    )

    for value in pattern.findall(html):

        if not value:
            continue

        value = value.strip()

        if value.lower().startswith(
            (
                "javascript:",
                "mailto:",
                "tel:",
                "data:",
                "#",
            )
        ):
            continue

        full_url = urljoin(
            base_url,
            value
        )

        full_url, _ = urldefrag(
            full_url
        )

        if not is_http_url(full_url):
            continue

        full_url = canonicalize_url(
            full_url
        )

        if full_url:
            links.add(full_url)

    return sorted(links)


# ============================================================
# JAVASCRIPT EXTRACTION
# ============================================================

def extract_script_urls(html, base_url):
    """
    Extract JavaScript source URLs.
    """

    scripts = set()

    if not html:
        return []

    pattern = re.compile(
        r"<script\b[^>]*?\bsrc\s*=\s*"
        r"[\"']([^\"']+)[\"']",
        re.I
    )

    for src in pattern.findall(html):

        if not src:
            continue

        src = src.strip()

        full_url = urljoin(
            base_url,
            src
        )

        full_url, _ = urldefrag(
            full_url
        )

        if is_http_url(full_url):

            full_url = canonicalize_url(
                full_url
            )

            if full_url:
                scripts.add(full_url)

    return sorted(scripts)


# ============================================================
# CSS EXTRACTION
# ============================================================

def extract_css_urls(html, base_url):
    """
    Extract CSS stylesheet URLs.
    """

    stylesheets = set()

    if not html:
        return []

    # Standard <link href="...">
    pattern = re.compile(
        r"<link\b[^>]*?\bhref\s*=\s*"
        r"[\"']([^\"']+)[\"']",
        re.I
    )

    for href in pattern.findall(html):

        if not href:
            continue

        href = href.strip()

        full_url = urljoin(
            base_url,
            href
        )

        full_url, _ = urldefrag(
            full_url
        )

        if not is_http_url(full_url):
            continue

        lower = full_url.lower()

        if (
            ".css" in lower
            or "stylesheet" in lower
        ):

            full_url = canonicalize_url(
                full_url
            )

            if full_url:
                stylesheets.add(
                    full_url
                )

    return sorted(stylesheets)


# ============================================================
# FORM EXTRACTION
# ============================================================

def extract_forms(html, base_url):
    """
    Extract HTML forms and input names/types.
    """

    forms = []

    if not html:
        return forms

    form_pattern = re.compile(
        r"<form\b([^>]*)>(.*?)</form>",
        re.I | re.S
    )

    for attributes, body in form_pattern.findall(
        html
    ):

        action_match = re.search(
            r'\baction\s*=\s*["\']([^"\']*)["\']',
            attributes,
            re.I
        )

        method_match = re.search(
            r'\bmethod\s*=\s*["\']([^"\']*)["\']',
            attributes,
            re.I
        )

        action = (
            action_match.group(1)
            if action_match
            else ""
        )

        method = (
            method_match.group(1).upper()
            if method_match
            else "GET"
        )

        action_url = urljoin(
            base_url,
            action
        )

        action_url = canonicalize_url(
            action_url
        )

        inputs = []

        # INPUT
        for input_match in re.finditer(
            r"<input\b([^>]*)>",
            body,
            re.I
        ):

            input_attrs = (
                input_match.group(1)
            )

            name_match = re.search(
                r'\bname\s*=\s*["\']([^"\']+)["\']',
                input_attrs,
                re.I
            )

            type_match = re.search(
                r'\btype\s*=\s*["\']([^"\']+)["\']',
                input_attrs,
                re.I
            )

            value_match = re.search(
                r'\bvalue\s*=\s*["\']([^"\']*)["\']',
                input_attrs,
                re.I
            )

            inputs.append({
                "name": (
                    name_match.group(1)
                    if name_match
                    else ""
                ),
                "type": (
                    type_match.group(1)
                    if type_match
                    else "text"
                ),
                "value": (
                    value_match.group(1)
                    if value_match
                    else ""
                )
            })

        # SELECT
        for select_match in re.finditer(
            r"<select\b([^>]*)>",
            body,
            re.I
        ):

            select_attrs = (
                select_match.group(1)
            )

            name_match = re.search(
                r'\bname\s*=\s*["\']([^"\']+)["\']',
                select_attrs,
                re.I
            )

            inputs.append({
                "name": (
                    name_match.group(1)
                    if name_match
                    else ""
                ),
                "type": "select",
                "value": ""
            })

        # TEXTAREA
        for textarea_match in re.finditer(
            r"<textarea\b([^>]*)>",
            body,
            re.I
        ):

            textarea_attrs = (
                textarea_match.group(1)
            )

            name_match = re.search(
                r'\bname\s*=\s*["\']([^"\']+)["\']',
                textarea_attrs,
                re.I
            )

            inputs.append({
                "name": (
                    name_match.group(1)
                    if name_match
                    else ""
                ),
                "type": "textarea",
                "value": ""
            })

        forms.append({
            "action": action_url,
            "method": method,
            "inputs": inputs
        })

    return forms


# ============================================================
# URL PARAMETERS
# ============================================================

def extract_parameters(url):
    """
    Extract query parameter names.
    """

    parameters = []

    try:

        parsed = urlparse(url)

        if not parsed.query:
            return parameters

        for item in parsed.query.split("&"):

            if "=" in item:
                name = item.split(
                    "=",
                    1
                )[0]
            else:
                name = item

            name = name.strip()

            if name:
                parameters.append(name)

    except Exception:
        pass

    return sorted(
        set(parameters)
    )


# ============================================================
# API DETECTION
# ============================================================

def looks_like_api(url):
    """
    Identify API/auth/documentation-looking URLs.
    """

    if not url:
        return False

    lower = url.lower()

    patterns = [
        "/api/",
        "/api?",
        "/graphql",
        "/rest/",
        "/rest?",
        "/v1/",
        "/v2/",
        "/v3/",
        "/v4/",
        "/swagger",
        "/openapi",
        "/wp-json/",
        "/wp-json?",
        "/ajax/",
        "/ajax?",
        "/json/",
        "/oauth/",
        "/oauth?",
        "/auth/",
        "/auth?",
        "/token",
        "/login",
        "/logout",
    ]

    return any(
        pattern in lower
        for pattern in patterns
    )


def extract_api_candidates(
    html,
    base_url
):
    """
    Discover API-looking URLs from HTML.
    """

    endpoints = set()

    if not html:
        return []

    base_host = get_hostname(
        base_url
    )

    # Absolute URLs
    absolute_urls = re.findall(
        r'https?://[^\s"\'<>]+',
        html,
        re.I
    )

    for value in absolute_urls:

        value = value.rstrip(
            ".,);]}>"
        )

        value = canonicalize_url(
            value
        )

        if not value:
            continue

        if same_host(
            value,
            base_host
        ):
            if looks_like_api(value):
                endpoints.add(value)

    # Relative URLs
    relative_paths = re.findall(
        r'["\'](\/[^"\']{1,500})["\']',
        html,
        re.I
    )

    for path in relative_paths:

        if looks_like_api(path):

            endpoint = canonicalize_url(
                urljoin(
                    base_url,
                    path
                )
            )

            if endpoint:
                endpoints.add(
                    endpoint
                )

    return sorted(endpoints)


# ============================================================
# JAVASCRIPT ENDPOINT EXTRACTION
# ============================================================

def extract_js_endpoints(
    javascript,
    base_url
):
    """
    Extract endpoint-looking paths from JavaScript.
    """

    endpoints = set()

    if not javascript:
        return []

    patterns = [
        r'["\'](\/api\/[^"\']+)["\']',
        r'["\'](\/v[0-9]+\/[^"\']+)["\']',
        r'["\'](\/graphql[^"\']*)["\']',
        r'["\'](\/rest\/[^"\']+)["\']',
        r'["\'](\/auth\/[^"\']+)["\']',
        r'["\'](\/oauth\/[^"\']+)["\']',
        r'["\'](\/ajax\/[^"\']+)["\']',
        r'["\'](\/wp-json\/[^"\']*)["\']',
        r'["\'](\/login[^"\']*)["\']',
        r'["\'](\/logout[^"\']*)["\']',
        r'["\'](\/token[^"\']*)["\']',
    ]

    for pattern in patterns:

        for path in re.findall(
            pattern,
            javascript,
            re.I
        ):

            if not path:
                continue

            endpoint = urljoin(
                base_url,
                path
            )

            endpoint = canonicalize_url(
                endpoint
            )

            if is_http_url(endpoint):
                endpoints.add(
                    endpoint
                )

    return sorted(endpoints)


# ============================================================
# ROBOTS.TXT
# ============================================================

def parse_robots(
    base_url,
    session
):

    url = urljoin(
        base_url + "/",
        "robots.txt"
    )

    result = {
        "url": url,
        "status_code": None,
        "available": False,
        "paths": [],
        "sitemaps": [],
        "error": None
    }

    try:

        response = session.get(
            url,
            timeout=DEFAULT_TIMEOUT,
            allow_redirects=True
        )

        result["status_code"] = (
            response.status_code
        )

        if response.status_code != 200:
            return result

        result["available"] = True

        for line in response.text.splitlines():

            line = line.strip()

            if not line:
                continue

            line = line.split(
                "#",
                1
            )[0].strip()

            lower = line.lower()

            if lower.startswith(
                "disallow:"
            ):

                value = line.split(
                    ":",
                    1
                )[1].strip()

                if value:
                    result["paths"].append(
                        value
                    )

            elif lower.startswith(
                "sitemap:"
            ):

                value = line.split(
                    ":",
                    1
                )[1].strip()

                if value:
                    result["sitemaps"].append(
                        value
                    )

    except requests.RequestException as exc:

        result["error"] = str(exc)

    result["paths"] = sorted(
        set(result["paths"])
    )

    result["sitemaps"] = sorted(
        set(result["sitemaps"])
    )

    return result


# ============================================================
# SITEMAP.XML
# ============================================================

def parse_sitemap(
    base_url,
    session
):

    url = urljoin(
        base_url + "/",
        "sitemap.xml"
    )

    result = {
        "url": url,
        "status_code": None,
        "available": False,
        "urls": [],
        "sitemaps": [],
        "error": None
    }

    try:

        response = session.get(
            url,
            timeout=DEFAULT_TIMEOUT,
            allow_redirects=True
        )

        result["status_code"] = (
            response.status_code
        )

        if response.status_code != 200:
            return result

        result["available"] = True

        values = re.findall(
            r"<loc>\s*(.*?)\s*</loc>",
            response.text,
            re.I
        )

        for value in values:

            value = value.strip()

            if not value:
                continue

            value = canonicalize_url(
                value
            )

            if not value:
                continue

            if same_host(
                value,
                get_hostname(base_url)
            ):

                if (
                    value.lower().endswith(
                        ".xml"
                    )
                    and (
                        "sitemap"
                        in value.lower()
                        or
                        "index"
                        in value.lower()
                    )
                ):

                    result["sitemaps"].append(
                        value
                    )

                else:

                    result["urls"].append(
                        value
                    )

    except requests.RequestException as exc:

        result["error"] = str(exc)

    result["urls"] = sorted(
        set(result["urls"])
    )

    result["sitemaps"] = sorted(
        set(result["sitemaps"])
    )

    return result


# ============================================================
# PAGE RECORD
# ============================================================

def build_page_record(
    requested_url,
    response
):

    final_url = (
        response.url
        if response
        else requested_url
    )

    final_url = canonicalize_url(
        final_url
    )

    return {
        "url": final_url,
        "requested_url": requested_url,
        "status_code": (
            response.status_code
            if response
            else None
        ),
        "content_type": (
            get_content_type(response)
            if response
            else ""
        ),
        "size": (
            len(response.content)
            if response
            else 0
        ),
        "title": "",
    }


def extract_page_title(html):

    if not html:
        return ""

    match = re.search(
        r"<title\b[^>]*>(.*?)</title>",
        html,
        re.I | re.S
    )

    if not match:
        return ""

    title = re.sub(
        r"\s+",
        " ",
        match.group(1)
    ).strip()

    return title


# ============================================================
# MAIN CRAWLER
# ============================================================

def crawl_site(
    target,
    max_pages=DEFAULT_MAX_PAGES,
    progress_callback=None
):
    """
    Crawl an authorized target and build an
    application attack-surface inventory.

    Uses GET requests only.
    Does not submit forms.
    Does not modify application state.
    """

    target = canonicalize_url(
        target
    )

    result = {
        "target": target,
        "pages_crawled": 0,
        "pages": [],
        "urls": [],
        "internal_urls": [],
        "external_urls": [],
        "forms": [],
        "parameters": [],
        "api_endpoints": [],
        "javascript_files": [],
        "css_files": [],
        "js_endpoints": [],
        "robots": {},
        "sitemap": {},
        "errors": [],
        "statistics": {
            "pages": 0,
            "internal_urls": 0,
            "external_urls": 0,
            "forms": 0,
            "parameters": 0,
            "api_endpoints": 0,
            "javascript_files": 0,
            "css_files": 0,
            "js_endpoints": 0
        }
    }

    # ========================================================
    # VALIDATE TARGET
    # ========================================================

    if not target:

        result["errors"].append(
            "Invalid target URL."
        )

        report_progress(
            progress_callback,
            event="error",
            message="Invalid target URL.",
            pages=0,
            max_pages=max_pages
        )

        return result

    try:

        parsed_target = urlparse(
            target
        )

        base_host = (
            parsed_target.hostname
            or ""
        ).lower()

        if not base_host:

            result["errors"].append(
                "Unable to determine target host."
            )

            return result

    except Exception as exc:

        result["errors"].append(
            str(exc)
        )

        return result

    # ========================================================
    # MAX PAGES
    # ========================================================

    try:

        max_pages = int(
            max_pages
        )

    except (
        TypeError,
        ValueError
    ):

        max_pages = DEFAULT_MAX_PAGES

    max_pages = max(
        1,
        min(
            max_pages,
            500
        )
    )

    # ========================================================
    # START
    # ========================================================

    report_progress(
        progress_callback,
        event="start",
        message=(
            "Starting attack surface discovery..."
        ),
        pages=0,
        max_pages=max_pages,
        internal_urls=0,
        external_urls=0,
        forms=0,
        parameters=0,
        api_endpoints=0,
        javascript_files=0,
        css_files=0,
        js_endpoints=0
    )

    # ========================================================
    # SESSION
    # ========================================================

    session = create_session()

    # ========================================================
    # QUEUES / SETS
    # ========================================================

    queue = deque([
        target
    ])

    queued = {
        target
    }

    visited = set()

    internal_urls = set()
    external_urls = set()

    javascript_files = set()
    css_files = set()

    api_endpoints = set()
    js_endpoints = set()

    parameters = set()

    all_forms = []

    pages = []

    # ========================================================
    # IMPORTANT:
    # The initial target is itself an internal URL.
    # ========================================================

    internal_urls.add(
        target
    )

    # ========================================================
    # CRAWL
    # ========================================================

    while queue:

        if len(visited) >= max_pages:
            break

        current = queue.popleft()

        current = canonicalize_url(
            current
        )

        if not current:
            continue

        if current in visited:
            continue

        # ----------------------------------------------------
        # CLASSIFY URL
        # ----------------------------------------------------

        if not same_host(
            current,
            base_host
        ):

            external_urls.add(
                current
            )

            continue

        # This is definitely internal
        internal_urls.add(
            current
        )

        visited.add(
            current
        )

        current_page_number = (
            len(visited)
        )

        # ----------------------------------------------------
        # LIVE: BEFORE REQUEST
        # ----------------------------------------------------

        report_progress(
            progress_callback,
            event="page_start",
            message=(
                f"Crawling page "
                f"{current_page_number}/{max_pages}: "
                f"{current}"
            ),
            url=current,
            page=current_page_number,
            pages=current_page_number,
            max_pages=max_pages,
            internal_urls=len(
                internal_urls
            ),
            external_urls=len(
                external_urls
            ),
            forms=len(all_forms),
            parameters=len(parameters),
            api_endpoints=len(api_endpoints),
            javascript_files=len(
                javascript_files
            ),
            css_files=len(
                css_files
            ),
            js_endpoints=len(
                js_endpoints
            )
        )

        # ----------------------------------------------------
        # REQUEST
        # ----------------------------------------------------

        response = request_url(
            session,
            current
        )

        if not response:

            error_message = (
                f"Unable to retrieve: {current}"
            )

            result["errors"].append(
                error_message
            )

            report_progress(
                progress_callback,
                event="error",
                message=error_message,
                url=current,
                page=current_page_number,
                pages=len(pages),
                max_pages=max_pages,
                internal_urls=len(
                    internal_urls
                ),
                external_urls=len(
                    external_urls
                )
            )

            continue

        # ----------------------------------------------------
        # HANDLE REDIRECTED FINAL URL
        # ----------------------------------------------------

        final_url = canonicalize_url(
            response.url
        )

        if final_url:

            if same_host(
                final_url,
                base_host
            ):
                internal_urls.add(
                    final_url
                )
            else:
                external_urls.add(
                    final_url
                )

        # ----------------------------------------------------
        # PAGE RECORD
        # ----------------------------------------------------

        page_record = build_page_record(
            current,
            response
        )

        # ----------------------------------------------------
        # HTML
        # ----------------------------------------------------

        if is_html_response(
            response
        ):

            html = response.text

            page_record["title"] = (
                extract_page_title(
                    html
                )
            )

            # ------------------------------------------------
            # LINKS
            # ------------------------------------------------

            links = extract_links(
                html,
                response.url
            )

            for link in links:

                if same_host(
                    link,
                    base_host
                ):

                    # Correctly classify as INTERNAL
                    internal_urls.add(
                        link
                    )

                    # API detection
                    if looks_like_api(
                        link
                    ):
                        api_endpoints.add(
                            link
                        )

                    # Queue only new internal URLs
                    if (
                        link not in visited
                        and link not in queued
                    ):

                        queue.append(
                            link
                        )

                        queued.add(
                            link
                        )

                else:

                    # Correctly classify as EXTERNAL
                    external_urls.add(
                        link
                    )

            # ------------------------------------------------
            # PARAMETERS
            # ------------------------------------------------

            for link in links:

                for parameter in (
                    extract_parameters(
                        link
                    )
                ):

                    parameters.add(
                        parameter
                    )

            for parameter in (
                extract_parameters(
                    response.url
                )
            ):

                parameters.add(
                    parameter
                )

            # ------------------------------------------------
            # FORMS
            # ------------------------------------------------

            forms = extract_forms(
                html,
                response.url
            )

            all_forms.extend(
                forms
            )

            # ------------------------------------------------
            # JAVASCRIPT
            # ------------------------------------------------

            scripts = extract_script_urls(
                html,
                response.url
            )

            for script in scripts:

                if same_host(
                    script,
                    base_host
                ):

                    javascript_files.add(
                        script
                    )

                else:

                    # External JS is not counted
                    # as an external URL page.
                    pass

            # ------------------------------------------------
            # CSS
            # ------------------------------------------------

            stylesheets = (
                extract_css_urls(
                    html,
                    response.url
                )
            )

            for stylesheet in stylesheets:

                if same_host(
                    stylesheet,
                    base_host
                ):

                    css_files.add(
                        stylesheet
                    )

            # ------------------------------------------------
            # API CANDIDATES
            # ------------------------------------------------

            for endpoint in (
                extract_api_candidates(
                    html,
                    response.url
                )
            ):

                api_endpoints.add(
                    endpoint
                )

            # ------------------------------------------------
            # JAVASCRIPT ANALYSIS
            # ------------------------------------------------

            report_progress(
                progress_callback,
                event="javascript_analysis",
                message=(
                    f"Analyzing JavaScript "
                    f"from page "
                    f"{current_page_number}/"
                    f"{max_pages}"
                ),
                url=current,
                page=current_page_number,
                pages=len(pages),
                max_pages=max_pages,
                internal_urls=len(
                    internal_urls
                ),
                external_urls=len(
                    external_urls
                ),
                javascript_files=len(
                    javascript_files
                ),
                css_files=len(
                    css_files
                )
            )

            # ------------------------------------------------
            # FETCH SAME-HOST JS
            # ------------------------------------------------

            for script_url in scripts:

                if not same_host(
                    script_url,
                    base_host
                ):
                    continue

                try:

                    js_response = (
                        session.get(
                            script_url,
                            timeout=DEFAULT_TIMEOUT,
                            allow_redirects=True
                        )
                    )

                    if (
                        js_response.status_code
                        != 200
                    ):
                        continue

                    js_text = (
                        js_response.text
                    )

                    discovered_js = (
                        extract_js_endpoints(
                            js_text,
                            response.url
                        )
                    )

                    for endpoint in (
                        discovered_js
                    ):

                        js_endpoints.add(
                            endpoint
                        )

                        api_endpoints.add(
                            endpoint
                        )

                        for parameter in (
                            extract_parameters(
                                endpoint
                            )
                        ):

                            parameters.add(
                                parameter
                            )

                except requests.RequestException:

                    continue

        # ----------------------------------------------------
        # ADD PAGE
        # ----------------------------------------------------

        pages.append(
            page_record
        )

        # ----------------------------------------------------
        # LIVE: PAGE COMPLETE
        # ----------------------------------------------------

        report_progress(
            progress_callback,
            event="page_complete",
            message=(
                f"Discovered page "
                f"{len(pages)}/{max_pages}: "
                f"{page_record['url']}"
            ),
            url=page_record["url"],
            page=len(pages),
            pages=len(pages),
            max_pages=max_pages,
            status_code=(
                page_record["status_code"]
            ),
            title=(
                page_record["title"]
            ),
            internal_urls=len(
                internal_urls
            ),
            external_urls=len(
                external_urls
            ),
            forms=len(all_forms),
            parameters=len(parameters),
            api_endpoints=len(
                api_endpoints
            ),
            javascript_files=len(
                javascript_files
            ),
            css_files=len(
                css_files
            ),
            js_endpoints=len(
                js_endpoints
            )
        )

    # ========================================================
    # ROBOTS.TXT
    # ========================================================

    report_progress(
        progress_callback,
        event="robots",
        message="Checking robots.txt...",
        pages=len(pages),
        max_pages=max_pages,
        internal_urls=len(
            internal_urls
        ),
        external_urls=len(
            external_urls
        ),
        forms=len(all_forms),
        parameters=len(parameters),
        api_endpoints=len(
            api_endpoints
        )
    )

    result["robots"] = parse_robots(
        target,
        session
    )

    # ========================================================
    # SITEMAP.XML
    # ========================================================

    report_progress(
        progress_callback,
        event="sitemap",
        message="Checking sitemap.xml...",
        pages=len(pages),
        max_pages=max_pages,
        internal_urls=len(
            internal_urls
        ),
        external_urls=len(
            external_urls
        ),
        forms=len(all_forms),
        parameters=len(parameters),
        api_endpoints=len(
            api_endpoints
        )
    )

    result["sitemap"] = parse_sitemap(
        target,
        session
    )

    # --------------------------------------------------------
    # SITEMAP URLS
    # --------------------------------------------------------

    sitemap_urls = (
        result["sitemap"].get(
            "urls",
            []
        )
    )

    for sitemap_url in sitemap_urls:

        sitemap_url = canonicalize_url(
            sitemap_url
        )

        if not sitemap_url:
            continue

        if same_host(
            sitemap_url,
            base_host
        ):

            internal_urls.add(
                sitemap_url
            )

    # ========================================================
    # DEDUPLICATE FORMS
    # ========================================================

    unique_forms = []

    seen_forms = set()

    for form in all_forms:

        input_key = tuple(
            (
                item.get(
                    "name",
                    ""
                ),
                item.get(
                    "type",
                    ""
                )
            )
            for item in form.get(
                "inputs",
                []
            )
        )

        key = (
            form.get(
                "action",
                ""
            ),
            form.get(
                "method",
                "GET"
            ),
            input_key
        )

        if key in seen_forms:
            continue

        seen_forms.add(
            key
        )

        unique_forms.append(
            form
        )

    # ========================================================
    # IMPORTANT FINAL INTERNAL URL FIX
    # ========================================================

    # Every successfully crawled page is an internal URL.
    for page in pages:

        page_url = canonicalize_url(
            page.get(
                "url",
                ""
            )
        )

        if (
            page_url
            and same_host(
                page_url,
                base_host
            )
        ):

            internal_urls.add(
                page_url
            )

    # ========================================================
    # REMOVE INTERNAL URLS FROM EXTERNAL SET
    # ========================================================

    external_urls = {
        url
        for url in external_urls
        if not same_host(
            url,
            base_host
        )
    }

    # ========================================================
    # FINAL RESULT
    # ========================================================

    result["pages"] = pages

    result["pages_crawled"] = len(
        pages
    )

    result["urls"] = [
        page.get("url")
        for page in pages
        if page.get("url")
    ]

    result["internal_urls"] = sorted(
        internal_urls
    )

    result["external_urls"] = sorted(
        external_urls
    )

    result["forms"] = unique_forms

    result["parameters"] = sorted(
        parameters
    )

    result["api_endpoints"] = sorted(
        api_endpoints
    )

    result["javascript_files"] = sorted(
        javascript_files
    )

    result["css_files"] = sorted(
        css_files
    )

    result["js_endpoints"] = sorted(
        js_endpoints
    )

    # ========================================================
    # STATISTICS
    # ========================================================

    result["statistics"] = {
        "pages": len(
            result["pages"]
        ),
        "internal_urls": len(
            result["internal_urls"]
        ),
        "external_urls": len(
            result["external_urls"]
        ),
        "forms": len(
            result["forms"]
        ),
        "parameters": len(
            result["parameters"]
        ),
        "api_endpoints": len(
            result["api_endpoints"]
        ),
        "javascript_files": len(
            result["javascript_files"]
        ),
        "css_files": len(
            result["css_files"]
        ),
        "js_endpoints": len(
            result["js_endpoints"]
        )
    }

    # ========================================================
    # COMPLETE
    # ========================================================

    report_progress(
        progress_callback,
        event="complete",
        message=(
            "Attack surface discovery completed."
        ),
        pages=len(
            result["pages"]
        ),
        max_pages=max_pages,
        internal_urls=len(
            result["internal_urls"]
        ),
        external_urls=len(
            result["external_urls"]
        ),
        forms=len(
            result["forms"]
        ),
        parameters=len(
            result["parameters"]
        ),
        api_endpoints=len(
            result["api_endpoints"]
        ),
        javascript_files=len(
            result["javascript_files"]
        ),
        css_files=len(
            result["css_files"]
        ),
        js_endpoints=len(
            result["js_endpoints"]
        )
    )

    return result


# ============================================================
# COMMAND-LINE TEST
# ============================================================

if __name__ == "__main__":

    target = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "https://example.com"
    )

    try:

        pages = (
            int(sys.argv[2])
            if len(sys.argv) > 2
            else 10
        )

    except ValueError:

        pages = 10

    print()
    print("=" * 60)
    print("VAPT ATTACK SURFACE DISCOVERY")
    print("=" * 60)
    print(f"[+] Target: {target}")
    print(f"[+] Max pages: {pages}")
    print("[+] Starting attack-surface discovery...")
    print()

    def cli_progress(info):

        message = info.get(
            "message",
            "Crawler running..."
        )

        print(
            f"[CRAWLER] {message}",
            flush=True
        )

    result = crawl_site(
        target,
        max_pages=pages,
        progress_callback=cli_progress
    )

    print()
    print("=" * 60)
    print("CRAWL COMPLETED")
    print("=" * 60)

    print(
        json.dumps(
            result,
            indent=2
        )
    )