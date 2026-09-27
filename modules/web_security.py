import re
import time
from urllib.parse import urljoin

import requests


DEFAULT_TIMEOUT = 15

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/140.0 Safari/537.36"
)


# ============================================================
# BASIC HELPERS
# ============================================================

def normalize_url(url):
    url = (url or "").strip()

    if not url:
        return ""

    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url

    return url.rstrip("/")


def safe_get(url, **kwargs):
    headers = kwargs.pop("headers", {})

    headers.setdefault("User-Agent", USER_AGENT)

    kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
    kwargs.setdefault("allow_redirects", True)

    kwargs["headers"] = headers

    try:
        return requests.get(url, **kwargs)
    except requests.RequestException:
        return None


def safe_options(url):
    try:
        return requests.options(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=DEFAULT_TIMEOUT,
            allow_redirects=True
        )
    except requests.RequestException:
        return None


def version_from_url(value):
    """
    Extract version from ?ver=VERSION or ?version=VERSION
    """

    if not value:
        return None

    match = re.search(
        r"(?:[?&](?:ver|version)=)"
        r"([0-9]+(?:\.[0-9]+){0,4})",
        value,
        re.I
    )

    if match:
        return match.group(1)

    return None


def extract_version(value):
    if not value:
        return None

    match = re.search(
        r"\b([0-9]+(?:\.[0-9]+){1,4})\b",
        value
    )

    if match:
        return match.group(1)

    return None


def add_technology(
    technologies,
    category,
    name,
    source,
    evidence,
    confidence="Medium"
):
    """
    Adds a technology and merges duplicate detections.

    Same category + same technology name = one entry.
    Evidence from multiple sources is combined.
    """

    if not name:
        return

    normalized_name = name.strip().lower()
    normalized_category = category.strip().lower()

    confidence_rank = {
        "Low": 1,
        "Medium": 2,
        "High": 3
    }

    for existing in technologies:

        existing_name = str(
            existing.get("name", "")
        ).strip().lower()

        existing_category = str(
            existing.get("technology", "")
        ).strip().lower()

        if (
            existing_name == normalized_name
            and existing_category == normalized_category
        ):

            old_confidence = existing.get(
                "confidence",
                "Medium"
            )

            old_rank = confidence_rank.get(
                old_confidence,
                2
            )

            new_rank = confidence_rank.get(
                confidence,
                2
            )

            if new_rank > old_rank:
                existing["confidence"] = confidence

            # ------------------------------------------------
            # Merge evidence
            # ------------------------------------------------

            old_evidence = str(
                existing.get("evidence", "")
            )

            if evidence:

                evidence = str(evidence)

                if evidence not in old_evidence:

                    if old_evidence:
                        existing["evidence"] = (
                            old_evidence +
                            " | " +
                            evidence
                        )
                    else:
                        existing["evidence"] = evidence

            return

    technologies.append({
        "technology": category,
        "name": name,
        "source": source,
        "evidence": evidence,
        "confidence": confidence
    })


def extract_script_urls(html, base_url):
    scripts = []

    if not html:
        return scripts

    matches = re.findall(
        r"<script[^>]+src=[\"']([^\"']+)[\"']",
        html,
        re.I
    )

    for src in matches:
        scripts.append(
            urljoin(base_url, src)
        )

    return scripts


def extract_css_urls(html, base_url):
    stylesheets = []

    if not html:
        return stylesheets

    matches = re.findall(
        r"<link[^>]+href=[\"']([^\"']+)[\"']",
        html,
        re.I
    )

    for href in matches:

        if ".css" in href.lower():

            stylesheets.append(
                urljoin(base_url, href)
            )

    return stylesheets


def get_cookie_attributes(response):
    cookies = []

    if not response:
        return cookies

    # requests-level cookie information
    for cookie in response.cookies:

        cookies.append({
            "name": cookie.name,
            "value": cookie.value,
            "secure": bool(cookie.secure),
            "httponly": False,
            "samesite": None,
            "path": cookie.path,
            "domain": cookie.domain
        })

    # Parse Set-Cookie manually for HttpOnly / SameSite
    raw_headers = response.headers.get(
        "Set-Cookie",
        ""
    )

    if raw_headers:

        for line in raw_headers.split("\n"):

            line = line.strip()

            if not line:
                continue

            parts = [
                x.strip()
                for x in line.split(";")
            ]

            if not parts:
                continue

            first = parts[0]

            if "=" not in first:
                continue

            name = first.split(
                "=",
                1
            )[0].strip()

            secure = any(
                p.lower() == "secure"
                for p in parts[1:]
            )

            httponly = any(
                p.lower() == "httponly"
                for p in parts[1:]
            )

            samesite = None

            for p in parts[1:]:

                if p.lower().startswith(
                    "samesite="
                ):

                    samesite = p.split(
                        "=",
                        1
                    )[1]

            found = False

            for cookie in cookies:

                if cookie["name"] == name:

                    cookie["secure"] = secure
                    cookie["httponly"] = httponly
                    cookie["samesite"] = samesite

                    found = True
                    break

            if not found:

                cookies.append({
                    "name": name,
                    "value": "",
                    "secure": secure,
                    "httponly": httponly,
                    "samesite": samesite,
                    "path": None,
                    "domain": None
                })

    return cookies


# ============================================================
# HEADER TECHNOLOGY DETECTION
# ============================================================

def detect_header_technologies(
    response,
    technologies
):
    if not response:
        return

    headers = response.headers

    # --------------------------------------------------------
    # Server
    # --------------------------------------------------------

    server = headers.get(
        "Server",
        ""
    )

    if server:

        server_lower = server.lower()

        if "litespeed" in server_lower:

            add_technology(
                technologies,
                "Web Server",
                "LiteSpeed",
                "Server header",
                server,
                "High"
            )

        elif "nginx" in server_lower:

            add_technology(
                technologies,
                "Web Server",
                "Nginx",
                "Server header",
                server,
                "High"
            )

        elif "apache" in server_lower:

            add_technology(
                technologies,
                "Web Server",
                "Apache",
                "Server header",
                server,
                "High"
            )

        elif "microsoft-iis" in server_lower:

            add_technology(
                technologies,
                "Web Server",
                "Microsoft IIS",
                "Server header",
                server,
                "High"
            )

        else:

            add_technology(
                technologies,
                "Web Server",
                server,
                "Server header",
                server,
                "Medium"
            )

    # --------------------------------------------------------
    # X-Powered-By / PHP
    # --------------------------------------------------------

    powered = headers.get(
        "X-Powered-By",
        ""
    )

    if powered:

        match = re.search(
            r"PHP[/\s-]*"
            r"([0-9]+(?:\.[0-9]+){1,3})",
            powered,
            re.I
        )

        if match:

            add_technology(
                technologies,
                "Backend",
                f"PHP {match.group(1)}",
                "X-Powered-By header",
                powered,
                "High"
            )

        elif "php" in powered.lower():

            add_technology(
                technologies,
                "Backend",
                "PHP",
                "X-Powered-By header",
                powered,
                "High"
            )

    # --------------------------------------------------------
    # Hostinger
    # --------------------------------------------------------

    header_text = " ".join(
        f"{k}: {v}"
        for k, v in headers.items()
    )

    if "hostinger" in header_text.lower():

        add_technology(
            technologies,
            "Hosting",
            "Hostinger",
            "HTTP headers",
            "hostinger",
            "High"
        )

    # --------------------------------------------------------
    # LiteSpeed Cache
    # --------------------------------------------------------

    cache_header = headers.get(
        "X-LiteSpeed-Cache",
        ""
    )

    if cache_header:

        add_technology(
            technologies,
            "Caching",
            "LiteSpeed Cache",
            "HTTP headers",
            cache_header,
            "High"
        )

    elif "litespeed-cache" in header_text.lower():

        add_technology(
            technologies,
            "Caching",
            "LiteSpeed Cache",
            "HTTP headers",
            "LiteSpeed cache indicators",
            "High"
        )


# ============================================================
# GENERATOR META TAGS
# ============================================================

def detect_generator_tags(
    html,
    technologies
):
    if not html:
        return

    generator_matches = re.findall(
        r'<meta[^>]+name=["\']generator["\']'
        r'[^>]+content=["\']([^"\']+)["\']',
        html,
        re.I
    )

    for generator in generator_matches:

        # WordPress
        wp_match = re.search(
            r"WordPress\s+"
            r"([0-9]+(?:\.[0-9]+){1,3})",
            generator,
            re.I
        )

        if wp_match:

            add_technology(
                technologies,
                "CMS",
                f"WordPress {wp_match.group(1)}",
                "Generator meta tag",
                generator,
                "Medium"
            )

        elif "wordpress" in generator.lower():

            add_technology(
                technologies,
                "CMS",
                "WordPress",
                "Generator meta tag",
                generator,
                "Medium"
            )

        # Elementor
        elementor_match = re.search(
            r"Elementor\s+"
            r"([0-9]+(?:\.[0-9]+){1,3})",
            generator,
            re.I
        )

        if elementor_match:

            add_technology(
                technologies,
                "WordPress Plugin / Page Builder",
                f"Elementor {elementor_match.group(1)}",
                "Generator meta tag",
                generator,
                "High"
            )

        elif "elementor" in generator.lower():

            add_technology(
                technologies,
                "WordPress Plugin / Page Builder",
                "Elementor",
                "Generator meta tag",
                generator,
                "High"
            )


# ============================================================
# HTML TECHNOLOGY DETECTION
# ============================================================

def detect_html_technologies(
    html,
    technologies
):
    if not html:
        return

    lower = html.lower()

    # --------------------------------------------------------
    # WordPress
    # --------------------------------------------------------

    if (
        "/wp-content/" in lower
        or "/wp-includes/" in lower
    ):

        add_technology(
            technologies,
            "CMS",
            "WordPress",
            "HTML signature",
            "/wp-content/",
            "High"
        )

    # --------------------------------------------------------
    # Elementor
    # --------------------------------------------------------

    if (
        "elementor" in lower
        or "e-con" in lower
        or "elementor-widget" in lower
    ):

        add_technology(
            technologies,
            "WordPress Plugin / Page Builder",
            "Elementor",
            "HTML signature",
            "Elementor HTML classes/assets",
            "High"
        )

    # --------------------------------------------------------
    # Google Fonts
    # --------------------------------------------------------

    if (
        "fonts.googleapis.com" in lower
        or "fonts.gstatic.com" in lower
    ):

        add_technology(
            technologies,
            "Font Service",
            "Google Fonts",
            "External resource",
            "fonts.googleapis.com",
            "High"
        )

    # --------------------------------------------------------
    # Google Analytics
    # --------------------------------------------------------

    if (
        "google-analytics.com" in lower
        or "googletagmanager.com" in lower
        or "gtag(" in lower
        or "google-analytics" in lower
    ):

        add_technology(
            technologies,
            "Analytics",
            "Google Analytics",
            "HTML / JavaScript signature",
            "Google Analytics / GTM indicators",
            "High"
        )

    # --------------------------------------------------------
    # Google Tag Manager
    # --------------------------------------------------------

    if "googletagmanager.com" in lower:

        add_technology(
            technologies,
            "Analytics / Tag Management",
            "Google Tag Manager",
            "HTML / JavaScript signature",
            "googletagmanager.com",
            "High"
        )

    # --------------------------------------------------------
    # Google reCAPTCHA
    # --------------------------------------------------------

    if "recaptcha" in lower:

        add_technology(
            technologies,
            "Security / CAPTCHA",
            "Google reCAPTCHA",
            "HTML signature",
            "reCAPTCHA indicators",
            "High"
        )

    # --------------------------------------------------------
    # Hotjar
    # --------------------------------------------------------

    if "hotjar" in lower:

        add_technology(
            technologies,
            "Analytics",
            "Hotjar",
            "HTML signature",
            "Hotjar indicators",
            "High"
        )

    # --------------------------------------------------------
    # Sentry
    # --------------------------------------------------------

    if "sentry" in lower:

        add_technology(
            technologies,
            "Monitoring",
            "Sentry",
            "HTML signature",
            "Sentry indicators",
            "High"
        )


# ============================================================
# WORDPRESS / ASSET VERSION DETECTION
# ============================================================

def detect_wordpress_asset_versions(
    html,
    technologies
):
    """
    Detect versions only where the asset path identifies the
    technology reliably.
    """

    if not html:
        return

    # --------------------------------------------------------
    # Elementor
    #
    # Exclude Elementor Pro.
    # Exclude Elementor's internal Swiper library.
    # --------------------------------------------------------

    elementor_pattern = re.compile(
        r"/wp-content/plugins/elementor/"
        r"(?!pro/)"
        r"[^\"']+",
        re.I
    )

    for asset in elementor_pattern.findall(html):

        lower = asset.lower()

        # Do not interpret bundled Swiper versions
        # as Elementor versions.
        if "/lib/swiper/" in lower:
            continue

        version = version_from_url(
            asset
        )

        if version:

            add_technology(
                technologies,
                "WordPress Plugin / Page Builder",
                f"Elementor {version}",
                "WordPress asset version",
                asset,
                "High"
            )

            break

    # --------------------------------------------------------
    # Elementor Pro
    # --------------------------------------------------------

    elementor_pro_pattern = re.compile(
        r"/wp-content/plugins/"
        r"elementor-pro/[^\"']+",
        re.I
    )

    for asset in elementor_pro_pattern.findall(html):

        version = version_from_url(
            asset
        )

        if version:

            add_technology(
                technologies,
                "WordPress Plugin",
                f"Elementor Pro {version}",
                "WordPress asset version",
                asset,
                "High"
            )

            break

    # --------------------------------------------------------
    # Astra
    # --------------------------------------------------------

    astra_pattern = re.compile(
        r"/wp-content/themes/astra/"
        r"[^\"']+",
        re.I
    )

    for asset in astra_pattern.findall(html):

        version = version_from_url(
            asset
        )

        if version:

            add_technology(
                technologies,
                "WordPress Theme",
                f"Astra {version}",
                "WordPress asset version",
                asset,
                "High"
            )

            break

    # --------------------------------------------------------
    # jQuery Core
    # --------------------------------------------------------

    jquery_pattern = re.compile(
        r"(?:^|/)"
        r"jquery(?:\.min)?\.js"
        r"(?:\?[^\"']*)?",
        re.I
    )

    for asset in jquery_pattern.findall(html):

        version = version_from_url(
            asset
        )

        if version:

            add_technology(
                technologies,
                "JavaScript Library",
                f"jQuery {version}",
                "JavaScript asset version",
                asset,
                "High"
            )

            break

    # --------------------------------------------------------
    # jQuery Migrate
    # --------------------------------------------------------

    migrate_pattern = re.compile(
        r"(?:^|/)"
        r"jquery-migrate(?:\.min)?\.js"
        r"(?:\?[^\"']*)?",
        re.I
    )

    for asset in migrate_pattern.findall(html):

        version = version_from_url(
            asset
        )

        if version:

            add_technology(
                technologies,
                "JavaScript Library",
                f"jQuery Migrate {version}",
                "JavaScript asset version",
                asset,
                "High"
            )

            break

    # --------------------------------------------------------
    # jQuery UI
    # --------------------------------------------------------

    jquery_ui_pattern = re.compile(
        r"/jquery/ui/[^\"']+\.js"
        r"(?:\?[^\"']*)?",
        re.I
    )

    for asset in jquery_ui_pattern.findall(html):

        version = version_from_url(
            asset
        )

        if version:

            add_technology(
                technologies,
                "JavaScript UI Library",
                f"jQuery UI {version}",
                "JavaScript asset version",
                asset,
                "High"
            )

            break

    # --------------------------------------------------------
    # Swiper
    # --------------------------------------------------------

    swiper_pattern = re.compile(
        r"/swiper/v"
        r"(\d+(?:\.\d+){1,3})/"
        r"[^\"']+",
        re.I
    )

    for version in swiper_pattern.findall(html):

        add_technology(
            technologies,
            "JavaScript / UI Library",
            f"Swiper {version}",
            "Swiper asset path",
            f"/swiper/v{version}/",
            "High"
        )

        break


# ============================================================
# JAVASCRIPT TECHNOLOGY DETECTION
# ============================================================

def detect_script_technologies(
    html,
    base_url,
    technologies
):
    scripts = extract_script_urls(
        html,
        base_url
    )

    for script in scripts:

        lower = script.lower()

        # ----------------------------------------------------
        # jQuery Core
        # ----------------------------------------------------

        if re.search(
            r"/jquery(?:\.min)?\.js",
            lower
        ):

            # Avoid jquery-migrate matching
            if "jquery-migrate" not in lower:

                version = version_from_url(
                    script
                )

                name = "jQuery"

                if version:
                    name += f" {version}"

                add_technology(
                    technologies,
                    "JavaScript Library",
                    name,
                    "JavaScript source",
                    script,
                    "High"
                )

        # ----------------------------------------------------
        # jQuery Migrate
        # ----------------------------------------------------

        if re.search(
            r"/jquery-migrate(?:\.min)?\.js",
            lower
        ):

            version = version_from_url(
                script
            )

            name = "jQuery Migrate"

            if version:
                name += f" {version}"

            add_technology(
                technologies,
                "JavaScript Library",
                name,
                "JavaScript source",
                script,
                "High"
            )

        # ----------------------------------------------------
        # jQuery UI
        # ----------------------------------------------------

        if re.search(
            r"/jquery/ui/",
            lower
        ):

            version = version_from_url(
                script
            )

            name = "jQuery UI"

            if version:
                name += f" {version}"

            add_technology(
                technologies,
                "JavaScript UI Library",
                name,
                "JavaScript source",
                script,
                "High"
            )

        # ----------------------------------------------------
        # Bootstrap
        # ----------------------------------------------------

        if "bootstrap" in lower:

            version = version_from_url(
                script
            )

            name = "Bootstrap"

            if version:
                name += f" {version}"

            add_technology(
                technologies,
                "CSS / UI Framework",
                name,
                "JavaScript source",
                script,
                "High"
            )

        # ----------------------------------------------------
        # React
        # ----------------------------------------------------

        if re.search(
            r"(^|[/_.-])react(?:[/_.-]|$)",
            lower
        ):

            add_technology(
                technologies,
                "JavaScript Framework",
                "React",
                "JavaScript source",
                script,
                "High"
            )

        # ----------------------------------------------------
        # Vue.js
        # ----------------------------------------------------

        if re.search(
            r"(^|[/_.-])vue(?:\.min)?\.js",
            lower
        ):

            add_technology(
                technologies,
                "JavaScript Framework",
                "Vue.js",
                "JavaScript source",
                script,
                "High"
            )

        # ----------------------------------------------------
        # Angular
        # ----------------------------------------------------

        if (
            "angular" in lower
            or "@angular" in lower
        ):

            add_technology(
                technologies,
                "JavaScript Framework",
                "Angular",
                "JavaScript source",
                script,
                "High"
            )

        # ----------------------------------------------------
        # Next.js
        # ----------------------------------------------------

        if "_next/" in lower:

            add_technology(
                technologies,
                "JavaScript Framework",
                "Next.js",
                "JavaScript source",
                script,
                "High"
            )

        # ----------------------------------------------------
        # Nuxt.js
        # ----------------------------------------------------

        if "_nuxt/" in lower:

            add_technology(
                technologies,
                "JavaScript Framework",
                "Nuxt.js",
                "JavaScript source",
                script,
                "High"
            )

        # ----------------------------------------------------
        # Axios
        # ----------------------------------------------------

        if "axios" in lower:

            add_technology(
                technologies,
                "JavaScript Library",
                "Axios",
                "JavaScript source",
                script,
                "High"
            )

        # ----------------------------------------------------
        # Lodash
        # ----------------------------------------------------

        if "lodash" in lower:

            add_technology(
                technologies,
                "JavaScript Library",
                "Lodash",
                "JavaScript source",
                script,
                "High"
            )

        # ----------------------------------------------------
        # GSAP
        # ----------------------------------------------------

        if "gsap" in lower:

            add_technology(
                technologies,
                "JavaScript Library",
                "GSAP",
                "JavaScript source",
                script,
                "High"
            )

        # ----------------------------------------------------
        # Three.js
        # ----------------------------------------------------

        if (
            "three" in lower
            and ".js" in lower
        ):

            add_technology(
                technologies,
                "JavaScript Library",
                "Three.js",
                "JavaScript source",
                script,
                "Medium"
            )

        # ----------------------------------------------------
        # Google Analytics
        # ----------------------------------------------------

        if (
            "google-analytics.com" in lower
            or "gtag" in lower
        ):

            add_technology(
                technologies,
                "Analytics",
                "Google Analytics",
                "JavaScript source",
                script,
                "High"
            )

        # ----------------------------------------------------
        # Google Tag Manager
        # ----------------------------------------------------

        if "googletagmanager.com" in lower:

            add_technology(
                technologies,
                "Analytics / Tag Management",
                "Google Tag Manager",
                "JavaScript source",
                script,
                "High"
            )

        # ----------------------------------------------------
        # Google reCAPTCHA
        # ----------------------------------------------------

        if "recaptcha" in lower:

            add_technology(
                technologies,
                "Security / CAPTCHA",
                "Google reCAPTCHA",
                "JavaScript source",
                script,
                "High"
            )

        # ----------------------------------------------------
        # Hotjar
        # ----------------------------------------------------

        if "hotjar" in lower:

            add_technology(
                technologies,
                "Analytics",
                "Hotjar",
                "JavaScript source",
                script,
                "High"
            )

        # ----------------------------------------------------
        # Sentry
        # ----------------------------------------------------

        if "sentry" in lower:

            add_technology(
                technologies,
                "Monitoring",
                "Sentry",
                "JavaScript source",
                script,
                "High"
            )


# ============================================================
# CSS TECHNOLOGY DETECTION
# ============================================================

def detect_css_technologies(
    html,
    base_url,
    technologies
):
    stylesheets = extract_css_urls(
        html,
        base_url
    )

    for stylesheet in stylesheets:

        lower = stylesheet.lower()

        # ----------------------------------------------------
        # IMPORTANT:
        # Check Swiper BEFORE Elementor.
        #
        # Elementor contains:
        # /plugins/elementor/assets/lib/swiper/v8/
        #
        # ?ver=8.4.5 is Swiper version,
        # NOT Elementor version.
        # ----------------------------------------------------

        if "/swiper/" in lower:

            version = None

            match = re.search(
                r"/swiper/v"
                r"(\d+(?:\.\d+){1,3})/",
                lower
            )

            if match:
                version = match.group(1)

            if not version:
                version = version_from_url(
                    stylesheet
                )

            name = "Swiper"

            if version:
                name += f" {version}"

            add_technology(
                technologies,
                "JavaScript / UI Library",
                name,
                "CSS asset",
                stylesheet,
                "High"
            )

            continue

        # ----------------------------------------------------
        # Elementor Pro
        # ----------------------------------------------------

        if "/plugins/elementor-pro/" in lower:

            version = version_from_url(
                stylesheet
            )

            name = "Elementor Pro"

            if version:
                name += f" {version}"

            add_technology(
                technologies,
                "WordPress Plugin",
                name,
                "CSS asset",
                stylesheet,
                "High"
            )

            continue

        # ----------------------------------------------------
        # Elementor
        # ----------------------------------------------------

        if (
            "/plugins/elementor/" in lower
            and "/elementor-pro/" not in lower
        ):

            version = version_from_url(
                stylesheet
            )

            name = "Elementor"

            if version:
                name += f" {version}"

            add_technology(
                technologies,
                "WordPress Plugin / Page Builder",
                name,
                "CSS asset",
                stylesheet,
                "High"
            )

        # ----------------------------------------------------
        # Astra
        # ----------------------------------------------------

        if "/themes/astra/" in lower:

            version = version_from_url(
                stylesheet
            )

            name = "Astra"

            if version:
                name += f" {version}"

            add_technology(
                technologies,
                "WordPress Theme",
                name,
                "CSS asset",
                stylesheet,
                "High"
            )

        # ----------------------------------------------------
        # Bootstrap
        # ----------------------------------------------------

        if "bootstrap" in lower:

            version = version_from_url(
                stylesheet
            )

            name = "Bootstrap"

            if version:
                name += f" {version}"

            add_technology(
                technologies,
                "CSS / UI Framework",
                name,
                "CSS asset",
                stylesheet,
                "High"
            )

        # ----------------------------------------------------
        # Tailwind
        # ----------------------------------------------------

        if "tailwind" in lower:

            add_technology(
                technologies,
                "CSS Framework",
                "Tailwind CSS",
                "CSS asset",
                stylesheet,
                "High"
            )

        # ----------------------------------------------------
        # Font Awesome
        # ----------------------------------------------------

        if (
            "font-awesome" in lower
            or "fontawesome" in lower
        ):

            add_technology(
                technologies,
                "Icon Library",
                "Font Awesome",
                "CSS asset",
                stylesheet,
                "High"
            )


# ============================================================
# COOKIE TECHNOLOGY DETECTION
# ============================================================

def detect_cookie_technologies(
    response,
    technologies
):
    if not response:
        return

    cookie_names = [
        cookie.name.lower()
        for cookie in response.cookies
    ]

    cookie_string = " ".join(
        cookie_names
    )

    if "_ga" in cookie_string:

        add_technology(
            technologies,
            "Analytics",
            "Google Analytics",
            "Cookie",
            "_ga cookie",
            "High"
        )

    if (
        "wordpress_logged_in" in cookie_string
        or "wp-settings" in cookie_string
        or "wordpress_test_cookie" in cookie_string
    ):

        add_technology(
            technologies,
            "CMS",
            "WordPress",
            "Cookie",
            "WordPress cookie",
            "High"
        )


# ============================================================
# SECURITY HEADER CHECKS
# ============================================================

def check_security_headers(
    response
):
    findings = []

    if not response:
        return findings

    headers = response.headers

    # --------------------------------------------------------
    # Recommended security headers
    # --------------------------------------------------------

    expected_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    missing = []

    for header in expected_headers:

        if not headers.get(header):
            missing.append(header)

    if missing:

        findings.append({
            "title": "Missing Security Headers",
            "severity": "Low",
            "cwe": "CWE-693",
            "description": (
                "One or more recommended HTTP security "
                "headers were not observed."
            ),
            "risk": (
                "Missing browser security controls may "
                "reduce protection against common web attacks."
            ),
            "impact": (
                "The actual impact depends on the application's "
                "functionality and attack surface."
            ),
            "evidence": ", ".join(
                missing
            ),
            "root_cause": (
                "Recommended security headers are not configured "
                "at the web server or application layer."
            ),
            "recommendation": (
                "Configure suitable security headers according "
                "to the application's requirements."
            )
        })

    # --------------------------------------------------------
    # Clickjacking
    # --------------------------------------------------------

    x_frame = headers.get(
        "X-Frame-Options",
        ""
    ).strip()

    csp = headers.get(
        "Content-Security-Policy",
        ""
    )

    frame_ancestors = re.search(
        r"(?:^|;)\s*frame-ancestors\s+([^;]+)",
        csp,
        re.I
    )

    if (
        not x_frame
        and not frame_ancestors
    ):

        findings.append({
            "title": (
                "Clickjacking – Missing "
                "Anti-Clickjacking Protection"
            ),
            "severity": "Medium",
            "cwe": "CWE-1021",
            "description": (
                "The application does not return X-Frame-Options "
                "and no effective CSP frame-ancestors directive "
                "was observed."
            ),
            "risk": (
                "An attacker may attempt to embed the application "
                "within a malicious iframe."
            ),
            "impact": (
                "If sensitive actions are available without "
                "additional protections, users may be tricked "
                "into performing unintended actions."
            ),
            "evidence": (
                "X-Frame-Options: missing; "
                "CSP frame-ancestors: missing"
            ),
            "root_cause": (
                "Anti-framing controls are not configured "
                "at the application or web-server layer."
            ),
            "recommendation": (
                "Implement a restrictive CSP frame-ancestors "
                "directive and/or X-Frame-Options where appropriate."
            )
        })

    # --------------------------------------------------------
    # Server disclosure
    # --------------------------------------------------------

    server = headers.get(
        "Server"
    )

    if server:

        findings.append({
            "title": (
                "Web Server Version / Banner Disclosure"
            ),
            "severity": "Low",
            "cwe": "CWE-200",
            "description": (
                "The HTTP response exposes server information "
                "through the Server header."
            ),
            "risk": (
                "Server information may assist attackers "
                "during technology fingerprinting."
            ),
            "impact": (
                "The finding primarily provides reconnaissance "
                "information rather than direct compromise."
            ),
            "evidence": (
                f"Server: {server}"
            ),
            "root_cause": (
                "The web server exposes its identification banner."
            ),
            "recommendation": (
                "Minimize unnecessary server banner information."
            )
        })

    # --------------------------------------------------------
    # X-Powered-By
    # --------------------------------------------------------

    powered = headers.get(
        "X-Powered-By"
    )

    if powered:

        findings.append({
            "title": (
                "Technology Version Disclosure"
            ),
            "severity": "Low",
            "cwe": "CWE-200",
            "description": (
                "The response exposes backend technology "
                "information through the X-Powered-By header."
            ),
            "risk": (
                "Technology information can assist attackers "
                "during reconnaissance."
            ),
            "impact": (
                "The finding primarily provides fingerprinting "
                "information."
            ),
            "evidence": (
                f"X-Powered-By: {powered}"
            ),
            "root_cause": (
                "The backend runtime exposes technology "
                "information through HTTP headers."
            ),
            "recommendation": (
                "Disable unnecessary X-Powered-By headers."
            )
        })

    return findings


# ============================================================
# COOKIE SECURITY
# ============================================================

def check_cookie_security(
    response
):
    findings = []

    if not response:
        return findings

    cookies = get_cookie_attributes(
        response
    )

    for cookie in cookies:

        name = cookie.get(
            "name"
        )

        if not name:
            continue

        # ----------------------------------------------------
        # Secure
        # ----------------------------------------------------

        if not cookie.get("secure"):

            findings.append({
                "title": (
                    f"Cookie Missing Secure Attribute: {name}"
                ),
                "severity": "Medium",
                "cwe": "CWE-614",
                "description": (
                    f"The cookie '{name}' was observed "
                    "without the Secure attribute."
                ),
                "risk": (
                    "The cookie may be exposed if transmitted "
                    "over an insecure connection."
                ),
                "impact": (
                    "Depending on the cookie's purpose, exposure "
                    "could contribute to session compromise."
                ),
                "evidence": (
                    f"Cookie '{name}' does not include Secure."
                ),
                "root_cause": (
                    "The Secure attribute is not configured."
                ),
                "recommendation": (
                    "Set Secure on security-sensitive cookies."
                )
            })

        # ----------------------------------------------------
        # HttpOnly
        # ----------------------------------------------------

        if not cookie.get("httponly"):

            findings.append({
                "title": (
                    f"Cookie Missing HttpOnly Attribute: {name}"
                ),
                "severity": "Low",
                "cwe": "CWE-1004",
                "description": (
                    f"The cookie '{name}' was observed "
                    "without the HttpOnly attribute."
                ),
                "risk": (
                    "Client-side JavaScript may be able "
                    "to access the cookie."
                ),
                "impact": (
                    "If the cookie contains session information, "
                    "successful XSS could potentially expose it."
                ),
                "evidence": (
                    f"Cookie '{name}' does not include HttpOnly."
                ),
                "root_cause": (
                    "The HttpOnly attribute has not been configured."
                ),
                "recommendation": (
                    "Set HttpOnly on cookies that do not require "
                    "client-side JavaScript access."
                )
            })

    return findings


# ============================================================
# CORS
# ============================================================

def check_cors(
    response
):
    result = {
        "enabled": False,
        "access_control_allow_origin": None,
        "access_control_allow_credentials": None,
        "headers": {},
        "finding": None
    }

    if not response:
        return result

    headers = response.headers

    origin = headers.get(
        "Access-Control-Allow-Origin"
    )

    credentials = headers.get(
        "Access-Control-Allow-Credentials"
    )

    if origin:

        result["enabled"] = True

        result["access_control_allow_origin"] = origin

        result[
            "access_control_allow_credentials"
        ] = credentials

        result["headers"] = {
            k: v
            for k, v in headers.items()
            if k.lower().startswith(
                "access-control-"
            )
        }

        if origin.strip() == "*":

            result["finding"] = {
                "title": "Wildcard CORS Policy",
                "severity": "Medium",
                "cwe": "CWE-942",
                "description": (
                    "The application allows cross-origin "
                    "requests from any origin."
                ),
                "risk": (
                    "A permissive cross-origin policy may expose "
                    "resources to untrusted origins."
                ),
                "impact": (
                    "Actual impact depends on whether sensitive "
                    "resources are accessible through affected endpoints."
                ),
                "evidence": (
                    "Access-Control-Allow-Origin: *"
                ),
                "root_cause": (
                    "The CORS policy allows all origins."
                ),
                "recommendation": (
                    "Restrict allowed origins to trusted "
                    "application domains."
                )
            }

    return result


# ============================================================
# HTTP METHODS
# ============================================================

def check_http_methods(
    url
):
    result = {
        "status_code": None,
        "allow": [],
        "headers": {}
    }

    response = safe_options(
        url
    )

    if not response:
        return result

    result["status_code"] = (
        response.status_code
    )

    allow = response.headers.get(
        "Allow",
        ""
    )

    if allow:

        result["allow"] = [
            x.strip()
            for x in allow.split(",")
            if x.strip()
        ]

    result["headers"] = {
        k: v
        for k, v in response.headers.items()
    }

    return result


# ============================================================
# COMMON FILES
# ============================================================

def check_common_files(
    base_url
):
    common_paths = [
        "/robots.txt",
        "/sitemap.xml",
        "/security.txt",
        "/.well-known/security.txt",
        "/license.txt",
        "/readme.html",
        "/xmlrpc.php",
        "/wp-login.php",
        "/wp-admin/",
        "/wp-json/",
        "/wp-json/wp/v2/users/",
        "/.git/HEAD",
        "/.env",
        "/phpinfo.php"
    ]

    results = []

    for path in common_paths:

        url = urljoin(
            base_url + "/",
            path.lstrip("/")
        )

        try:

            response = requests.get(
                url,
                headers={
                    "User-Agent": USER_AGENT
                },
                timeout=8,
                allow_redirects=False
            )

            status = response.status_code

            interesting = status in (
                200,
                206,
                301,
                302,
                307,
                308,
                401,
                403
            )

            if interesting:

                results.append({
                    "path": path,
                    "url": url,
                    "status_code": status,
                    "content_type": response.headers.get(
                        "Content-Type",
                        ""
                    ),
                    "length": len(
                        response.content
                    )
                })

        except requests.RequestException:
            continue

    return results


# ============================================================
# MAIN WEB SECURITY SCAN
# ============================================================

def scan_web_security(
    target
):
    start_time = time.time()

    base_url = normalize_url(
        target
    )

    result = {
        "target": base_url,
        "status_code": None,
        "final_url": None,
        "response_time": None,

        "technologies": [],

        "security_headers": {},
        "cookies": [],
        "cors": {},
        "http_methods": {},
        "common_files": [],

        "findings": [],
        "error": None
    }

    if not base_url:

        result["error"] = (
            "Invalid target URL."
        )

        return result

    # ========================================================
    # MAIN HTTP REQUEST
    # ========================================================

    response = safe_get(
        base_url
    )

    if not response:

        result["error"] = (
            "Unable to connect to target."
        )

        return result

    # ========================================================
    # BASIC INFORMATION
    # ========================================================

    result["status_code"] = (
        response.status_code
    )

    result["final_url"] = (
        response.url
    )

    html = response.text

    # ========================================================
    # TECHNOLOGY DETECTION
    # ========================================================

    technologies = []

    detect_header_technologies(
        response,
        technologies
    )

    detect_generator_tags(
        html,
        technologies
    )

    detect_html_technologies(
        html,
        technologies
    )

    detect_wordpress_asset_versions(
        html,
        technologies
    )

    detect_script_technologies(
        html,
        base_url,
        technologies
    )

    detect_css_technologies(
        html,
        base_url,
        technologies
    )

    detect_cookie_technologies(
        response,
        technologies
    )

    result["technologies"] = technologies

    # ========================================================
    # SECURITY HEADERS
    # ========================================================

    result["security_headers"] = {
        key: value
        for key, value in response.headers.items()
    }

    result["findings"].extend(
        check_security_headers(
            response
        )
    )

    # ========================================================
    # COOKIES
    # ========================================================

    result["cookies"] = (
        get_cookie_attributes(
            response
        )
    )

    result["findings"].extend(
        check_cookie_security(
            response
        )
    )

    # ========================================================
    # CORS
    # ========================================================

    result["cors"] = check_cors(
        response
    )

    cors_finding = result[
        "cors"
    ].get(
        "finding"
    )

    if cors_finding:

        result["findings"].append(
            cors_finding
        )

    # ========================================================
    # HTTP METHODS
    # ========================================================

    result["http_methods"] = (
        check_http_methods(
            base_url
        )
    )

    # ========================================================
    # COMMON FILES
    # ========================================================

    result["common_files"] = (
        check_common_files(
            base_url
        )
    )

    # ========================================================
    # FINAL RESPONSE TIME
    # ========================================================

    result["response_time"] = round(
        time.time() - start_time,
        3
    )

    return result