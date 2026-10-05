# 🛡️ VAPT Automation Tool

### Live Security Assessment & Attack Surface Management Platform

A Flask-based **Vulnerability Assessment and Penetration Testing (VAPT)** platform for authorized web application, infrastructure, service, and attack-surface security assessments.

<p align="center">

<a href="https://vapt-automation-tool.onrender.com/">
  <img src="https://img.shields.io/badge/Live%20Demo-Open%20Application-success?style=for-the-badge" alt="Live Demo">
</a>

<a href="https://github.com/Anu123-cyber/VAPT-Automation-Tool">
  <img src="https://img.shields.io/badge/GitHub-Repository-black?style=for-the-badge&logo=github" alt="GitHub Repository">
</a>

</p>

---

## 🚀 Live Demo

**Open the VAPT Automation Tool:**

👉 **https://vapt-automation-tool.onrender.com/**

The application is deployed on **Render** and provides a browser-based security assessment dashboard with live scan progress, security findings, attack-surface information, and report generation.

> ⚠️ **Authorization Required**
>
> Only perform security assessments against systems, applications, APIs, domains, or infrastructure that you own or have explicit permission to test.

---

## 📸 Dashboard

The dashboard provides a centralized interface for monitoring security assessments.

### Dashboard Preview

Add your screenshots to:

```text
docs/
└── screenshots/
    ├── dashboard.png
    ├── live-scan.png
    ├── findings.png
    └── reports.png
```

Then display them in this section:

![VAPT Dashboard](docs/screenshots/dashboard.png)

### Dashboard Capabilities

* 🔴 Live security assessment progress
* 🛡️ Findings and severity summary
* 🔌 Open-port discovery
* 🌐 Subdomain enumeration
* 📜 Certificate Transparency results
* 🔍 Technology detection
* 🕷️ Web crawling statistics
* 🔐 Security header analysis
* 🌍 HTTP methods detection
* 🔄 CORS assessment
* 📊 Scan statistics
* 📄 Report generation
* 📦 JSON / CSV / HTML / PDF / ZIP exports where enabled

---

# 🔍 Features

The platform is organized into multiple security assessment areas.

## 🌐 Infrastructure

| Module                   | Description                                           |
| ------------------------ | ----------------------------------------------------- |
| Subdomain Enumeration    | Discover publicly resolvable subdomains               |
| Certificate Transparency | Identify certificates and related hostnames           |
| DNS Reconnaissance       | Collect DNS records and infrastructure information    |
| DNS History / NS Recon   | Analyze DNS and nameserver information                |
| ASN / BGP Intelligence   | Infrastructure and network ownership intelligence     |
| Dev / Staging Discovery  | Identify potentially exposed development environments |
| Forgotten / EOL Assets   | Identify potentially outdated or forgotten assets     |
| Cloud Storage Checks     | Identify publicly observable cloud-storage exposure   |

---

## 🔌 Services

| Module                    | Description                                       |
| ------------------------- | ------------------------------------------------- |
| TCP Port Scanning         | Identify accessible TCP services                  |
| Service Detection         | Detect services running on discovered ports       |
| Technology Fingerprinting | Identify technologies used by exposed services    |
| Nmap Discovery            | Network/service discovery using Nmap              |
| HTTP / HTTPS Detection    | Identify web services                             |
| Open Port Reporting       | Display discovered open services in the dashboard |

---

## 🕷️ Web Security

| Module                     | Description                                             |
| -------------------------- | ------------------------------------------------------- |
| Security Headers           | Analyze HTTP security headers                           |
| HTTP Methods               | Detect supported HTTP methods                           |
| CORS Assessment            | Analyze Cross-Origin Resource Sharing configuration     |
| Server / Banner Disclosure | Identify exposed server information                     |
| TLS / Certificate Analysis | Collect TLS and certificate information                 |
| Common File Discovery      | Check common publicly accessible files                  |
| Web Security Findings      | Generate security findings where evidence supports them |
| CWE Information            | Associate findings with CWE identifiers where available |

---

## 🕸️ Web Crawler

The crawler collects information from pages that can actually be reached during the assessment.

| Capability             | Description                    |
| ---------------------- | ------------------------------ |
| Internal URLs          | Discover internal links        |
| External URLs          | Identify external links        |
| Sitemap Discovery      | Process sitemap URLs           |
| Robots.txt             | Analyze robots.txt information |
| JavaScript Discovery   | Identify JavaScript resources  |
| CSS Discovery          | Identify stylesheet resources  |
| API Endpoint Discovery | Identify API-like endpoints    |
| Parameter Discovery    | Identify discovered parameters |
| Form Discovery         | Detect HTML forms              |
| Page Crawling          | Crawl accessible pages         |
| Crawl Statistics       | Display real crawl statistics  |

The crawler respects configured page limits and reports the data actually collected.

---

## 🔎 OSINT

Publicly observable intelligence can be collected from sources such as:

* Public infrastructure information
* Public repository indicators
* Public Git / Paste references
* Technology intelligence
* Attack-surface information
* Publicly observable asset information

---

## 🛡️ Threat Intelligence

Threat-intelligence related checks include:

* Public threat indicators
* Exposure-surface checks
* Credential-exposure surface indicators
* Session-token exposure indicators
* Public repository metadata
* Publicly observable exposure information

> The platform is designed to collect security-relevant indicators without intentionally harvesting authentication passwords or session-token values.

---

# 📊 Dashboard Metrics

The dashboard summarizes information collected during each assessment.

| Metric            | Description                                        |
| ----------------- | -------------------------------------------------- |
| **Findings**      | Security findings identified during the assessment |
| **Open Ports**    | Network services detected by the port scanner      |
| **Subdomains**    | Discovered subdomains                              |
| **Certificates**  | Certificate Transparency results                   |
| **Technologies**  | Detected technologies and platforms                |
| **Pages**         | Successfully crawled pages                         |
| **Internal URLs** | Internal URLs discovered                           |
| **External URLs** | External URLs discovered                           |
| **API Endpoints** | API-like endpoints identified                      |
| **Parameters**    | Parameters discovered during crawling              |
| **Forms**         | Forms detected                                     |
| **JS Files**      | JavaScript resources discovered                    |
| **CSS Files**     | CSS resources discovered                           |

### Accuracy

The platform is designed to report **observed scan results rather than fabricated values**.

If a module cannot obtain information from the target, the dashboard should reflect the unavailable/empty result rather than inventing a security finding or count.

---

# 🏗️ Architecture

```text
                    ┌─────────────────────────┐
                    │       Web Browser       │
                    │    VAPT Dashboard       │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │       Flask App         │
                    │         app.py           │
                    └────────────┬────────────┘
                                 │
             ┌───────────────────┼───────────────────┐
             │                   │                   │
             ▼                   ▼                   ▼
      ┌───────────────┐  ┌───────────────┐  ┌───────────────┐
      │ Infrastructure│  │   Services    │  │ Web Security  │
      ├───────────────┤  ├───────────────┤  ├───────────────┤
      │ DNS           │  │ Nmap          │  │ Headers       │
      │ Subdomains    │  │ Port Scanning │  │ CORS          │
      │ Certificate   │  │ Fingerprinting│  │ HTTP Methods  │
      │ Transparency  │  │ Service Scan  │  │ TLS           │
      └───────────────┘  └───────────────┘  └───────────────┘
             │                   │                   │
             └───────────────────┼───────────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │      Web Crawler        │
                    ├─────────────────────────┤
                    │ URLs / APIs / JS / CSS  │
                    │ Forms / Parameters      │
                    │ Sitemap / Robots        │
                    └────────────┬────────────┘
                                 │
                    ┌────────────┴────────────┐
                    ▼                         ▼
             ┌──────────────┐         ┌────────────────┐
             │     OSINT    │         │ Threat Intel   │
             └──────────────┘         └────────────────┘
                    │                         │
                    └────────────┬────────────┘
                                 ▼
                    ┌─────────────────────────┐
                    │     Scan Results        │
                    │       Findings          │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │   Reports / Export      │
                    │ JSON / CSV / HTML / PDF │
                    │ ZIP where enabled       │
                    └─────────────────────────┘
```

---

# 📁 Project Structure

```text
VAPT-Automation-Tool/
│
├── app.py
├── app_consolidated.py
├── app_live_dashboard.py
│
├── core/
│   ├── __init__.py
│   └── scanner.py
│
├── modules/
│   ├── __init__.py
│   │
│   ├── infrastructure/
│   │   ├── dns.py
│   │   ├── subdomains.py
│   │   └── cert_transparency.py
│   │
│   ├── services/
│   │   └── services_port_scan.py
│   │
│   ├── osint/
│   │   └── __init__.py
│   │
│   ├── threat_intel/
│   │   └── __init__.py
│   │
│   ├── web_crawler.py
│   └── web_security.py
│
├── templates/
│   ├── index.html
│   └── login.html
│
├── requirements.txt
├── Dockerfile
├── README.md
└── .gitignore
```

---

# 💻 Installation

## Windows

### 1. Clone the repository

```powershell
git clone https://github.com/Anu123-cyber/VAPT-Automation-Tool.git
cd VAPT-Automation-Tool
```

### 2. Create a virtual environment

```powershell
py -m venv .venv
```

### 3. Activate the virtual environment

```powershell
.venv\Scripts\activate
```

### 4. Install dependencies

```powershell
pip install -r requirements.txt
```

### 5. Run the application

```powershell
python app.py
```

Open:

```text
http://127.0.0.1:5000/
```

---

# 🐧 Linux

```bash
git clone https://github.com/Anu123-cyber/VAPT-Automation-Tool.git
cd VAPT-Automation-Tool

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt

python app.py
```

Then open:

```text
http://127.0.0.1:5000/
```

---

# ☁️ Deployment

The application can be deployed using a platform such as **Render**.

### Render Configuration

**Build Command**

```bash
pip install -r requirements.txt
```

**Start Command**

```bash
python app.py
```

The application should listen on the port supplied by the hosting platform.

For production deployment, configure authentication and application secrets through the hosting provider's environment-variable settings.

---

# 🔐 Environment Variables

Sensitive values should **not** be committed to GitHub.

Example environment variables:

```text
VAPT_SECRET_KEY=<strong-random-secret>

VAPT_ADMIN_USERNAME=<admin-username>

VAPT_ADMIN_PASSWORD_HASH=<password-hash>

HIBP_API_KEY=<optional-api-key>
```

Keep real API keys, passwords, tokens, cookies, private keys, and other credentials outside the repository.

---

# 🔒 Security & Authorization

This project is intended for **authorized security testing only**.

Before scanning a target, ensure that you have explicit permission from the system owner.

### Recommended use cases

* Authorized penetration testing
* Internal security assessments
* Web application security testing
* Infrastructure assessments
* Attack-surface discovery
* Security research in controlled environments
* Security labs and test environments

### Do not use the platform to:

* Scan systems without authorization
* Attempt unauthorized access
* Collect credentials from systems you do not own
* Disrupt production services
* Perform denial-of-service testing without explicit authorization
* Bypass security controls without permission

---

# 📄 Reporting

The platform supports report/export functionality where enabled.

Available formats may include:

```text
JSON
CSV
HTML
PDF
ZIP
```

Reports can contain information such as:

* Target information
* Scan status
* Discovered services
* Open ports
* Subdomains
* Certificates
* Technologies
* Crawler statistics
* Security findings
* Evidence collected during the assessment

---

# 🧪 Accuracy & False Positives

The project is designed with an emphasis on **evidence-based security results**.

The platform aims to:

* Use actual scan output
* Avoid fabricated statistics
* Avoid inventing vulnerabilities
* Preserve raw module results where possible
* Associate findings with evidence
* Display empty results when information cannot be obtained
* Distinguish unavailable modules from completed modules

Security findings should still be manually validated before being treated as confirmed vulnerabilities in a professional penetration-testing report.

---

# 🛠️ Technology Stack

| Technology                   | Purpose                            |
| ---------------------------- | ---------------------------------- |
| **Python**                   | Application backend                |
| **Flask**                    | Web application framework          |
| **Nmap**                     | Network and service discovery      |
| **HTML / CSS / JavaScript**  | Dashboard interface                |
| **DNS tools**                | DNS reconnaissance                 |
| **Certificate Transparency** | Certificate and hostname discovery |
| **Web Crawler**              | Web attack-surface discovery       |
| **OSINT modules**            | Public intelligence collection     |
| **Threat Intelligence**      | Exposure and indicator analysis    |
| **Render**                   | Cloud deployment                   |

---

# 📌 Current Scope

The current platform focuses on:

```text
Infrastructure Discovery
        ↓
Service Discovery
        ↓
Technology Detection
        ↓
Web Security Analysis
        ↓
Web Crawling
        ↓
OSINT
        ↓
Threat Intelligence
        ↓
Findings
        ↓
Reports
```

The available functionality depends on the target, network accessibility, installed dependencies, external data sources, and the modules enabled in the deployment.

---

# 🤝 Contributing

Contributions, bug reports, feature suggestions, and improvements are welcome.

### Contribution workflow

```bash
git clone https://github.com/Anu123-cyber/VAPT-Automation-Tool.git

cd VAPT-Automation-Tool

git checkout -b feature/my-feature

# Make your changes

git add .

git commit -m "Add my feature"

git push origin feature/my-feature
```

Then open a Pull Request on GitHub.

---

# 🐛 Issues

If you discover a bug or have a feature request, please open an issue:

👉 https://github.com/Anu123-cyber/VAPT-Automation-Tool/issues

When reporting a problem, include:

* Operating system
* Python version
* Relevant module
* Error message
* Steps to reproduce
* Expected behavior
* Actual behavior

Do not include passwords, API keys, tokens, cookies, or other sensitive information.

---

# 👩‍💻 Author

**Anu123-cyber**

GitHub:

👉 https://github.com/Anu123-cyber

---

# ⚠️ Disclaimer

This tool is provided for **authorized security assessment, penetration testing, research, and educational purposes**.

The author is not responsible for misuse of the software or unauthorized security testing.

Always obtain appropriate authorization before scanning or assessing a target.

---

<p align="center">

### 🛡️ VAPT Automation Tool

**Live Security Assessment & Attack Surface Management**

<a href="https://vapt-automation-tool.onrender.com/">
  <img src="https://img.shields.io/badge/🚀_Open-Live_Dashboard-success?style=for-the-badge" alt="Open Live Dashboard">
</a>

</p>
