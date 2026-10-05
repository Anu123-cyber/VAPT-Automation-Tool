🛡️ VAPT Automation Tool

<p align="center"> <strong>Live Security Assessment & Attack Surface Management Platform</strong> </p>

<p align="center"> A Flask-based VAPT platform for authorized web application, infrastructure, service, and attack-surface security assessments. </p>

<p align="center"> <a href="https://vapt-automation-tool.onrender.com/"> <img src="https://img.shields.io/badge/🚀%20Live%20Demo-Open%20Application-success?style=for-the-badge" alt="Live Demo"> </a> <a href="https://github.com/Anu123-cyber/VAPT-Automation-Tool"> <img src="https://img.shields.io/badge/GitHub-Repository-black?style=for-the-badge&logo=github" alt="GitHub Repository"> </a> </p>

🚀 Live Demo
Open VAPT Automation Tool →

The application is deployed on Render and provides a browser-based security assessment dashboard.

Authorization required: Only perform security assessments against systems, applications, APIs, domains, or infrastructure that you own or have explicit permission to test.

📸 Dashboard

Add screenshots of the live dashboard here.

docs/
└── screenshots/
    ├── dashboard.png
    ├── live-scan.png
    ├── findings.png
    └── reports.png

Example:

![VAPT Dashboard](docs/screenshots/dashboard.png)
Dashboard capabilities
Live security assessment progress
Findings and severity summary
Open-port discovery
Subdomain enumeration
Certificate Transparency results
Technology detection
Web crawling statistics
Security headers analysis
HTTP methods detection
CORS assessment
Report generation
JSON / CSV / HTML / PDF / ZIP exports where enabled
🔍 Features

The platform is organized into multiple security assessment areas.

🌐 Infrastructure
Subdomain Enumeration
Certificate Transparency Mining
DNS Reconnaissance
DNS History / NS Recon
ASN / BGP Intelligence
Exposed Development / Staging Assets
Forgotten / EOL Asset Identification
Cloud Storage Exposure Checks
🔌 Services
TCP Port Scanning
Service Detection
Technology Fingerprinting
Nmap-based Network Discovery
HTTP/HTTPS Service Detection
Open Port Reporting
🕷️ Web Security
Security Header Analysis
HTTP Methods Detection
CORS Assessment
Server / Banner Disclosure
TLS / Certificate Information
Common Web File Discovery
Web Security Findings
CWE-associated finding information where available
🕸️ Web Crawler
Internal URL Discovery
External URL Discovery
Sitemap Discovery
Robots.txt Discovery
JavaScript File Discovery
CSS File Discovery
API Endpoint Discovery
Parameter Discovery
Form Discovery
Page Crawling Statistics
🔎 OSINT
Public Intelligence Collection
Public Repository Indicators
Public Git / Paste References
Technology and infrastructure intelligence
Publicly observable attack-surface information
🛡️ Threat Intelligence
Public threat indicators
Exposure checks
Credential-exposure surface checks
Session-token surface detection
Public repository metadata indicators

The platform is designed to collect security-relevant indicators without intentionally harvesting authentication secrets or session-token values.

📊 Dashboard

The dashboard provides a centralized view of the current assessment.

Typical dashboard metrics include:

Metric	Description
Findings	Security findings identified during the assessment
Open Ports	Network services detected by the port scanner
Subdomains	Discovered subdomains
Certificates	Certificate Transparency results
Technologies	Detected technologies and platforms
Pages	Pages successfully crawled
Internal URLs	Internal URLs discovered
External URLs	External URLs discovered
API Endpoints	API-like endpoints identified
Parameters	Parameters discovered during crawling
Forms	Forms detected
JS Files	JavaScript resources discovered
CSS Files	CSS resources discovered

Results are based on the data actually collected during the scan. The tool does not intentionally invent findings or counts when a module cannot obtain the relevant information.

🏗️ Architecture
                         ┌─────────────────────────┐
                         │       Web Browser        │
                         │     VAPT Dashboard       │
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │       Flask App          │
                         │        app.py             │
                         └────────────┬────────────┘
                                      │
              ┌───────────────────────┼───────────────────────┐
              │                       │                       │
              ▼                       ▼                       ▼
      ┌───────────────┐       ┌───────────────┐       ┌───────────────┐
      │ Infrastructure│       │    Services   │       │ Web Security  │
      │               │       │               │       │               │
      │ DNS           │       │ Nmap          │       │ Headers       │
      │ Subdomains    │       │ Port Scan     │       │ CORS          │
      │ CT            │       │ Fingerprint   │       │ HTTP Methods  │
      └───────────────┘       └───────────────┘       │ TLS           │
                                                      └───────────────┘
              │                       │                       │
              └───────────────────────┼───────────────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │     Web Crawler         │
                         │                         │
                         │ URLs / APIs / JS / CSS  │
                         │ Forms / Parameters      │
                         └────────────┬────────────┘
                                      │
                         ┌────────────┴────────────┐
                         ▼                         ▼
                 ┌───────────────┐       ┌────────────────┐
                 │     OSINT     │       │ Threat Intel   │
                 └───────────────┘       └────────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │ Scan Results / Findings │
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │ Reports / Export        │
                         │ JSON / CSV / HTML / PDF │
                         └─────────────────────────┘
📁 Project Structure
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
│   ├── infrastructure/
│   │   ├── dns.py
│   │   ├── subdomains.py
│   │   └── cert_transparency.py
│   │
│   ├── services/
│   │   └── services_port_scan.py
│   │
│   ├── osint/
│   ├── threat_intel/
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
💻 Installation
Windows

Clone the repository:

git clone https://github.com/Anu123-cyber/VAPT-Automation-Tool.git
cd VAPT-Automation-Tool

Create a virtual environment:

py -m venv .venv

Activate it:

.venv\Scripts\activate

Install dependencies:

pip install -r requirements.txt

Start the application:

python app.py

Open:

http://127.0.0.1:5000/
Using the project virtual environment directly

On Windows, you can also run:

.venv\Scripts\python.exe app.py
🐧 Linux
git clone https://github.com/Anu123-cyber/VAPT-Automation-Tool.git
cd VAPT-Automation-Tool

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt

python app.py

Then open:

http://127.0.0.1:5000/
☁️ Deployment
Render

The application is deployed using Render.

Live application:

https://vapt-automation-tool.onrender.com/

For a Render deployment:

Create a Render Web Service.
Connect the GitHub repository.
Configure the Python environment.
Install dependencies from requirements.txt.
Configure required environment variables.
Deploy the application.
Open the generated Render URL.
Environment Variables

Production secrets should be configured through the hosting platform's environment-variable system.

Example:

VAPT_SECRET_KEY=<random-production-secret>
VAPT_ADMIN_USERNAME=<admin-username>
VAPT_ADMIN_PASSWORD_HASH=<password-hash>
HIBP_API_KEY=<optional-api-key>

Never commit production secrets to GitHub.

🔐 Security & Authorization

This project is intended for:

Authorized penetration testing
Vulnerability assessment
Attack-surface discovery
Security research
Security education
Internal security testing
Bug bounty testing where explicitly permitted
Responsible Use

Only scan systems where you have explicit authorization.

Do not use this tool to:

Scan third-party systems without permission
Attempt unauthorized authentication
Access private data
Steal credentials or session tokens
Disrupt services
Evade security controls
Conduct denial-of-service attacks
Perform unauthorized exploitation

The user operating this software is responsible for ensuring that all testing complies with applicable laws, contracts, and the target organization's authorization and scope.

🧪 Accuracy & False Positives

The platform is designed to report information based on actual scan results.

Where possible:

Findings are supported by collected evidence.
Network ports are reported from actual scanning results.
Crawled pages are counted from successfully processed pages.
Security-header findings are based on observed HTTP responses.
HTTP methods are based on observed server behavior.
Technology information is based on detected indicators.
Unavailable modules should not be represented as successful findings.

Security testing results should still be manually validated before being used in a professional penetration-testing report.

📄 Reporting

The platform supports security assessment reporting and exports where enabled by the deployed version.

Potential report formats include:

JSON
CSV
HTML
PDF
ZIP

Reports can contain information such as:

Target information
Scan metadata
Findings
Severity
CWE information
Evidence
Open ports
Technologies
Subdomains
Certificates
Web-crawler results

Do not publicly share reports containing client or sensitive assessment data.

🛠️ Technology Stack
Component	Technology
Backend	Python
Web Framework	Flask
Frontend	HTML / CSS / JavaScript
Network Scanner	Nmap
Database	SQLite where configured
Certificate Intelligence	Certificate Transparency
Deployment	Render
Version Control	Git / GitHub
Reporting	JSON / CSV / HTML / PDF / ZIP
📌 Current Scope

The project is actively developed and may contain modules that are experimental, environment-dependent, or require additional configuration.

Some security checks depend on:

Target accessibility
DNS configuration
Network connectivity
Nmap availability
Target HTTP behavior
External intelligence sources
API configuration
Hosting environment restrictions

A module returning no results does not necessarily mean the target is secure.

🤝 Contributing

Contributions, bug reports, feature suggestions, and security improvements are welcome.

Before submitting changes:

Test the affected module.
Avoid committing secrets or credentials.
Do not include client assessment data.
Keep changes focused.
Document new functionality where appropriate.
🐛 Issues

If you discover a bug or have a feature request, open an issue in the GitHub repository:

Report an issue →

For security-sensitive issues, avoid publicly posting credentials, tokens, private information, or client assessment data.

📜 License

Add your chosen open-source license here.

If no license has been selected yet, the repository should be considered all rights reserved by default, even though the source code is publicly viewable.

👤 Author

Anusha

Cybersecurity / VAPT

GitHub:

https://github.com/Anu123-cyber

<p align="center"> <strong>VAPT Automation Tool</strong><br> Built for authorized security assessment and attack-surface visibility. </p>
