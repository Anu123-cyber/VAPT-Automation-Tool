
# VAPT Attack Surface Console

A local Flask dashboard for authorized security assessments. It contains the six feature groups from the supplied UI and 42 clickable modules.

## Run on Windows

```powershell
cd VAPT-Tool
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open: http://127.0.0.1:5000/

## Optional security tools

The application automatically uses these if they are installed and available in PATH:
- subfinder: subdomain enumeration
- nuclei: optional target-scoped vulnerability templates

The built-in engine performs passive/low-impact HTTP, DNS, TLS and TCP checks.

## Important

Only test systems for which you have explicit authorization. The credential/people/threat-intelligence modules are intentionally designed as defensive exposure-assessment/integration points and do not harvest credentials, validate stolen passwords, steal cookies, collect private personal data, or interact with illegal leak infrastructure.

## Data

Scan metadata and findings are stored in `vapt.db` (SQLite) in the project directory.
JSON export is available after a completed scan.
