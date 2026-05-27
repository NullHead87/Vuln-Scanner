# Vuln-Scanner

A server-side REST API built with Python and FastAPI that performs automated security scanning on web targets. Identifies common misconfigurations, exposed headers, TLS issues, DNS records, open ports, subdomains, and known CVE vulnerabilities.  

---

## Features

- HTTP security header analysis
- TLS/SSL certificate inspection
- Redirect and open redirect detection
- DNS record checks (SPF, DMARC, DKIM)
- HTTP method testing (PUT, DELETE, TRACE, PATCH, OPTIONS)
- Cookie flag validation (Secure, HttpOnly, SameSite)
- Port scanning for common services
- Subdomain enumeration
- CVE lookup via NVD API based on detected server software
- PDF report generation
- SQLite result storage with full history
- Interactive browser UI with explanation sidebar

---

## Requirements

- Python 3.10+
- pip

---

## Installation

### 1. Clone or download the project

```bash
git clone <repository-url>
cd vuln_scanner
```

### 2. Create virtual environment

```bash
python -m venv venv
```

### 3. Activate virtual environment

**Windows:**
```bash
venv\Scripts\activate
```

**Linux / macOS:**
```bash
source venv/bin/activate
```

### 4. Install dependencies

```bash
pip install fastapi uvicorn httpx sqlalchemy aiosqlite aiofiles dnspython reportlab
```

---

## Usage

### Start the server

```bash
uvicorn main:app --reload
```

Server starts at `http://localhost:8000`

### Browser UI

Open `http://localhost:8000` in your browser.

1. Enter a target URL, e.g. `https://example.com`
2. Click **Scan** or press Enter
3. Results appear below — click any finding to see an explanation in the sidebar
4. Score bar shows overall security rating (green / yellow / red)
5. Click **↓ PDF** to download a full report

### API Documentation (Swagger UI)

```
http://localhost:8000/docs
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan` | Run a new scan |
| GET | `/api/results` | List all saved scans |
| GET | `/api/results/{id}` | Get scan by ID |
| GET | `/api/results/{id}/pdf` | Download scan report as PDF |

### Example request (PowerShell)

```powershell
Invoke-WebRequest -Uri "http://localhost:8000/api/scan" `
  -Method POST `
  -ContentType "application/json" `
  -Body '{"url": "https://example.com"}'
```

---

## Checks Performed

### HTTP Security Headers

| Header | Description |
|--------|-------------|
| Strict-Transport-Security | Enforces HTTPS connections |
| Content-Security-Policy | Prevents XSS attacks |
| X-Frame-Options | Prevents clickjacking |
| X-Content-Type-Options | Prevents MIME sniffing |
| Referrer-Policy | Controls referrer information |
| Permissions-Policy | Controls browser feature access |

### TLS / SSL
- TLS version (recommended: TLSv1.2 or TLSv1.3)
- Certificate expiry
- Certificate Common Name (CN)

### DNS
- SPF record
- DMARC record
- DKIM record (default selector)

### HTTP Methods
- Tests PUT, DELETE, TRACE, PATCH, OPTIONS
- Flags methods that return 2xx responses

### Cookies
- Secure flag
- HttpOnly flag
- SameSite flag

### Port Scan

| Port | Service |
|------|---------|
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 25 | SMTP |
| 80 | HTTP |
| 443 | HTTPS |
| 3306 | MySQL |
| 5432 | PostgreSQL |
| 6379 | Redis |
| 8080 | HTTP-alt |
| 8443 | HTTPS-alt |
| 27017 | MongoDB |

### Subdomain Enumeration
Tests common subdomains: `www`, `mail`, `ftp`, `admin`, `dev`, `staging`, `api`, `test`, `portal`, `vpn`, `remote`, `shop`, `blog`, `app`, `beta`, `secure`, `login`, `cpanel`

### CVE Lookup
Automatically queries the NVD API for known vulnerabilities based on detected server software (Apache, nginx, IIS, Drupal, etc.)

---

## Project Structure

```
vuln_scanner/
├── main.py              # FastAPI app, startup and routing
├── database.py          # Database connection and initialization
├── models.py            # SQLAlchemy models
├── scanner/
│   ├── headers.py       # HTTP security header checks
│   ├── tls.py           # TLS/SSL checks
│   ├── redirects.py     # Redirect checks
│   ├── dns_check.py     # DNS record checks
│   ├── methods.py       # HTTP method checks
│   ├── cookies.py       # Cookie flag checks
│   ├── ports.py         # Port scanning
│   ├── subdomains.py    # Subdomain enumeration
│   └── cve_check.py     # CVE lookup via NVD API
├── routers/
│   └── scan.py          # API endpoints and PDF generation
├── static/
│   ├── style.css        # Frontend styles
│   └── app.js           # Frontend logic
├── frontend.html        # Browser UI
└── README.md            # This file
```

---

## Database

Scan results are stored automatically in a local SQLite database (`scanner.db`). The database is created automatically on first startup. The file is excluded from version control via `.gitignore`.

---

## Notes

-Some of features are still under construction and may not work!

- CVE lookups use the public NVD API (5 requests/second limit without API key)
- Port scanning may be slow on targets with strict firewalls
- Subdomain enumeration only tests a predefined list of common names
- Scanner is intended for authorized testing only

---

## Author

NullHead87
