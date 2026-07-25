# Webinfo - Professional Web Reconnaissance Platform

A comprehensive, enterprise-grade web reconnaissance and security assessment platform designed for penetration testers, SOC analysts, bug bounty hunters, security researchers, and students.

```
  WEBINFO - Professional Web Reconnaissance Platform
  Comprehensive Security Assessment Suite
  Modules:
   - DNS/WHOIS/SPF/DKIM/DMARC/DNSSEC Analysis
   - SSL/TLS Certificate Grading (A+ to F)
   - HTTP Security Headers & Cookie Audit
   - Technology & CVE Detection
   - Port Scanning (200+ ports)
   - Vulnerability Assessment (OWASP mapped)
   - Subdomain Enumeration (CT logs + DNS)
   - Email Security (MX/SPF/DKIM/DMARC)
   - Sensitive File Discovery (150+ paths)
   - Performance, SEO & Accessibility Checks
   - Security Scoring & Grading
   - Report Export (JSON/HTML/CSV/Markdown)
   - REST API with Auth & Rate Limiting
  MADE BY PRIYANSHU PRAJAPAT
```

## Features

### Reconnaissance
- **DNS Analysis**: A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA, PTR, reverse DNS
- **WHOIS Lookup**: Registrar, dates, contacts, name servers, domain age
- **IP Intelligence**: Geolocation, ASN, ISP, cloud provider detection
- **Subdomain Enumeration**: Certificate Transparency logs (crt.sh), DNS brute-force (200+ wordlist)
- **Technology Fingerprinting**: 30+ CMS, frameworks, libraries, servers with version detection
- **Sensitive File Discovery**: 150+ paths including .env, .git, admin panels, backups, config files

### Security Assessment
- **SSL/TLS Analysis**: Certificate details, TLS version, cipher strength, expiry, self-signed detection, **A+ to F grading**
- **Security Header Audit**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, COEP, CORP
- **Vulnerability Scanning**: SQLi, XSS, path traversal, open redirect, directory listing, info disclosure, CORS misconfig, cookie security, form analysis, HTML comments
- **OWASP Mapping**: All findings mapped to OWASP Top 10 categories
- **Email Security**: SPF, DKIM, DMARC records with policy analysis and grade
- **Port Scanning**: 200+ common ports with service identification and banner grabbing
- **Cookie Audit**: Secure, HttpOnly, SameSite flag analysis

### Performance & SEO
- Load time measurement, response size analysis
- SEO meta tags, Open Graph, JSON-LD, canonical URL detection
- Accessibility: lang attribute, viewport, charset, image alt-text

### Reporting
- **Security Score**: 0-100 with letter grade (A+ to F)
- **Attack Surface Metrics**: Ports, paths, subdomains, tech fingerprint
- **Export Formats**: JSON, HTML report, CSV, Markdown
- **Executive Summary**: Critical/High/Medium/Low breakdown

### Technical Features
- **REST API**: Full API with authentication (API key generation)
- **Rate Limiting**: 60 requests/minute per client
- **Caching**: In-memory scan cache (300s TTL)
- **Concurrent Scanning**: Multi-threaded parallel execution
- **Dark/Light Mode**: Persistent theme preference
- **Responsive Design**: Desktop, tablet, mobile
- **Docker Support**: Containerized deployment
- **CI/CD**: GitHub Actions with linting, testing, coverage

## Quick Start

### Local Installation
```bash
git clone <repo> Webinfo
cd Webinfo
pip install -r requirements.txt
python backend.py
```

### Docker
```bash
docker build -t webinfo .
docker run -p 5000:5000 webinfo
```

### Docker Compose
```bash
docker-compose up --build
```

## Usage

1. Open **http://localhost:5000** in your browser
2. Enter a target URL (e.g., `https://example.com`)
3. Select scan modules (Port Scan, Subdomains, Sensitive Paths, etc.)
4. Click **Scan Target**
5. View results: security score, vulnerabilities, DNS, SSL, headers, ports, tech
6. Export reports: JSON, HTML, CSV, Markdown

### Dashboard
- Access at **http://localhost:5000/dashboard**
- Vulnerability distribution chart (doughnut)
- Attack surface radar chart
- Quick scan from dashboard
- Recent scan history

### REST API
```bash
# Generate API key
curl -X POST http://localhost:5000/api/auth/generate

# Analyze a target
curl "http://localhost:5000/api/analyze?url=example.com"

# With API key
curl -H "X-API-Key: YOUR_KEY" "http://localhost:5000/api/analyze?url=example.com"

# Generate report
curl -X POST http://localhost:5000/api/report/generate?format=html \
  -H "Content-Type: application/json" \
  -d '{"hostname": "example.com", ...}'
```

## Architecture

```
Webinfo/
├── backend.py              # Flask entry point
├── config.py               # Configuration management
├── app/
│   ├── __init__.py         # App factory
│   ├── scanners/           # Scan engine modules
│   │   ├── dns_scanner.py
│   │   ├── ssl_scanner.py
│   │   ├── http_scanner.py
│   │   ├── port_scanner.py
│   │   ├── tech_scanner.py
│   │   ├── vuln_scanner.py
│   │   ├── subdomain_scanner.py
│   │   ├── email_scanner.py
│   │   ├── sensitive_files.py
│   │   └── performance.py
│   ├── routes/             # API endpoints
│   │   ├── analyze.py
│   │   ├── reports.py
│   │   └── auth.py
│   ├── utils/              # Helpers
│   │   ├── cache.py
│   │   ├── rate_limiter.py
│   │   └── helpers.py
│   ├── templates/          # HTML views
│   └── static/             # CSS/JS
├── tests/                  # Unit tests
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## Requirements

- Python 3.10+
- Flask 3.0+
- See `requirements.txt` for full list

## Security & Ethics

- **Passive reconnaissance is the default** - no exploitation or destructive actions
- Active scans require explicit user permission
- Rate limiting prevents abuse
- API authentication for programmatic access
- Designed for authorized security testing and educational purposes only

---

**MADE BY PRIYANSHU PRAJAPAT**
