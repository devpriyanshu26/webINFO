import os
import sys
from app import create_app

app = create_app(os.environ.get("FLASK_ENV", "development"))

if __name__ == "__main__":
    print("=" * 65)
    print("  WEBINFO - Professional Web Reconnaissance Platform")
    print("  Comprehensive Security Assessment Suite")
    print("=" * 65)
    print("  Modules:")
    print("   - DNS/WHOIS/SPF/DKIM/DMARC/DNSSEC Analysis")
    print("   - SSL/TLS Certificate Grading (A+ to F)")
    print("   - HTTP Security Headers & Cookie Audit")
    print("   - Technology & CVE Detection")
    print("   - Port Scanning (200+ ports)")
    print("   - Vulnerability Assessment (OWASP mapped)")
    print("   - Subdomain Enumeration (CT logs + DNS)")
    print("   - Email Security (MX/SPF/DKIM/DMARC)")
    print("   - Sensitive File Discovery (150+ paths)")
    print("   - Performance, SEO & Accessibility Checks")
    print("   - Security Scoring & Grading")
    print("   - Report Export (JSON/HTML/CSV/Markdown)")
    print("   - REST API with Auth & Rate Limiting")
    print("=" * 65)
    print(f"  Server: http://127.0.0.1:5000")
    print(f"  Dashboard: http://127.0.0.1:5000/dashboard")
    print("  MADE BY PRIYANSHU PRAJAPAT")
    print("=" * 65)
    app.run(debug=True, host="0.0.0.0", port=5000)
