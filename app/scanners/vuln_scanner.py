import re
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from config import Config

OWASP_MAPPING = {
    "SQL Injection": "A03:2021 – Injection",
    "XSS": "A03:2021 – Injection",
    "Path Traversal": "A01:2021 – Broken Access Control",
    "Security Misconfiguration": "A05:2021 – Security Misconfiguration",
    "Sensitive Data Exposure": "A04:2021 – Sensitive Data Exposure",
    "Broken Authentication": "A07:2021 – Identification and Authentication Failures",
    "CORS Misconfiguration": "A01:2021 – Broken Access Control",
    "Missing HSTS": "A05:2021 – Security Misconfiguration",
    "Missing CSP": "A03:2021 – Injection",
    "Open Redirect": "A01:2021 – Broken Access Control",
    "Directory Listing": "A01:2021 – Broken Access Control",
    "Information Disclosure": "A04:2021 – Sensitive Data Exposure",
    "Weak SSL/TLS": "A02:2021 – Cryptographic Failures",
    "Cookie Without Secure": "A04:2021 – Sensitive Data Exposure",
    "Cookie Without HttpOnly": "A05:2021 – Security Misconfiguration",
}

class VulnScanner:
    def __init__(self, url, hostname, page_text, headers_info, ssl_info, tech):
        self.url = url
        self.hostname = hostname
        self.page_text = page_text
        self.headers_info = headers_info
        self.ssl_info = ssl_info
        self.tech = tech
        self.findings = []

    def scan(self):
        self._check_security_headers()
        self._check_ssl_issues()
        self._check_info_disclosure()
        self._check_sqli()
        self._check_xss()
        self._check_path_traversal()
        self._check_open_redirect()
        self._check_emails()
        self._check_comments()
        self._check_cookies()
        self._check_cors()
        self._check_dir_listing()
        self._check_insecure_forms()
        self._check_open_ports_risks()
        self._map_owasp()
        return self.findings

    def _add(self, vuln_type, severity, details, owasp=None):
        self.findings.append({
            "type": vuln_type,
            "severity": severity,
            "details": details,
            "owasp": owasp or OWASP_MAPPING.get(vuln_type, "General"),
        })

    def _check_security_headers(self):
        sh = self.headers_info.get("security_headers", {})
        checks = [
            ("strict-transport-security", "Missing HSTS", "Medium",
             "HTTP Strict-Transport-Security header missing. Vulnerable to SSL stripping and downgrade attacks. "
             "Fix: Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` header."),
            ("x-frame-options", "Missing X-Frame-Options", "Medium",
             "X-Frame-Options header missing. Vulnerable to clickjacking attacks. "
             "Fix: Add `X-Frame-Options: DENY` or `SAMEORIGIN` header."),
            ("x-content-type-options", "Missing X-Content-Type-Options", "Low",
             "X-Content-Type-Options header missing. Vulnerable to MIME type sniffing. "
             "Fix: Add `X-Content-Type-Options: nosniff` header."),
            ("content-security-policy", "Missing CSP", "High",
             "Content-Security-Policy header missing. Vulnerable to XSS and data injection attacks. "
             "Fix: Add a CSP header with appropriate directives."),
            ("referrer-policy", "Missing Referrer-Policy", "Low",
             "Referrer-Policy header missing. Referrer information may leak in cross-origin requests. "
             "Fix: Add `Referrer-Policy: strict-origin-when-cross-origin`."),
            ("permissions-policy", "Missing Permissions-Policy", "Low",
             "Permissions-Policy header missing. No feature policy restrictions enforced. "
             "Fix: Add a Permissions-Policy header restricting unused features."),
        ]
        for key, vtype, sev, msg in checks:
            if isinstance(sh.get(key), dict) and not sh[key].get("present", False):
                self._add(vtype, sev, msg)
            elif sh.get(key) == "MISSING":
                self._add(vtype, sev, msg)

    def _check_ssl_issues(self):
        if not self.ssl_info:
            self._add("No SSL/TLS", "Critical",
                       "Website does not use HTTPS. All data transmitted in cleartext. "
                       "Fix: Install an SSL certificate and redirect HTTP to HTTPS.",
                       "A02:2021 – Cryptographic Failures")
            return

        if self.ssl_info.get("error"):
            self._add("SSL Connection Error", "High",
                       f"Could not establish SSL connection: {self.ssl_info['error']}",
                       "A02:2021 – Cryptographic Failures")
            return

        if self.ssl_info.get("expired"):
            self._add("SSL Certificate Expired", "Critical",
                       f"SSL certificate expired {abs(self.ssl_info['days_remaining'])} days ago. "
                       "Fix: Renew the SSL certificate immediately.",
                       "A02:2021 – Cryptographic Failures")

        if self.ssl_info.get("expiring_soon"):
            self._add("SSL Certificate Expiring Soon", "Medium",
                       f"SSL certificate expires in {self.ssl_info['days_remaining']} days. "
                       "Fix: Renew the SSL certificate before expiry.",
                       "A02:2021 – Cryptographic Failures")

        if self.ssl_info.get("self_signed"):
            self._add("Self-Signed Certificate", "High",
                       "SSL certificate is self-signed. Browsers will show security warnings. "
                       "Fix: Use a certificate from a trusted CA.",
                       "A02:2021 – Cryptographic Failures")

        tls = (self.ssl_info.get("tls_version") or "").lower()
        if "tlsv1" in tls and "tlsv1.3" not in tls and "tlsv1.2" not in tls:
            self._add("Weak TLS Version", "High",
                       f"Server uses {self.ssl_info['tls_version']} which is deprecated. "
                       "Fix: Disable TLS 1.0/1.1, enable TLS 1.2 and 1.3.",
                       "A02:2021 – Cryptographic Failures")

    def _check_info_disclosure(self):
        server = self.headers_info.get("server", "")
        if server and server not in ("Unknown", None):
            self._add("Server Info Disclosure", "Medium",
                       f"Server header exposes: {server}. This helps attackers identify vulnerable software. "
                       "Fix: Obfuscate or remove the Server header.")

        powered = self.headers_info.get("x_powered_by", "")
        if powered and powered not in ("Unknown", None):
            self._add("Technology Info Disclosure", "Low",
                       f"X-Powered-By header exposes: {powered}. "
                       "Fix: Remove or obfuscate the X-Powered-By header.")

    def _check_sqli(self):
        try:
            parsed = urlparse(self.url)
            params = {"test": "' OR '1'='1"}
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
            r = requests.get(test_url, params=params, timeout=8, headers={"User-Agent": Config.USER_AGENT})
            errors = ["sql", "mysql", "syntax error", "unclosed quotation", "odbc", "driver error",
                      "ora-", "microsoft ole db", "postgresql", "sqlite"]
            if any(e in r.text.lower() for e in errors):
                self._add("Possible SQL Injection", "Critical",
                          "SQL injection may be possible. Parameters reflected with database error messages. "
                          "Fix: Use parameterized queries and input validation.",
                          "A03:2021 – Injection")
        except:
            pass

    def _check_xss(self):
        try:
            parsed = urlparse(self.url)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
            payload = "?<script>alert(1)</script>"
            r = requests.get(test_url + payload, timeout=8, headers={"User-Agent": Config.USER_AGENT})
            if "<script>alert(1)</script>" in r.text:
                self._add("Possible Reflected XSS", "Critical",
                          "Input is reflected unsanitized in HTTP response. "
                          "Fix: Properly encode all user-supplied data in output.",
                          "A03:2021 – Injection")
        except:
            pass

    def _check_path_traversal(self):
        try:
            parsed = urlparse(self.url)
            root = f"{parsed.scheme}://{parsed.netloc}"
            r = requests.get(root + "/%2e%2e%2f%2e%2e%2fetc/passwd", timeout=8,
                             headers={"User-Agent": Config.USER_AGENT})
            if "root:" in r.text and "nobody:" in r.text:
                self._add("Path Traversal / LFI", "Critical",
                          "Path traversal vulnerability detected via encoded path. "
                          "Fix: Validate and sanitize file path inputs.",
                          "A01:2021 – Broken Access Control")
        except:
            pass

    def _check_open_redirect(self):
        test_urls = ["//evil.com", "https://evil.com", "//evil.com%2F"]
        parsed = urlparse(self.url)
        root = f"{parsed.scheme}://{parsed.netloc}"
        for tu in test_urls:
            try:
                r = requests.get(root + "/?" + tu, timeout=5, allow_redirects=False,
                                 headers={"User-Agent": Config.USER_AGENT})
                loc = r.headers.get("Location", "")
                if "evil.com" in loc:
                    self._add("Open Redirect", "High",
                              f"Open redirect vulnerability: {tu} redirects to external domain. "
                              "Fix: Validate and whitelist redirect URLs.",
                              "A01:2021 – Broken Access Control")
                    break
            except:
                pass

    def _check_emails(self):
        if not self.page_text:
            return
        emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', self.page_text))
        emails = {e for e in emails if not e.endswith(('.png', '.jpg', '.gif', '.css', '.js', '.svg', '.ico'))
                  and not e.startswith(('note@', 'example@', 'user@', 'test@'))}
        if emails:
            self._add("Email Address Disclosure", "Low",
                       f"Email addresses found in page source: {', '.join(list(emails)[:8])}. "
                       "Fix: Remove plaintext email addresses or obfuscate them.",
                       "A04:2021 – Sensitive Data Exposure")

    def _check_comments(self):
        if not self.page_text:
            return
        comments = re.findall(r'<!--(.*?)-->', self.page_text, re.DOTALL)
        keywords = ['todo', 'fixme', 'hack', 'password', 'secret', 'key', 'api', 'token',
                     'credential', 'vuln', 'bug', 'admin', 'db_', 'sql', 'pass', 'username',
                     'delete', 'remove', 'update', 'hack', 'exploit']
        sensitive = [c.strip() for c in comments if any(k in c.lower() for k in keywords)]
        if sensitive:
            self._add("Sensitive HTML Comments", "Medium",
                       f"Sensitive comments found: {sensitive[:5]}. "
                       "Fix: Remove sensitive comments from production HTML.",
                       "A04:2021 – Sensitive Data Exposure")

    def _check_cookies(self):
        cookies = self.headers_info.get("cookies", [])
        for c in cookies:
            if not c.get("secure"):
                self._add(f"Insecure Cookie: {c['name']}", "Medium",
                          f"Cookie '{c['name']}' missing Secure flag. Sent over unencrypted HTTP. "
                          "Fix: Add the Secure flag to all cookies.",
                          "A04:2021 – Sensitive Data Exposure")
            if not c.get("httponly"):
                self._add(f"Non-HttpOnly Cookie: {c['name']}", "Medium",
                          f"Cookie '{c['name']}' missing HttpOnly flag. Accessible via JavaScript. "
                          "Fix: Add the HttpOnly flag to all cookies.",
                          "A05:2021 – Security Misconfiguration")

    def _check_cors(self):
        cors = self.headers_info.get("cors", {})
        if cors.get("is_permissive"):
            self._add("CORS Misconfiguration", "Medium",
                      f"CORS allows arbitrary origins: {cors.get('access_control_allow_origin')}. "
                      "Fix: Restrict CORS to specific trusted origins.",
                      "A01:2021 – Broken Access Control")

    def _check_dir_listing(self):
        parsed = urlparse(self.url)
        root = f"{parsed.scheme}://{parsed.netloc}"
        dirs = ["/images/", "/css/", "/js/", "/uploads/", "/assets/", "/static/", "/backup/", "/logs/"]
        for d in dirs:
            try:
                r = requests.get(root + d, timeout=5, headers={"User-Agent": Config.USER_AGENT})
                if r.status_code == 200 and any(x in r.text for x in ["Index of", "Directory listing", "<title>Index of"]):
                    self._add("Directory Listing Enabled", "Medium",
                              f"Directory listing enabled at: {d}. Exposes file structure to attackers. "
                              "Fix: Disable directory listing on the web server.",
                              "A01:2021 – Broken Access Control")
                    break
            except:
                pass

    def _check_insecure_forms(self):
        if not self.page_text:
            return
        soup = BeautifulSoup(self.page_text, "html.parser")
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").upper()
            password_inputs = form.find_all("input", type="password")
            if password_inputs and not action.startswith("https"):
                self._add("Password Form Over HTTP", "Critical",
                          "A password form submits data over unencrypted HTTP. "
                          "Fix: Ensure all forms with sensitive data use HTTPS.",
                          "A02:2021 – Cryptographic Failures")
            if password_inputs and method != "POST":
                self._add("Password Form Uses GET", "High",
                          "A password form uses the GET method. Credentials exposed in URL. "
                          "Fix: Use POST method for login forms.",
                          "A04:2021 – Sensitive Data Exposure")

    def _check_open_ports_risks(self):
        pass

    def _map_owasp(self):
        for f in self.findings:
            if "owasp" not in f:
                f["owasp"] = OWASP_MAPPING.get(f["type"], "General")
