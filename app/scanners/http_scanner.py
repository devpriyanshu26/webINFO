import requests
from urllib.parse import urlparse
from config import Config

class HTTPScanner:
    def __init__(self, url):
        self.url = url
        self.parsed = urlparse(url)

    def scan(self):
        result = {
            "url": self.url,
            "status_code": None,
            "server": None,
            "x_powered_by": None,
            "content_type": None,
            "content_length": None,
            "redirect_chain": [],
            "hsts": None,
            "security_headers": {},
            "headers_raw": {},
            "cookies": [],
            "http_methods": [],
            "caching": {},
            "compression": None,
            "cors": {},
        }

        try:
            r = requests.get(
                self.url,
                timeout=12,
                headers={"User-Agent": Config.USER_AGENT},
                allow_redirects=True,
            )
            result["status_code"] = r.status_code
            result["server"] = r.headers.get("Server")
            result["x_powered_by"] = r.headers.get("X-Powered-By")
            result["content_type"] = r.headers.get("Content-Type")
            result["content_length"] = r.headers.get("Content-Length")
            result["headers_raw"] = dict(r.headers)

            result["hsts"] = self._parse_hsts(r.headers.get("Strict-Transport-Security", ""))

            result["security_headers"] = {
                "strict-transport-security": {"value": r.headers.get("Strict-Transport-Security", "MISSING"), "present": "Strict-Transport-Security" in r.headers},
                "x-frame-options": {"value": r.headers.get("X-Frame-Options", "MISSING"), "present": "X-Frame-Options" in r.headers},
                "x-content-type-options": {"value": r.headers.get("X-Content-Type-Options", "MISSING"), "present": "X-Content-Type-Options" in r.headers},
                "content-security-policy": {"value": r.headers.get("Content-Security-Policy", "MISSING"), "present": "Content-Security-Policy" in r.headers},
                "x-xss-protection": {"value": r.headers.get("X-XSS-Protection", "MISSING"), "present": "X-XSS-Protection" in r.headers},
                "referrer-policy": {"value": r.headers.get("Referrer-Policy", "MISSING"), "present": "Referrer-Policy" in r.headers},
                "permissions-policy": {"value": r.headers.get("Permissions-Policy", "MISSING"), "present": "Permissions-Policy" in r.headers},
                "access-control-allow-origin": {"value": r.headers.get("Access-Control-Allow-Origin", "MISSING"), "present": "Access-Control-Allow-Origin" in r.headers},
                "cross-origin-embedder-policy": {"value": r.headers.get("Cross-Origin-Embedder-Policy", "MISSING"), "present": "Cross-Origin-Embedder-Policy" in r.headers},
                "cross-origin-opener-policy": {"value": r.headers.get("Cross-Origin-Opener-Policy", "MISSING"), "present": "Cross-Origin-Opener-Policy" in r.headers},
            }

            for c in r.cookies:
                result["cookies"].append({
                    "name": c.name,
                    "value": c.value[:40] + "..." if len(c.value) > 40 else c.value,
                    "domain": c.domain,
                    "path": c.path,
                    "secure": c.secure,
                    "httponly": c.has_nonstandard_attr("HttpOnly"),
                    "samesite": c.get_nonstandard_attr("SameSite", "N/A"),
                    "expires": str(c.expires) if c.expires else None,
                })

            if r.history:
                for h in r.history:
                    result["redirect_chain"].append({
                        "url": h.url,
                        "status_code": h.status_code,
                        "location": h.headers.get("Location", ""),
                    })

            result["compression"] = r.headers.get("Content-Encoding")
            result["caching"] = {
                "cache_control": r.headers.get("Cache-Control"),
                "pragma": r.headers.get("Pragma"),
                "expires": r.headers.get("Expires"),
                "etag": r.headers.get("ETag"),
                "last_modified": r.headers.get("Last-Modified"),
            }

            acao = r.headers.get("Access-Control-Allow-Origin", "")
            result["cors"] = {
                "access_control_allow_origin": acao,
                "access_control_allow_methods": r.headers.get("Access-Control-Allow-Methods"),
                "access_control_allow_headers": r.headers.get("Access-Control-Allow-Headers"),
                "is_permissive": acao == "*" or acao.startswith("http"),
            }

            result["http_methods"] = self._check_methods()

        except Exception as e:
            result["error"] = str(e)

        return result

    def _parse_hsts(self, hsts_str):
        if not hsts_str:
            return {"enabled": False, "max_age": 0, "include_subdomains": False, "preload": False}
        parts = hsts_str.split(";")
        result = {"enabled": True, "max_age": 0, "include_subdomains": False, "preload": False}
        for p in parts:
            p = p.strip()
            if p.startswith("max-age="):
                try:
                    result["max_age"] = int(p.split("=")[1])
                except:
                    pass
            elif p == "includeSubDomains":
                result["include_subdomains"] = True
            elif p == "preload":
                result["preload"] = True
        return result

    def _check_methods(self):
        methods = []
        try:
            r = requests.options(self.url, timeout=8, headers={"User-Agent": Config.USER_AGENT})
            allow = r.headers.get("Allow", "")
            if allow:
                methods = [m.strip() for m in allow.split(",")]
        except:
            pass
        return methods
