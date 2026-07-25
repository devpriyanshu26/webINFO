import requests
import re
from bs4 import BeautifulSoup
from config import Config

class TechScanner:
    def __init__(self, url):
        self.url = url

    def scan(self):
        try:
            r = requests.get(self.url, timeout=12, headers={"User-Agent": Config.USER_AGENT})
        except:
            return {"technologies": [], "cves": []}

        soup = BeautifulSoup(r.text, "html.parser")
        html = r.text.lower()
        headers = r.headers
        tech = []
        versions = {}

        cms_patterns = {
            "WordPress": ["/wp-content/", "/wp-includes/", "wordpress", "wp-json", "wp-admin"],
            "Joomla": ["joomla", "/components/", "/modules/", "com_content"],
            "Drupal": ["drupal", "/sites/default/", "drupal.js"],
            "Magento": ["/skin/frontend/", "mage/", "Magento"],
            "Shopify": ["myshopify.com", "/cdn/shop/", "Shopify"],
            "Wix": ["wix.com", "wixstatic.com", "WixEditor"],
            "Squarespace": ["squarespace.com", "squarespace"],
            "Ghost": ["ghost", "ghost.io"],
            "TYPO3": ["typo3"],
            "OctoberCMS": ["octobercms"],
        }

        framework_patterns = {
            "React": ["react", "reactroot", "__react", "react-dom"],
            "Angular": ["angular", "ng-version", "ng-app"],
            "Vue.js": ["vue", "vuejs", "v-bind", "v-model"],
            "Next.js": [".next", "__next", "next.js"],
            "Nuxt.js": ["nuxt"],
            "Svelte": ["svelte"],
            "jQuery": ["jquery", "jQuery"],
            "Bootstrap": ["bootstrap", "bootstrap-"],
            "Tailwind CSS": ["tailwind", "tailwindcss"],
            "Laravel": ["laravel", "csrf-token", "laravel_session"],
            "Django": ["django", "csrfmiddlewaretoken", "__admin"],
            "ASP.NET": ["asp.net", "__viewstate", "__eventvalidation"],
            "Ruby on Rails": ["rails", "ruby on rails", "csrf-param"],
            "Spring Boot": ["spring", "springboot"],
            "Symfony": ["symfony"],
            "Yii": ["yii", "yii.js"],
            "CodeIgniter": ["codeigniter"],
            "Express.js": ["express"],
            "Flask": ["flask"],
            "FastAPI": ["fastapi"],
            "Gatsby": ["gatsby", "_gatsby"],
            "SvelteKit": ["sveltekit"],
        }

        server = headers.get("Server", "").lower()
        powered = headers.get("X-Powered-By", "")
        generator = headers.get("X-Generator", "")

        server_map = {
            "nginx": "Nginx", "apache": "Apache", "cloudflare": "Cloudflare",
            "openresty": "OpenResty", "iis": "IIS", "caddy": "Caddy",
            "gunicorn": "Gunicorn", "lighttpd": "Lighttpd", "cowboy": "Cowboy",
            "varnish": "Varnish", "envoy": "Envoy", "traefik": "Traefik",
            "awselb": "AWS ELB", "amazon": "AWS", "googlefrontend": "GCP LB",
        }
        for key, name in server_map.items():
            if key in server:
                tech.append(name)

        for name, patterns in cms_patterns.items():
            if any(p in html for p in patterns):
                tech.append(name)
                self._try_extract_version(name, html, headers, soup, versions)

        for name, patterns in framework_patterns.items():
            if any(p in html for p in patterns):
                if name not in tech:
                    tech.append(name)
                    self._try_extract_version(name, html, headers, soup, versions)

        meta_generator = soup.find("meta", attrs={"name": "generator"})
        if meta_generator and meta_generator.get("content"):
            gen = meta_generator["content"].strip()
            if gen not in tech:
                tech.append(gen)

        if "cf-ray" in headers.get("cf-ray", "") or "cloudflare" in html:
            if "Cloudflare" not in tech:
                tech.append("Cloudflare")
        if "x-amz-" in str(headers).lower() or "aws" in html:
            if "AWS" not in tech:
                tech.append("AWS")

        if soup.find("meta", attrs={"name": "csrf-token"}) or soup.find("input", attrs={"name": "csrf_token"}):
            tech.append("CSRF Protection")

        if "json" in r.headers.get("Content-Type", ""):
            tech.append("REST API")

        if soup.find("link", rel="manifest"):
            tech.append("PWA")

        return {
            "technologies": sorted(list(set(tech))),
            "versions": versions,
            "server_banner": headers.get("Server", "N/A"),
            "x_powered_by": headers.get("X-Powered-By", "N/A"),
            "count": len(set(tech)),
        }

    def _try_extract_version(self, name, html, headers, soup, versions):
        patterns = {
            "WordPress": [r"ver=([\d.]+)", r"version/([\d.]+)", r"wordpress\s+([\d.]+)"],
            "jQuery": [r"jquery/v?([\d.]+)", r"jquery-([\d.]+)"],
            "Bootstrap": [r"bootstrap/v?([\d.]+)", r"bootstrap-([\d.]+)"],
            "Angular": [r"angular/v?([\d.]+)", r"ng-version=\"([\d.]+)"],
            "Vue.js": [r"vue/v?([\d.]+)", r"vue-([\d.]+)"],
            "React": [r"react/v?([\d.]+)", r"react@([\d.]+)"],
            "Drupal": [r"drupal/v?([\d.]+)", r"Drupal\s+([\d.]+)"],
            "Joomla": [r"joomla/v?([\d.]+)", r"Joomla\s+([\d.]+)"],
            "Laravel": [r"laravel/v?([\d.]+)"],
            "Nginx": [r"nginx/([\d.]+)"],
            "Apache": [r"Apache/([\d.]+)"],
            "IIS": [r"IIS/([\d.]+)"],
        }
        if name in patterns:
            for pat in patterns[name]:
                m = re.search(pat, html)
                if m:
                    versions[name] = m.group(1)
                    break
