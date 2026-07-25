import time
import json
import concurrent.futures
from urllib.parse import urlparse
from flask import Blueprint, jsonify, request, render_template
from config import Config
from app.scanners import (
    DNSScanner, SSLScanner, HTTPScanner, PortScanner,
    TechScanner, VulnScanner, SubdomainScanner,
    EmailSecurityScanner, SensitiveFilesScanner, PerformanceScanner,
)
from app.utils.cache import scan_cache
from app.utils.rate_limiter import rate_limiter
from app.utils.helpers import calculate_security_score, get_grade, severity_order

analyze_bp = Blueprint("analyze", __name__)

@analyze_bp.route("/api/analyze", methods=["GET"])
def analyze():
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "URL parameter is required"}), 400

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return jsonify({"error": "Invalid URL"}), 400

    client_ip = request.remote_addr or "127.0.0.1"
    if not rate_limiter.is_allowed(client_ip):
        return jsonify({"error": "Rate limit exceeded. Try again later."}), 429

    cache_key = scan_cache.make_key(url)
    cached = scan_cache.get(cache_key)
    if cached:
        return jsonify(cached)

    start_time = time.time()
    results = {"url": url, "hostname": hostname}

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        f_dns = ex.submit(DNSScanner(hostname).scan)
        f_ssl = ex.submit(SSLScanner(hostname).scan)
        f_http = ex.submit(HTTPScanner(url).scan)
        f_ports = ex.submit(PortScanner(hostname, fast=True).scan)
        f_tech = ex.submit(TechScanner(url).scan)
        f_sub = ex.submit(SubdomainScanner(hostname).scan)
        f_email = ex.submit(EmailSecurityScanner(hostname).scan)
        f_sens = ex.submit(SensitiveFilesScanner(url).scan)
        f_perf = ex.submit(PerformanceScanner(url).scan)

        try: results["dns"] = f_dns.result(timeout=30)
        except: results["dns"] = {"error": "DNS scan timed out"}

        try: results["ssl"] = f_ssl.result(timeout=30)
        except: results["ssl"] = {"error": "SSL scan timed out"}

        try: results["http"] = f_http.result(timeout=25)
        except: results["http"] = {"error": "HTTP scan timed out"}

        try: results["open_ports"] = f_ports.result(timeout=40)
        except: results["open_ports"] = []

        try: results["technologies"] = f_tech.result(timeout=25)
        except: results["technologies"] = {"technologies": [], "count": 0}

        try: results["subdomains"] = f_sub.result(timeout=35)
        except: results["subdomains"] = {"total_found": 0, "resolved": []}

        try: results["email_security"] = f_email.result(timeout=20)
        except: results["email_security"] = {"grade": "N/A"}

        try: results["sensitive_paths"] = f_sens.result(timeout=65)
        except: results["sensitive_paths"] = []

        try: results["performance"] = f_perf.result(timeout=20)
        except: results["performance"] = {"error": "Performance scan timed out"}

    page_text = ""
    try:
        import requests
        r = requests.get(url, timeout=10, headers={"User-Agent": Config.USER_AGENT})
        page_text = r.text
    except:
        pass

    vuln_scanner = VulnScanner(
        url, hostname, page_text,
        results.get("http", {}),
        results.get("ssl", {}),
        results.get("technologies", {}).get("technologies", []),
    )
    vulnerabilities = vuln_scanner.scan()
    vulnerabilities.sort(key=severity_order)
    results["vulnerabilities"] = vulnerabilities

    score = calculate_security_score(vulnerabilities)
    results["security_score"] = score
    results["security_grade"] = get_grade(score)

    results["vulnerability_count"] = {
        "critical": sum(1 for v in vulnerabilities if v.get("severity") == "Critical"),
        "high": sum(1 for v in vulnerabilities if v.get("severity") == "High"),
        "medium": sum(1 for v in vulnerabilities if v.get("severity") == "Medium"),
        "low": sum(1 for v in vulnerabilities if v.get("severity") == "Low"),
        "total": len(vulnerabilities),
    }

    results["scan_time"] = round(time.time() - start_time, 1)
    results["scan_timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    tech_list = results.get("technologies", {}).get("technologies", [])
    results["attack_surface"] = {
        "open_ports": len(results.get("open_ports", [])),
        "exposed_paths": len(results.get("sensitive_paths", [])),
        "subdomains": results.get("subdomains", {}).get("total_found", 0),
        "technologies": len(tech_list),
        "cookies": len(results.get("http", {}).get("cookies", [])),
        "forms": 0,
        "dangerous_ports": sum(1 for p in results.get("open_ports", []) if p.get("dangerous")),
    }

    scan_cache.set(cache_key, results)
    return jsonify(results)

@analyze_bp.route("/")
def index():
    return render_template("index.html")

@analyze_bp.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")
