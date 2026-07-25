import json
import csv
import io
from datetime import datetime
from flask import Blueprint, jsonify, request, render_template_string, Response
from app.utils.helpers import get_grade, generate_report_id

reports_bp = Blueprint("reports", __name__, url_prefix="/api/report")

REPORT_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Security Report - {{ hostname }}</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0a14;color:#e0e0e0;max-width:1100px;margin:0 auto;padding:30px}
h1{background:linear-gradient(135deg,#00d4ff,#7b2ff7);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
h2{color:#7b2ff7;border-bottom:1px solid #2a2a3e;padding-bottom:8px;margin-top:30px}
.score-box{display:inline-block;padding:15px 30px;border-radius:12px;font-size:2em;font-weight:800;margin:10px 0}
.score-A{background:rgba(68,255,136,0.15);color:#44ff88;border:2px solid #44ff88}
.score-B{background:rgba(0,212,255,0.15);color:#00d4ff;border:2px solid #00d4ff}
.score-C{background:rgba(255,171,0,0.15);color:#ffab00;border:2px solid #ffab00}
.score-D{background:rgba(255,109,0,0.15);color:#ff6d00;border:2px solid #ff6d00}
.score-F{background:rgba(255,68,68,0.15);color:#ff4444;border:2px solid #ff4444}
table{width:100%;border-collapse:collapse;margin:10px 0}
td,th{padding:8px 10px;border-bottom:1px solid #1e1e3a;text-align:left;font-size:0.9em}
th{color:#7b2ff7}
.vuln-item{background:#12122a;border-left:4px solid #555;padding:10px 14px;margin:8px 0;border-radius:6px}
.vuln-critical{border-color:#ff4444}.vuln-high{border-color:#ff6d00}.vuln-medium{border-color:#ffab00}.vuln-low{border-color:#ffd600}
.sev{display:inline-block;padding:2px 8px;border-radius:10px;font-size:0.8em;font-weight:700}
.sev-critical{background:#ff1744;color:#fff}.sev-high{background:#ff6d00;color:#fff}
.sev-medium{background:#ffab00;color:#000}.sev-low{background:#ffd600;color:#000}
.footer{margin-top:40px;padding-top:20px;border-top:1px solid #2a2a3e;color:#555;font-size:0.85em;text-align:center}
@media print{body{background:#fff;color:#333}.vuln-item{background:#f5f5f5}}
</style></head>
<body>
<h1>Web Reconnaissance Report</h1>
<p style="color:#888">{{ hostname }} | {{ date }}</p>
<div class="score-box score-{{ grade }}">{{ score }}/100 ({{ grade }})</div>
<h2>Executive Summary</h2>
<p>Security assessment of <strong>{{ hostname }}</strong> completed on {{ date }}.
Total vulnerabilities found: <strong>{{ vuln_count }}</strong>.
Security score: <strong>{{ score }}/100</strong> (Grade {{ grade }}).</p>
{% if vuln_count > 0 %}
<p>Critical: {{ critical_count }}, High: {{ high_count }}, Medium: {{ medium_count }}, Low: {{ low_count }}</p>
{% endif %}
<h2>Vulnerability Breakdown</h2>
{% if vulnerabilities %}
{% for v in vulnerabilities %}
<div class="vuln-item vuln-{{ v.severity.lower() }}">
<strong>{{ v.type }}</strong>
<span class="sev sev-{{ v.severity.lower() }}">{{ v.severity }}</span>
<p style="color:#999;font-size:0.85em;margin:5px 0 0">{{ v.details }}</p>
{% if v.owasp %}<p style="color:#666;font-size:0.8em;margin:3px 0 0">OWASP: {{ v.owasp }}</p>{% endif %}
</div>
{% endfor %}
{% else %}
<p>No vulnerabilities detected.</p>
{% endif %}
<h2>DNS Records</h2>
<table>{% for k, v in dns_items %}<tr><td>{{ k }}</td><td>{{ v|join(", ") }}</td></tr>{% endfor %}</table>
<h2>SSL/TLS</h2>
<table>{% for k, v in ssl_items %}<tr><td>{{ k }}</td><td>{{ v }}</td></tr>{% endfor %}</table>
<h2>HTTP Security Headers</h2>
<table>{% for k, v in header_items %}<tr><td>{{ k }}</td><td>{{ v }}</td></tr>{% endfor %}</table>
<h2>Technologies</h2>
<p>{{ technologies|join(", ") if technologies else "None detected" }}</p>
<h2>Open Ports</h2>
<p>{{ port_summary if port_summary else "None found" }}</p>
<div class="footer">
<p>Report ID: {{ report_id }} | Generated: {{ date }}</p>
<p>MADE BY PRIYANSHU PRAJAPAT</p>
</div>
</body></html>"""

@reports_bp.route("/generate", methods=["POST"])
def generate_report():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Scan data required"}), 400

    fmt = request.args.get("format", "json")
    hostname = data.get("hostname", "unknown")
    vulns = data.get("vulnerabilities", [])
    score = data.get("security_score", 0)
    grade = get_grade(score)
    report_id = generate_report_id()
    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    critical = sum(1 for v in vulns if v.get("severity") == "Critical")
    high = sum(1 for v in vulns if v.get("severity") == "High")
    medium = sum(1 for v in vulns if v.get("severity") == "Medium")
    low = sum(1 for v in vulns if v.get("severity") == "Low")

    dns = data.get("dns_records", {}).get("records", {})
    ssl = data.get("ssl_info", {})
    headers = data.get("headers", {}).get("security_headers", {})
    tech = data.get("technologies", [])
    ports = data.get("open_ports", [])

    if fmt == "html":
        rendered = render_template_string(
            REPORT_HTML_TEMPLATE,
            hostname=hostname,
            date=date,
            score=score,
            grade=grade,
            vuln_count=len(vulns),
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            vulnerabilities=vulns,
            dns_items=[(k, v) for k, v in dns.items()],
            ssl_items=[(k, str(v)) for k, v in ssl.items() if v and k != "san_list"],
            header_items=[(k, v.get("value", "MISSING")) for k, v in headers.items()],
            technologies=tech if isinstance(tech, list) else (tech.get("technologies", []) if isinstance(tech, dict) else []),
            port_summary=", ".join([f"{p['port']}/{p['service']}" for p in ports[:20]]),
            report_id=report_id,
        )
        return Response(rendered, mimetype="text/html",
                        headers={"Content-Disposition": f"attachment; filename=report_{hostname}.html"})

    elif fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Type", "Severity", "Details", "OWASP"])
        for v in vulns:
            writer.writerow([v.get("type", ""), v.get("severity", ""), v.get("details", ""), v.get("owasp", "")])
        return Response(output.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename=report_{hostname}.csv"})

    elif fmt == "markdown":
        md = f"# Security Report: {hostname}\n\n"
        md += f"**Date:** {date}  \n**Score:** {score}/100 (Grade {grade})  \n**Total Vulns:** {len(vulns)}  \n\n"
        if vulns:
            md += "## Vulnerabilities\n\n"
            for v in vulns:
                md += f"### {v.get('type')} [{v.get('severity')}]\n{v.get('details')}\n\n"
        return Response(md, mimetype="text/markdown",
                        headers={"Content-Disposition": f"attachment; filename=report_{hostname}.md"})

    return jsonify({
        "report_id": report_id,
        "hostname": hostname,
        "date": date,
        "score": score,
        "grade": grade,
        "vulnerability_count": {"critical": critical, "high": high, "medium": medium, "low": low, "total": len(vulns)},
        "vulnerabilities": vulns,
    })
