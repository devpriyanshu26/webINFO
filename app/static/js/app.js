let scanStartTime;
let scanTimer;

function toggleTheme() {
    const html = document.documentElement;
    const current = html.getAttribute("data-theme");
    const next = current === "dark" ? "light" : "dark";
    html.setAttribute("data-theme", next);
    document.getElementById("themeIcon").textContent = next === "dark" ? "\u260C" : "\u2600";
    localStorage.setItem("theme", next);
}

const savedTheme = localStorage.getItem("theme");
if (savedTheme) {
    document.documentElement.setAttribute("data-theme", savedTheme);
    document.getElementById("themeIcon").textContent = savedTheme === "dark" ? "\u260C" : "\u2600";
}

async function startScan() {
    const url = document.getElementById("urlInput").value.trim();
    if (!url) { alert("Please enter a URL"); return; }

    const btn = document.getElementById("scanBtn");
    const loading = document.getElementById("loading");
    const results = document.getElementById("results");

    btn.disabled = true;
    results.classList.add("hidden");
    loading.classList.remove("hidden");

    scanStartTime = Date.now();
    resetProgress();
    startTimer();

    try {
        const apiUrl = "/api/analyze?url=" + encodeURIComponent(url);
        const res = await fetch(apiUrl);
        const data = await res.json();
        clearInterval(scanTimer);

        if (data.error) {
            results.innerHTML = `<div class="error">${escape(data.error)}</div>`;
        } else {
            renderResults(data);
        }
    } catch (e) {
        clearInterval(scanTimer);
        results.innerHTML = `<div class="error">Connection Error: ${escape(e.message)}</div>`;
    }

    btn.disabled = false;
    loading.classList.add("hidden");
    results.classList.remove("hidden");
    updateProgress("all", "done");
}

function resetProgress() {
    ["Dns", "Ssl", "Http", "Ports", "Tech", "Subs", "Vulns"].forEach(s => {
        const el = document.getElementById("s" + s);
        if (el) { el.className = "stat-dot waiting"; el.style.color = ""; }
    });
    document.getElementById("progressFill").style.width = "0%";
    document.getElementById("scanStatus").textContent = "Scanning target...";
}

function startTimer() {
    scanTimer = setInterval(() => {
        const elapsed = Math.floor((Date.now() - scanStartTime) / 1000);
        document.getElementById("scanTimer").textContent = elapsed + "s";
        const pct = Math.min(90, elapsed * 3);
        document.getElementById("progressFill").style.width = pct + "%";
    }, 200);
}

function updateProgress(module, status) {
    const el = document.getElementById("s" + module);
    if (el) el.className = "stat-dot " + status;
}

function escape(t) {
    if (t === 0 || t === false) return String(t);
    if (!t) return "N/A";
    return String(t).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

function table(rows) {
    if (!rows || !rows.length) return '<div class="empty">No data</div>';
    return '<table>' + rows.map(r => '<tr><td>' + r[0] + '</td><td>' + r[1] + '</td></tr>').join('') + '</table>';
}

function sev(s) {
    const m = {Critical:'critical',High:'high',Medium:'medium',Low:'low'};
    const c = m[s] || 'low';
    return '<span class="sev-badge ' + c + '">' + s + '</span>';
}

function renderResults(d) {
    let html = '';
    const score = d.security_score || 0;
    const grade = d.security_grade || 'N/A';
    const vc = d.vulnerability_count || {};
    const sc = score >= 80 ? '#44ff88' : score >= 60 ? '#ffab00' : score >= 40 ? '#ff6d00' : '#ff4444';

    html += '<div class="score-hero">';
    html += '<div class="score-circle" style="border-color:' + sc + ';color:' + sc + '">';
    html += '<span class="score-num">' + score + '</span>';
    html += '<span class="score-grade">' + grade + '</span></div>';
    html += '<div class="score-meta">';
    html += '<div class="score-stat"><span class="num" style="color:#ff1744">' + (vc.critical||0) + '</span><span class="lbl">Critical</span></div>';
    html += '<div class="score-stat"><span class="num" style="color:#ff6d00">' + (vc.high||0) + '</span><span class="lbl">High</span></div>';
    html += '<div class="score-stat"><span class="num" style="color:#ffab00">' + (vc.medium||0) + '</span><span class="lbl">Medium</span></div>';
    html += '<div class="score-stat"><span class="num" style="color:#ffd600">' + (vc.low||0) + '</span><span class="lbl">Low</span></div>';
    html += '<div class="score-stat"><span class="num" style="color:var(--accent2)">' + (d.scan_time || 0) + 's</span><span class="lbl">Scan Time</span></div>';
    html += '</div></div>';

    html += '<div class="actions">';
    html += '<button onclick="exportJSON()">Export JSON</button>';
    html += '<button onclick="exportHTML()">Export HTML Report</button>';
    html += '<button onclick="exportMarkdown()">Export Markdown</button>';
    html += '<button onclick="exportCSV()">Export CSV</button>';
    html += '</div>';

    html += '<div class="grid">';

    html += card("Target Information", table([
        ["URL", escape(d.url)],
        ["Hostname", escape(d.hostname)],
        ["IP Address", escape((d.dns||{}).ip_address)],
        ["Reverse DNS", escape((d.dns||{}).reverse_dns)],
        ["Domain Age", ((d.dns||{}).domain_age_days || 0) + " days"],
        ["Scan Time", d.scan_time + "s"],
    ]));

    if (d.dns && d.dns.records) {
        html += card("DNS Records", renderDNS(d.dns));
    }

    if (d.dns && (d.dns.spf || d.dns.dmarc || d.dns.dkim)) {
        html += card("Email Security", renderEmail(d.dns, d.email_security));
    }

    if (d.subdomains) {
        html += card("Subdomains Found (" + (d.subdomains.total_found||0) + ")", renderSubdomains(d.subdomains));
    }

    if (d.ssl) {
        html += card("SSL/TLS Certificate (" + (d.ssl.grade||'N/A') + ")", renderSSL(d.ssl));
    }

    if (d.http) {
        html += card("HTTP Security Headers", renderHeaders(d.http));
    }

    if (d.technologies && d.technologies.technologies && d.technologies.technologies.length) {
        html += card("Technologies (" + d.technologies.count + ")",
            d.technologies.technologies.map(t => '<span class="tech-badge">' + escape(t) + '</span>').join(' '));
    }

    if (d.vulnerabilities && d.vulnerabilities.length) {
        html += card("Vulnerabilities (" + d.vulnerabilities.length + ")", renderVulns(d.vulnerabilities));
    }

    if (d.open_ports && d.open_ports.length) {
        html += card("Open Ports (" + d.open_ports.length + ")", renderPorts(d.open_ports));
    }

    if (d.sensitive_paths && d.sensitive_paths.length) {
        html += card("Sensitive Paths (" + d.sensitive_paths.length + ")", renderPaths(d.sensitive_paths));
    }

    if (d.performance) {
        html += card("Performance &amp; SEO", renderPerformance(d.performance));
    }

    html += '</div>';

    window._scanData = d;
    document.getElementById("results").innerHTML = html;
}

function card(title, content) {
    return '<div class="card"><h2>' + title + '</h2>' + content + '</div>';
}

function renderDNS(dns) {
    let html = '';
    const records = dns.records || {};
    for (const [k, v] of Object.entries(records)) {
        if (v && v.length) {
            html += '<div class="dns-record"><span class="dns-type">' + escape(k) + '</span><span class="dns-value">' + escape(v.join(', ')) + '</span></div>';
        }
    }
    return html || '<div class="empty">No records found</div>';
}

function renderEmail(dns, email) {
    let html = '<h3>SPF</h3>';
    if (dns.spf && dns.spf.present) {
        html += '<div class="dns-record"><span class="dns-type" style="background:rgba(68,255,136,0.12);color:#44ff88">OK</span><span class="dns-value">' + escape(dns.spf.raw) + '</span></div>';
    } else {
        html += '<div class="dns-record"><span class="dns-type" style="background:rgba(255,68,68,0.12);color:#ff4444">MISS</span><span class="dns-value">No SPF record found</span></div>';
    }

    html += '<h3>DKIM</h3>';
    if (dns.dkim && dns.dkim.present) {
        html += '<div class="dns-record"><span class="dns-type" style="background:rgba(68,255,136,0.12);color:#44ff88">OK</span><span class="dns-value">Selector: ' + escape(dns.dkim.selector) + '</span></div>';
    } else {
        html += '<div class="dns-record"><span class="dns-type" style="background:rgba(255,68,68,0.12);color:#ff4444">MISS</span><span class="dns-value">No DKIM record found</span></div>';
    }

    html += '<h3>DMARC</h3>';
    if (dns.dmarc && dns.dmarc.present) {
        html += '<div class="dns-record"><span class="dns-type" style="background:rgba(68,255,136,0.12);color:#44ff88">OK</span><span class="dns-value">Policy: ' + escape(dns.dmarc.policy) + '</span></div>';
    } else {
        html += '<div class="dns-record"><span class="dns-type" style="background:rgba(255,68,68,0.12);color:#ff4444">MISS</span><span class="dns-value">No DMARC record found</span></div>';
    }

    if (email && email.grade) {
        html += '<p style="margin-top:10px;font-size:0.85em">Email Security Grade: <strong>' + email.grade + '</strong></p>';
    }
    return html;
}

function renderSubdomains(sub) {
    if (!sub.resolved || !sub.resolved.length) return '<div class="empty">No subdomains found</div>';
    return sub.resolved.map(s =>
        '<div class="sub-item"><span>' + escape(s.subdomain) + '</span><span style="color:var(--text2)">' + escape(s.ip) + '</span></div>'
    ).join('');
}

function renderSSL(ssl) {
    if (ssl.error) return '<div class="empty">' + escape(ssl.error) + '</div>';
    const rows = [];
    for (const [k, v] of Object.entries(ssl)) {
        if (k === 'san_list' || k === 'grade') continue;
        if (v === null || v === undefined) continue;
        let val = v;
        if (typeof val === 'object') val = JSON.stringify(val);
        rows.push(['<span class="key">' + k.replace(/_/g, ' ') + '</span>', escape(val)]);
    }
    return table(rows);
}

function renderHeaders(http) {
    let html = '';
    const sh = http.security_headers || {};
    let present = [], missing = [];
    for (const [k, v] of Object.entries(sh)) {
        const val = typeof v === 'object' ? (v.present ? v.value : 'MISSING') : v;
        if (val === 'MISSING' || val === 'Missing') missing.push(k);
        else present.push([k, val]);
    }

    if (missing.length) {
        html += '<h3>Missing Security Headers</h3>';
        html += missing.map(k => '<div class="header-item"><span>' + escape(k) + '</span><span class="hdr-missing">MISSING</span></div>').join('');
    }
    if (present.length) {
        html += '<h3>Present</h3>';
        html += present.map(([k, v]) => '<div class="header-item"><span>' + escape(k) + '</span><span class="hdr-present">' + escape(typeof v === 'string' ? v.slice(0,80) : v) + '</span></div>').join('');
    }
    if (http.hsts && http.hsts.enabled) {
        html += '<h3>HSTS Details</h3>' + table([
            ['Max-Age', http.hsts.max_age + 's (' + Math.floor(http.hsts.max_age/86400) + ' days)'],
            ['Include Subdomains', http.hsts.include_subdomains ? 'Yes' : 'No'],
            ['Preload', http.hsts.preload ? 'Yes' : 'No'],
        ]);
    }
    if (http.cookies && http.cookies.length) {
        html += '<h3>Cookies (' + http.cookies.length + ')</h3>';
        html += http.cookies.map(c => {
            const flags = [c.secure && 'Secure', c.httponly && 'HttpOnly', c.samesite && 'SameSite='+c.samesite].filter(Boolean).join(' ');
            return '<div class="cookie-item"><span>' + escape(c.name) + '</span><span class="cookie-flags">' + flags + '</span></div>';
        }).join('');
    }
    if (http.http_methods && http.http_methods.length) {
        html += '<h3>HTTP Methods</h3><p style="font-size:0.85em">' + http.http_methods.join(', ') + '</p>';
    }
    return html || '<div class="empty">No header data</div>';
}

function renderVulns(vulns) {
    return vulns.map(v => {
        const sev = (v.severity || '').toLowerCase();
        return '<div class="vuln-item ' + sev + '">' +
            '<div class="vuln-header"><span class="vuln-type">' + escape(v.type) + '</span>' + sevBadge(v.severity) + '</div>' +
            '<div class="vuln-details">' + escape(v.details) + '</div>' +
            (v.owasp ? '<div class="vuln-owasp">' + escape(v.owasp) + '</div>' : '') +
            '</div>';
    }).join('');
}

function sevBadge(s) {
    const m = {Critical:'critical',High:'high',Medium:'medium',Low:'low'};
    return '<span class="sev-badge ' + (m[s]||'low') + '">' + s + '</span>';
}

function renderPorts(ports) {
    return '<div class="port-list">' + ports.map(p => {
        const cls = p.dangerous ? ' port-item dangerous' : '';
        return '<div class="port-item' + cls + '"><span class="port-num">' + p.port + '</span><span class="port-svc">' + escape(p.service) + '</span>' +
            (p.banner ? '<span class="port-banner">' + escape(p.banner) + '</span>' : '') + '</div>';
    }).join('') + '</div>';
}

function renderPaths(paths) {
    return '<div class="path-list">' + paths.map(p =>
        '<div class="path-item"><span class="path-url">' + escape(p.path) + '</span>' +
        '<span class="path-status code-' + p.status + '">' + p.status + '</span>' +
        '<span style="color:var(--text3);font-size:0.85em">' + (p.size_kb||0) + 'KB</span></div>'
    ).join('') + '</div>';
}

function renderPerformance(perf) {
    if (perf.error) return '<div class="empty">' + escape(perf.error) + '</div>';
    let html = table([
        ['Load Time', perf.load_time_ms + ' ms'],
        ['Response Size', perf.response_size_kb + ' KB'],
        ['Speed Grade', perf.speed_grade || 'N/A'],
    ]);
    if (perf.seo) {
        html += '<h3>SEO</h3>';
        html += table(Object.entries(perf.seo).map(([k, v]) => [k.replace(/_/g, ' '), typeof v === 'boolean' ? (v ? 'Yes' : 'No') : v]));
    }
    return html;
}

// Export functions
function exportJSON() {
    if (!window._scanData) return;
    const blob = new Blob([JSON.stringify(window._scanData, null, 2)], {type: 'application/json'});
    downloadBlob(blob, 'webinfo-report.json');
}

function exportHTML() {
    if (!window._scanData) return;
    fetch('/api/report/generate?format=html', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(window._scanData)
    }).then(r => r.blob()).then(b => downloadBlob(b, 'webinfo-report.html'));
}

function exportMarkdown() {
    if (!window._scanData) return;
    fetch('/api/report/generate?format=markdown', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(window._scanData)
    }).then(r => r.blob()).then(b => downloadBlob(b, 'webinfo-report.md'));
}

function exportCSV() {
    if (!window._scanData) return;
    fetch('/api/report/generate?format=csv', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(window._scanData)
    }).then(r => r.blob()).then(b => downloadBlob(b, 'webinfo-report.csv'));
}

function downloadBlob(blob, name) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
}

document.getElementById("urlInput").addEventListener("keydown", e => { if (e.key === "Enter") startScan(); });
