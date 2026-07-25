import requests
import json
import concurrent.futures
from urllib.parse import urlparse
from config import Config

COMMON_SUBDOMAINS = [
    "www", "mail", "admin", "api", "blog", "dev", "test", "staging",
    "app", "m", "mobile", "web", "secure", "portal", "shop", "store",
    "cdn", "static", "assets", "img", "images", "css", "js",
    "docs", "help", "support", "status", "forum", "community",
    "wiki", "git", "github", "bitbucket", "jenkins", "ci",
    "vpn", "remote", "ssh", "ftp", "smtp", "imap", "pop3",
    "webmail", "mail2", "smtp2", "mx", "ns1", "ns2", "ns3",
    "db", "mysql", "database", "redis", "mongo", "elastic",
    "backup", "logs", "monitor", "grafana", "kibana", "prometheus",
    "dashboard", "adminer", "phpmyadmin", "pma", "phpPgAdmin",
    "demo", "sandbox", "beta", "alpha", "release", "production",
    "stage", "qa", "testing", "preview", "new", "old",
    "v2", "v3", "api2", "api3", "graphql", "swagger",
    "redmine", "mantis", "bugzilla", "jira", "confluence",
    "s3", "storage", "files", "upload", "download", "media",
    "stream", "video", "tv", "radio", "music",
    "news", "events", "calendar", "booking", "tickets",
    "accounts", "login", "signup", "register", "password",
    "terms", "privacy", "about", "contact", "careers", "jobs",
    "partners", "affiliates", "vendors", "suppliers",
    "analytics", "tracking", "stats", "metrics",
    "cache", "proxy", "lb", "loadbalancer",
    "ns1", "ns2", "auth", "ldap", "radius",
    "dns", "dns1", "dns2", "dnsserver",
    "ssh", "sftp", "transfer", "data",
    "monitor", "nagios", "zabbix", "munin",
    "kibana", "logstash", "filebeat", "metricbeat",
    "docker", "k8s", "kubernetes", "swarm", "rancher",
    "jenkins2", "teamcity", "bamboo", "circleci", "travis",
    "sonar", "sonarqube", "nexus", "artifactory",
    "gitlab", "gitea", "gogs", "gitweb",
    "learning", "learn", "training", "edu",
    "api-docs", "apidocs", "documentation", "devportal",
    "service", "services", "webhook", "hooks",
]

class SubdomainScanner:
    def __init__(self, hostname):
        self.hostname = hostname
        self.tld = ".".join(hostname.split(".")[-2:]) if len(hostname.split(".")) >= 2 else hostname

    def scan(self):
        found = {}
        ct_logs = self._crtsh_search()
        if ct_logs:
            found["certificate_transparency"] = ct_logs

        common_found = self._bruteforce_common()
        if common_found:
            found["common_bruteforce"] = common_found

        ip_results = {}
        found_subdomains = []
        all_subdomains = []

        if ct_logs:
            all_subdomains.extend(ct_logs)
        if common_found:
            all_subdomains.extend(common_found)

        resolved = self._resolve_subdomains(all_subdomains[:50])
        found["resolved"] = resolved
        found["total_found"] = len(set(all_subdomains))
        found["total_resolved"] = len(resolved)

        return found

    def _crtsh_search(self):
        try:
            r = requests.get(
                f"https://crt.sh/?q=%.{self.tld}&output=json",
                timeout=15,
                headers={"User-Agent": Config.USER_AGENT},
            )
            if r.status_code == 200:
                data = r.json()
                subdomains = set()
                for entry in data[:100]:
                    name = entry.get("name_value", "")
                    for n in name.split("\n"):
                        n = n.strip().lower()
                        if n.endswith(self.tld) and n != self.tld and "*" not in n:
                            subdomains.add(n)
                return sorted(subdomains)[:30]
        except:
            pass
        return []

    def _bruteforce_common(self):
        found = []
        def check(sub):
            try:
                import dns.resolver
                answers = dns.resolver.resolve(f"{sub}.{self.tld}", "A", lifetime=3)
                if answers:
                    return f"{sub}.{self.tld}"
            except:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(check, s): s for s in COMMON_SUBDOMAINS}
            for future in concurrent.futures.as_completed(futures, timeout=30):
                result = future.result()
                if result:
                    found.append(result)
        return found

    def _resolve_subdomains(self, subs):
        resolved = []
        def resolve(sub):
            try:
                import dns.resolver
                answers = dns.resolver.resolve(sub, "A", lifetime=3)
                ip = str(answers[0])
                return {"subdomain": sub, "ip": ip}
            except:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            futures = {ex.submit(resolve, s): s for s in subs[:50]}
            for future in concurrent.futures.as_completed(futures, timeout=20):
                result = future.result()
                if result:
                    resolved.append(result)
        return sorted(resolved, key=lambda x: x["subdomain"])
