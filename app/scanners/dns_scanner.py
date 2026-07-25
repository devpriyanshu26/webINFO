import socket
import dns.resolver
import dns.dnssec
import dns.name
import concurrent.futures
from datetime import datetime
from config import Config

class DNSScanner:
    def __init__(self, hostname):
        self.hostname = hostname
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = 5
        self.resolver.timeout = 3

    def scan(self):
        records = {}
        ip = None

        ip = self._get_a_record()
        records["A"] = self._resolve("A")
        records["AAAA"] = self._resolve("AAAA")
        records["MX"] = self._resolve("MX")
        records["NS"] = self._resolve("NS")
        records["TXT"] = self._resolve("TXT")
        records["CNAME"] = self._resolve("CNAME")
        records["SOA"] = self._resolve("SOA")
        records["SRV"] = self._resolve("SRV")
        records["CAA"] = self._resolve("CAA")
        records["PTR"] = self._resolve_ptr(ip) if ip else []

        spf = self._check_spf(records.get("TXT", []))
        dkim = self._check_dkim()
        dmarc = self._check_dmarc()
        dnssec = self._check_dnssec()
        domain_age = self._check_domain_age()

        return {
            "hostname": self.hostname,
            "ip_address": ip,
            "records": {k: v for k, v in records.items() if v},
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "dnssec": dnssec,
            "domain_age_days": domain_age,
            "reverse_dns": self._reverse_dns(ip) if ip else None,
        }

    def _get_a_record(self):
        try:
            return socket.gethostbyname(self.hostname)
        except:
            return None

    def _resolve(self, rtype):
        try:
            answers = self.resolver.resolve(self.hostname, rtype)
            return [str(r) for r in answers]
        except:
            return []

    def _resolve_ptr(self, ip):
        try:
            name = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(name, "PTR")
            return [str(r) for r in answers]
        except:
            return []

    def _reverse_dns(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return None

    def _check_spf(self, txt_records):
        for r in txt_records:
            if r.startswith("v=spf1"):
                return {"present": True, "raw": r, "valid": "all" in r}
        return {"present": False, "raw": None, "valid": False}

    def _check_dkim(self):
        for selector in ["default", "google", "dkim", "mail", "zoho", "protonmail", "sendgrid", "mailgun", "sparkpost"]:
            try:
                dkim_domain = f"{selector}._domainkey.{self.hostname}"
                answers = self.resolver.resolve(dkim_domain, "TXT")
                return {"present": True, "selector": selector, "raw": str(answers[0])}
            except:
                continue
        return {"present": False, "selector": None, "raw": None}

    def _check_dmarc(self):
        try:
            answers = self.resolver.resolve(f"_dmarc.{self.hostname}", "TXT")
            raw = str(answers[0])
            policy = "none"
            if "p=reject" in raw:
                policy = "reject"
            elif "p=quarantine" in raw:
                policy = "quarantine"
            return {"present": True, "raw": raw, "policy": policy}
        except:
            return {"present": False, "raw": None, "policy": "none"}

    def _check_dnssec(self):
        try:
            answers = self.resolver.resolve(self.hostname, "DNSKEY")
            return {"enabled": True, "records": len(answers)}
        except dns.resolver.NoAnswer:
            return {"enabled": False, "records": 0}
        except:
            return {"enabled": False, "records": 0}

    def _check_domain_age(self):
        try:
            import whois
            w = whois.whois(self.hostname)
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    cd = w.creation_date[0]
                else:
                    cd = w.creation_date
                if isinstance(cd, datetime):
                    delta = datetime.now() - cd
                    return delta.days
            return None
        except:
            return None
