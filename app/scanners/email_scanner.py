import dns.resolver

class EmailSecurityScanner:
    def __init__(self, hostname):
        self.hostname = hostname

    def scan(self):
        mx = self._get_mx()
        spf = self._get_spf()
        dmarc = self._get_dmarc()
        dkim = self._get_dkim()

        grade = self._calculate_grade(spf, dmarc, dkim, mx)

        return {
            "mx_records": mx,
            "spf": spf,
            "dmarc": dmarc,
            "dkim": dkim,
            "grade": grade,
            "has_email_security": spf.get("valid", False) and dmarc.get("present", False),
        }

    def _get_mx(self):
        try:
            answers = dns.resolver.resolve(self.hostname, "MX", lifetime=5)
            records = []
            for r in answers:
                records.append({
                    "preference": r.preference,
                    "exchange": str(r.exchange).rstrip("."),
                })
            return sorted(records, key=lambda x: x["preference"])
        except:
            return []

    def _get_spf(self):
        try:
            answers = dns.resolver.resolve(self.hostname, "TXT", lifetime=5)
            for r in answers:
                txt = str(r)
                if txt.startswith("v=spf1"):
                    return {
                        "present": True,
                        "raw": txt,
                        "valid": "all" in txt and ("-all" in txt or "~all" in txt),
                        "strict": "-all" in txt,
                        "softfail": "~all" in txt,
                        "neutral": "?all" in txt,
                    }
            return {"present": False, "raw": None, "valid": False, "strict": False}
        except:
            return {"present": False, "raw": None, "valid": False, "strict": False}

    def _get_dmarc(self):
        try:
            answers = dns.resolver.resolve(f"_dmarc.{self.hostname}", "TXT", lifetime=5)
            raw = str(answers[0])
            policy = "none"
            subdomain_policy = "none"
            pct = 100
            rua = None
            ruf = None
            sp = "none"
            adkim = "r"
            aspf = "r"

            for part in raw.split(";"):
                part = part.strip()
                if part.startswith("p="):
                    policy = part[2:].strip()
                elif part.startswith("sp="):
                    subdomain_policy = part[3:].strip()
                elif part.startswith("pct="):
                    try:
                        pct = int(part[4:].strip())
                    except:
                        pass
                elif part.startswith("rua="):
                    rua = part[4:].strip()
                elif part.startswith("ruf="):
                    ruf = part[4:].strip()

            return {
                "present": True,
                "raw": raw,
                "policy": policy,
                "subdomain_policy": subdomain_policy,
                "pct": pct,
                "rua": rua,
                "ruf": ruf,
                "strict": policy in ("reject", "quarantine"),
            }
        except:
            return {"present": False, "raw": None, "policy": "none", "strict": False}

    def _get_dkim(self):
        for selector in ["default", "google", "dkim", "mail", "zoho",
                         "protonmail", "sendgrid", "mailgun", "sparkpost",
                         "mandrill", "smtp", "postmark", "ses"]:
            try:
                answers = dns.resolver.resolve(f"{selector}._domainkey.{self.hostname}", "TXT", lifetime=3)
                return {"present": True, "selector": selector, "raw": str(answers[0])}
            except:
                continue
        return {"present": False, "selector": None, "raw": None}

    def _calculate_grade(self, spf, dmarc, dkim, mx):
        score = 0
        if mx: score += 10
        if spf.get("valid"): score += 20
        if spf.get("strict"): score += 10
        if dmarc.get("present"): score += 20
        if dmarc.get("strict"): score += 15
        if dkim.get("present"): score += 15
        if spf.get("valid") and dmarc.get("present") and dkim.get("present"):
            score += 10

        if score >= 90: return "A"
        elif score >= 70: return "B"
        elif score >= 50: return "C"
        elif score >= 30: return "D"
        else: return "F"
