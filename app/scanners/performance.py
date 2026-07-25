import requests
import time
from config import Config

class PerformanceScanner:
    def __init__(self, url):
        self.url = url

    def scan(self):
        result = {"load_time_ms": None, "response_size": None, "seo": {}, "accessibility": {}}

        start = time.time()
        try:
            r = requests.get(self.url, timeout=15, headers={"User-Agent": Config.USER_AGENT})
            elapsed = (time.time() - start) * 1000
            result["load_time_ms"] = round(elapsed, 1)
            result["response_size"] = len(r.content)
            result["response_size_kb"] = round(len(r.content) / 1024, 1)
            result["status_code"] = r.status_code

            if elapsed < 500:
                result["speed_grade"] = "A"
            elif elapsed < 1500:
                result["speed_grade"] = "B"
            elif elapsed < 3000:
                result["speed_grade"] = "C"
            elif elapsed < 5000:
                result["speed_grade"] = "D"
            else:
                result["speed_grade"] = "F"

            result["seo"] = self._check_seo(r.text)
            result["accessibility"] = self._check_accessibility(r.text)

        except Exception as e:
            result["error"] = str(e)

        return result

    def _check_seo(self, html):
        import re
        seo = {}
        seo["has_title"] = bool(re.search(r'<title[^>]*>.*?</title>', html, re.IGNORECASE | re.DOTALL))
        seo["has_meta_description"] = bool(re.search(r'<meta[^>]*name=["\']description["\']', html, re.IGNORECASE))
        seo["has_meta_keywords"] = bool(re.search(r'<meta[^>]*name=["\']keywords["\']', html, re.IGNORECASE))
        seo["has_canonical"] = bool(re.search(r'<link[^>]*rel=["\']canonical["\']', html, re.IGNORECASE))
        seo["has_og_tags"] = bool(re.search(r'<meta[^>]*property=["\']og:', html, re.IGNORECASE))
        seo["has_json_ld"] = bool(re.search(r'application/ld\+json', html, re.IGNORECASE))
        seo["has_hreflang"] = bool(re.search(r'hreflang=["\']', html, re.IGNORECASE))
        seo["has_robots_meta"] = bool(re.search(r'<meta[^>]*name=["\']robots["\']', html, re.IGNORECASE))
        seo["score"] = sum(1 for v in seo.values() if v)
        return seo

    def _check_accessibility(self, html):
        import re
        acc = {}
        acc["has_lang"] = bool(re.search(r'<html[^>]*lang=["\']', html, re.IGNORECASE))
        acc["has_viewport"] = bool(re.search(r'<meta[^>]*name=["\']viewport["\']', html, re.IGNORECASE))
        acc["has_charset"] = bool(re.search(r'<meta[^>]*charset', html, re.IGNORECASE))
        acc["images_with_alt"] = len(re.findall(r'<img[^>]*alt=["\']', html, re.IGNORECASE))
        acc["images_total"] = len(re.findall(r'<img[^>]*>', html, re.IGNORECASE))
        acc["alt_percentage"] = round((acc["images_with_alt"] / acc["images_total"] * 100) if acc["images_total"] > 0 else 0, 1)
        return acc
