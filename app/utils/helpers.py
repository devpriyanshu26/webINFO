import uuid
from datetime import datetime

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

SEVERITY_WEIGHTS = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3, "Info": 1}

def calculate_security_score(vulnerabilities):
    score = 100
    for v in vulnerabilities:
        sev = v.get("severity", "Low")
        score -= SEVERITY_WEIGHTS.get(sev, 3)
    return max(0, min(100, score))

def get_grade(score):
    if score >= 90: return "A+"
    elif score >= 80: return "A"
    elif score >= 70: return "B"
    elif score >= 60: return "C"
    elif score >= 40: return "D"
    else: return "F"

def format_duration(seconds):
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    else:
        return f"{seconds // 3600}h {(seconds % 3600) // 60}m"

def generate_report_id():
    return f"REP-{uuid.uuid4().hex[:12].upper()}-{datetime.now().strftime('%Y%m%d')}"

def severity_order(v):
    return SEVERITY_ORDER.get(v.get("severity", "Low"), 5)
