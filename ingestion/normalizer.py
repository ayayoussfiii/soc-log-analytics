from typing import Optional
from datetime import datetime
import re


# ─── Schéma JSON commun ───────────────────────────────────────────────────────
def normalize(parsed_log: dict) -> dict:
    """
    Transforme un log parsé en schéma commun JSON :
    ip, user, process, severity, timestamp normalisé
    """
    return {
        "timestamp":      normalize_timestamp(parsed_log.get("timestamp", "")),
        "hostname":       parsed_log.get("hostname", "unknown"),
        "ip":             extract_ip(parsed_log.get("message", "")),
        "user":           extract_user(parsed_log.get("message", "")),
        "process":        parsed_log.get("process", "unknown"),
        "pid":            parsed_log.get("pid"),
        "message":        parsed_log.get("message", ""),
        "severity":       parsed_log.get("severity", 6),
        "severity_label": parsed_log.get("severity_label", "INFO"),
        "format":         parsed_log.get("format", "UNKNOWN"),
        "raw":            parsed_log.get("raw", ""),
        "parsed_at":      parsed_log.get("parsed_at", datetime.utcnow().isoformat()),
        "tags":           extract_tags(parsed_log.get("message", ""))
    }


# ─── Extraction IP ────────────────────────────────────────────────────────────
IP_PATTERN = re.compile(r'\b(\d{1,3}\.){3}\d{1,3}\b')

def extract_ip(message: str) -> Optional[str]:
    match = IP_PATTERN.search(message)
    return match.group(0) if match else None


# ─── Extraction User ──────────────────────────────────────────────────────────
USER_PATTERN = re.compile(
    r'(?:for|user|by)\s+(\w+)', re.IGNORECASE
)

def extract_user(message: str) -> Optional[str]:
    match = USER_PATTERN.search(message)
    return match.group(1) if match else None


# ─── Normalisation Timestamp ──────────────────────────────────────────────────
MONTHS = {
    "Jan":"01","Feb":"02","Mar":"03","Apr":"04",
    "May":"05","Jun":"06","Jul":"07","Aug":"08",
    "Sep":"09","Oct":"10","Nov":"11","Dec":"12"
}

def normalize_timestamp(ts: str) -> str:
    """Convertit différents formats en ISO 8601."""
    if not ts:
        return datetime.utcnow().isoformat()

    # Déjà ISO 8601
    if "T" in ts or "-" in ts:
        return ts

    # Format syslog : "Oct 11 22:14:15"
    try:
        parts = ts.split()
        if len(parts) == 3:
            month = MONTHS.get(parts[0], "01")
            day   = parts[1].zfill(2)
            time  = parts[2]
            year  = datetime.utcnow().year
            return f"{year}-{month}-{day}T{time}Z"
    except Exception:
        pass

    return ts


# ─── Tags automatiques ────────────────────────────────────────────────────────
TAGS_RULES = {
    "brute_force":    r'(failed password|authentication failure|invalid user)',
    "privilege_esc":  r'(sudo|su root|su -)',
    "login_success":  r'(accepted password|session opened)',
    "logout":         r'(session closed|logged out)',
    "port_scan":      r'(port scan|nmap)',
    "malware":        r'(malware|trojan|virus|ransomware)',
}

def extract_tags(message: str) -> list:
    tags = []
    for tag, pattern in TAGS_RULES.items():
        if re.search(pattern, message, re.IGNORECASE):
            tags.append(tag)
    return tags


# ─── Normaliser une liste de logs ─────────────────────────────────────────────
def normalize_batch(parsed_logs: list) -> list:
    return [normalize(log) for log in parsed_logs]


if __name__ == "__main__":
    import json
    from log_parser import parse_line

    test_lines = [
        "May 24 13:00:01 myhost sshd[1234]: Failed password for root from 192.168.1.1",
        "May 24 13:01:00 myhost sudo[5678]: user admin : sudo su root",
        "May 24 13:02:00 myhost sshd[9999]: Accepted password for john from 10.0.0.5"
    ]

    for line in test_lines:
        parsed     = parse_line(line)
        normalized = normalize(parsed)
        print(json.dumps(normalized, indent=2))
