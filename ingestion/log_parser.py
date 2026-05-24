import re
import json
from datetime import datetime
from typing import Optional

# ─── Regex Syslog RFC 3164 ───────────────────────────────────────────────────
RFC3164_PATTERN = re.compile(
    r'<(?P<priority>\d+)>'
    r'(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<process>\S+?)(\[(?P<pid>\d+)\])?:\s+'
    r'(?P<message>.+)'
)

# ─── Regex Syslog RFC 5424 ───────────────────────────────────────────────────
RFC5424_PATTERN = re.compile(
    r'<(?P<priority>\d+)>1\s+'
    r'(?P<timestamp>\S+)\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<appname>\S+)\s+'
    r'(?P<procid>\S+)\s+'
    r'(?P<msgid>\S+)\s+'
    r'(?P<structured_data>\[.*?\]|-)\s*'
    r'(?P<message>.*)'
)

# ─── Regex auth.log ──────────────────────────────────────────────────────────
AUTH_PATTERN = re.compile(
    r'(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<process>\S+?)(\[(?P<pid>\d+)\])?:\s+'
    r'(?P<message>.+)'
)


def parse_priority(priority: int) -> dict:
    """Décompose la priorité en facility et severity."""
    facility = priority >> 3
    severity = priority & 0x07
    severity_map = {
        0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL",
        3: "ERROR", 4: "WARNING", 5: "NOTICE",
        6: "INFO", 7: "DEBUG"
    }
    return {
        "facility": facility,
        "severity": severity,
        "severity_label": severity_map.get(severity, "UNKNOWN")
    }


def parse_rfc3164(line: str) -> Optional[dict]:
    match = RFC3164_PATTERN.match(line.strip())
    if not match:
        return None
    d = match.groupdict()
    priority_info = parse_priority(int(d["priority"]))
    return {
        "raw": line.strip(),
        "format": "RFC3164",
        "timestamp": d["timestamp"],
        "hostname": d["hostname"],
        "process": d["process"],
        "pid": d.get("pid"),
        "message": d["message"],
        **priority_info
    }


def parse_rfc5424(line: str) -> Optional[dict]:
    match = RFC5424_PATTERN.match(line.strip())
    if not match:
        return None
    d = match.groupdict()
    priority_info = parse_priority(int(d["priority"]))
    return {
        "raw": line.strip(),
        "format": "RFC5424",
        "timestamp": d["timestamp"],
        "hostname": d["hostname"],
        "process": d["appname"],
        "pid": d.get("procid"),
        "message": d["message"],
        **priority_info
    }


def parse_auth_log(line: str) -> Optional[dict]:
    match = AUTH_PATTERN.match(line.strip())
    if not match:
        return None
    d = match.groupdict()
    return {
        "raw": line.strip(),
        "format": "AUTH_LOG",
        "timestamp": d["timestamp"],
        "hostname": d["hostname"],
        "process": d["process"],
        "pid": d.get("pid"),
        "message": d["message"],
        "severity": 6,
        "severity_label": "INFO"
    }


def parse_line(line: str) -> Optional[dict]:
    """Essaie tous les parsers dans l'ordre."""
    for parser in [parse_rfc5424, parse_rfc3164, parse_auth_log]:
        result = parser(line)
        if result:
            result["parsed_at"] = datetime.utcnow().isoformat()
            return result
    return {
        "raw": line.strip(),
        "format": "UNKNOWN",
        "parsed_at": datetime.utcnow().isoformat(),
        "severity_label": "UNKNOWN"
    }


def parse_file(filepath: str) -> list:
    """Parse un fichier log ligne par ligne."""
    results = []
    with open(filepath, "r", errors="replace") as f:
        for line in f:
            if line.strip():
                parsed = parse_line(line)
                if parsed:
                    results.append(parsed)
    return results


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        logs = parse_file(sys.argv[1])
        for log in logs[:5]:
            print(json.dumps(log, indent=2))
    else:
        # Test rapide
        test_lines = [
            "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for user on /dev/pts/8",
            "<165>1 2026-05-24T13:00:00Z myhost myapp 1234 ID47 - Login failed for root",
            "May 24 13:00:01 myhost sshd[1234]: Failed password for root from 192.168.1.1"
        ]
        for line in test_lines:
            print(json.dumps(parse_line(line), indent=2))
