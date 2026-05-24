import json
import os
from datetime import datetime
from collections import defaultdict

FEATURE_FILE = "store/features.json"


# ─── Charger le store ─────────────────────────────────────────────────────────
def _load() -> dict:
    if not os.path.exists(FEATURE_FILE):
        return {}
    with open(FEATURE_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


# ─── Sauvegarder le store ─────────────────────────────────────────────────────
def _save(data: dict):
    os.makedirs("store", exist_ok=True)
    with open(FEATURE_FILE, "w") as f:
        json.dump(data, f, indent=2, default=str)


# ─── Brute-force counter par IP ───────────────────────────────────────────────
def increment_brute_force(ip: str):
    data = _load()
    if "brute_force" not in data:
        data["brute_force"] = {}
    data["brute_force"][ip] = data["brute_force"].get(ip, 0) + 1
    _save(data)


def get_brute_force_count(ip: str) -> int:
    data = _load()
    return data.get("brute_force", {}).get(ip, 0)


# ─── Entropy / Rarity score ───────────────────────────────────────────────────
import math

def compute_entropy(messages: list) -> float:
    """Calcule l'entropie de Shannon d'une liste de messages."""
    if not messages:
        return 0.0
    freq = defaultdict(int)
    for m in messages:
        freq[m] += 1
    total = len(messages)
    entropy = -sum(
        (c / total) * math.log2(c / total)
        for c in freq.values()
    )
    return round(entropy, 4)


def compute_rarity_score(value: str, all_values: list) -> float:
    """Score de rareté : 1.0 = très rare, 0.0 = très commun."""
    if not all_values:
        return 1.0
    count = all_values.count(value)
    return round(1.0 - (count / len(all_values)), 4)


# ─── Time-based patterns ──────────────────────────────────────────────────────
def store_event_time(ip: str, timestamp: str):
    data = _load()
    if "event_times" not in data:
        data["event_times"] = {}
    if ip not in data["event_times"]:
        data["event_times"][ip] = []
    data["event_times"][ip].append(timestamp)
    # Garder seulement les 100 derniers
    data["event_times"][ip] = data["event_times"][ip][-100:]
    _save(data)


def get_event_frequency(ip: str) -> dict:
    data = _load()
    times = data.get("event_times", {}).get(ip, [])
    return {
        "ip":          ip,
        "total_events": len(times),
        "first_seen":  times[0] if times else None,
        "last_seen":   times[-1] if times else None,
    }


# ─── Enrichir un log avec les features du store ───────────────────────────────
def enrich_log(log: dict) -> dict:
    ip = log.get("ip")
    if ip:
        log["brute_force_store_count"] = get_brute_force_count(ip)
        freq = get_event_frequency(ip)
        log["total_events_seen"] = freq["total_events"]
        if "brute_force" in log.get("tags", []):
            increment_brute_force(ip)
        if log.get("timestamp"):
            store_event_time(ip, log["timestamp"])
    return log


if __name__ == "__main__":
    # Test
    increment_brute_force("192.168.1.1")
    increment_brute_force("192.168.1.1")
    print("Brute force count:", get_brute_force_count("192.168.1.1"))

    msgs = ["Failed password", "Failed password", "Accepted password", "sudo su"]
    print("Entropy:", compute_entropy(msgs))
    print("Rarity:", compute_rarity_score("sudo su", msgs))
