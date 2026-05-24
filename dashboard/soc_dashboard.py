import json
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime
from store.alert_store import get_alerts, get_stats


# ─── Couleurs terminal ────────────────────────────────────────────────────────
class Color:
    RED     = "\033[91m"
    ORANGE  = "\033[93m"
    YELLOW  = "\033[33m"
    GREEN   = "\033[92m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"


def risk_color(risk: str) -> str:
    colors = {
        "CRITICAL": Color.RED,
        "HIGH":     Color.ORANGE,
        "MEDIUM":   Color.YELLOW,
        "LOW":      Color.GREEN,
        "INFO":     Color.CYAN,
    }
    return colors.get(risk, Color.WHITE)


# ─── Header ───────────────────────────────────────────────────────────────────
def print_header():
    print(Color.CYAN + Color.BOLD)
    print("=" * 65)
    print("   ███████╗ ██████╗  ██████╗    Dashboard")
    print("   ██╔════╝██╔═══██╗██╔════╝    SOC Big Data Log Analytics")
    print("   ███████╗██║   ██║██║         v1.0.0")
    print("   ╚════██║██║   ██║██║         ")
    print("   ███████║╚██████╔╝╚██████╗    ")
    print("   ╚══════╝ ╚═════╝  ╚═════╝    ")
    print("=" * 65)
    print(f"   📅 {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print("=" * 65)
    print(Color.RESET)


# ─── Stats globales ───────────────────────────────────────────────────────────
def print_stats():
    stats = get_stats()
    print(Color.BOLD + "\n📊 STATISTIQUES GLOBALES\n" + Color.RESET)

    print(f"  Total alertes    : {Color.WHITE}{stats['total']}{Color.RESET}")
    print(f"  🔴 CRITICAL      : {Color.RED}{stats['critical']}{Color.RESET}")
    print(f"  🟠 HIGH          : {Color.ORANGE}{stats['high']}{Color.RESET}")
    print(f"  🟡 MEDIUM        : {Color.YELLOW}{stats['medium']}{Color.RESET}")
    print(f"  🟢 LOW           : {Color.GREEN}{stats['low']}{Color.RESET}")

    if stats["top_ips"]:
        print(Color.BOLD + "\n🌐 TOP IPs SUSPECTES\n" + Color.RESET)
        for ip, count in stats["top_ips"]:
            print(f"  {Color.CYAN}{ip:<20}{Color.RESET} → {count} alertes")

    if stats["top_users"]:
        print(Color.BOLD + "\n👤 TOP USERS SUSPECTS\n" + Color.RESET)
        for user, count in stats["top_users"]:
            print(f"  {Color.CYAN}{user:<20}{Color.RESET} → {count} alertes")

    if stats["mitre_coverage"]:
        print(Color.BOLD + "\n🎯 COUVERTURE MITRE ATT&CK\n" + Color.RESET)
        for tag, count in stats["mitre_coverage"]:
            print(f"  {Color.YELLOW}{tag:<15}{Color.RESET} → {count} occurrences")


# ─── Live Alert Feed ──────────────────────────────────────────────────────────
def print_alerts(limit: int = 20, risk_filter: str = None):
    alerts = get_alerts(limit=limit, risk_filter=risk_filter)

    title = f"\n🚨 ALERTES RÉCENTES"
    if risk_filter:
        title += f" [{risk_filter}]"
    print(Color.BOLD + title + "\n" + Color.RESET)

    if not alerts:
        print(f"  {Color.GREEN}Aucune alerte trouvée.{Color.RESET}\n")
        return

    for alert in alerts:
        risk    = alert.get("risk_level", "INFO")
        color   = risk_color(risk)
        score   = alert.get("final_score", 0)
        ip      = alert.get("ip", "N/A")
        user    = alert.get("user", "N/A")
        ts      = alert.get("timestamp", "")[:19]
        message = alert.get("message", "")[:50]
        mitre   = ", ".join(alert.get("mitre_tags", []))

        print(f"  {color}[{risk:<8}]{Color.RESET} "
              f"Score: {Color.WHITE}{score:.2f}{Color.RESET} | "
              f"IP: {Color.CYAN}{ip:<15}{Color.RESET} | "
              f"User: {Color.CYAN}{user:<10}{Color.RESET}")
        print(f"           {Color.WHITE}{ts}{Color.RESET} | "
              f"MITRE: {Color.YELLOW}{mitre}{Color.RESET}")
        print(f"           {message}")
        print()


# ─── Export rapport JSON ──────────────────────────────────────────────────────
def export_report(output_path: str = "store/report.json"):
    stats  = get_stats()
    alerts = get_alerts(limit=1000)

    report = {
        "generated_at": datetime.utcnow().isoformat(),
        "stats":        stats,
        "alerts":       alerts,
    }

    os.makedirs("store", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"\n{Color.GREEN}[✓] Rapport exporté : {output_path}{Color.RESET}")
    return report


# ─── Menu interactif ──────────────────────────────────────────────────────────
def run_dashboard():
    print_header()

    while True:
        print(Color.BOLD + "\n📋 MENU\n" + Color.RESET)
        print("  [1] Statistiques globales")
        print("  [2] Toutes les alertes")
        print("  [3] Alertes CRITICAL uniquement")
        print("  [4] Alertes HIGH uniquement")
        print("  [5] Exporter rapport JSON")
        print("  [0] Quitter")

        choice = input(f"\n{Color.CYAN}Choix : {Color.RESET}").strip()

        if choice == "1":
            print_stats()
        elif choice == "2":
            print_alerts(limit=20)
        elif choice == "3":
            print_alerts(limit=20, risk_filter="CRITICAL")
        elif choice == "4":
            print_alerts(limit=20, risk_filter="HIGH")
        elif choice == "5":
            export_report()
        elif choice == "0":
            print(f"\n{Color.GREEN}Au revoir !{Color.RESET}\n")
            break
        else:
            print(f"{Color.RED}Choix invalide.{Color.RESET}")


if __name__ == "__main__":
    run_dashboard()
