import ipaddress
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# -----------------------------
# Configuration
# -----------------------------

MAX_FAILED_ATTEMPTS = 5
BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "security.log"
ALERT_FILE = BASE_DIR / "alerts.log"
LOG_PATTERN = re.compile(
    r"^\s*\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\s*\|\s*([^|]+?)\s*\|\s*([A-Z_]+)\s*$"
)


# -----------------------------
# Read security log
# -----------------------------

def read_logs():
    try:
        with LOG_FILE.open("r", encoding="utf-8") as file:
            return file.readlines()
    except FileNotFoundError:
        print("Security log file not found.")
        return []


# -----------------------------
# Analyze failed login attempts
# -----------------------------

def analyze_failed_logins(logs):
    failed_attempts = defaultdict(int)

    for line in logs:
        match = LOG_PATTERN.fullmatch(line.rstrip("\r\n"))
        if not match:
            continue

        ip, event = match.groups()
        if event != "FAILED_LOGIN":
            continue

        try:
            ip = str(ipaddress.IPv4Address(ip.strip()))
        except ipaddress.AddressValueError:
            continue

        failed_attempts[ip] += 1

    return failed_attempts


# -----------------------------
# Detect suspicious IPs
# -----------------------------

def detect_intrusions(failed_attempts):
    suspicious_ips = {}

    for ip, attempts in failed_attempts.items():
        if attempts >= MAX_FAILED_ATTEMPTS:
            suspicious_ips[ip] = {
                "attempts": attempts,
                "threat": "Possible Brute Force Attack",
                "severity": "HIGH"
            }

    return suspicious_ips


# -----------------------------
# Generate security alerts
# -----------------------------

def generate_alerts(suspicious_ips):
    if not suspicious_ips:
        print("\nNo suspicious activity detected.")
        return

    print("\n" + "=" * 50)
    print("          SECURITY ALERTS")
    print("=" * 50)

    with ALERT_FILE.open("a", encoding="utf-8") as file:
        for ip, data in suspicious_ips.items():
            time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            alert = (
                f"{time} | {ip} | "
                f"{data['threat']} | "
                f"Attempts: {data['attempts']} | "
                f"Severity: {data['severity']}"
            )

            print("\n🚨", alert)
            file.write(alert + "\n")


# -----------------------------
# Display statistics
# -----------------------------

def display_statistics(logs, failed_attempts, suspicious_ips):
    print("\n" + "=" * 50)
    print("        MINI INTRUSION DETECTION SYSTEM")
    print("=" * 50)

    print("\nTotal Events       :", len(logs))

    total_failed = sum(failed_attempts.values())

    print("Failed Logins      :", total_failed)
    print("Unique IPs         :", len(failed_attempts))
    print("Suspicious IPs     :", len(suspicious_ips))


# -----------------------------
# Main IDS
# -----------------------------

def run_ids():
    logs = read_logs()

    if not logs:
        return

    failed_attempts = analyze_failed_logins(logs)

    suspicious_ips = detect_intrusions(failed_attempts)

    display_statistics(
        logs,
        failed_attempts,
        suspicious_ips
    )

    generate_alerts(suspicious_ips)


# -----------------------------
# Program starts here
# -----------------------------

if __name__ == "__main__":
    run_ids()
