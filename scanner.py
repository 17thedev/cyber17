import os
import subprocess
from datetime import datetime

NETWORK = "10.82.223.0/24"  # change if needed
REPORT_DIR = "reports"
SCAN_DIR = "scans"

os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(SCAN_DIR, exist_ok=True)

def run_command(command, output_file):
    with open(output_file, "w") as f:
        subprocess.run(command, stdout=f, stderr=subprocess.STDOUT, text=True)

def main():
    print("[+] Starting Network Audit")
    print("[+] Target Network:", NETWORK)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("[+] Discovering live hosts...")
    run_command(
        ["nmap", "-sn", NETWORK],
        f"{SCAN_DIR}/hosts.txt"
    )

    print("[+] Scanning gateway for open ports...")
    run_command(
        ["nmap", "10.82.223.25"],
        f"{SCAN_DIR}/ports.txt"
    )

    print("[+] Writing audit report...")
    with open(f"{REPORT_DIR}/audit_report.txt", "w") as report:
        report.write("Network Audit Report\n")
        report.write("====================\n")
        report.write(f"Date: {timestamp}\n\n")
        report.write("Network: " + NETWORK + "\n\n")
        report.write("Scan results saved in /scans folder\n")

    print("[+] Audit complete!")

if __name__ == "__main__":
    main()