import argparse
import time
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from ftp import scan_ftp
from smb import scan_smb
from report import generate_html_report

# ---------------------------------------------------------------------------
# Setup Industrial Logging System
# ---------------------------------------------------------------------------
# This configures console logging to be clean and readable, while allowing
# deep debug tracing when writing to files.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("PivotRaid.Main")

# ---------------------------------------------------------------------------
# ASCII Art Banner
# ---------------------------------------------------------------------------
def print_banner():
    banner = r"""
 ███████████   ███                        █████    ███████████              ███      █████
░░███░░░░░███ ░░░                        ░░███    ░░███░░░░░███            ░░░      ░░███
 ░███    ░███ ████  █████ █████  ██████  ███████   ░███    ░███   ██████   ████   ███████
 ░██████████ ░░███ ░░███ ░░███  ███░░███░░░███░    ░██████████   ░░░░░███ ░░███  ███░░███
 ░███░░░░░░   ░███  ░███  ░███ ░███ ░███  ░███     ░███░░░░░███   ███████  ░███ ░███ ░███
 ░███         ░███  ░░███ ███  ░███ ░███  ░███ ███ ░███    ░███  ███░░███  ░███ ░███ ░███
 █████        █████  ░░█████   ░░██████   ░░█████  █████   █████░░████████ █████░░████████
░░░░░        ░░░░░    ░░░░░     ░░░░░░     ░░░░░  ░░░░░   ░░░░░  ░░░░░░░░ ░░░░░  ░░░░░░░░
"""
    # Using standard terminal colors
    print("\033[91m" + banner + "\033[0m")
    print("\033[1mPivotRaid - Lateral Movement & Exposure Engine\033[0m")
    print("Developed for authorized security assessments.\n" + "=" * 80 + "\n")


# ---------------------------------------------------------------------------
# Structured Results Printer
# ---------------------------------------------------------------------------
def print_result(result):
    """Prints a highly readable, standardized summary of a service scan."""
    service = result.get("service", "UNKNOWN")
    status = result.get("status", "CLOSED")
    score = result.get("score", 0)
    verdict = result.get("verdict", "UNKNOWN")

    print(f"\n[+] {service} (Port {result.get('port')}) -> {status}")
    print(f"    Risk Severity : {verdict} ({score}/100)")
    print(f"    Confidence    : {result.get('confidence', 0)}/100")
    print(f"    Scan Duration : {result.get('scan_time', 0)}s")

    if result.get("findings"):
        print("    Findings:")
        for f in result["findings"]:
            print(f"      - {f}")

    if result.get("vulns"):
        print("    Identified Vulnerabilities (CVEs):")
        for v in result["vulns"]:
            print(f"      [*] {v['title']} (Severity: {v['severity']}) -> EDB-ID: {v['id']}")

    if result.get("attack_path"):
        print("    Local Path Projection:")
        for i, step in enumerate(result["attack_path"], 1):
            print(f"      {i}. {step}")


# ---------------------------------------------------------------------------
# Cross-Service Threat Correlation Engine
# ---------------------------------------------------------------------------
def correlate_intelligence(results):
    """
    Acts as the brain of PivotRaid.
    Analyzes independent results to find pivot patterns and lateral pathways.
    """
    intel = {
        "credentials": [],
        "vulns": [],
        "services": {},
        "attack_paths": []
    }

    # Map findings into an intelligence directory
    for r in results:
        service_name = r.get("service")
        intel["services"][service_name] = r

        if r.get("weak_creds"):
            intel["credentials"].append((service_name, r["weak_creds"]))
        if r.get("vulns"):
            intel["vulns"].extend(r["vulns"])

    ftp = intel["services"].get("FTP", {})
    smb = intel["services"].get("SMB", {})

    # Correlation Node A: Credential Harvesting & Reuse
    if intel["credentials"]:
        creds_str = ", ".join([f"{svc}({pair})" for svc, pair in intel["credentials"]])
        intel["attack_paths"].append(
            f"Credential Harvesting: Reuse discovered credentials [{creds_str}] across other infrastructure hosts."
        )

    # Correlation Node B: FTP Data Leaks to SMB Pivot
    ftp_has_creds = ftp.get("classified_hits", {}).get("credentials")
    if ftp_has_creds and smb.get("status") == "OPEN":
        intel["attack_paths"].append(
            "FTP to SMB Lateral Pivot: Extract hardcoded configuration keys from FTP files -> Use credentials to access SMB Admin shares."
        )

    # Correlation Node C: Direct Remote Exploitation
    high_vulns = [v for v in intel["vulns"] if v["severity"] in ["CRITICAL", "HIGH"]]
    if high_vulns:
        for v in high_vulns:
            intel["attack_paths"].append(
                f"Direct Host Exploitation: Leverage CVE (Exploit-DB: {v['id']}) on public service interfaces to execute arbitrary system code."
            )

    # Correlation Node D: Write access manipulation
    if ftp.get("writable") and smb.get("status") == "OPEN":
        intel["attack_paths"].append(
            "Payload Drop Pivot: Upload persistent webshell payload via FTP write permissions -> Trigger execution or capture domain credentials."
        )

    return intel


# ---------------------------------------------------------------------------
# Assessment Summarizer
# ---------------------------------------------------------------------------
def display_summary(results, total_time):
    """Displays a clean executive summary in the command-line interface."""
    print("\n" + "=" * 80)
    print("EXECUTIVE SECURITY SUMMARY")
    print("=" * 80)

    # Sort results to place the highest risk targets at the top
    results_sorted = sorted(results, key=lambda x: x.get("score", 0), reverse=True)

    for r in results_sorted:
        print(f" - {r.get('service')}: {r.get('verdict')} (Score: {r.get('score')}/100)")

    if results_sorted:
        top = results_sorted[0]
        print(f"\n[!] Critical Action Item: Focus triage efforts on {top.get('service')} (Risk Score: {top.get('score')}/100)")

    intel = correlate_intelligence(results)

    print("\n[★] Projected Attack Chains & Lateral Paths:")
    if intel["attack_paths"]:
        for path in intel["attack_paths"]:
            print(f"  → {path}")
    else:
        print("  → No direct cross-service compromise chains projected.")

    print(f"\nScan Statistics: {len(results)} services assessed in {round(total_time, 2)} seconds.\n")


# ---------------------------------------------------------------------------
# Thread-Safe Scan Coordinator
# ---------------------------------------------------------------------------
def run_scan_safe(scanner, target, timeout):
    """
    Executes a scanner within an isolated, error-resistant execution wall.
    Prevents runtime anomalies in individual scanner threads from crashing main.py.
    """
    service_name = scanner.__name__.replace("scan_", "").upper()
    try:
        logger.debug(f"Launching thread for {service_name} scanner...")
        result = scanner(target, timeout=timeout)
        return result
    except Exception as e:
        logger.error(f"Thread runtime crash in {service_name} scanner: {e}", exc_info=True)
        return {
            "service": service_name,
            "port": 0,
            "status": "CRASHED",
            "findings": [f"Scanner Exception: {str(e)}"],
            "impact": [],
            "score": 0,
            "confidence": 0,
            "verdict": "UNKNOWN",
            "scan_time": 0,
            "vulns": []
        }


# ---------------------------------------------------------------------------
# Main Execution Entrypoint
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="PivotRaid - Automated Lateral Movement & Service Exposure Core Engines.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-t", "--target", required=True, help="IP address or hostname of target system")
    parser.add_argument("--timeout", type=int, default=5, help="Network connection timeout limits")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debugging log outputs")

    args = parser.parse_args()
    target = args.target

    # Adjust module logging levels based on user request
    if args.verbose:
        logging.getLogger("PivotRaid").setLevel(logging.DEBUG)
        logger.debug("Verbose debug logging enabled.")
    else:
        logging.getLogger("PivotRaid").setLevel(logging.INFO)

    print_banner()
    logger.info(f"Target system locked: {target}")

    start_time = time.time()
    results = []

    # Dynamic plugin-style scanners registry
    scanners = [scan_ftp, scan_smb]

    # ThreadPoolExecutor manages threads natively and guarantees thread-safety
    # upon task collection.
    with ThreadPoolExecutor(max_workers=len(scanners)) as executor:
        # Submit tasks to pool
        futures_map = {
            executor.submit(run_scan_safe, scanner, target, args.timeout): scanner
            for scanner in scanners
        }

        # Collect future results safely as they finish execution
        for future in as_completed(futures_map):
            result = future.result()
            results.append(result)
            print_result(result)

    total_time = time.time() - start_time

    # Process and summarize the findings
    display_summary(results, total_time)

    # Compile the final interactive HTML report
    try:
        generate_html_report(results, target)
    except Exception as e:
        logger.error(f"Failed to compile the final HTML report: {e}", exc_info=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Execution interrupted by operator. Exiting.")
        sys.exit(1)
