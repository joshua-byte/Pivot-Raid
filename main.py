import argparse
import time
import threading

from ftp import scan_ftp
from smb import scan_smb
from report import generate_html_report


# -------------------------------
# Banner
# -------------------------------
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
    print("\033[91m" + banner + "\033[0m")  # red color
    print("\033[1mPivotRaid\033[0m")
    print("FTP/SMB Lateral Movement & Exposure Engine\n")


# -------------------------------
# Pretty Print
# -------------------------------
def print_result(result):
    print("\n" + "=" * 50)

    print(f"[{result.get('service')}] {result.get('status')} | "
          f"Risk: {result.get('verdict')} ({result.get('score')}/100)")

    print(f"Confidence: {result.get('confidence', 0)}")
    print(f"Scan Time: {result.get('scan_time')}s")

    if result.get("findings"):
        print("\nFindings:")
        for f in result["findings"]:
            print(f" - {f}")

    if result.get("impact"):
        print("\nImpact:")
        for i in result["impact"]:
            print(f" - {i}")

    if result.get("attack_path"):
        print("\nLocal Attack Path:")
        for step in result["attack_path"]:
            print(f" → {step}")


# -------------------------------
# Correlation Engine
# -------------------------------
def correlate(results):
    intelligence = {
        "credentials": [],
        "services": {},
        "attack_paths": []
    }

    for r in results:
        service = r.get("service")
        intelligence["services"][service] = r

        if r.get("weak_creds"):
            intelligence["credentials"].append(r["weak_creds"])

    ftp = intelligence["services"].get("FTP", {})
    smb = intelligence["services"].get("SMB", {})

    if intelligence["credentials"]:
        creds = intelligence["credentials"]
        intelligence["attack_paths"].append(
            f"Reuse discovered credentials ({', '.join(creds)}) across FTP/SMB"
        )

    if ftp.get("evidence", {}).get("sample_files") and smb.get("status") == "OPEN":
        intelligence["attack_paths"].append(
            "Analyze FTP files → extract credentials/configs → pivot to SMB"
        )

    if smb.get("accessible_shares"):
        intelligence["attack_paths"].append(
            "Access SMB shares → enumerate files → extract sensitive data"
        )

    if ftp.get("anonymous") and ftp.get("writable"):
        intelligence["attack_paths"].append(
            "Upload payload via FTP → potential execution via misconfigured service"
        )

    return intelligence


# -------------------------------
# Summary
# -------------------------------
def summarize(results, total_time):
    print("\n" + "=" * 50)
    print("Attack Surface Summary:\n")

    results_sorted = sorted(results, key=lambda x: x.get("score", 0), reverse=True)

    for r in results_sorted:
        print(f" - {r.get('service')}: {r.get('verdict')} ({r.get('score')}/100)")

    if results_sorted:
        top = results_sorted[0]
        print("\nPriority Target:")
        print(f" → {top.get('service')} ({top.get('verdict')} | {top.get('score')}/100)")

    intel = correlate(results)

    print("\nCross-Service Attack Paths:")
    if intel["attack_paths"]:
        for path in intel["attack_paths"]:
            print(f" → {path}")
    else:
        print(" → No strong attack paths identified")

    print(f"\nServices Scanned: {len(results)}")
    print(f"Total Scan Time: {round(total_time, 2)}s")


# -------------------------------
# Thread Runner
# -------------------------------
def run_scan(scanner, target, results):
    try:
        res = scanner(target)
        results.append(res)
        print_result(res)
    except Exception as e:
        results.append({
            "service": scanner.__name__,
            "status": "ERROR",
            "score": 0,
            "verdict": "UNKNOWN",
            "findings": [str(e)]
        })


# -------------------------------
# Main
# -------------------------------
def main():
    parser = argparse.ArgumentParser(description="PivotRaid - FTP/SMB Attack Surface Analyzer")
    parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")

    args = parser.parse_args()
    target = args.target

    print_banner()
    print(f"[+] Target: {target}\n")

    start_time = time.time()
    results = []
    threads = []

    scanners = [scan_ftp, scan_smb]

    for scanner in scanners:
        t = threading.Thread(target=run_scan, args=(scanner, target, results))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    total_time = time.time() - start_time
    summarize(results, total_time)

    # HTML report
    generate_html_report(results, target)


if __name__ == "__main__":
    main()
