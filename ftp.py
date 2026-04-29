from ftplib import FTP, error_perm
import time
import io


# -------------------------------
# Scoring
# -------------------------------
def get_verdict(score):
    if score >= 90:
        return "CRITICAL – Immediate exploitation possible"
    elif score >= 70:
        return "HIGH – Significant security risk"
    elif score >= 40:
        return "MEDIUM – Moderate exposure"
    else:
        return "LOW – Limited risk"


def add_score(result, value, reason, confidence=5):
    result["score"] += value
    result["confidence"] += confidence
    result["findings"].append(reason)


def normalize_score(result):
    if result["score"] > 85:
        result["score"] = int(85 + (result["score"] - 85) * 0.5)


# -------------------------------
# Layer 1: Access
# -------------------------------
def check_access(ftp, result):
    try:
        ftp.login("anonymous", "anonymous")
        result["anonymous"] = True
        add_score(result, 30, "[HIGH] Anonymous login allowed", 10)
    except error_perm:
        result["findings"].append("[INFO] Anonymous login not allowed")

    creds = [
        ("ftp", "ftp"),
        ("admin", "admin"),
        ("user", "password")
    ]

    for user, pwd in creds:
        try:
            ftp.login(user, pwd)
            result["weak_creds"] = f"{user}:{pwd}"
            add_score(result, 40, f"[CRITICAL] Weak credentials: {user}:{pwd}", 15)
            return
        except:
            continue


# -------------------------------
# Layer 2: Enumeration
# -------------------------------
def recursive_list(ftp, path="", depth=2):
    collected = []

    if depth < 0:
        return collected

    try:
        ftp.cwd(path)
        items = ftp.nlst()

        for item in items:
            if item in [".", ".."]:
                continue

            try:
                ftp.cwd(item)
                collected += recursive_list(ftp, item, depth - 1)
                ftp.cwd("..")
            except:
                collected.append(f"{path}/{item}".strip("/"))

    except:
        pass

    return collected


# -------------------------------
# Layer 3: Classification
# -------------------------------
def classify_files(files, result):
    categories = {
        "credentials": [".env", "passwd", "shadow", "id_rsa"],
        "configs": [".conf", ".ini", ".cfg", "config"],
        "databases": [".sql", ".db"],
        "backups": [".bak", ".zip", ".tar", ".gz"],
        "code": [".php", ".py", ".js"]
    }

    hits = {k: [] for k in categories}

    for f in files:
        for cat, keywords in categories.items():
            if any(k in f.lower() for k in keywords):
                hits[cat].append(f)

    if hits["credentials"]:
        add_score(result, 40, "[CRITICAL] Credential files found", 15)
        result["impact"].append("Direct credential exposure possible")

    if hits["databases"]:
        add_score(result, 30, "[CRITICAL] Database dumps found", 10)
        result["impact"].append("Full data exfiltration possible")

    if hits["backups"]:
        add_score(result, 20, "[HIGH] Backup files found", 5)

    if hits["configs"]:
        add_score(result, 20, "[HIGH] Config files found", 5)

    result["classified_hits"] = hits


# -------------------------------
# Layer 4: Exposure Depth
# -------------------------------
def analyze_exposure(files, result):
    count = len(files)

    if count > 100:
        add_score(result, 20, "[HIGH] Large exposure (>100 files)", 10)
    elif count > 30:
        add_score(result, 10, "[MEDIUM] Moderate exposure", 5)

    result["file_count"] = count


# -------------------------------
# Layer 5: Capability Testing
# -------------------------------
def test_permissions(ftp, result):
    test_file = "ftp_test.txt"

    try:
        ftp.storbinary(f"STOR {test_file}", io.BytesIO(b"test"))
        result["writable"] = True
        add_score(result, 30, "[CRITICAL] Writable FTP (upload allowed)", 15)
        result["impact"].append("Attacker can upload malicious files")

        try:
            ftp.delete(test_file)
            result["findings"].append("[INFO] Uploaded file successfully deleted")
        except:
            result["findings"].append("[INFO] Could not delete uploaded file")

    except:
        result["findings"].append("[INFO] Upload not permitted")


# -------------------------------
# Layer 6: Interpretation
# -------------------------------
def build_attack_path(result):
    hits = result.get("classified_hits", {})

    if hits.get("credentials"):
        result["attack_path"] = [
            "Download credential files",
            "Extract usernames/passwords",
            "Reuse credentials across SMB/SSH"
        ]

    elif hits.get("databases"):
        result["attack_path"] = [
            "Download database dumps",
            "Extract sensitive records",
            "Identify users and credentials"
        ]

    elif result.get("writable"):
        result["attack_path"] = [
            "Upload malicious file",
            "Attempt execution via misconfigured service"
        ]

    elif result.get("anonymous"):
        result["attack_path"] = [
            "Enumerate directories",
            "Search for sensitive files"
        ]


# -------------------------------
# Main Scanner
# -------------------------------
def scan_ftp(target, timeout=5):
    start = time.time()

    result = {
        "service": "FTP",
        "port": 21,
        "status": "CLOSED",
        "findings": [],
        "impact": [],
        "score": 0,
        "confidence": 0,
        "verdict": "",
        "scan_time": 0,
        "anonymous": False,
        "writable": False,
        "file_count": 0,
        "evidence": {
            "sample_files": []
        }
    }

    ftp = None

    try:
        ftp = FTP()
        ftp.connect(target, 21, timeout=timeout)
        result["status"] = "OPEN"

        # Banner
        try:
            banner = ftp.getwelcome()
            result["findings"].append(f"[INFO] Banner: {banner}")
        except:
            result["findings"].append("[INFO] Banner not available")

        # Layer 1
        check_access(ftp, result)

        # Layer 2
        files = recursive_list(ftp, depth=2)
        if files:
            result["findings"].append(f"[INFO] Enumerated {len(files)} files")

        # Evidence
        result["evidence"]["sample_files"] = files[:15]

        # Layer 3
        classify_files(files, result)

        # Layer 4
        analyze_exposure(files, result)

        # Layer 5
        test_permissions(ftp, result)

        # Baseline risk
        add_score(result, 10, "[MEDIUM] FTP transmits credentials in plaintext", 5)

        # Layer 6
        build_attack_path(result)

    except:
        result["findings"].append("[INFO] FTP not accessible")

    finally:
        if ftp:
            try:
                ftp.quit()
            except:
                pass

    normalize_score(result)

    result["score"] = min(result["score"], 100)
    result["verdict"] = get_verdict(result["score"])
    result["scan_time"] = round(time.time() - start, 2)

    result["summary"] = (
        "FTP exposure may allow unauthorized file access and credential leakage, "
        "with potential for data exfiltration or further system compromise."
    )

    return result
