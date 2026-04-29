from impacket.smbconnection import SMBConnection
import time


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
# Layer 1: Connection
# -------------------------------
def establish_connection(target, timeout, result):
    try:
        conn = SMBConnection(target, target, sess_port=445, timeout=timeout)
        result["status"] = "OPEN"
        return conn
    except:
        result["findings"].append("[INFO] SMB not accessible")
        return None


# -------------------------------
# Layer 3: Protocol Analysis
# -------------------------------
def check_signing(conn, result):
    try:
        if conn.isSigningRequired():
            result["findings"].append("[INFO] SMB signing enforced")
        else:
            add_score(result, 20, "[HIGH] SMB signing not required", 10)
            result["impact"].append("Susceptible to SMB relay attacks")
    except:
        result["findings"].append("[INFO] Could not determine SMB signing")


def analyze_dialect(conn, result):
    try:
        dialect = conn.getDialect()

        dialect_map = {
            0x0202: "SMB 2.0.2",
            0x0210: "SMB 2.1",
            0x0300: "SMB 3.0",
            0x0302: "SMB 3.0.2",
            0x0311: "SMB 3.1.1"
        }

        if dialect == "NT LM 0.12":
            add_score(result, 25, "[HIGH] SMBv1 detected", 15)
            result["impact"].append("Legacy SMBv1 is vulnerable to known exploits")
        else:
            result["findings"].append(
                f"[INFO] SMB dialect: {dialect_map.get(dialect, str(dialect))}"
            )

    except:
        result["findings"].append("[INFO] Could not determine SMB dialect")


# -------------------------------
# Layer 2: Authentication
# -------------------------------
def check_null_session(conn, result):
    try:
        conn.login("", "")
        result["anonymous"] = True
        result["findings"].append("[INFO] Null session login allowed")
    except:
        result["findings"].append("[INFO] Null session not allowed")


def check_weak_credentials(conn, result):
    creds = [
        ("guest", ""),
        ("admin", "admin"),
        ("administrator", "password"),
        ("user", "password"),
    ]

    for user, pwd in creds:
        try:
            conn.login(user, pwd)
            result["weak_creds"] = f"{user}:{pwd}"
            result["findings"].append(f"[INFO] Valid credentials: {user}:{pwd}")
            return
        except:
            continue


# -------------------------------
# Layer 2: Share Enumeration
# -------------------------------
def enumerate_shares(conn, result):
    try:
        shares = conn.listShares()
        share_names = [s['shi1_netname'][:-1] for s in shares]

        result["shares"] = share_names

        normal = [s for s in share_names if not s.endswith("$")]
        hidden = [s for s in share_names if s.endswith("$")]

        if normal:
            result["findings"].append(f"[INFO] Shares: {', '.join(normal)}")

        if hidden:
            result["findings"].append(f"[INFO] Hidden shares: {', '.join(hidden)}")

        return share_names

    except:
        result["findings"].append("[INFO] Share enumeration failed")
        return []


# -------------------------------
# Layer 3: Share Access Analysis
# -------------------------------
def analyze_share_access(conn, shares, result):
    accessible = []

    for share in shares:
        try:
            files = conn.listPath(share, '*')
            accessible.append(share)

            if len(files) > 20:
                add_score(result, 15, f"[HIGH] Large share exposure: {share}", 10)

        except:
            continue

    if accessible:
        add_score(result, 40, "[HIGH] Accessible shares with read access", 15)
        result["impact"].append("Data can be enumerated or exfiltrated")

    result["accessible_shares"] = accessible
    return accessible


# -------------------------------
# File Enumeration (Controlled)
# -------------------------------
def enumerate_files(conn, share, depth=1):
    collected = []

    try:
        files = conn.listPath(share, '*')

        for f in files:
            name = f.get_filename()  # ✅ FIXED BUG

            if f.is_directory():
                if depth > 0 and name not in ['.', '..']:
                    collected += enumerate_files(conn, f"{share}/{name}", depth - 1)
            else:
                collected.append(name)

    except:
        pass

    return collected


# -------------------------------
# Layer 3: Data Classification
# -------------------------------
def classify_files(files, result):
    categories = {
        "credentials": [".env", "passwd", "shadow", "id_rsa"],
        "configs": [".conf", ".ini", ".cfg", "config"],
        "databases": [".sql", ".db"],
        "backups": [".bak", ".zip", ".tar", ".gz"]
    }

    hits = {k: [] for k in categories}

    for f in files:
        for cat, keywords in categories.items():
            if any(k in f.lower() for k in keywords):
                hits[cat].append(f)

    if hits["credentials"]:
        add_score(result, 40, "[CRITICAL] Credential files found", 15)
        result["impact"].append("Credential exposure possible")

    if hits["databases"]:
        add_score(result, 30, "[CRITICAL] Database files found", 10)
        result["impact"].append("Sensitive data exposure")

    if hits["backups"]:
        add_score(result, 20, "[HIGH] Backup files found", 5)

    if hits["configs"]:
        add_score(result, 20, "[HIGH] Config files found", 5)

    result["classified_hits"] = hits


# -------------------------------
# Final Scoring Logic
# -------------------------------
def finalize_scoring(result):
    weak = result.get("weak_creds")
    access = result.get("accessible_shares")

    if weak and access:
        add_score(result, 40, "[CRITICAL] Weak credentials with share access", 15)
    elif weak:
        add_score(result, 15, "[MEDIUM] Weak credentials but limited access", 5)

    if result.get("anonymous") and access:
        add_score(result, 30, "[HIGH] Anonymous access to shares", 10)


# -------------------------------
# Attack Path
# -------------------------------
def build_attack_path(result):
    if result.get("accessible_shares"):
        result["attack_path"] = [
            "Access SMB shares",
            "Enumerate files within shares",
            "Search for credentials/configuration data",
            "Reuse discovered data for lateral movement"
        ]
    elif result.get("anonymous"):
        result["attack_path"] = [
            "Use null session to enumerate users and shares",
            "Attempt deeper access using discovered information"
        ]
    elif result["status"] == "OPEN":
        result["attack_path"] = [
            "Probe authentication mechanisms",
            "Attempt credential-based access"
        ]


# -------------------------------
# Main Scanner
# -------------------------------
def scan_smb(target, timeout=5):
    start_time = time.time()

    result = {
        "service": "SMB",
        "port": 445,
        "status": "CLOSED",
        "findings": [],
        "impact": [],
        "score": 0,
        "confidence": 0,
        "verdict": "",
        "scan_time": 0,
        "shares": [],
        "accessible_shares": [],
        "anonymous": False,
        "evidence": {
            "shares": [],
            "sample_files": []
        }
    }

    conn = establish_connection(target, timeout, result)

    if not conn:
        return result

    try:
        # Protocol
        check_signing(conn, result)
        analyze_dialect(conn, result)

        # Auth
        check_null_session(conn, result)
        check_weak_credentials(conn, result)

        # Shares
        shares = enumerate_shares(conn, result)
        accessible = analyze_share_access(conn, shares, result)

        result["evidence"]["shares"] = accessible

        # File analysis
        for share in accessible[:2]:
            files = enumerate_files(conn, share, depth=1)

            result["evidence"]["sample_files"].extend(files[:10])
            classify_files(files, result)

        # Final logic
        finalize_scoring(result)
        build_attack_path(result)

    finally:
        try:
            conn.close()
        except:
            pass

    normalize_score(result)

    result["score"] = min(result["score"], 100)
    result["verdict"] = get_verdict(result["score"])
    result["scan_time"] = round(time.time() - start_time, 2)

    result["summary"] = (
        "SMB misconfiguration allows access to shared resources, "
        "potentially exposing sensitive data and enabling lateral movement."
    )

    return result
