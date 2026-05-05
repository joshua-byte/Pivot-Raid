import subprocess
import json
import shutil
import logging

logger = logging.getLogger("PivotRaid.Vulns")

# ---------------------------------------------------------------------------
# High-Profile Fallback Static Signature Engine
# ---------------------------------------------------------------------------
# This guarantees that even if searchsploit is missing, broken, or offline,
# PivotRaid will ALWAYS flag critical, industry-defining vulnerabilities.
STATIC_CVE_SIGNATURES = {
    "ftp": {
        "vsftpd": {
            "2.3.4": [
                {
                    "id": "17491",
                    "title": "vsFTPd 2.3.4 - Backdoor Command Execution (Metasploit)",
                    "cve": "CVE-2011-2523",
                    "severity": "CRITICAL",
                    "score": 95,
                    "url": "https://www.exploit-db.com/exploits/17491"
                }
            ]
        }
    },
    "smb": {
        "microsoft-ds": {
            "1.0": [
                {
                    "id": "41891",
                    "title": "Microsoft Windows - 'EternalBlue' SMB Remote Code Execution (MS17-010)",
                    "cve": "CVE-2017-0143",
                    "severity": "CRITICAL",
                    "score": 95,
                    "url": "https://www.exploit-db.com/exploits/41891"
                }
            ]
        }
    }
}

# ---------------------------------------------------------------------------
# Core Query Function
# ---------------------------------------------------------------------------
def query_searchsploit(software_name, version=""):
    """
    Queries the local searchsploit database and falls back to a 
    static high-profile signature matching engine if offline or failed.
    """
    software_clean = software_name.lower().strip()
    version_clean = version.lower().strip()

    # Phase A: Check Fallback Static Signatures
    for service_type, software_dict in STATIC_CVE_SIGNATURES.items():
        if software_clean in software_dict:
            if version_clean in software_dict[software_clean]:
                logger.debug(f"Static signature match found: {software_clean} {version_clean}")
                return software_dict[software_clean][version_clean]

    # Phase B: Run searchsploit system command
    if not shutil.which("searchsploit"):
        logger.debug("searchsploit binary not found in system PATH. Skipping live query.")
        return []

    search_term = f"{software_clean} {version_clean}".strip()
    try:
        # Run searchsploit with JSON output configuration
        process = subprocess.run(
            ["searchsploit", search_term, "--json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )
        
        if not process.stdout.strip():
            return []

        data = json.loads(process.stdout)
        # Searchsploit JSON uses the "RESULTS_EXPLOIT" key for standard exploits
        results = data.get("RESULTS_EXPLOIT", [])
        
        filtered_vulns = []
        for exploit in results:
            title = exploit.get("Title", "")
            path = exploit.get("Path", "")
            edb_id = exploit.get("EDB-ID", "")

            # Infer severity based on keyword heuristics
            severity, score = analyze_exploit_severity(title)
            
            # We filter for HIGH and CRITICAL findings to keep report noise low
            if severity in ["HIGH", "CRITICAL"]:
                filtered_vulns.append({
                    "id": edb_id,
                    "title": title,
                    "path": path,
                    "severity": severity,
                    "score": score,
                    "url": f"https://www.exploit-db.com/exploits/{edb_id}"
                })
                
        return filtered_vulns

    except subprocess.TimeoutExpired:
        logger.warning(f"Searchsploit query timed out for term: {search_term}")
        return []
    except Exception as e:
        logger.debug(f"Error querying searchsploit: {e}")
        return []

# ---------------------------------------------------------------------------
# Heuristic Scoring Engine
# ---------------------------------------------------------------------------
def analyze_exploit_severity(title):
    """Categorizes exploit titles into threat classes and scores."""
    title_lower = title.lower()
    
    # Critical threat vectors (Remote Execution / Auth Bypasses)
    if any(k in title_lower for k in ["rce", "remote code execution", "auth bypass", "authentication bypass", "backdoor"]):
        return "CRITICAL", 95
    # High threat vectors (Local Privilege Escalation / Overflows / File Writes)
    elif any(k in title_lower for k in ["buffer overflow", "privilege escalation", "arbitrary file", "upload"]):
        return "HIGH", 80
    # Medium threat vectors (Info Leakage / Traversal / Crash-DoS)
    elif any(k in title_lower for k in ["disclosure", "traversal", "dos", "denial of service"]):
        return "MEDIUM", 50
    
    return "LOW", 25
