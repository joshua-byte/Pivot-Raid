import io
import re
import time
import logging
from ftplib import FTP, error_perm, error_temp

# Local import from our custom vulnerability engine
try:
    from vulnerabilities import query_searchsploit
except ImportError:
    # Fallback to prevent crashes if run standalone
    def query_searchsploit(software, version): return []

# ---------------------------------------------------------------------------
# Setup Module-Specific Logger (No raw print statements allowed)
# ---------------------------------------------------------------------------
logger = logging.getLogger("PivotRaid.FTP")

# ---------------------------------------------------------------------------
# Core Scanner Class (OOP Pattern)
# ---------------------------------------------------------------------------
class FTPScanner:
    """
    An enterprise-grade, state-aware scanner for evaluating security posture,
    credential strength, directory exposure, and vulnerabilities on FTP services.
    """
    def __init__(self, target, port=21, timeout=5):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.ftp = None

        # Explicit initialization schema
        self.result = {
            "service": "FTP",
            "port": port,
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
            "vulns": [],
            "classified_hits": {},
            "attack_path": [],
            "evidence": {
                "banner": "",
                "sample_files": []
            }
        }

    def add_score(self, value, reason, confidence=5):
        """Standardized risk-scoring injection mechanism."""
        self.result["score"] += value
        self.result["confidence"] += confidence
        self.result["findings"].append(reason)
        logger.debug(f"Score adjusted (+{value}) -> Total: {self.result['score']} | Reason: {reason}")

    def normalize_score(self):
        """Asymptotic scoring compression to prevent score overflows."""
        if self.result["score"] > 85:
            self.result["score"] = int(85 + (self.result["score"] - 85) * 0.5)
        self.result["score"] = min(self.result["score"], 100)

    def get_verdict(self):
        score = self.result["score"]
        if score >= 90:
            return "CRITICAL – Immediate exploitation possible"
        elif score >= 70:
            return "HIGH – Significant security risk"
        elif score >= 40:
            return "MEDIUM – Moderate exposure"
        return "LOW – Limited risk"

    # -----------------------------------------------------------------------
    # Layer 1: Protocol Handshake & OS/Software Fingerprinting
    # -----------------------------------------------------------------------
    def extract_version_from_banner(self, banner):
        """
        Extracts software names and semantic versions from typical RFC959 FTP banners.
        Ex: "220 (vsFTPd 2.3.4)" -> ("vsftpd", "2.3.4")
        """
        if not banner:
            return None, None

        # General regex to match banner structures like "Software Name X.Y.Z"
        match = re.search(r"([a-zA-Z\-]+)\s*v?([\d\.]+)", banner)
        if match:
            software = match.group(1).strip().lower()
            version = match.group(2).strip()
            return software, version
        return None, None

    def finger_print_service(self):
        """Connects and extracts software versions to feed our Exploit-DB Engine."""
        try:
            self.ftp = FTP()
            self.ftp.connect(self.target, self.port, timeout=self.timeout)
            self.result["status"] = "OPEN"

            try:
                banner = self.ftp.getwelcome()
                self.result["evidence"]["banner"] = banner
                self.result["findings"].append(f"[INFO] Welcome Banner: {banner.strip()}")

                # Run the version parser
                software, version = self.extract_version_from_banner(banner)
                if software:
                    self.result["findings"].append(f"[INFO] Fingerprinted: {software} {version}")

                    # Programmatic SearchSploit execution
                    exploits = query_searchsploit(software, version)
                    if exploits:
                        self.result["vulns"].extend(exploits)
                        # Dynamically elevate score based on the highest vulnerability found
                        max_exploit = max(exploits, key=lambda x: x["score"])
                        self.add_score(max_exploit["score"], f"[CRITICAL] EDB Exploit Found: {max_exploit['title']}", 20)

            except Exception as e:
                self.result["findings"].append("[INFO] Banner extraction failed.")
                logger.debug(f"Banner extraction error: {e}")

            return True
        except Exception as e:
            logger.warning(f"Failed to connect to FTP on {self.target}:{self.port} - {e}")
            return False

    # -----------------------------------------------------------------------
    # Layer 2: Targeted & Defensive Authentication Auditing
    # -----------------------------------------------------------------------
    def audit_authentication(self):
        """Safely audits for anonymous login and common weak administrator credentials."""
        if self.result["status"] != "OPEN" or not self.ftp:
            return

        # Phase A: Anonymous Login Check
        try:
            self.ftp.login("anonymous", "anonymous@test.com")
            self.result["anonymous"] = True
            self.add_score(30, "[HIGH] Anonymous login allowed", 10)
            return  # No need to brute-force weak accounts if anonymous works
        except (error_perm, error_temp) as e:
            self.result["findings"].append("[INFO] Anonymous access disabled.")
            logger.debug(f"Anonymous login denied: {e}")

        # Phase B: Targeted Weak Credential Dictionary Assessment
        weak_pairs = [
            ("ftp", "ftp"),
            ("admin", "admin"),
            ("user", "password"),
            ("root", "root")
        ]

        for user, pwd in weak_pairs:
            try:
                # Re-establish a clean session to prevent protocol state desynchronization
                self.ftp.close()
                self.ftp.connect(self.target, self.port, timeout=self.timeout)
                self.ftp.login(user, pwd)

                self.result["weak_creds"] = f"{user}:{pwd}"
                self.add_score(40, f"[CRITICAL] Weak Credentials Identified: {user}:{pwd}", 15)
                logger.info(f"Valid credentials found on {self.target} -> {user}:{pwd}")
                return  # Stop testing on first validated credentials
            except (error_perm, error_temp):
                continue
            except Exception as e:
                logger.debug(f"Authentication audit exception: {e}")
                break

    # -----------------------------------------------------------------------
    # Layer 3: Controlled Recursive File Listing (Prevents infinite loops)
    # -----------------------------------------------------------------------
    def list_files_safely(self, path="", depth=2):
        """
        Safely enumerates files.
        Addresses infinite loops, recursion traps, and broken pipe socket crashes.
        """
        collected = []
        if depth < 0:
            return collected

        try:
            self.ftp.cwd(path)
            items = self.ftp.nlst()

            for item in items:
                # Standard directory loops protection
                if item in [".", ".."] or not item.strip():
                    continue

                try:
                    # Defensive testing: Attempt to change directory to see if item is a folder
                    self.ftp.cwd(item)
                    collected += self.list_files_safely(item, depth - 1)
                    self.ftp.cwd("..")
                except (error_perm, error_temp):
                    # Not a directory, treat as flat file
                    collected.append(f"{path}/{item}".strip("/"))
        except Exception as e:
            logger.debug(f"Recursion error at path '{path}': {e}")

        return collected

    # -----------------------------------------------------------------------
    # Layer 4: Sensitive File Categorization
    # -----------------------------------------------------------------------
    def classify_discovered_files(self, files):
        """Categorizes files and tracks metrics to support our attack-path compiler."""
        categories = {
            "credentials": [".env", "passwd", "shadow", "id_rsa", "config.json", "credentials.txt"],
            "configs": [".conf", ".ini", ".cfg", "config", "settings.xml"],
            "databases": [".sql", ".db", ".sqlite", ".mdb"],
            "backups": [".bak", ".zip", ".tar", ".gz", ".tgz"],
            "code": [".php", ".py", ".js", ".asp", ".aspx"]
        }

        hits = {k: [] for k in categories}
        self.result["file_count"] = len(files)

        for f in files:
            for cat, keywords in categories.items():
                if any(k in f.lower() for k in keywords):
                    hits[cat].append(f)

        # Trigger analytical risk increments based on classifications
        if hits["credentials"]:
            self.add_score(40, "[CRITICAL] Sensitive credential files exposed", 15)
            self.result["impact"].append("Exposure of plaintext credentials, configuration variables, or private SSH keys.")
        if hits["databases"]:
            self.add_score(30, "[CRITICAL] Exposed database structures / backups found", 10)
            self.result["impact"].append("Complete exfiltration of structural backend database files.")
        if hits["backups"]:
            self.add_score(20, "[HIGH] Exposure of backup partitions", 5)
        if hits["configs"]:
            self.add_score(20, "[HIGH] Server configuration structures exposed", 5)

        self.result["classified_hits"] = hits

    # -----------------------------------------------------------------------
    # Layer 5: Safe Write Permission Verification
    # -----------------------------------------------------------------------
    def test_upload_permissions(self):
        """Verifies if the directory allows write operations using a unique temp file."""
        test_filename = f"pivotraid_{int(time.time())}.txt"

        try:
            self.ftp.storbinary(f"STOR {test_filename}", io.BytesIO(b"pivotraid_audit_payload"))
            self.result["writable"] = True
            self.add_score(30, "[CRITICAL] Writable directory allowed (Arbitrary File Upload)", 15)
            self.result["impact"].append("Unrestricted file upload could allow planting persistent web shells or backdoors.")

            # Clean up the test file
            try:
                self.ftp.delete(test_filename)
                self.result["findings"].append("[INFO] Cleanup verified: Temporary test file removed.")
            except Exception as e:
                self.result["findings"].append("[INFO] Write access confirmed; automatic cleanup failed.")
                logger.debug(f"Failed to delete test file {test_filename}: {e}")

        except (error_perm, error_temp, OSError):
            self.result["findings"].append("[INFO] Strict write protection active.")

    # -----------------------------------------------------------------------
    # Layer 6: Dynamic Attack Path Aggregating
    # -----------------------------------------------------------------------
    def build_attack_path(self):
        """Builds a local attack chain structure to construct graph coordinates."""
        hits = self.result.get("classified_hits", {})
        vulns = self.result.get("vulns", [])

        # Priority A: Check Exploit-DB entries
        if any(v["severity"] in ["CRITICAL", "HIGH"] for v in vulns):
            critical_vuln = next(v for v in vulns if v["severity"] in ["CRITICAL", "HIGH"])
            self.result["attack_path"] = [
                f"Identify vulnerable software banner ({self.result['evidence']['banner'].strip()})",
                f"Match version with Exploit-DB vulnerability (EDB-ID: {critical_vuln['id']})",
                "Execute known exploit script against active listener",
                "Obtain system shell access"
            ]
        # Priority B: Exploit credential exposures
        elif hits.get("credentials"):
            self.result["attack_path"] = [
                "Establish anonymous access session to file host",
                "Recursively crawl system paths and extract credential assets",
                "Attempt cross-service credential reuse (SSH / SMB) using harvested credentials"
            ]
        # Priority C: Web shell drop
        elif self.result.get("writable"):
            self.result["attack_path"] = [
                "Establish authenticated connection to write-permitted folder",
                "Upload web shell or listener payloads",
                "Enumerate web roots or daemon configs to trigger shell execution"
            ]
        # Priority D: Simple read-only exposure
        elif self.result.get("anonymous"):
            self.result["attack_path"] = [
                "Gain zero-interaction anonymous network access",
                "Exfiltrate read-accessible sensitive data"
            ]

    # -----------------------------------------------------------------------
    # Orchestrator
    # -----------------------------------------------------------------------
    def execute_scan(self):
        """Runs the scan steps sequentially inside clean execution walls."""
        start_time = time.time()
        logger.info(f"Beginning FTP security assessment on {self.target}:{self.port}")

        try:
            if not self.finger_print_service():
                return self.result

            # Run Audit Layers
            self.audit_authentication()

            # Enumerate files securely
            files = self.list_files_safely(depth=2)
            if files:
                self.result["findings"].append(f"[INFO] Discovered {len(files)} files.")
                self.result["evidence"]["sample_files"] = files[:15]
                self.classify_discovered_files(files)

            # Test permission constraints
            self.test_upload_permissions()

            # Baseline network encryption risk
            self.add_score(10, "[MEDIUM] FTP transmits credentials and session data in cleartext", 5)

            # Build localized attack chain
            self.build_attack_path()

        except Exception as e:
            logger.critical(f"Panic error during FTP scanner runtime: {e}", exc_info=True)
            self.result["findings"].append(f"[ERROR] Scan execution terminated abruptly: {str(e)}")

        finally:
            # Safely tear down active sockets
            if self.ftp:
                try:
                    self.ftp.quit()
                except Exception:
                    try:
                        self.ftp.close()
                    except Exception:
                        pass

        # Package scores and verdicts
        self.normalize_score()
        self.result["verdict"] = self.get_verdict()
        self.result["scan_time"] = round(time.time() - start_time, 2)

        logger.info(f"FTP scan completed on {self.target} in {self.result['scan_time']}s. Rating: {self.result['verdict']}")
        return self.result

# ---------------------------------------------------------------------------
# Standardized Interface function for main.py integration
# ---------------------------------------------------------------------------
def scan_ftp(target, timeout=5):
    scanner = FTPScanner(target, timeout=timeout)
    return scanner.execute_scan()
