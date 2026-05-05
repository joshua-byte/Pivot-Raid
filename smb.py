import time
import logging
from impacket.smbconnection import SMBConnection

# Local import from our custom vulnerability engine
try:
    from vulnerabilities import query_searchsploit
except ImportError:
    # Fallback to prevent crashes if run standalone
    def query_searchsploit(software, version): return []

# ---------------------------------------------------------------------------
# Setup Module-Specific Logger (No raw print statements allowed)
# ---------------------------------------------------------------------------
logger = logging.getLogger("PivotRaid.SMB")

# ---------------------------------------------------------------------------
# Core SMB Scanner Class (OOP Pattern)
# ---------------------------------------------------------------------------
class SMBScanner:
    """
    An enterprise-grade, state-aware scanner for evaluating SMB dialect support,
    signing enforcement, null sessions, credential exposure, and share classification.
    """
    def __init__(self, target, timeout=5):
        self.target = target
        self.timeout = timeout
        self.conn = None

        # Explicit initialization schema matching ftp.py
        self.result = {
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
            "weak_creds": "",
            "vulns": [],
            "classified_hits": {},
            "attack_path": [],
            "evidence": {
                "shares": [],
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
    # Layer 1: Protocol Negotiation & Connection
    # -----------------------------------------------------------------------
    def establish_connection(self):
        """Attempts to negotiate and establish an initial raw SMB connection."""
        try:
            # Impacket SMBConnection handles negotiation automatically
            self.conn = SMBConnection(self.target, self.target, sess_port=445, timeout=self.timeout)
            self.result["status"] = "OPEN"
            return True
        except Exception as e:
            self.result["findings"].append("[INFO] SMB service not accessible.")
            logger.debug(f"Connection failure to {self.target}:445 - {e}")
            return False

    # -----------------------------------------------------------------------
    # Layer 2: Dialect Analysis & Message Signing Verification
    # -----------------------------------------------------------------------
    def analyze_protocol_properties(self):
        """Audits target signing requirements and negotiates dialects to discover CVEs."""
        if not self.conn:
            return

        # Phase A: Check SMB Signing Enforcement
        try:
            if self.conn.isSigningRequired():
                self.result["findings"].append("[INFO] SMB signing is enforced.")
            else:
                self.add_score(20, "[HIGH] SMB signing not required", 10)
                self.result["impact"].append("Susceptible to local SMB authentication relaying attacks (e.g., ntlmrelayx).")
        except Exception as e:
            self.result["findings"].append("[INFO] Could not determine SMB signing enforcement.")
            logger.debug(f"Signing query error: {e}")

        # Phase B: Analyze Negotiated SMB Dialect
        try:
            dialect = self.conn.getDialect()
            dialect_map = {
                0x0100: "SMBv1 (NT LM 0.12)",
                0x0202: "SMB 2.0.2",
                0x0210: "SMB 2.1",
                0x0300: "SMB 3.0",
                0x0302: "SMB 3.0.2",
                0x0311: "SMB 3.1.1"
            }

            dialect_name = dialect_map.get(dialect, f"Unknown (0x{dialect:X})")
            self.result["findings"].append(f"[INFO] Negotiated Dialect: {dialect_name}")

            # SMBv1 (0x0100) check -> High vulnerability risk (EternalBlue MS17-010)
            if dialect == 0x0100:
                self.add_score(30, "[HIGH] Deprecated SMBv1 protocol detected", 15)
                self.result["impact"].append("Legacy SMBv1 is highly susceptible to critical remote execution exploits like MS17-010.")

                # Active SearchSploit lookup for SMBv1 exploits
                exploits = query_searchsploit("Samba" if "Samba" in dialect_name else "SMBv1", "")
                if exploits:
                    self.result["vulns"].extend(exploits)
                    max_exploit = max(exploits, key=lambda x: x["score"])
                    self.add_score(max_exploit["score"], f"[CRITICAL] EDB Exploit Found: {max_exploit['title']}", 20)

        except Exception as e:
            self.result["findings"].append("[INFO] Failed to identify SMB dialect.")
            logger.debug(f"Dialect retrieval error: {e}")

    # -----------------------------------------------------------------------
    # Layer 3: Authentication Auditing (Null Sessions & Weak Creds)
    # -----------------------------------------------------------------------
    def audit_authentication(self):
        """Audits authentication barriers for null sessions or weak system credentials."""
        if not self.conn:
            return

        # Phase A: Null Session Assessment (Empty User/Password)
        try:
            self.conn.login("", "")
            self.result["anonymous"] = True
            self.result["findings"].append("[INFO] Null session connection accepted.")
            return  # No need to attempt dictionary brute force if null sessions work
        except Exception as e:
            self.result["findings"].append("[INFO] Null session connection rejected.")
            logger.debug(f"Null session login denied: {e}")

        # Phase B: Targeted Weak Credential Audit
        weak_pairs = [
            ("guest", ""),
            ("admin", "admin"),
            ("administrator", "password"),
            ("user", "password")
        ]

        for user, pwd in weak_pairs:
            try:
                # Reinitialize socket to prevent state leakage between auth attempts
                self.conn.close()
                self.conn = SMBConnection(self.target, self.target, sess_port=445, timeout=self.timeout)
                self.conn.login(user, pwd)

                self.result["weak_creds"] = f"{user}:{pwd}"
                self.add_score(40, f"[CRITICAL] Weak credentials allowed: {user}:{pwd}", 15)
                logger.info(f"Valid SMB credentials discovered -> {user}:{pwd}")
                return
            except Exception:
                continue

    # -----------------------------------------------------------------------
    # Layer 4: Share Enumeration & Access Control Mapping
    # -----------------------------------------------------------------------
    def enumerate_shares(self):
        """Extracts visible SMB shares and divides them into administrative and standard paths."""
        if not self.conn:
            return []

        try:
            shares = self.conn.listShares()
            # Impakcet yields share structures with trailing null characters, clean them up cleanly
            share_names = [s['shi1_netname'].strip('\x00').strip() for s in shares]
            self.result["shares"] = share_names

            normal = [s for s in share_names if not s.endswith("$")]
            hidden = [s for s in share_names if s.endswith("$")]

            if normal:
                self.result["findings"].append(f"[INFO] Enumerated Shares: {', '.join(normal)}")
            if hidden:
                self.result["findings"].append(f"[INFO] Administrative Hidden Shares ($): {', '.join(hidden)}")

            return share_names
        except Exception as e:
            self.result["findings"].append("[INFO] Unable to enumerate active shares.")
            logger.debug(f"Share listing error: {e}")
            return []

    def analyze_share_access(self, shares):
        """Tests read permissions on listed shares to quantify sensitive file exposure."""
        if not self.conn or not shares:
            return []

        accessible = []
        for share in shares:
            try:
                # Test read capacity by listing the top root level directory
                files = self.conn.listPath(share, '*')
                accessible.append(share)

                # Flag massive file shares for exfiltration scanning
                if len(files) > 20:
                    self.add_score(15, f"[HIGH] Large share file exposure in path: {share}", 10)
            except Exception:
                continue

        if accessible:
            self.add_score(40, "[HIGH] Read privileges granted on active share drives", 15)
            self.result["impact"].append("Unauthorized actors can list files, exfiltrate data, or locate backup containers.")
            self.result["accessible_shares"] = accessible
            self.result["evidence"]["shares"] = accessible

        return accessible

    # -----------------------------------------------------------------------
    # Layer 5: Safe Recursive File Crawling (Prevents Windows Traps)
    # -----------------------------------------------------------------------
    def list_files_safely(self, share, path="*", depth=1):
        """
        Safely explores folder structures, ignoring recursion traps and blacklisted paths.
        """
        collected = []
        if depth < 0:
            return collected

        # Essential Windows directory exclusion list to prevent scanning hangs
        BLACK_LIST = {".", "..", "system volume information", "$recycle.bin"}

        try:
            files = self.conn.listPath(share, path)
            for f in files:
                name = f.get_filename().strip()
                if name.lower() in BLACK_LIST:
                    continue

                if f.is_directory():
                    if depth > 0:
                        # Construct path delimiters dynamically for the SMB tree
                        sub_path = f"{path.strip('*')}{name}/*"
                        collected += self.list_files_safely(share, sub_path, depth - 1)
                else:
                    collected.append(name)
        except Exception as e:
            logger.debug(f"Exception listing SMB share path '{share}/{path}': {e}")

        return collected

    # -----------------------------------------------------------------------
    # Layer 6: Data Classification
    # -----------------------------------------------------------------------
    def classify_discovered_files(self, files):
        """Examines found files for key operational assets and adjusts threat metrics."""
        categories = {
            "credentials": [".env", "passwd", "shadow", "id_rsa", "unattend.xml", "web.config"],
            "configs": [".conf", ".ini", ".cfg", "config", "settings.json"],
            "databases": [".sql", ".db", ".sqlite", ".bak"],
            "backups": [".zip", ".tar", ".gz", "backup"]
        }

        hits = {k: [] for k in categories}
        for f in files:
            for cat, keywords in categories.items():
                if any(k in f.lower() for k in keywords):
                    hits[cat].append(f)

        if hits["credentials"]:
            self.add_score(40, "[CRITICAL] Highly sensitive credential documents found in share", 15)
            self.result["impact"].append("plaintext passwords or encryption keys exposed within network files.")
        if hits["databases"]:
            self.add_score(30, "[CRITICAL] Operational databases leaked", 10)
            self.result["impact"].append("Full exfiltration of local or system database containers.")
        if hits["backups"]:
            self.add_score(20, "[HIGH] Exposure of backup archives", 5)
        if hits["configs"]:
            self.add_score(20, "[HIGH] Application config details accessible", 5)

        self.result["classified_hits"] = hits

    # -----------------------------------------------------------------------
    # Final Metric Balancing & Attack Pathway Calculation
    # -----------------------------------------------------------------------
    def finalize_scoring_and_paths(self):
        """Correlates access control state with credential strength to compile attack path chains."""
        weak = self.result.get("weak_creds")
        access = self.result.get("accessible_shares")
        vulns = self.result.get("vulns", [])

        # Step A: Update compound scoring rules
        if weak and access:
            self.add_score(40, "[CRITICAL] Confirmed credentials linked with uninhibited share drive access", 15)
        elif weak:
            self.add_score(15, "[MEDIUM] Credential validity checked with restricted network share privileges", 5)

        if self.result.get("anonymous") and access:
            self.add_score(30, "[HIGH] Active anonymous access allowed on file shares", 10)

        # Step B: Build realistic local attack chain
        if any(v["severity"] in ["CRITICAL", "HIGH"] for v in vulns):
            critical_vuln = next(v for v in vulns if v["severity"] in ["CRITICAL", "HIGH"])
            self.result["attack_path"] = [
                "Establish initial SMB protocol negotiation loop.",
                f"Identify host vulnerabilities associated with {critical_vuln['title']}.",
                f"Deploy remote shell agent utilizing Exploit-DB vulnerability (ID: {critical_vuln['id']})."
            ]
        elif access and self.result["classified_hits"].get("credentials"):
            self.result["attack_path"] = [
                "Map unauthenticated/weakly authenticated share endpoints.",
                "Crawl shared directories, downloading localized target configuration files.",
                "Extract system secrets to pivot or elevate privileges on target domains."
            ]
        elif access:
            self.result["attack_path"] = [
                "Connect to the active target network path via client driver.",
                "Exfiltrate read-permissive proprietary documents from exposed directories."
            ]
        elif self.result["status"] == "OPEN":
            self.result["attack_path"] = [
                "Attempt to brute force local or active directory accounts.",
                "Verify access controls across identified shares."
            ]

    # -----------------------------------------------------------------------
    # Orchestrator
    # -----------------------------------------------------------------------
    def execute_scan(self):
        """Runs the SMB scan sequence securely."""
        start_time = time.time()
        logger.info(f"Initiating security assessment on SMB target {self.target}:445")

        try:
            if not self.establish_connection():
                return self.result

            # Run Analysis Layers
            self.analyze_protocol_properties()
            self.audit_authentication()

            # Share & File Auditing
            shares = self.enumerate_shares()
            accessible = self.analyze_share_access(shares)

            # Restrict exhaustive crawling: maximum 2 shares, depth of 1 level
            discovered_files = []
            for share in accessible[:2]:
                files = self.list_files_safely(share, depth=1)
                discovered_files.extend(files)

            if discovered_files:
                self.result["evidence"]["sample_files"] = discovered_files[:10]
                self.classify_discovered_files(discovered_files)

            # Compile Scoring and Paths
            self.finalize_scoring_and_paths()

        except Exception as e:
            logger.critical(f"Panic error during SMB scanner runtime: {e}", exc_info=True)
            self.result["findings"].append(f"[ERROR] Scan execution terminated: {str(e)}")

        finally:
            # Safely close open sockets
            if self.conn:
                try:
                    self.conn.close()
                except Exception:
                    pass

        # Package scores and verdicts
        self.normalize_score()
        self.result["verdict"] = self.get_verdict()
        self.result["scan_time"] = round(time.time() - start_time, 2)

        logger.info(f"SMB scan completed in {self.result['scan_time']}s. Rating: {self.result['verdict']}")
        return self.result

# ---------------------------------------------------------------------------
# Standardized Interface function for main.py integration
# ---------------------------------------------------------------------------
def scan_smb(target, timeout=5):
    scanner = SMBScanner(target, timeout=timeout)
    return scanner.execute_scan()
