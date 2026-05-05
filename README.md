# PivotRaid

[![Language](https://img.shields.io/badge/Language-Python%203-blue.svg)](https://www.python.org/)
[![Focus](https://img.shields.io/badge/Focus-Infrastructure%20VAPT-red.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

PivotRaid is a lightweight, red-team-oriented automation tool designed to analyze exposed **FTP** and **SMB** services. It automates the tedious process of manual service enumeration to identify file exposure, weak configurations, and cross-service lateral movement pathways.

By correlating data from both protocols, PivotRaid identifies how an attacker can leverage weak configurations or shared file contents on one service to pivot and compromise another.

---

## 🛠️ Key Features

* **FTP Security Auditing:** Automatically tests for anonymous login, enumerates directories, and grabs service banners to flag outdated, vulnerable versions.
* **SMB Share Analysis:** Validates null session access, enumerates active shares, and tests read/write permissions across accessible directories.
* **Sensitive File Exposure Detection:** Scans directories using optimized regex patterns to flag high-value targets (e.g., `.git`, `.env`, backups, SSH keys, configuration files, and database credentials).
* **Cross-Service Correlation Engine:** Evaluates findings from both services to map realistic local and lateral attack paths (e.g., finding credentials on an open SMB share and testing them against FTP).
* **Risk Scoring & Analytics:** Provides a confidence-based severity score for discovered attack paths to help defenders prioritize remediation.
* **Professional Reporting:** Generates an executive-ready, interactive **HTML report** detailing findings, evidence, mapped attack paths, and remediation steps.

---

## 📐 Tool Architecture & Data Flow

```
                      [ Target IP ]
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
        [ FTP Module ]             [ SMB Module ]
         - Anon Login               - Null Sessions
         - Banner Grabbing          - Share Enumeration
         - Dir Enumeration          - Read/Write Checks
              │                           │
              └─────────────┬─────────────┘
                            ▼
               [ Sensitive File Finder ]
                - Custom Regex Engine
                - Credentials / SSH / DBs
                            │
                            ▼
              [ Correlation & Path Engine ]
                - Cross-Service Pivot Mapping
                - Confidence Risk Scoring
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
       [ Terminal UI ]            [ HTML Report ]
       - Real-time Output         - Executive Summary
       - Actionable Insights      - Formatted Evidence
```

---

## 🚀 Installation & Setup

Ensure you have Python 3.x installed on your system.

1. **Clone the repository:**
   ```bash
   git clone https://github.com/joshua-byte/PivotRaid.git
   cd PivotRaid
   ```

2. **Install the required dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 💻 Usage

Run the orchestrator by passing the target IP address:

```bash
python3 main.py -t <target_ip>
```

### Example

```bash
python3 main.py -t 192.168.1.10
```

---

## 📊 Sample Output

<img width="1907" height="982" alt="image" src="https://github.com/user-attachments/assets/d0d69bbd-9218-4fd0-81c9-b3d49f5996b0" />

---

## 📁 Project Structure

```text
PivotRaid/
├── main.py          # Orchestrator and central correlation engine
├── ftp.py           # FTP enumeration, banner grabbing, and scanning module
├── smb.py           # SMB null session validation and share scanning module
├── report.py        # Generates the styled HTML report with structured tables
├── report.html      # Sample report output 
├── requirements.txt # Project dependencies (e.g., impacket, beautifulsoup4)
└── README.md        # Documentation
```

---

## ⚖️ Disclaimer

This tool is intended solely for educational purposes, defensive hardening, and authorized security assessments. Operating this tool against targets without explicit, prior written permission from the system owner is illegal. The author accepts no liability for any misuse or damage caused by this software.
