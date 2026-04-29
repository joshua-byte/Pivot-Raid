# PivotRaid

PivotRaid is a red-team-oriented tool that analyzes FTP and SMB services to identify file exposure, weak configurations, and potential lateral movement paths.

It focuses on how attackers can move across services by leveraging shared data, weak credentials, and misconfigurations.

---

## Features

- FTP enumeration and misconfiguration detection  
- SMB share analysis and access validation  
- Detection of sensitive files (credentials, configs, backups)  
- Cross-service attack path correlation  
- Confidence-based risk scoring  
- Structured HTML report generation  

---

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/joshua-byte/PivotRaid.git
cd PivotRaid
pip install -r requirements.txt
```

---

## Usage

```bash
python3 main.py -t <target_ip>
```

Example:

```bash
python3 main.py -t 192.168.1.10
```

---

## Output

### Terminal
- Service status (OPEN/CLOSED)
- Risk score and verdict
- Findings and impact
- Local attack paths
- Cross-service attack paths

### HTML Report
- `report.html`
  - Executive summary  
  - Service-wise analysis  
  - Evidence (files, shares)  
  - Attack paths  

---

## Project Structure

```
PivotRaid/
├── main.py        # Orchestrator and correlation engine
├── ftp.py         # FTP analysis module
├── smb.py         # SMB analysis module
├── report.py      # HTML report generator
├── requirements.txt
```

## Disclaimer

This tool is intended for **educational purposes and authorized security testing only**.  
Do not use it against systems without explicit permission.
