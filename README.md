# Network Scanner Tool

## Overview
This Network Scanner Tool is a Python-based script that scans a target IP address for open ports, identifies running services, checks for known vulnerabilities, and generates a report automatically.

## Features
- Scans all 65535 ports on a target IP.
- Identifies services running on open ports.
- Fetches known vulnerabilities using the NVD API.
- Generates a JSON report with scan results.

## Requirements
- Python 3.x
- Required libraries: `socket`, `nmap`, `json`, `requests`, `datetime`

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/network-scanner-tool.git
   cd network-scanner-tool
   ```
2. Install dependencies:
   ```bash
   pip install python-nmap requests
   ```

## Usage
1. Run the script:
   ```bash
   python network_scanner.py
   ```
2. Enter the target IP address when prompted.
3. The script scans for open ports and retrieves vulnerability data.
4. The results are saved in a JSON report named `{target_ip}_scan_report.json`.

## Example Output
```json
{
    "target": "192.168.1.1",
    "scan_time": "2025-01-30 12:00:00",
    "open_ports": [
        {"port": 22, "service": "ssh", "vulnerabilities": ["CVE-2021-1234"]},
        {"port": 80, "service": "http", "vulnerabilities": ["CVE-2020-5678"]}
    ]
}
```

## Disclaimer
This tool is intended for educational and security auditing purposes only. Unauthorized scanning of networks you do not own is illegal.

## License
MIT License

