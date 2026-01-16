# IP Scanner Utility

A powerful, standalone IP scanning utility built with Python and Nmap. Featuring a modern GUI, multi-target support, and advanced information gathering.

## Features
- **Nmap Integration**: Bundled portable Nmap for ease of use.
- **Multi-Target Scanning**: Scan multiple IP addresses or URLs simultaneously.
- **Rich Information**:
  - **Geo-location**: IP-based country, city, and ISP information.
  - **WHOIS**: Domain registration and ownership details.
  - **Netlas Integration**: Passive port scanning and vulnerability data.
- **Extended Probes**:
  - **SSH Banner Grabbing**: Identifies SSH versions.
  - **HTTP Headers**: Fetches and displays web server headers.
- **Traceroute**: Map the network path to your targets.
- **Reporting**: Real-time output and full report export.

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd warped-magnetar
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Ensure [Npcap](https://npcap.com/#download) is installed on your Windows system for full Nmap functionality.

## Usage

Run the main application:
```bash
python main.py
```

Or use the pre-built executables in the `dist/` folder (if provided).

## Disclaimer
This tool is for educational and authorized testing purposes only. Always ensure you have permission before scanning any targets.
