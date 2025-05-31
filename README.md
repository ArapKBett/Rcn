# Bug Bounty Reconnaissance Program

A Python-based tool for automating bug bounty reconnaissance and vulnerability scanning, with support for local execution and deployment on Render.

## Features
- Subdomain enumeration with `subfinder` and `assetfinder`
- Live domain filtering with `httpx`
- Subdomain takeover checks with `subzy` and `subjack`
- JavaScript parsing with `katana`
- Secret finding with `SecretFinder`
- Screenshot capture with `EyeWitness`
- Additional scans with `nuclei`, `dirsearch`, `ffuf`, and `sqlmap`
- PDF report generation with `reportlab`
- Web interface with Flask for Render deployment

## Prerequisites
- **System**: Linux/macOS/Windows
- **Dependencies**:
  - Python 3.8+
  - Go (`go install`)
  - Git
  - Docker (for Render)
- **Tools**:
  - Install Go-based tools:
    ```bash
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install github.com/tomnomnom/assetfinder@latest
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install github.com/pentestpad/subzy@latest
    go install github.com/haccer/subjack@latest
    go install github.com/projectdiscovery/katana/cmd/katana@latest
    go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    go install github.com/ffuf/ffuf@latest
    ```
  - Clone Git-based tools:
    ```bash
    git clone https://github.com/FortyNorthSecurity/EyeWitness
    git clone https://github.com/m4ll0k/SecretFinder
    git clone https://github.com/maurosoria/dirsearch
    git clone https://github.com/sqlmapproject/sqlmap
    ```
  - Install EyeWitness dependencies:
    ```bash
    pip install -r EyeWitness/Python/requirements.txt
    ```
- **API Keys**: Configure `subfinder` API keys in `~/.config/subfinder/config.yaml` for services like Censys, Shodan, etc.

## Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/ArapKBett/Rcn
   cd Rcn
