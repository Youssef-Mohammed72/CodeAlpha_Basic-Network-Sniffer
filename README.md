# BASIC NETWORK SNIFFER

### Table of Contents
1. [Project Overview](#project-overview)
2. [Features](#features)
3. [Usage](#usage)
4. [Requirements](#requirements)
5. [Installation](#installation)
6. [Contributing](#contributing)

### Project Overview
This project is a basic network sniffer implemented using Python and Scapy. It captures network traffic on a specified interface and logs detailed information about packets.

### Features
- Captures TCP, UDP, ICMP packets
- Logs protocol information (TCP, UDP, ICMP)
- Extracts IP addresses for TCP, UDP packets
- Identifies common protocols (HTTP, HTTPS, FTP, SSH, SMTP, POP3, NetBIOS, DNS, DHCP, etc.)
- Captures payload for HTTP requests
- Supports custom filtering of packets
- Provides verbose mode for additional information

### Usage
To use this sniffer:

`python Packet_Sniffer.py <interface> [filter] [verbose]`

- `<interface>`: The network interface to capture packets from (e.g., eth0)
- `[filter]`: Optional filter string (e.g., "tcp")
- `[verbose]`: Optional flag for verbose output (default: False)

### Requirements
- Python 3.x
- Scapy library (`pip install scapy`)

### Installation
1. Clone this repository: `git clone https://github.com/Youssef-Mohammed72/CodeAlpha_Basic-Network-Sniffer.git`
2. Navigate to the project directory: `cd CodeAlpha_Basic-Network-Sniffer`
3. Install dependencies: `pip install -r requirements.txt`

### Contributing
Contributions are welcome! Please fork this repository and submit pull requests.

### License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Acknowledgments
This project was developed during an internship at CodeAlpha and uses Scapy library for packet processing.
