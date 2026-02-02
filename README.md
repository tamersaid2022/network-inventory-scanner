<div align="center">

# 🔍 Network Inventory Scanner

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![SNMP](https://img.shields.io/badge/SNMP-v2c%2Fv3-009688?style=for-the-badge)](https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol)
[![Nmap](https://img.shields.io/badge/Nmap-Network_Scanner-4682B4?style=for-the-badge)](https://nmap.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

**Automated network device discovery and inventory documentation**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Output](#-output-formats)

---

</div>

## 🎯 Overview

The **Network Inventory Scanner** automatically discovers network devices, collects detailed inventory information via SNMP, SSH, and active scanning, then generates comprehensive documentation in multiple formats.

### Key Capabilities

| Feature | Description |
|---------|-------------|
| 🔍 **Auto-Discovery** | Scan subnets to find active network devices |
| 📊 **SNMP Collection** | Gather detailed device info via SNMP v2c/v3 |
| 🔌 **SSH Collection** | Collect data via CLI commands |
| 📋 **Multi-Format Export** | CSV, JSON, Excel, HTML reports |
| 🔄 **Delta Detection** | Track inventory changes over time |
| 📈 **Visualization** | Network topology diagrams |

---

## ⚡ Features

```
┌─────────────────────────────────────────────────────────────────┐
│                    DISCOVERY METHODS                            │
├─────────────────────────────────────────────────────────────────┤
│  ICMP PING         │  TCP SCAN          │  ARP SCAN            │
│  ───────────────   │  ───────────────   │  ───────────────     │
│  • Fast sweep      │  • Port detection  │  • Local segment     │
│  • Subnet range    │  • Service ID      │  • MAC address       │
│  • Parallel        │  • Banner grab     │  • Vendor lookup     │
├─────────────────────────────────────────────────────────────────┤
│                    COLLECTION METHODS                           │
├─────────────────────────────────────────────────────────────────┤
│  SNMP              │  SSH/CLI           │  API                 │
│  ───────────────   │  ───────────────   │  ───────────────     │
│  • System OIDs     │  • Show commands   │  • REST endpoints    │
│  • Interface MIB   │  • Multi-vendor    │  • Vendor APIs       │
│  • Entity MIB      │  • Netmiko         │  • JSON parsing      │
│  • Custom OIDs     │  • Custom parsers  │  • Authentication    │
├─────────────────────────────────────────────────────────────────┤
│                    COLLECTED DATA                               │
├─────────────────────────────────────────────────────────────────┤
│  • Hostname        │  • Model           │  • Interfaces        │
│  • IP Addresses    │  • Serial Number   │  • Neighbors (CDP)   │
│  • MAC Addresses   │  • Software Ver    │  • VLANs             │
│  • Vendor/OUI      │  • Uptime          │  • Routing Tables    │
│  • Location        │  • Memory/CPU      │  • ARP Tables        │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📦 Installation

```bash
# Clone repository
git clone https://github.com/tamersaid2022/network-inventory-scanner.git
cd network-inventory-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Install Nmap (if using port scanning)
# Ubuntu/Debian: sudo apt install nmap
# RHEL/CentOS: sudo yum install nmap
# macOS: brew install nmap
```

### Requirements

```txt
pysnmp>=4.4.12
netmiko>=4.2.0
python-nmap>=0.7.1
scapy>=2.5.0
pandas>=2.0.0
openpyxl>=3.1.0
jinja2>=3.1.0
pyyaml>=6.0
rich>=13.0.0
mac-vendor-lookup>=0.1.12
ipaddress>=1.0.23
concurrent-log-handler>=0.9.24
```

---

## 🚀 Usage

### Quick Start

```python
from network_scanner import NetworkScanner

# Initialize scanner
scanner = NetworkScanner(
    networks=["192.168.1.0/24", "10.0.0.0/24"],
    snmp_community="public",
    ssh_username="admin",
    ssh_password="password"
)

# Run discovery
devices = scanner.discover()

# Collect detailed inventory
inventory = scanner.collect_inventory(devices)

# Export results
scanner.export_csv("inventory.csv")
scanner.export_excel("inventory.xlsx")
scanner.export_html("inventory.html")
```

### Command Line Interface

```bash
# Scan single subnet
python network_scanner.py scan --network 192.168.1.0/24

# Scan multiple networks
python network_scanner.py scan --network 192.168.1.0/24 --network 10.0.0.0/24

# Scan with SNMP collection
python network_scanner.py scan --network 192.168.1.0/24 --snmp-community public

# Scan with SSH collection
python network_scanner.py scan --network 192.168.1.0/24 --ssh-user admin --ssh-pass password

# Full scan with all collection methods
python network_scanner.py scan --network 192.168.1.0/24 \
    --snmp-community public \
    --ssh-user admin --ssh-pass password \
    --output inventory.xlsx

# Export to multiple formats
python network_scanner.py export --input inventory.json --format csv,excel,html

# Compare inventories (delta report)
python network_scanner.py diff --old inventory_old.json --new inventory_new.json

# Schedule periodic scans
python network_scanner.py schedule --interval 24h --config scan_config.yaml
```

---

## 📋 Configuration

### scan_config.yaml

```yaml
# scan_config.yaml
---
discovery:
  networks:
    - 192.168.1.0/24
    - 192.168.2.0/24
    - 10.0.0.0/24
  methods:
    - icmp
    - tcp
    - arp
  tcp_ports:
    - 22    # SSH
    - 23    # Telnet
    - 80    # HTTP
    - 443   # HTTPS
    - 161   # SNMP
  timeout: 2
  threads: 50
  
snmp:
  enabled: true
  version: 2c
  community: "${SNMP_COMMUNITY}"
  # For SNMPv3:
  # version: 3
  # username: snmpuser
  # auth_protocol: SHA
  # auth_password: "${SNMP_AUTH_PASS}"
  # priv_protocol: AES
  # priv_password: "${SNMP_PRIV_PASS}"
  timeout: 5
  retries: 2
  
ssh:
  enabled: true
  username: "${SSH_USER}"
  password: "${SSH_PASS}"
  # Or use key-based auth:
  # key_file: ~/.ssh/id_rsa
  timeout: 30
  
output:
  directory: ./inventory
  formats:
    - json
    - csv
    - excel
    - html
  timestamp: true
  
scheduling:
  enabled: false
  interval: 24h
  notify:
    email: netops@company.com
```

---

## 📊 Output Formats

### Console Output

```
╔══════════════════════════════════════════════════════════════════════════╗
║                    NETWORK INVENTORY SCAN RESULTS                        ║
╠══════════════════════════════════════════════════════════════════════════╣
║  Scan Date:     2024-01-15 14:30:00                                      ║
║  Networks:      192.168.1.0/24, 10.0.0.0/24                             ║
║  Total IPs:     512                                                      ║
║  Active Hosts:  47                                                       ║
║  Network Devices: 23                                                     ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  IP Address      Hostname         Vendor          Model       Version    ║
║  ─────────────────────────────────────────────────────────────────────   ║
║  192.168.1.1     core-router-01   Cisco           ISR4451     16.12.4   ║
║  192.168.1.2     core-router-02   Cisco           ISR4451     16.12.4   ║
║  192.168.1.10    dist-sw-01       Cisco           C9300-48P   17.6.3    ║
║  192.168.1.11    dist-sw-02       Cisco           C9300-48P   17.6.3    ║
║  192.168.1.20    access-sw-01     Cisco           C2960X-48   15.2.7    ║
║  192.168.1.100   firewall-01      Palo Alto       PA-850      10.2.3    ║
║  192.168.1.101   wlc-01           Cisco           C9800-40    17.6.2    ║
║  10.0.0.1        dc-core-01       Cisco           N9K-C93180  10.2.5    ║
║  10.0.0.2        dc-core-02       Cisco           N9K-C93180  10.2.5    ║
║  ...                                                                     ║
╚══════════════════════════════════════════════════════════════════════════╝
```

### Excel Report

The Excel export includes multiple worksheets:

| Sheet | Contents |
|-------|----------|
| **Summary** | Scan statistics and overview |
| **Devices** | Complete device inventory |
| **Interfaces** | All interface details |
| **Neighbors** | CDP/LLDP neighbor data |
| **VLANs** | VLAN configurations |
| **Changes** | Delta from previous scan |

### HTML Report

Beautiful, interactive HTML report with:
- Sortable/filterable tables
- Search functionality
- Device detail modals
- Network topology diagram
- Export buttons

---

## 🔧 Collected Data Fields

### Device Information

| Field | Source | Description |
|-------|--------|-------------|
| IP Address | Discovery | Primary IP address |
| Hostname | SNMP/SSH | Device hostname |
| Vendor | OUI/SNMP | Manufacturer |
| Model | SNMP/SSH | Hardware model |
| Serial Number | SNMP/SSH | Device serial |
| Software Version | SNMP/SSH | OS version |
| Uptime | SNMP/SSH | System uptime |
| Location | SNMP | sysLocation |
| Contact | SNMP | sysContact |
| MAC Address | ARP/SNMP | Primary MAC |
| Device Type | Detection | Router/Switch/FW/etc |

### Interface Information

| Field | Source | Description |
|-------|--------|-------------|
| Interface Name | SNMP/SSH | Interface identifier |
| Description | SNMP/SSH | Interface description |
| IP Address | SNMP/SSH | Assigned IP |
| MAC Address | SNMP/SSH | Interface MAC |
| Speed | SNMP | Link speed |
| Admin Status | SNMP/SSH | Admin up/down |
| Oper Status | SNMP/SSH | Operational state |
| VLAN | SNMP/SSH | Access/trunk VLAN |
| Errors | SNMP | Error counters |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    NETWORK SCANNER                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐        │
│  │  Discovery  │    │  Collector  │    │  Exporter   │        │
│  │   Engine    │───▶│   Engine    │───▶│   Engine    │        │
│  └─────────────┘    └─────────────┘    └─────────────┘        │
│         │                  │                  │                │
│    ┌────┴────┐       ┌────┴────┐       ┌────┴────┐           │
│    │         │       │         │       │         │           │
│  ┌─▼─┐ ┌───┐ │    ┌──▼──┐ ┌──▼──┐  ┌──▼──┐ ┌──▼──┐        │
│  │ICMP│ │TCP│ │    │SNMP │ │SSH  │  │JSON │ │Excel│        │
│  └───┘ └───┘ │    └─────┘ └─────┘  └─────┘ └─────┘        │
│    ┌───┐     │    ┌─────┐          ┌─────┐ ┌─────┐        │
│    │ARP│     │    │API  │          │CSV  │ │HTML │        │
│    └───┘     │    └─────┘          └─────┘ └─────┘        │
│                                                             │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
network-inventory-scanner/
├── network_scanner.py      # Main scanner script
├── scan_config.yaml        # Configuration file
├── requirements.txt        # Dependencies
├── lib/
│   ├── discovery.py       # Discovery engines
│   ├── snmp_collector.py  # SNMP collection
│   ├── ssh_collector.py   # SSH/CLI collection
│   ├── exporters.py       # Export formatters
│   └── utils.py           # Utility functions
├── templates/
│   ├── report.html.j2     # HTML report template
│   └── email.html.j2      # Email notification
├── inventory/              # Output directory
│   ├── inventory_20240115.json
│   ├── inventory_20240115.xlsx
│   └── inventory_20240115.html
└── tests/
    └── test_scanner.py    # Unit tests
```

---

## 🔐 Security Considerations

| Concern | Mitigation |
|---------|------------|
| **Credentials** | Use environment variables or vault |
| **SNMP Community** | Use SNMPv3 with auth/privacy |
| **Network Impact** | Rate limiting, off-hours scanning |
| **Data Storage** | Encrypt sensitive fields |
| **Access Control** | Restrict who can run scans |

### Environment Variables

```bash
# Set credentials securely
export SNMP_COMMUNITY='your-community'
export SSH_USER='admin'
export SSH_PASS='password'
export SNMP_AUTH_PASS='authpass'
export SNMP_PRIV_PASS='privpass'
```

---

## 📈 Delta Reporting

Track changes between inventory scans:

```bash
# Compare two inventory files
python network_scanner.py diff --old inventory_jan.json --new inventory_feb.json

# Output:
# ╔════════════════════════════════════════════════════════════════╗
# ║                    INVENTORY CHANGES                           ║
# ╠════════════════════════════════════════════════════════════════╣
# ║  NEW DEVICES (3)                                               ║
# ║  ├─ 192.168.1.50 - New access switch (C2960X)                 ║
# ║  ├─ 192.168.1.51 - New access switch (C2960X)                 ║
# ║  └─ 10.0.0.100 - New server (Dell PowerEdge)                  ║
# ║                                                                ║
# ║  REMOVED DEVICES (1)                                           ║
# ║  └─ 192.168.1.30 - Old switch decommissioned                  ║
# ║                                                                ║
# ║  CHANGED DEVICES (2)                                           ║
# ║  ├─ 192.168.1.1 - Version: 16.12.3 → 16.12.4                 ║
# ║  └─ 192.168.1.10 - Interfaces: 48 → 52                        ║
# ╚════════════════════════════════════════════════════════════════╝
```

---

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

### 👨‍💻 Author

**Tamer Khalifa** - *Network Automation Engineer*

[![CCIE](https://img.shields.io/badge/CCIE-68867-1BA0D7?style=flat-square&logo=cisco&logoColor=white)](https://www.cisco.com/c/en/us/training-events/training-certifications/certifications/expert.html)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=flat-square&logo=linkedin)](https://linkedin.com/in/tamerkhalifa2022)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?style=flat-square&logo=github)](https://github.com/tamersaid2022)

---

⭐ **Star this repo if you find it useful!** ⭐

</div>
