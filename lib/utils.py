"""
Network Inventory Scanner - Utility Functions
Author: Tamer Khalifa (CCIE #68867)
"""

import re
import logging

logger = logging.getLogger(__name__)

# MAC OUI Vendor Database (top entries)
OUI_DATABASE = {
    "00:00:0C": "Cisco", "00:01:42": "Cisco", "00:1A:A1": "Cisco",
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:15:5D": "Microsoft Hyper-V",
    "00:1B:21": "Intel", "00:24:D7": "Intel",
    "00:26:88": "Juniper", "00:05:85": "Juniper",
    "00:1C:73": "Arista", "00:50:0B": "Extreme",
    "00:09:0F": "Fortinet", "00:17:8F": "Dell",
    "58:97:1E": "Palo Alto", "00:86:9C": "Palo Alto",
}


def mac_vendor_lookup(mac_address: str) -> str:
    """Look up vendor from MAC address OUI"""
    mac = mac_address.upper().replace("-", ":").replace(".", ":")
    oui = ":".join(mac.split(":")[:3])
    return OUI_DATABASE.get(oui, "Unknown")


def parse_cidr(network: str) -> tuple:
    """Parse CIDR notation to network and prefix"""
    import ipaddress
    net = ipaddress.ip_network(network, strict=False)
    return str(net.network_address), net.prefixlen


def format_uptime(seconds: int) -> str:
    """Format seconds to human-readable uptime"""
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    parts = []
    if days: parts.append(f"{days}d")
    if hours: parts.append(f"{hours}h")
    if minutes: parts.append(f"{minutes}m")
    return " ".join(parts) or "0m"


def sanitize_hostname(hostname: str) -> str:
    """Clean hostname for file naming"""
    return re.sub(r'[^a-zA-Z0-9_-]', '_', hostname)
