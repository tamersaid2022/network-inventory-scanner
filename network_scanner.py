#!/usr/bin/env python3
"""
Network Inventory Scanner
Automated network device discovery and inventory documentation

Author: Tamer Khalifa (CCIE #68867)
GitHub: https://github.com/tamersaid2022
"""

import os
import sys
import json
import socket
import struct
import logging
import argparse
import ipaddress
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess

import yaml
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Optional imports with graceful fallback
try:
    from pysnmp.hlapi import *
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False
    print("⚠️ pysnmp not installed. SNMP collection disabled.")

try:
    from netmiko import ConnectHandler
    from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
    NETMIKO_AVAILABLE = True
except ImportError:
    NETMIKO_AVAILABLE = False
    print("⚠️ netmiko not installed. SSH collection disabled.")

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("⚠️ python-nmap not installed. Port scanning disabled.")

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    print("⚠️ pandas not installed. Excel export disabled.")

try:
    from mac_vendor_lookup import MacLookup
    MAC_LOOKUP_AVAILABLE = True
except ImportError:
    MAC_LOOKUP_AVAILABLE = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.panel import Panel
    console = Console()
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    console = None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class NetworkInterface:
    """Network interface information"""
    name: str
    description: str = ""
    ip_address: str = ""
    mac_address: str = ""
    speed: str = ""
    admin_status: str = ""
    oper_status: str = ""
    vlan: str = ""
    errors_in: int = 0
    errors_out: int = 0


@dataclass
class DeviceInfo:
    """Network device information"""
    ip_address: str
    hostname: str = ""
    vendor: str = ""
    model: str = ""
    serial_number: str = ""
    software_version: str = ""
    uptime: str = ""
    location: str = ""
    contact: str = ""
    mac_address: str = ""
    device_type: str = ""
    discovery_method: str = ""
    snmp_reachable: bool = False
    ssh_reachable: bool = False
    interfaces: List[NetworkInterface] = field(default_factory=list)
    neighbors: List[Dict] = field(default_factory=list)
    vlans: List[Dict] = field(default_factory=list)
    raw_data: Dict = field(default_factory=dict)
    scan_timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for export"""
        data = asdict(self)
        data['scan_timestamp'] = self.scan_timestamp.isoformat()
        data['interfaces'] = [asdict(i) for i in self.interfaces]
        return data


@dataclass
class ScanResult:
    """Results of a network scan"""
    networks: List[str]
    scan_start: datetime
    scan_end: datetime = None
    total_ips: int = 0
    active_hosts: int = 0
    network_devices: int = 0
    devices: List[DeviceInfo] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


# =============================================================================
# SNMP OIDS
# =============================================================================

SNMP_OIDS = {
    # System MIB
    'sysDescr': '1.3.6.1.2.1.1.1.0',
    'sysObjectID': '1.3.6.1.2.1.1.2.0',
    'sysUpTime': '1.3.6.1.2.1.1.3.0',
    'sysContact': '1.3.6.1.2.1.1.4.0',
    'sysName': '1.3.6.1.2.1.1.5.0',
    'sysLocation': '1.3.6.1.2.1.1.6.0',
    
    # Entity MIB (for serial numbers, model)
    'entPhysicalDescr': '1.3.6.1.2.1.47.1.1.1.1.2',
    'entPhysicalSerialNum': '1.3.6.1.2.1.47.1.1.1.1.11',
    'entPhysicalModelName': '1.3.6.1.2.1.47.1.1.1.1.13',
    
    # Interfaces MIB
    'ifDescr': '1.3.6.1.2.1.2.2.1.2',
    'ifType': '1.3.6.1.2.1.2.2.1.3',
    'ifSpeed': '1.3.6.1.2.1.2.2.1.5',
    'ifPhysAddress': '1.3.6.1.2.1.2.2.1.6',
    'ifAdminStatus': '1.3.6.1.2.1.2.2.1.7',
    'ifOperStatus': '1.3.6.1.2.1.2.2.1.8',
    
    # IP Address Table
    'ipAdEntAddr': '1.3.6.1.2.1.4.20.1.1',
    'ipAdEntIfIndex': '1.3.6.1.2.1.4.20.1.2',
}


# =============================================================================
# VENDOR OUI DATABASE (Common vendors)
# =============================================================================

VENDOR_OUI = {
    '00:00:0C': 'Cisco',
    '00:01:42': 'Cisco',
    '00:1A:A1': 'Cisco',
    '00:1B:D4': 'Cisco',
    '00:1C:0F': 'Cisco',
    '00:1E:13': 'Cisco',
    '00:1E:F7': 'Cisco',
    '00:21:D7': 'Cisco',
    '00:22:BD': 'Cisco',
    '00:23:04': 'Cisco',
    '00:24:C4': 'Cisco',
    '00:25:84': 'Cisco',
    '00:26:98': 'Cisco',
    '00:0D:28': 'Cisco',
    '28:6F:7F': 'Cisco',
    '5C:50:15': 'Cisco',
    '64:00:F1': 'Cisco',
    'F8:C2:88': 'Cisco',
    '00:05:73': 'Cisco',
    '00:0E:38': 'Cisco',
    '00:14:A8': 'Cisco',
    '00:17:94': 'Cisco',
    '00:18:73': 'Cisco',
    '00:19:2F': 'Cisco',
    '00:1A:2F': 'Cisco',
    
    '00:01:E6': 'Juniper',
    '00:05:85': 'Juniper',
    '00:10:DB': 'Juniper',
    '00:12:1E': 'Juniper',
    '00:14:F6': 'Juniper',
    '00:17:CB': 'Juniper',
    '00:19:E2': 'Juniper',
    '00:1B:C0': 'Juniper',
    '00:1D:B5': 'Juniper',
    '00:1F:12': 'Juniper',
    '00:21:59': 'Juniper',
    '00:22:83': 'Juniper',
    '00:23:9C': 'Juniper',
    '00:24:DC': 'Juniper',
    
    '00:1C:73': 'Arista',
    '28:99:3A': 'Arista',
    '44:4C:A8': 'Arista',
    
    '00:1B:17': 'Palo Alto',
    'B4:0C:25': 'Palo Alto',
    'E4:A7:49': 'Palo Alto',
    
    '00:09:0F': 'Fortinet',
    '00:60:6E': 'Fortinet',
    '08:5B:0E': 'Fortinet',
    '70:4C:A5': 'Fortinet',
    '90:6C:AC': 'Fortinet',
    
    '00:04:96': 'HP/Aruba',
    '00:0B:CD': 'HP/Aruba',
    '00:11:85': 'HP/Aruba',
    '00:14:C2': 'HP/Aruba',
    '00:17:A4': 'HP/Aruba',
    '00:18:71': 'HP/Aruba',
    '00:19:BB': 'HP/Aruba',
    '00:1B:78': 'HP/Aruba',
    '00:1C:C4': 'HP/Aruba',
    '00:1E:0B': 'HP/Aruba',
    '00:1F:29': 'HP/Aruba',
    '00:21:F7': 'HP/Aruba',
    '00:22:64': 'HP/Aruba',
    '00:23:47': 'HP/Aruba',
    '00:24:A8': 'HP/Aruba',
    '00:25:B3': 'HP/Aruba',
    '00:26:F1': 'HP/Aruba',
    
    '00:18:0A': 'Dell',
    '00:1A:A0': 'Dell',
    '00:1C:23': 'Dell',
    '00:1D:09': 'Dell',
    '00:1E:4F': 'Dell',
    '00:21:9B': 'Dell',
    '00:22:19': 'Dell',
    '00:23:AE': 'Dell',
    '00:24:E8': 'Dell',
    '00:26:B9': 'Dell',
    '14:18:77': 'Dell',
    '18:A9:9B': 'Dell',
    '18:DB:F2': 'Dell',
    '1C:40:24': 'Dell',
    
    '00:0C:29': 'VMware',
    '00:50:56': 'VMware',
}


# =============================================================================
# DISCOVERY ENGINE
# =============================================================================

class DiscoveryEngine:
    """Network device discovery"""
    
    def __init__(self, timeout: float = 2.0, threads: int = 100):
        self.timeout = timeout
        self.threads = threads
        self.mac_lookup = MacLookup() if MAC_LOOKUP_AVAILABLE else None
    
    def discover_network(self, network: str) -> List[str]:
        """
        Discover active hosts in a network
        
        Args:
            network: CIDR notation (e.g., "192.168.1.0/24")
            
        Returns:
            List of active IP addresses
        """
        active_hosts = []
        
        try:
            net = ipaddress.ip_network(network, strict=False)
            hosts = list(net.hosts())
            
            logger.info(f"🔍 Scanning {len(hosts)} hosts in {network}")
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self._ping_host, str(ip)): str(ip) for ip in hosts}
                
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        if future.result():
                            active_hosts.append(ip)
                    except Exception as e:
                        logger.debug(f"Error scanning {ip}: {e}")
            
            logger.info(f"✅ Found {len(active_hosts)} active hosts in {network}")
            
        except Exception as e:
            logger.error(f"Discovery error for {network}: {e}")
        
        return active_hosts
    
    def _ping_host(self, ip: str) -> bool:
        """Ping a single host"""
        try:
            # Use system ping command
            if sys.platform == 'win32':
                cmd = ['ping', '-n', '1', '-w', str(int(self.timeout * 1000)), ip]
            else:
                cmd = ['ping', '-c', '1', '-W', str(int(self.timeout)), ip]
            
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=self.timeout + 1)
            return result.returncode == 0
            
        except subprocess.TimeoutExpired:
            return False
        except Exception:
            return False
    
    def tcp_scan(self, ip: str, ports: List[int] = None) -> Dict[int, bool]:
        """
        Scan TCP ports
        
        Args:
            ip: Target IP address
            ports: List of ports to scan
            
        Returns:
            Dictionary of port: open status
        """
        ports = ports or [22, 23, 80, 443, 161, 162]
        results = {}
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                results[port] = (result == 0)
                sock.close()
            except:
                results[port] = False
        
        return results
    
    def get_vendor_from_mac(self, mac: str) -> str:
        """Get vendor from MAC address"""
        if not mac:
            return "Unknown"
        
        # Normalize MAC address
        mac = mac.upper().replace('-', ':')
        oui = mac[:8]
        
        # Check local database first
        if oui in VENDOR_OUI:
            return VENDOR_OUI[oui]
        
        # Try mac-vendor-lookup library
        if self.mac_lookup:
            try:
                return self.mac_lookup.lookup(mac)
            except:
                pass
        
        return "Unknown"


# =============================================================================
# SNMP COLLECTOR
# =============================================================================

class SNMPCollector:
    """SNMP data collection"""
    
    def __init__(self, community: str = "public", version: str = "2c", 
                 timeout: int = 5, retries: int = 2):
        self.community = community
        self.version = version
        self.timeout = timeout
        self.retries = retries
    
    def collect(self, ip: str) -> Optional[Dict]:
        """
        Collect device information via SNMP
        
        Args:
            ip: Target IP address
            
        Returns:
            Dictionary of collected data or None if unreachable
        """
        if not SNMP_AVAILABLE:
            return None
        
        data = {}
        
        # Get system information
        for name, oid in SNMP_OIDS.items():
            if name.startswith('sys'):
                value = self._get_snmp(ip, oid)
                if value:
                    data[name] = value
        
        # Get entity information (serial, model)
        entity_data = self._walk_snmp(ip, SNMP_OIDS['entPhysicalSerialNum'])
        if entity_data:
            # Usually first entry is chassis
            for _, value in entity_data.items():
                if value and len(value) > 5:
                    data['serial_number'] = value
                    break
        
        model_data = self._walk_snmp(ip, SNMP_OIDS['entPhysicalModelName'])
        if model_data:
            for _, value in model_data.items():
                if value and len(value) > 2:
                    data['model'] = value
                    break
        
        return data if data else None
    
    def _get_snmp(self, ip: str, oid: str) -> Optional[str]:
        """Get single SNMP value"""
        try:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(self.community, mpModel=1 if self.version == '2c' else 0),
                UdpTransportTarget((ip, 161), timeout=self.timeout, retries=self.retries),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )
            
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
            
            if errorIndication or errorStatus:
                return None
            
            for varBind in varBinds:
                return str(varBind[1])
            
        except Exception as e:
            logger.debug(f"SNMP get error for {ip}: {e}")
        
        return None
    
    def _walk_snmp(self, ip: str, oid: str) -> Dict[str, str]:
        """Walk SNMP table"""
        results = {}
        
        try:
            for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                SnmpEngine(),
                CommunityData(self.community, mpModel=1 if self.version == '2c' else 0),
                UdpTransportTarget((ip, 161), timeout=self.timeout, retries=self.retries),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False
            ):
                if errorIndication or errorStatus:
                    break
                
                for varBind in varBinds:
                    results[str(varBind[0])] = str(varBind[1])
                    
        except Exception as e:
            logger.debug(f"SNMP walk error for {ip}: {e}")
        
        return results
    
    def is_reachable(self, ip: str) -> bool:
        """Check if host responds to SNMP"""
        return self._get_snmp(ip, SNMP_OIDS['sysName']) is not None


# =============================================================================
# SSH COLLECTOR
# =============================================================================

class SSHCollector:
    """SSH/CLI data collection"""
    
    # Device type detection patterns
    DEVICE_TYPE_PATTERNS = {
        'cisco_ios': ['Cisco IOS', 'C2960', 'C3750', 'C4500', 'C6500', 'ISR'],
        'cisco_nxos': ['Nexus', 'NX-OS', 'N9K', 'N7K', 'N5K'],
        'cisco_asa': ['ASA', 'Adaptive Security'],
        'juniper_junos': ['Juniper', 'JUNOS', 'SRX', 'EX', 'MX', 'QFX'],
        'arista_eos': ['Arista', 'EOS'],
        'paloalto_panos': ['Palo Alto', 'PAN-OS', 'PA-'],
    }
    
    # Commands for each device type
    COMMANDS = {
        'cisco_ios': {
            'version': 'show version',
            'hostname': 'show running-config | include hostname',
            'interfaces': 'show ip interface brief',
            'neighbors': 'show cdp neighbors detail',
            'inventory': 'show inventory',
            'vlans': 'show vlan brief',
        },
        'cisco_nxos': {
            'version': 'show version',
            'hostname': 'show hostname',
            'interfaces': 'show ip interface brief vrf all',
            'neighbors': 'show cdp neighbors detail',
            'inventory': 'show inventory',
            'vlans': 'show vlan brief',
        },
        'juniper_junos': {
            'version': 'show version',
            'hostname': 'show system hostname',
            'interfaces': 'show interfaces terse',
            'neighbors': 'show lldp neighbors',
            'inventory': 'show chassis hardware',
        },
    }
    
    def __init__(self, username: str, password: str, timeout: int = 30):
        self.username = username
        self.password = password
        self.timeout = timeout
    
    def collect(self, ip: str, device_type: str = None) -> Optional[Dict]:
        """
        Collect device information via SSH
        
        Args:
            ip: Target IP address
            device_type: Netmiko device type (auto-detected if None)
            
        Returns:
            Dictionary of collected data or None if unreachable
        """
        if not NETMIKO_AVAILABLE:
            return None
        
        # Auto-detect device type if not specified
        if not device_type:
            device_type = self._detect_device_type(ip)
            if not device_type:
                device_type = 'cisco_ios'  # Default
        
        data = {'device_type': device_type}
        
        try:
            connection = ConnectHandler(
                device_type=device_type,
                host=ip,
                username=self.username,
                password=self.password,
                timeout=self.timeout
            )
            
            commands = self.COMMANDS.get(device_type, self.COMMANDS['cisco_ios'])
            
            for cmd_name, cmd in commands.items():
                try:
                    output = connection.send_command(cmd, read_timeout=30)
                    data[cmd_name] = output
                except:
                    pass
            
            connection.disconnect()
            
            # Parse collected data
            parsed_data = self._parse_output(data, device_type)
            data.update(parsed_data)
            
            return data
            
        except NetmikoAuthenticationException:
            logger.debug(f"SSH authentication failed for {ip}")
        except NetmikoTimeoutException:
            logger.debug(f"SSH timeout for {ip}")
        except Exception as e:
            logger.debug(f"SSH error for {ip}: {e}")
        
        return None
    
    def _detect_device_type(self, ip: str) -> Optional[str]:
        """Try to detect device type"""
        # Try common device types
        for device_type in ['cisco_ios', 'cisco_nxos', 'juniper_junos']:
            try:
                connection = ConnectHandler(
                    device_type=device_type,
                    host=ip,
                    username=self.username,
                    password=self.password,
                    timeout=10
                )
                connection.disconnect()
                return device_type
            except:
                continue
        
        return None
    
    def _parse_output(self, data: Dict, device_type: str) -> Dict:
        """Parse command output to extract structured data"""
        parsed = {}
        
        # Parse version output
        if 'version' in data:
            version_output = data['version']
            
            if device_type == 'cisco_ios':
                # Extract version
                import re
                version_match = re.search(r'Version (\S+)', version_output)
                if version_match:
                    parsed['software_version'] = version_match.group(1)
                
                # Extract model
                model_match = re.search(r'cisco (\S+)', version_output, re.IGNORECASE)
                if model_match:
                    parsed['model'] = model_match.group(1)
                
                # Extract serial
                serial_match = re.search(r'Processor board ID (\S+)', version_output)
                if serial_match:
                    parsed['serial_number'] = serial_match.group(1)
                
                # Extract uptime
                uptime_match = re.search(r'uptime is (.+)', version_output)
                if uptime_match:
                    parsed['uptime'] = uptime_match.group(1)
        
        # Parse hostname
        if 'hostname' in data:
            import re
            hostname_match = re.search(r'hostname (\S+)', data['hostname'])
            if hostname_match:
                parsed['hostname'] = hostname_match.group(1)
        
        return parsed
    
    def is_reachable(self, ip: str) -> bool:
        """Check if SSH is accessible"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((ip, 22))
            sock.close()
            return result == 0
        except:
            return False


# =============================================================================
# EXPORTER
# =============================================================================

class Exporter:
    """Export inventory data to various formats"""
    
    def __init__(self, output_dir: str = "./inventory"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def export_json(self, scan_result: ScanResult, filename: str = None) -> str:
        """Export to JSON"""
        filename = filename or f"inventory_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = self.output_dir / filename
        
        data = {
            'scan_info': {
                'networks': scan_result.networks,
                'scan_start': scan_result.scan_start.isoformat(),
                'scan_end': scan_result.scan_end.isoformat() if scan_result.scan_end else None,
                'total_ips': scan_result.total_ips,
                'active_hosts': scan_result.active_hosts,
                'network_devices': scan_result.network_devices,
            },
            'devices': [d.to_dict() for d in scan_result.devices]
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        logger.info(f"📄 Exported JSON: {filepath}")
        return str(filepath)
    
    def export_csv(self, scan_result: ScanResult, filename: str = None) -> str:
        """Export to CSV"""
        filename = filename or f"inventory_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = self.output_dir / filename
        
        # Flatten device data
        rows = []
        for device in scan_result.devices:
            row = {
                'ip_address': device.ip_address,
                'hostname': device.hostname,
                'vendor': device.vendor,
                'model': device.model,
                'serial_number': device.serial_number,
                'software_version': device.software_version,
                'uptime': device.uptime,
                'location': device.location,
                'contact': device.contact,
                'mac_address': device.mac_address,
                'device_type': device.device_type,
                'snmp_reachable': device.snmp_reachable,
                'ssh_reachable': device.ssh_reachable,
                'interface_count': len(device.interfaces),
                'scan_timestamp': device.scan_timestamp.isoformat(),
            }
            rows.append(row)
        
        if PANDAS_AVAILABLE:
            df = pd.DataFrame(rows)
            df.to_csv(filepath, index=False)
        else:
            import csv
            if rows:
                with open(filepath, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                    writer.writeheader()
                    writer.writerows(rows)
        
        logger.info(f"📄 Exported CSV: {filepath}")
        return str(filepath)
    
    def export_excel(self, scan_result: ScanResult, filename: str = None) -> str:
        """Export to Excel with multiple sheets"""
        if not PANDAS_AVAILABLE:
            logger.warning("pandas not available - cannot export Excel")
            return self.export_csv(scan_result, filename.replace('.xlsx', '.csv') if filename else None)
        
        filename = filename or f"inventory_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        filepath = self.output_dir / filename
        
        with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
            # Summary sheet
            summary_data = {
                'Metric': ['Networks Scanned', 'Total IPs', 'Active Hosts', 'Network Devices', 
                          'Scan Start', 'Scan End'],
                'Value': [', '.join(scan_result.networks), scan_result.total_ips, 
                         scan_result.active_hosts, scan_result.network_devices,
                         scan_result.scan_start.isoformat(),
                         scan_result.scan_end.isoformat() if scan_result.scan_end else 'N/A']
            }
            pd.DataFrame(summary_data).to_excel(writer, sheet_name='Summary', index=False)
            
            # Devices sheet
            device_rows = [{
                'IP Address': d.ip_address,
                'Hostname': d.hostname,
                'Vendor': d.vendor,
                'Model': d.model,
                'Serial Number': d.serial_number,
                'Software Version': d.software_version,
                'Uptime': d.uptime,
                'Location': d.location,
                'MAC Address': d.mac_address,
                'Device Type': d.device_type,
                'SNMP': '✅' if d.snmp_reachable else '❌',
                'SSH': '✅' if d.ssh_reachable else '❌',
            } for d in scan_result.devices]
            pd.DataFrame(device_rows).to_excel(writer, sheet_name='Devices', index=False)
            
            # Interfaces sheet
            interface_rows = []
            for device in scan_result.devices:
                for iface in device.interfaces:
                    interface_rows.append({
                        'Device': device.hostname or device.ip_address,
                        'Interface': iface.name,
                        'Description': iface.description,
                        'IP Address': iface.ip_address,
                        'MAC Address': iface.mac_address,
                        'Speed': iface.speed,
                        'Admin Status': iface.admin_status,
                        'Oper Status': iface.oper_status,
                        'VLAN': iface.vlan,
                    })
            if interface_rows:
                pd.DataFrame(interface_rows).to_excel(writer, sheet_name='Interfaces', index=False)
        
        logger.info(f"📊 Exported Excel: {filepath}")
        return str(filepath)
    
    def export_html(self, scan_result: ScanResult, filename: str = None) -> str:
        """Export to HTML report"""
        filename = filename or f"inventory_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = self.output_dir / filename
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Inventory Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4a5568; color: white; }}
        tr:nth-child(even) {{ background-color: #f9fafb; }}
        tr:hover {{ background-color: #e2e8f0; }}
    </style>
</head>
<body class="bg-gray-100 p-8">
    <div class="max-w-7xl mx-auto">
        <div class="bg-white rounded-lg shadow-lg p-6 mb-8">
            <h1 class="text-3xl font-bold text-gray-800 mb-4">🔍 Network Inventory Report</h1>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div class="bg-blue-100 rounded-lg p-4 text-center">
                    <div class="text-3xl font-bold text-blue-600">{scan_result.active_hosts}</div>
                    <div class="text-gray-600">Active Hosts</div>
                </div>
                <div class="bg-green-100 rounded-lg p-4 text-center">
                    <div class="text-3xl font-bold text-green-600">{scan_result.network_devices}</div>
                    <div class="text-gray-600">Network Devices</div>
                </div>
                <div class="bg-purple-100 rounded-lg p-4 text-center">
                    <div class="text-3xl font-bold text-purple-600">{scan_result.total_ips}</div>
                    <div class="text-gray-600">Total IPs Scanned</div>
                </div>
                <div class="bg-orange-100 rounded-lg p-4 text-center">
                    <div class="text-3xl font-bold text-orange-600">{len(scan_result.networks)}</div>
                    <div class="text-gray-600">Networks</div>
                </div>
            </div>
            <p class="text-gray-500 mt-4">
                Scan completed: {scan_result.scan_end.strftime('%Y-%m-%d %H:%M:%S') if scan_result.scan_end else 'N/A'}
            </p>
        </div>
        
        <div class="bg-white rounded-lg shadow-lg p-6">
            <h2 class="text-2xl font-bold text-gray-800 mb-4">Device Inventory</h2>
            <div class="overflow-x-auto">
                <table>
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Hostname</th>
                            <th>Vendor</th>
                            <th>Model</th>
                            <th>Version</th>
                            <th>Serial</th>
                            <th>SNMP</th>
                            <th>SSH</th>
                        </tr>
                    </thead>
                    <tbody>
"""
        
        for device in scan_result.devices:
            html += f"""
                        <tr>
                            <td>{device.ip_address}</td>
                            <td>{device.hostname or '-'}</td>
                            <td>{device.vendor or '-'}</td>
                            <td>{device.model or '-'}</td>
                            <td>{device.software_version or '-'}</td>
                            <td>{device.serial_number or '-'}</td>
                            <td>{'✅' if device.snmp_reachable else '❌'}</td>
                            <td>{'✅' if device.ssh_reachable else '❌'}</td>
                        </tr>
"""
        
        html += """
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="text-center text-gray-500 mt-8">
            Generated by Network Inventory Scanner | Author: Tamer Khalifa (CCIE #68867)
        </div>
    </div>
</body>
</html>
"""
        
        with open(filepath, 'w') as f:
            f.write(html)
        
        logger.info(f"🌐 Exported HTML: {filepath}")
        return str(filepath)


# =============================================================================
# MAIN SCANNER CLASS
# =============================================================================

class NetworkScanner:
    """Main network scanner orchestrator"""
    
    def __init__(self, networks: List[str] = None, snmp_community: str = "public",
                 ssh_username: str = None, ssh_password: str = None,
                 timeout: float = 2.0, threads: int = 100):
        """
        Initialize network scanner
        
        Args:
            networks: List of networks to scan (CIDR notation)
            snmp_community: SNMP community string
            ssh_username: SSH username
            ssh_password: SSH password
            timeout: Discovery timeout in seconds
            threads: Number of parallel threads
        """
        self.networks = networks or []
        self.timeout = timeout
        self.threads = threads
        
        # Initialize engines
        self.discovery = DiscoveryEngine(timeout=timeout, threads=threads)
        self.snmp_collector = SNMPCollector(community=snmp_community) if SNMP_AVAILABLE else None
        self.ssh_collector = SSHCollector(
            username=ssh_username or os.getenv('SSH_USER', 'admin'),
            password=ssh_password or os.getenv('SSH_PASS', '')
        ) if NETMIKO_AVAILABLE else None
        self.exporter = Exporter()
        
        # Results
        self.scan_result = None
    
    def scan(self, networks: List[str] = None) -> ScanResult:
        """
        Run full network scan
        
        Args:
            networks: Networks to scan (uses init networks if not provided)
            
        Returns:
            ScanResult with all discovered devices
        """
        networks = networks or self.networks
        
        if not networks:
            raise ValueError("No networks specified for scanning")
        
        self.scan_result = ScanResult(
            networks=networks,
            scan_start=datetime.now()
        )
        
        # Phase 1: Discovery
        print("\n" + "="*60)
        print("PHASE 1: NETWORK DISCOVERY")
        print("="*60)
        
        all_active_hosts = []
        for network in networks:
            try:
                net = ipaddress.ip_network(network, strict=False)
                self.scan_result.total_ips += net.num_addresses - 2  # Exclude network/broadcast
            except:
                pass
            
            hosts = self.discovery.discover_network(network)
            all_active_hosts.extend(hosts)
        
        self.scan_result.active_hosts = len(all_active_hosts)
        
        # Phase 2: Collection
        print("\n" + "="*60)
        print("PHASE 2: DATA COLLECTION")
        print("="*60)
        
        for ip in all_active_hosts:
            device = self._collect_device_info(ip)
            self.scan_result.devices.append(device)
            
            if device.hostname or device.vendor:
                self.scan_result.network_devices += 1
        
        self.scan_result.scan_end = datetime.now()
        
        # Print summary
        self._print_summary()
        
        return self.scan_result
    
    def _collect_device_info(self, ip: str) -> DeviceInfo:
        """Collect all available information for a device"""
        device = DeviceInfo(ip_address=ip)
        device.discovery_method = "icmp"
        
        # Try SNMP collection
        if self.snmp_collector:
            logger.debug(f"Trying SNMP for {ip}")
            snmp_data = self.snmp_collector.collect(ip)
            if snmp_data:
                device.snmp_reachable = True
                device.hostname = snmp_data.get('sysName', '')
                device.location = snmp_data.get('sysLocation', '')
                device.contact = snmp_data.get('sysContact', '')
                device.serial_number = snmp_data.get('serial_number', '')
                device.model = snmp_data.get('model', '')
                
                # Parse sysDescr for vendor/version
                sys_descr = snmp_data.get('sysDescr', '')
                if 'cisco' in sys_descr.lower():
                    device.vendor = 'Cisco'
                elif 'juniper' in sys_descr.lower():
                    device.vendor = 'Juniper'
                elif 'arista' in sys_descr.lower():
                    device.vendor = 'Arista'
                
                device.raw_data['snmp'] = snmp_data
        
        # Try SSH collection
        if self.ssh_collector and self.ssh_collector.is_reachable(ip):
            logger.debug(f"Trying SSH for {ip}")
            ssh_data = self.ssh_collector.collect(ip)
            if ssh_data:
                device.ssh_reachable = True
                device.hostname = ssh_data.get('hostname') or device.hostname
                device.software_version = ssh_data.get('software_version', '')
                device.model = ssh_data.get('model') or device.model
                device.serial_number = ssh_data.get('serial_number') or device.serial_number
                device.uptime = ssh_data.get('uptime', '')
                device.device_type = ssh_data.get('device_type', '')
                device.raw_data['ssh'] = ssh_data
        
        # Determine vendor from hostname if not set
        if not device.vendor and device.hostname:
            hostname_lower = device.hostname.lower()
            if any(x in hostname_lower for x in ['cisco', 'cat', 'isr', 'asr', 'nexus']):
                device.vendor = 'Cisco'
            elif any(x in hostname_lower for x in ['juniper', 'srx', 'ex-', 'mx-']):
                device.vendor = 'Juniper'
            elif 'arista' in hostname_lower:
                device.vendor = 'Arista'
            elif 'palo' in hostname_lower or 'pa-' in hostname_lower:
                device.vendor = 'Palo Alto'
            elif 'forti' in hostname_lower:
                device.vendor = 'Fortinet'
        
        return device
    
    def _print_summary(self):
        """Print scan summary"""
        print("\n" + "="*60)
        print("SCAN RESULTS SUMMARY")
        print("="*60)
        print(f"Networks Scanned: {', '.join(self.scan_result.networks)}")
        print(f"Total IPs:        {self.scan_result.total_ips}")
        print(f"Active Hosts:     {self.scan_result.active_hosts}")
        print(f"Network Devices:  {self.scan_result.network_devices}")
        print(f"Scan Duration:    {(self.scan_result.scan_end - self.scan_result.scan_start).total_seconds():.1f}s")
        print("="*60)
        
        print(f"\n{'IP Address':<16} {'Hostname':<20} {'Vendor':<12} {'Model':<15} {'Version':<12}")
        print("-"*75)
        
        for device in self.scan_result.devices[:20]:  # Show first 20
            print(f"{device.ip_address:<16} {(device.hostname or '-'):<20} {(device.vendor or '-'):<12} {(device.model or '-'):<15} {(device.software_version or '-'):<12}")
        
        if len(self.scan_result.devices) > 20:
            print(f"\n... and {len(self.scan_result.devices) - 20} more devices")
    
    def export_csv(self, filename: str = None) -> str:
        """Export to CSV"""
        if not self.scan_result:
            raise ValueError("No scan results - run scan() first")
        return self.exporter.export_csv(self.scan_result, filename)
    
    def export_excel(self, filename: str = None) -> str:
        """Export to Excel"""
        if not self.scan_result:
            raise ValueError("No scan results - run scan() first")
        return self.exporter.export_excel(self.scan_result, filename)
    
    def export_json(self, filename: str = None) -> str:
        """Export to JSON"""
        if not self.scan_result:
            raise ValueError("No scan results - run scan() first")
        return self.exporter.export_json(self.scan_result, filename)
    
    def export_html(self, filename: str = None) -> str:
        """Export to HTML"""
        if not self.scan_result:
            raise ValueError("No scan results - run scan() first")
        return self.exporter.export_html(self.scan_result, filename)


# =============================================================================
# CLI INTERFACE
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Network Inventory Scanner - Automated device discovery and documentation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Scan single network:
    python network_scanner.py scan --network 192.168.1.0/24
    
  Scan with SNMP:
    python network_scanner.py scan --network 192.168.1.0/24 --snmp-community public
    
  Scan with SSH:
    python network_scanner.py scan --network 192.168.1.0/24 --ssh-user admin --ssh-pass password
    
  Full scan with export:
    python network_scanner.py scan --network 192.168.1.0/24 --snmp-community public \\
        --ssh-user admin --ssh-pass password --output inventory.xlsx

Author: Tamer Khalifa (CCIE #68867)
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan network for devices")
    scan_parser.add_argument("--network", "-n", action="append", required=True, help="Network to scan (CIDR)")
    scan_parser.add_argument("--snmp-community", "-c", help="SNMP community string")
    scan_parser.add_argument("--ssh-user", "-u", help="SSH username")
    scan_parser.add_argument("--ssh-pass", "-p", help="SSH password")
    scan_parser.add_argument("--timeout", "-t", type=float, default=2.0, help="Discovery timeout")
    scan_parser.add_argument("--threads", type=int, default=100, help="Parallel threads")
    scan_parser.add_argument("--output", "-o", help="Output file (auto-detects format from extension)")
    scan_parser.add_argument("--format", "-f", choices=['json', 'csv', 'excel', 'html', 'all'], default='all', help="Output format")
    
    # Export command
    export_parser = subparsers.add_parser("export", help="Export existing scan results")
    export_parser.add_argument("--input", "-i", required=True, help="Input JSON file")
    export_parser.add_argument("--format", "-f", default="all", help="Output format(s), comma-separated")
    
    # Diff command
    diff_parser = subparsers.add_parser("diff", help="Compare two inventory files")
    diff_parser.add_argument("--old", required=True, help="Old inventory JSON")
    diff_parser.add_argument("--new", required=True, help="New inventory JSON")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == "scan":
        scanner = NetworkScanner(
            networks=args.network,
            snmp_community=args.snmp_community or os.getenv('SNMP_COMMUNITY', 'public'),
            ssh_username=args.ssh_user,
            ssh_password=args.ssh_pass,
            timeout=args.timeout,
            threads=args.threads
        )
        
        # Run scan
        result = scanner.scan()
        
        # Export results
        if args.format == 'all' or args.output:
            if args.output:
                ext = Path(args.output).suffix.lower()
                if ext == '.json':
                    scanner.export_json(args.output)
                elif ext == '.csv':
                    scanner.export_csv(args.output)
                elif ext in ['.xlsx', '.xls']:
                    scanner.export_excel(args.output)
                elif ext in ['.html', '.htm']:
                    scanner.export_html(args.output)
                else:
                    scanner.export_json(args.output)
            else:
                scanner.export_json()
                scanner.export_csv()
                scanner.export_excel()
                scanner.export_html()
        elif args.format == 'json':
            scanner.export_json()
        elif args.format == 'csv':
            scanner.export_csv()
        elif args.format == 'excel':
            scanner.export_excel()
        elif args.format == 'html':
            scanner.export_html()
    
    elif args.command == "diff":
        print("Delta comparison feature - comparing inventories...")
        
        with open(args.old) as f:
            old_data = json.load(f)
        with open(args.new) as f:
            new_data = json.load(f)
        
        old_devices = {d['ip_address']: d for d in old_data.get('devices', [])}
        new_devices = {d['ip_address']: d for d in new_data.get('devices', [])}
        
        old_ips = set(old_devices.keys())
        new_ips = set(new_devices.keys())
        
        added = new_ips - old_ips
        removed = old_ips - new_ips
        
        print("\n" + "="*60)
        print("INVENTORY CHANGES")
        print("="*60)
        
        if added:
            print(f"\n✅ NEW DEVICES ({len(added)})")
            for ip in added:
                d = new_devices[ip]
                print(f"   {ip} - {d.get('hostname', 'Unknown')} ({d.get('vendor', 'Unknown')})")
        
        if removed:
            print(f"\n❌ REMOVED DEVICES ({len(removed)})")
            for ip in removed:
                d = old_devices[ip]
                print(f"   {ip} - {d.get('hostname', 'Unknown')} ({d.get('vendor', 'Unknown')})")
        
        if not added and not removed:
            print("\n✅ No changes detected")


if __name__ == "__main__":
    main()
