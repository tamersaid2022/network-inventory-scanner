"""
Network Inventory Scanner - SSH Collector
Author: Tamer Khalifa (CCIE #68867)

Collects device info via SSH using Netmiko.
"""

import re
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class SSHCollector:
    """Collect device information via SSH/CLI"""

    COMMANDS = {
        "cisco_ios": {
            "version": "show version",
            "interfaces": "show ip interface brief",
            "neighbors": "show cdp neighbors detail",
            "inventory": "show inventory",
        },
        "cisco_nxos": {
            "version": "show version",
            "interfaces": "show ip interface brief",
            "neighbors": "show cdp neighbors detail",
            "inventory": "show inventory",
        },
    }

    def __init__(self, username: str, password: str, timeout: int = 30):
        self.username = username
        self.password = password
        self.timeout = timeout

    def collect(self, host: str, device_type: str = "cisco_ios") -> Dict:
        """Collect device info via SSH"""
        info = {"ip": host, "ssh_reachable": False}

        try:
            from netmiko import ConnectHandler

            device = {
                "device_type": device_type,
                "host": host,
                "username": self.username,
                "password": self.password,
                "timeout": self.timeout,
            }

            with ConnectHandler(**device) as conn:
                info["ssh_reachable"] = True
                commands = self.COMMANDS.get(device_type, {})

                for name, cmd in commands.items():
                    try:
                        output = conn.send_command(cmd)
                        info[f"raw_{name}"] = output

                        if name == "version":
                            info.update(self._parse_version(output, device_type))
                    except Exception as e:
                        logger.debug(f"Command '{cmd}' failed on {host}: {e}")

        except ImportError:
            logger.warning("netmiko not available")
        except Exception as e:
            logger.debug(f"SSH collection failed for {host}: {e}")

        return info

    def _parse_version(self, output: str, device_type: str) -> Dict:
        """Parse show version output"""
        parsed = {}
        if "cisco_ios" in device_type:
            hostname = re.search(r"(\S+)\s+uptime is", output)
            if hostname:
                parsed["hostname"] = hostname.group(1)
            version = re.search(r"Version\s+(\S+)", output)
            if version:
                parsed["software_version"] = version.group(1)
            serial = re.search(r"Processor board ID\s+(\S+)", output)
            if serial:
                parsed["serial_number"] = serial.group(1)
            model = re.search(r"cisco\s+(\S+)\s+\(", output, re.IGNORECASE)
            if model:
                parsed["model"] = model.group(1)
        return parsed
