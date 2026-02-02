"""
Network Inventory Scanner - SNMP Collector
Author: Tamer Khalifa (CCIE #68867)

Collects device info via SNMP (v2c and v3).
"""

import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Standard SNMP OIDs
OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "entPhysicalSerialNum": "1.3.6.1.2.1.47.1.1.1.1.11.1",
    "entPhysicalModelName": "1.3.6.1.2.1.47.1.1.1.1.13.1",
}


class SNMPCollector:
    """Collect device information via SNMP"""

    def __init__(self, community: str = "public", version: str = "2c",
                 timeout: int = 5, retries: int = 2):
        self.community = community
        self.version = version
        self.timeout = timeout
        self.retries = retries

    def collect(self, host: str) -> Dict:
        """Collect device info via SNMP"""
        info = {"ip": host, "snmp_reachable": False}

        try:
            from pysnmp.hlapi import (
                getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
                ContextData, ObjectType, ObjectIdentity
            )

            for name, oid in OIDS.items():
                error_indication, error_status, _, var_binds = next(
                    getCmd(
                        SnmpEngine(),
                        CommunityData(self.community),
                        UdpTransportTarget((host, 161), timeout=self.timeout, retries=self.retries),
                        ContextData(),
                        ObjectType(ObjectIdentity(oid))
                    )
                )

                if not error_indication and not error_status:
                    for _, val in var_binds:
                        info[name] = str(val)
                    info["snmp_reachable"] = True

            # Parse vendor from sysDescr
            if "sysDescr" in info:
                info["vendor"] = self._detect_vendor(info["sysDescr"])

        except ImportError:
            logger.warning("pysnmp not available")
        except Exception as e:
            logger.debug(f"SNMP collection failed for {host}: {e}")

        return info

    def _detect_vendor(self, sys_descr: str) -> str:
        """Detect vendor from sysDescr"""
        desc = sys_descr.lower()
        if "cisco" in desc:
            return "Cisco"
        elif "juniper" in desc:
            return "Juniper"
        elif "arista" in desc:
            return "Arista"
        elif "palo alto" in desc:
            return "Palo Alto"
        elif "fortinet" in desc:
            return "Fortinet"
        elif "hp" in desc or "aruba" in desc:
            return "HP/Aruba"
        return "Unknown"
