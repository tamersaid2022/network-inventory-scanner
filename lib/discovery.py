"""
Network Inventory Scanner - Discovery Engines
Author: Tamer Khalifa (CCIE #68867)

Host discovery using ICMP, TCP, and ARP methods.
"""

import subprocess
import socket
import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set

logger = logging.getLogger(__name__)


class DiscoveryEngine:
    """Multi-method host discovery"""

    def __init__(self, timeout: int = 2, threads: int = 50):
        self.timeout = timeout
        self.threads = threads

    def discover(self, network: str, methods: List[str] = None) -> Set[str]:
        """Discover active hosts using specified methods"""
        methods = methods or ["icmp", "tcp"]
        active = set()

        hosts = list(ipaddress.ip_network(network, strict=False).hosts())
        logger.info(f"Scanning {len(hosts)} hosts in {network}")

        for method in methods:
            if method == "icmp":
                active.update(self._icmp_sweep(hosts))
            elif method == "tcp":
                active.update(self._tcp_sweep(hosts))
            elif method == "arp":
                active.update(self._arp_sweep(network))

        logger.info(f"Discovered {len(active)} active hosts")
        return active

    def _icmp_sweep(self, hosts: list) -> Set[str]:
        """ICMP ping sweep"""
        active = set()
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._ping, str(h)): str(h) for h in hosts}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    if future.result():
                        active.add(ip)
                except:
                    pass
        return active

    def _ping(self, host: str) -> bool:
        """Ping single host"""
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", str(self.timeout), host],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            return result.returncode == 0
        except:
            return False

    def _tcp_sweep(self, hosts: list, ports: List[int] = None) -> Set[str]:
        """TCP port sweep"""
        ports = ports or [22, 443, 80]
        active = set()
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for h in hosts:
                for p in ports:
                    futures[executor.submit(self._tcp_check, str(h), p)] = str(h)
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    if future.result():
                        active.add(ip)
                except:
                    pass
        return active

    def _tcp_check(self, host: str, port: int) -> bool:
        """Check single TCP port"""
        try:
            with socket.create_connection((host, port), timeout=self.timeout):
                return True
        except:
            return False

    def _arp_sweep(self, network: str) -> Set[str]:
        """ARP sweep (requires scapy and root)"""
        active = set()
        try:
            from scapy.all import ARP, Ether, srp
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
            result = srp(pkt, timeout=self.timeout, verbose=False)[0]
            for _, received in result:
                active.add(received.psrc)
        except ImportError:
            logger.warning("scapy not available for ARP discovery")
        except Exception as e:
            logger.warning(f"ARP sweep failed: {e}")
        return active
