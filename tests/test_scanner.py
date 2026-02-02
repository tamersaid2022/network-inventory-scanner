"""
Network Inventory Scanner - Unit Tests
Author: Tamer Khalifa (CCIE #68867)
Run: python -m pytest tests/test_scanner.py -v
"""
import unittest
from lib.utils import mac_vendor_lookup, format_uptime, sanitize_hostname

class TestUtils(unittest.TestCase):
    def test_mac_vendor_cisco(self):
        self.assertEqual(mac_vendor_lookup("00:00:0C:12:34:56"), "Cisco")

    def test_mac_vendor_vmware(self):
        self.assertEqual(mac_vendor_lookup("00:50:56:AA:BB:CC"), "VMware")

    def test_mac_vendor_unknown(self):
        self.assertEqual(mac_vendor_lookup("FF:FF:FF:FF:FF:FF"), "Unknown")

    def test_format_uptime(self):
        self.assertEqual(format_uptime(90061), "1d 1h 1m")

    def test_sanitize_hostname(self):
        self.assertEqual(sanitize_hostname("router@site.1"), "router_site_1")

if __name__ == "__main__":
    unittest.main()
