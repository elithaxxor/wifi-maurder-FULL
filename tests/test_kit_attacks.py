import unittest
from kit.attacks import build_deauth_cmd, build_packet, stop_attack
import subprocess

class TestAttacks(unittest.TestCase):
    def test_build_deauth_cmd_no_client(self):
        cmd = build_deauth_cmd('wlan0', 'AA:BB:CC:DD:EE:FF', '', 5)
        self.assertIn('aireplay-ng', cmd[0])
        self.assertIn('-a', cmd)
        self.assertIn('AA:BB:CC:DD:EE:FF', cmd)

    def test_build_deauth_cmd_with_client(self):
        cmd = build_deauth_cmd('wlan0', 'AA:BB:CC:DD:EE:FF', '11:22:33:44:55:66', 3)
        self.assertIn('-c', cmd)
        self.assertIn('11:22:33:44:55:66', cmd)

    def test_build_packet_variants(self):
        # Skip if Scapy not available
        from kit.attacks import build_packet
        try:
            pkt1 = build_packet('Deauth Flood', 'AA:BB:CC:DD:EE:FF')
        except RuntimeError:
            self.skipTest("Scapy not available")
        self.assertIsNotNone(pkt1)
        pkt2 = build_packet('Beacon Flood', 'TestSSID', '6')
        self.assertIsNotNone(pkt2)
        pkt3 = build_packet('Custom TCP', '192.168.1.1', '80')
        self.assertIsNotNone(pkt3)
        pkt4 = build_packet('Custom UDP', '192.168.1.1', '53')
        self.assertIsNotNone(pkt4)

    def test_stop_attack(self):
        class Proc:
            def __init__(self): self._poll = None
            def poll(self): return None
            def terminate(self): self._poll = 1
            def wait(self, timeout=None): pass
        proc = Proc()
        self.assertTrue(stop_attack(proc))