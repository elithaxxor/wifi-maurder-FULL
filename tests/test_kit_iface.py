import unittest
import subprocess
from unittest.mock import patch
from kit.iface import detect_interfaces, toggle_monitor_mode

class TestIface(unittest.TestCase):
    def test_detect_interfaces_returns_list(self):
        sample_output = b"wlan0     IEEE 802.11  ESSID:off/any\nwlan1     IEEE 802.11  ESSID:off/any"
        with patch('subprocess.check_output', return_value=sample_output):
            ifaces = detect_interfaces()
        self.assertIsInstance(ifaces, list)
        self.assertTrue('wlan0' in ifaces or 'wlan1' in ifaces)

    def test_detect_interfaces_fallback(self):
        with patch('subprocess.check_output', side_effect=Exception()):
            ifaces = detect_interfaces()
        self.assertEqual(ifaces, ['wlan0'])

    def test_toggle_monitor_mode_failure(self):
        with patch('subprocess.Popen', side_effect=FileNotFoundError()):
            result = toggle_monitor_mode('wlan0')
        self.assertFalse(result)

    def test_toggle_monitor_mode_success(self):
        class DummyPopen:
            def __init__(self, *args, **kwargs): pass
            def wait(self): pass
            @property
            def returncode(self): return 0
        with patch('subprocess.Popen', return_value=DummyPopen()):
            result = toggle_monitor_mode('wlan0')
        self.assertTrue(result)