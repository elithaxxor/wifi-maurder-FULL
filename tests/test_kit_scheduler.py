import json
import tempfile
import unittest
from unittest.mock import patch

from kit.scheduler import ScanScheduler
from kit.scan import ScanManager


class DummyDB:
    def insert_scan(self, iface, duration, output):
        pass


class TestScanScheduler(unittest.TestCase):
    def test_load_and_run(self):
        tmp = tempfile.NamedTemporaryFile('w+', delete=False)
        json.dump({"scans": [{"interface": "wlan0", "duration": 1, "interval": 0}]}, tmp)
        tmp.close()
        sched = ScanScheduler(DummyDB(), tmp.name)
        self.assertEqual(len(sched.schedule), 1)
        with patch.object(ScanManager, 'start', return_value=True) as pstart, \
             patch.object(ScanManager, 'stop') as pstop, \
             patch.object(ScanManager, 'record') as precord:
            sched.run_pending()
            pstart.assert_called_once_with('wlan0', 1)
            pstop.assert_called_once()
            precord.assert_called_once_with('wlan0')

