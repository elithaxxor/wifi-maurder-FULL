import os
import tempfile
import unittest
from unittest.mock import patch
from kit.scan import ScanManager

class DummyDB:
    def __init__(self): self.records = []
    def insert_scan(self, iface, duration, output):
        self.records.append((iface, duration, output))
        return 1

class TestScanManager(unittest.TestCase):
    def test_scan_start_failure(self):
        # Simulate Popen failure
        with patch('subprocess.Popen', side_effect=Exception()):
            sm = ScanManager(db_manager=None, tmp_dir=tempfile.gettempdir())
            ok = sm.start('wlan0', 10)
        self.assertFalse(ok)

    def test_scan_progress_and_stop(self):
        # Simulate running process
        class DummyProcess:
            def __init__(self, *args, **kwargs): self._poll = None
            def poll(self): return self._poll
            def terminate(self): pass
            def wait(self, timeout=None): pass
        with patch('subprocess.Popen', return_value=DummyProcess()):
            sm = ScanManager(db_manager=None, tmp_dir=tempfile.gettempdir())
            self.assertTrue(sm.start('wlan0', 1))
            elapsed, pct = sm.progress()
            self.assertIsInstance(elapsed, float)
            self.assertIsInstance(pct, int)
            # Stop should not error
            self.assertTrue(sm.stop())

    def test_parse_results_empty(self):
        tmp_dir = tempfile.mkdtemp()
        sm = ScanManager(db_manager=None, tmp_dir=tmp_dir)
        # No CSV files
        nets = sm.parse_results()
        self.assertEqual(nets, [])

    def test_record_inserts(self):
        class DummyDB:
            def __init__(self): self.records = []
            def insert_scan(self, iface, duration, output):
                self.records.append((iface, duration, output))
                return 1
        temp_db = DummyDB()
        sm = ScanManager(db_manager=temp_db, tmp_dir=tempfile.gettempdir())
        # Simulate empty parse_results
        sm.parse_results = lambda: []
        nets = sm.record('wlan0')
        self.assertEqual(nets, [])
        # Ensure insert_scan was called
        self.assertEqual(temp_db.records[0][0], 'wlan0')