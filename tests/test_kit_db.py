import os
import tempfile
import unittest
from kit.db import DatabaseManager

class TestDatabaseManager(unittest.TestCase):
    def setUp(self):
        self.db_file = os.path.join(tempfile.gettempdir(), 'test_db.sqlite')
        # remove if exists
        try:
            os.remove(self.db_file)
        except OSError:
            pass
        self.db = DatabaseManager(db_file=self.db_file)

    def tearDown(self):
        self.db.close()
        try:
            os.remove(self.db_file)
        except OSError:
            pass

    def test_insert_and_get_scan(self):
        sid = self.db.insert_scan('wlan0', 10, '[]')
        logs = self.db.get_scan_logs()
        self.assertTrue(any(row[0] == sid for row in logs))

    def test_insert_and_get_capture(self):
        sid = self.db.insert_scan('wlan0', 5, '[]')
        self.db.insert_capture(sid, 'AA:BB:CC', 'Test', 'handshake.cap')
        caps = self.db.get_captures_for_scan(sid)
        self.assertTrue(any(cap[1] == sid for cap in caps))

    def test_insert_and_get_deauth(self):
        sid = self.db.insert_scan('wlan0', 5, '[]')
        self.db.insert_deauth(sid, 'AA:BB:CC', 'FF:EE:DD')
        deauths = self.db.get_deauths_for_scan(sid)
        self.assertTrue(any(d[1] == sid for d in deauths))

    def test_custom_tables(self):
        # Test cracks table
        cid = self.db.insert_crack('hs.cap', 'wl.txt', 'started', '')
        all_cracks = self.db.get_all_cracks()
        self.assertTrue(any(c[0] == cid for c in all_cracks))
        # Test evilaps
        eid = self.db.insert_evilap('TestAP', 'pass', 'started')
        all_evil = self.db.get_all_evilaps()
        self.assertTrue(any(e[0] == eid for e in all_evil))
        # Test fakeauths
        fid = self.db.insert_fakeauth('AA:BB:CC', '11:22:33', 'started')
        all_fake = self.db.get_all_fakeauths()
        self.assertTrue(any(f[0] == fid for f in all_fake))