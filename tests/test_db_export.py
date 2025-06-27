import os
import tempfile
import unittest

from kit.db import DatabaseManager


class TestDBExport(unittest.TestCase):
    def test_export_csv(self):
        tmpdir = tempfile.mkdtemp()
        db = DatabaseManager(db_file=os.path.join(tmpdir, 'test.sqlite'))
        db.insert_scan('wlan0', 1, '[]')
        out_dir = os.path.join(tmpdir, 'csv')
        os.makedirs(out_dir)
        db.export_csv(out_dir)
        self.assertTrue(os.path.exists(os.path.join(out_dir, 'scans.csv')))
        db.close()


if __name__ == '__main__':
    unittest.main()
