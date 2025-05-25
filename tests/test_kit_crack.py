import os
import tempfile
import unittest
from unittest.mock import patch
from kit.crack import CrackManager

class DummyDB:
    pass

class TestCrackManager(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.cm = CrackManager(db_manager=DummyDB(), tmp_dir=self.tmp_dir)

    def test_start_failure(self):
        # Simulate missing aircrack-ng
        self.cm._log_fh = None
        with patch('subprocess.Popen', side_effect=OSError()):
            result = self.cm.start('nonexistent.cap', 'wordlist.txt')
        self.assertFalse(result)

    def test_progress_initial(self):
        # No log file yet
        a, t, k, d = self.cm.progress()
        self.assertEqual((a, t, k, d), (0, 0, None, False))

    def test_stop(self):
        # Stop without start
        self.assertTrue(self.cm.stop())