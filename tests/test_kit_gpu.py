import unittest
from unittest.mock import patch

from kit.gpu_monitor import query_gpu, GPUStats


class TestGPUMonitor(unittest.TestCase):
    def test_query_gpu_none(self):
        with patch('subprocess.check_output', side_effect=FileNotFoundError()):
            self.assertIsNone(query_gpu())

    def test_query_gpu_parse(self):
        fake_out = '10, 55'
        with patch('subprocess.check_output', return_value=fake_out):
            stats = query_gpu()
        self.assertIsInstance(stats, GPUStats)
        self.assertEqual(stats.utilization, 10)
        self.assertEqual(stats.temperature, 55)


if __name__ == '__main__':
    unittest.main()
