import unittest
import json
from collections import Counter
try:
    import matplotlib.pyplot as plt
except ImportError:
    plt = None
from kit.analytics import count_vendors, count_handshakes, count_attacks, plot_bar, plot_pie

class TestAnalytics(unittest.TestCase):
    def test_count_vendors_simple(self):
        logs = [
            (1, 'ts', 'iface', 1, json.dumps([{'bssid': 'AA:BB:CC', 'essid': 'X'}]))
        ]
        def lookup(v): return 'Vendor'
        res = count_vendors(logs, lookup)
        self.assertIsInstance(res, Counter)
        self.assertEqual(res['Vendor'], 1)

    def test_count_vendors_bad_json(self):
        logs = [(1, 'ts', 'iface', 1, 'not a json')]
        res = count_vendors(logs, lambda x: 'V')
        self.assertIsInstance(res, Counter)
        self.assertEqual(sum(res.values()), 0)

    def test_count_handshakes(self):
        caps = [(1, 1, 'bssid', 'ESSID', ''), (2, 1, 'b2', 'ESSID', '')]
        res = count_handshakes(caps)
        self.assertEqual(res['ESSID'], 2)

    def test_count_attacks(self):
        res = count_attacks([1,2], [1], [1,2,3])
        self.assertEqual(res, {'Deauths': 2, 'Captures':1, 'Decoys':3})

    def test_plot_bar_and_pie(self):
        if plt is None:
            self.skipTest("matplotlib not available")
        fig, ax = plt.subplots()
        c = Counter({'A': 1, 'B': 2})
        plot_bar(ax, c, 'Title')
        plot_pie(ax, {'X':1, 'Y':2}, 'Pie')
        plt.close(fig)