import unittest
from unittest.mock import patch
import importlib

if importlib.util.find_spec('requests') is None:
    raise unittest.SkipTest('requests not installed')

from kit.osint_enrich import enrich_ip


class TestOSINTEnrich(unittest.TestCase):
    @patch('kit.osint_enrich.ShodanClient')
    @patch('kit.osint_enrich.CensysClient')
    def test_enrich_ip(self, censys_cls, shodan_cls):
        shodan_cls.return_value.host_info.return_value = {'ip': '1.1.1.1'}
        censys_cls.return_value.host_info.return_value = {'ip': '1.1.1.1'}
        data = enrich_ip('1.1.1.1')
        self.assertIn('shodan', data)
        self.assertIn('censys', data)


if __name__ == '__main__':
    unittest.main()
