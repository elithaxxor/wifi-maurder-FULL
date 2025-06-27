import unittest
from unittest.mock import patch
from kit import nmap_scan

class TestNmapScan(unittest.TestCase):
    def test_run_scan(self):
        with patch('subprocess.check_output', return_value='<nmaprun></nmaprun>') as mock_co:
            out = nmap_scan.run_scan('localhost')
            self.assertIn('<nmaprun>', out)
            mock_co.assert_called()

    def test_parse_xml(self):
        sample = '''<nmaprun>
  <host>
    <address addr="192.168.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>'''
        res = nmap_scan.parse_xml(sample)
        self.assertEqual(res[0]['ip'], '192.168.0.1')
        self.assertEqual(res[0]['ports'][0]['port'], '80')
