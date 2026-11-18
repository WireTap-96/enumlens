import unittest
from enumlens.cli import analyze_xml

SAMPLE = '''<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><hostnames><hostname name="lab-web.example.test"/></hostnames><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port><port protocol="tcp" portid="23"><state state="closed"/></port></ports></host></nmaprun>'''

class EnumLensTests(unittest.TestCase):
    def test_extracts_up_hosts_and_open_services(self):
        result = analyze_xml(SAMPLE)
        self.assertEqual(result["hosts_in_report"], 1)
        self.assertEqual(result["open_services"], 1)
        self.assertEqual(result["hosts"][0]["open_ports"], [{"protocol":"tcp", "port":443, "service":"https"}])

    def test_rejects_non_nmap_xml(self):
        with self.assertRaises(ValueError):
            analyze_xml("<root/>")

    def test_rejects_malformed_xml(self):
        with self.assertRaises(ValueError):
            analyze_xml("<nmaprun>")

if __name__ == "__main__":
    unittest.main()
