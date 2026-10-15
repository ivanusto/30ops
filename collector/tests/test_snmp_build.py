"""snmp.yml: the if_mib module is exactly what snmp-build.py writes (the
qnap module needs QNAP's MIB, which is not committed, so only if_mib is
checked against the script)."""
import importlib.util
import re
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("snmp_build", HERE / "prometheus" / "snmp-build.py")
sb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sb)
SNMP = (HERE / "prometheus" / "snmp.yml").read_text()


class IfMib(unittest.TestCase):
    def test_module_is_the_script_output(self):
        self.assertTrue(SNMP.endswith(sb.IF_MIB_MODULE))
        self.assertEqual(SNMP.count("\n  if_mib:\n"), 1)

    def test_every_metric_is_walked(self):
        mod = sb.IF_MIB_MODULE
        walked = re.findall(r"^      - (\S+)$", mod, re.M)
        for oid in re.findall(r"^      oid: (\S+)$", mod, re.M):
            self.assertIn(oid, walked)
        for oid in re.findall(r"oid: ([0-9.]+), type", mod):     # lookups
            self.assertIn(oid, walked)


if __name__ == "__main__":
    unittest.main()
