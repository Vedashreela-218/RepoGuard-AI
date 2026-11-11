import sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import app as rg
class EngineTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();rg.DB_PATH=Path(self.tmp.name)/'test.db';rg.startup()
 def tearDown(self):self.tmp.cleanup()
 def test_normalization_and_unknown(self):
  m,u=rg.normalize('hostname demo\nip ssh version 2\nline vty 0 4\n transport input telnet','Cisco');self.assertEqual(m['ssh_version']['line'],2);self.assertTrue(m['telnet_enabled']['value']);self.assertEqual(u[0]['text'],'line vty 0 4')
 def test_absent_evidence_not_evaluated(self):self.assertTrue(all(x['status']=='Not Evaluated' for x in rg.evaluate({},'demo','Unknown')))
 def test_failure_preserves_evidence(self):
  m,_=rg.normalize('ip ssh version 1','Cisco');f=rg.evaluate(m,'demo','Cisco')[0];self.assertEqual(f['status'],'Fail');self.assertEqual(f['line'],1);self.assertTrue(f['remediation'])
 def test_vendor_detection(self):
  self.assertEqual(rg.vendor_of('config system global'),'Fortinet');self.assertEqual(rg.vendor_of('set system services ssh'),'Juniper');self.assertEqual(rg.vendor_of('hostname demo'),'Cisco')
if __name__=='__main__':unittest.main()
