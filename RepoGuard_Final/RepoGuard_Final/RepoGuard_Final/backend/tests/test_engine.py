import sys,tempfile,unittest
import io,json,zipfile
from pathlib import Path
from unittest.mock import patch
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
 def test_repository_scan_masks_secrets_and_finds_code_risk(self):
  findings,deps=rg.scan_repo({'src/app.py':'TOKEN = "ghp_abcdef1234567890"\nsubprocess.run(user_input, shell=True)\n','requirements.txt':'flask==3.0.1\n'})
  self.assertTrue(any(f['category']=='secret' and 'ghp_abcdef1234567890' not in f['evidence'] for f in findings));self.assertTrue(any(f['title']=='Shell command construction' for f in findings));self.assertEqual(deps[0]['name'],'flask')
 def test_zip_rejects_path_traversal_and_indexes_supported_files(self):
  import io,zipfile
  b=io.BytesIO()
  with zipfile.ZipFile(b,'w') as z:z.writestr('../escape.py','bad');z.writestr('repo/main.py','print("ok")');z.writestr('repo/node_modules/pkg/a.py','ignored')
  files=rg.files_from_zip(b.getvalue());self.assertIn('repo/main.py',files);self.assertNotIn('../escape.py',files);self.assertEqual(len(files),1)
 def test_private_github_token_is_used_for_import_but_never_stored(self):
  archive=io.BytesIO()
  with zipfile.ZipFile(archive,'w') as z:z.writestr('private/README.md','private test fixture')
  dummy='unit-test-token-do-not-use';req=rg.GithubRequest(url='https://github.com/example/private-repo',token=dummy)
  with patch.object(rg,'public_github_import',return_value=('private-repo',archive.getvalue(),[])) as fetch:
   result=rg.import_github(req);fetch.assert_called_once_with(req.url,dummy)
  self.assertEqual(result['name'],'private-repo')
  with rg.db() as c:stored=' '.join(str(v) for v in c.execute('SELECT * FROM repositories WHERE id=?',(result['id'],)).fetchone())
  self.assertNotIn(dummy,stored)
 def test_github_import_attaches_optional_bearer_token(self):
  archive=io.BytesIO()
  with zipfile.ZipFile(archive,'w') as z:z.writestr('repo/README.md','fixture')
  payloads=[json.dumps({'name':'private','default_branch':'main'}).encode(),archive.getvalue(),b'[]'];seen=[]
  class Reply:
   def __init__(self,data):self.data=data
   def __enter__(self):return self
   def __exit__(self,*args):pass
   def read(self,size=-1):return self.data if size<0 else self.data[:size]
  def mocked(request,*args,**kwargs):
   seen.append(request.get_header('Authorization'));return Reply(payloads.pop(0))
  with patch.object(rg.urllib.request,'urlopen',side_effect=mocked):
   name,_,commits=rg.public_github_import('https://github.com/example/private','unit-test-token')
  self.assertEqual(name,'private');self.assertEqual(commits,[]);self.assertEqual(seen,['Bearer unit-test-token']*3)
if __name__=='__main__':unittest.main()
