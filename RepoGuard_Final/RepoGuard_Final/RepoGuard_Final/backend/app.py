from __future__ import annotations
import json, os, re, sqlite3, uuid, zipfile, urllib.request, urllib.error, ssl, certifi
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from io import BytesIO
from typing import Any
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field, SecretStr
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer

DB_PATH=Path(os.getenv('REPOGUARD_DB_PATH',str(Path(__file__).with_name('repoguard.db')))); MAX_BYTES=1_000_000
app=FastAPI(title='RepoGuard AI',version='0.1.0',description='Read-only network configuration compliance prototype')
app.add_middleware(CORSMiddleware,allow_origins=['http://localhost:5173','http://127.0.0.1:5173','http://localhost:8080','http://127.0.0.1:8080'],allow_methods=['*'],allow_headers=['*'])
@contextmanager
def db():
 c=sqlite3.connect(DB_PATH); c.row_factory=sqlite3.Row
 try:
  yield c
  c.commit()
 except Exception:
  c.rollback(); raise
 finally:c.close()
@app.on_event('startup')
def startup():
 DB_PATH.parent.mkdir(parents=True,exist_ok=True)
 with db() as c: c.executescript('CREATE TABLE IF NOT EXISTS audits(id TEXT PRIMARY KEY,filename TEXT,vendor TEXT,device TEXT,created TEXT,raw TEXT,normalized TEXT,findings TEXT,unknown TEXT); CREATE TABLE IF NOT EXISTS mappings(id INTEGER PRIMARY KEY,vendor TEXT,pattern TEXT,parameter TEXT,value TEXT,approved INTEGER,created TEXT); CREATE TABLE IF NOT EXISTS repositories(id TEXT PRIMARY KEY,name TEXT,source TEXT,created TEXT,files TEXT,commits TEXT,findings TEXT,dependencies TEXT,approvals TEXT DEFAULT "[]");')
 try: DB_PATH.chmod(0o600)
 except OSError: pass
@app.get('/')
def root():return {'service':'RepoGuard AI API','status':'ok','health':'/api/health','docs':'/docs'}
def vendor_of(t):
 l=t.lower()
 if 'fortinet' in l or 'config system global' in l or 'config firewall' in l:return 'Fortinet'
 if 'junos' in l or 'set system services' in l or 'set security' in l:return 'Juniper'
 if 'cisco' in l or re.search(r'^\s*(hostname|service password-encryption|line vty|ip ssh)',t,re.M|re.I):return 'Cisco'
 return 'Unknown'
def normalize(t,v):
 model={k:None for k in ('ssh_version','telnet_enabled','http_management_enabled','logging_configured','password_encryption','admin_timeout_minutes')}; recognized=set(); lines=t.splitlines()
 def mark(i,k,x): model[k]={'value':x,'evidence':lines[i].strip(),'line':i+1}; recognized.add(i)
 for i,line in enumerate(lines):
  s=line.strip(); l=s.lower()
  if not s or s.startswith(('!','#','//')):recognized.add(i);continue
  if re.match(r'^(hostname\s+\S+|line\s+vty\b|exit)$',l):recognized.add(i);continue
  if re.search(r'ip ssh version 2|set system services ssh protocol-version v2',l):mark(i,'ssh_version','2')
  elif re.search(r'ip ssh version 1(?:\s|$)|protocol-version v1',l):mark(i,'ssh_version','1')
  elif l=='transport input telnet' or l.startswith('set system services telnet') or l=='set service telnet':mark(i,'telnet_enabled',True)
  elif l in ('no ip http server','no ip http secure-server') or 'set system services web-management https' in l:mark(i,'http_management_enabled',False)
  elif l=='ip http server' or 'set system services web-management http' in l or l=='set service http':mark(i,'http_management_enabled',True)
  elif l.startswith(('logging ','logging host ','set system syslog host','set log')):mark(i,'logging_configured',True)
  elif l in ('service password-encryption','set system login password format sha256'):mark(i,'password_encryption',True)
  elif l.startswith('exec-timeout '):
   try:mark(i,'admin_timeout_minutes',int(s.split()[1])/60)
   except (ValueError,IndexError):pass
  elif l.startswith('set session-timeout '):
   try:mark(i,'admin_timeout_minutes',int(s.split()[-1]))
   except ValueError:pass
  elif re.fullmatch(r'config( system| firewall| log| user).*',l) or l in ('end','next'):recognized.add(i)
 with db() as c: mappings=c.execute('SELECT vendor,pattern,parameter,value FROM mappings WHERE approved=1').fetchall()
 for i,s in enumerate(lines):
  if i in recognized:continue
  for m in mappings:
   if m['vendor'] in (v,'Any') and re.search(m['pattern'],s,re.I):
    model[m['parameter']]={'value':json.loads(m['value']),'evidence':s.strip(),'line':i+1,'source':'human-approved mapping'};recognized.add(i);break
 return model,[{'line':i+1,'text':s.strip()} for i,s in enumerate(lines) if i not in recognized and s.strip()]
RULES=[('CIS','CIS-NET-SSH-01','SSH management uses protocol version 2','ssh_version','2','high','Configure SSH protocol version 2; remove legacy SSHv1.'),('NIST SP 800-53','AC-17(2)','Telnet remote management is disabled','telnet_enabled',False,'high','Disable Telnet and use SSHv2 for remote administration.'),('CIS','CIS-NET-HTTP-01','Cleartext HTTP management is disabled','http_management_enabled',False,'medium','Disable HTTP management; use protected management access.'),('NIST SP 800-53','AU-2','Remote logging is configured','logging_configured',True,'medium','Configure centralized logging and verify events are collected.'),('DISA STIG','NET-ADMIN-TIMEOUT-01','Administrative idle timeout is at most 10 minutes','admin_timeout_minutes',10,'medium','Set an administrative idle timeout of 10 minutes or less.'),('ISO/IEC 27001','A.8.5','Password encryption is configured','password_encryption',True,'high','Use an approved secure password storage or secret management setting.')]
def evaluate(model,device,vendor):
 out=[]
 for fw,cid,title,key,expected,severity,fix in RULES:
  item=model.get(key); actual=item['value'] if item else None
  status='Not Evaluated' if actual is None else ('Pass' if actual<=expected else 'Fail') if key=='admin_timeout_minutes' else ('Pass' if actual==expected else 'Fail')
  out.append({'device':device,'vendor':vendor,'framework':fw,'control_id':cid,'title':title,'status':status,'severity':severity,'evidence':item['evidence'] if item else 'No recognized evidence; control was not evaluated.','line':item.get('line') if item else None,'detected_value':actual,'expected_value':expected,'explanation':f'Observed {actual!r}; expected {expected!r}.' if actual is not None else 'No recognized configuration evidence was found. This is not a pass.','remediation':fix})
 return out
def process(filename,raw):
 v=vendor_of(raw); m=re.search(r'^\s*hostname\s+(\S+)|^\s*set system host-name\s+(\S+)',raw,re.M|re.I); device=next((x for x in m.groups() if x),Path(filename).stem) if m else Path(filename).stem
 model,unknown=normalize(raw,v); findings=evaluate(model,device,v); a={'id':str(uuid.uuid4()),'filename':filename,'vendor':v,'device':device,'created':datetime.now(timezone.utc).isoformat(),'normalized':model,'findings':findings,'unknown':unknown}
 with db() as c:c.execute('INSERT INTO audits VALUES(?,?,?,?,?,?,?,?,?)',(a['id'],filename,v,device,a['created'],raw,json.dumps(model),json.dumps(findings),json.dumps(unknown)))
 return a
@app.get('/api/health')
def health():return {'status':'ok','mode':'read-only prototype','frameworks':['CIS','NIST SP 800-53','DISA STIG','ISO/IEC 27001']}
@app.post('/api/audits')
async def upload(files:list[UploadFile]=File(...)):
 out=[]
 for f in files:
  if Path(f.filename or '').suffix.lower() not in {'.txt','.cfg','.conf'}:raise HTTPException(400,'Only .txt, .cfg and .conf files are supported')
  data=await f.read(MAX_BYTES+1)
  if len(data)>MAX_BYTES:raise HTTPException(413,'Configuration exceeds 1 MB')
  try:raw=data.decode('utf-8')
  except UnicodeDecodeError:raise HTTPException(400,'Configuration must be UTF-8 text')
  out.append(process(f.filename or 'config.txt',raw))
 return {'audits':out}
def get_audits():
 with db() as c:rows=c.execute('SELECT * FROM audits ORDER BY created DESC').fetchall()
 return [{'id':r['id'],'filename':r['filename'],'vendor':r['vendor'],'device':r['device'],'created':r['created'],'normalized':json.loads(r['normalized']),'findings':json.loads(r['findings']),'unknown':json.loads(r['unknown'])} for r in rows]
@app.get('/api/audits')
def audits():return {'audits':get_audits()}
class MappingRequest(BaseModel):
 vendor:str=Field(min_length=1,max_length=40); pattern:str=Field(min_length=1,max_length=300); parameter:str; value:str; confirmed:bool
@app.post('/api/mappings')
def add_mapping(req:MappingRequest):
 if not req.confirmed:raise HTTPException(400,'Human confirmation is required before saving a mapping')
 allowed={'ssh_version','telnet_enabled','http_management_enabled','logging_configured','password_encryption','admin_timeout_minutes'}
 if req.parameter not in allowed:raise HTTPException(400,'Unsupported security parameter')
 try:re.compile(req.pattern)
 except re.error as e:raise HTTPException(400,f'Invalid pattern: {e}')
 value:Any=req.value
 if req.parameter in {'telnet_enabled','http_management_enabled','logging_configured','password_encryption'}:
  if value.lower() not in {'true','false'}:raise HTTPException(400,'Boolean parameters require true or false')
  value=value.lower()=='true'
 with db() as c:c.execute('INSERT INTO mappings(vendor,pattern,parameter,value,approved,created) VALUES(?,?,?,?,1,?)',(req.vendor,req.pattern,req.parameter,json.dumps(value),datetime.now(timezone.utc).isoformat()))
 return {'saved':True,'note':'Human-confirmed mapping saved. Re-upload configuration to reprocess.'}
@app.get('/api/reports/{audit_id}.pdf')
def report(audit_id:str):
 with db() as c:r=c.execute('SELECT * FROM audits WHERE id=?',(audit_id,)).fetchone()
 if not r:raise HTTPException(404,'Audit not found')
 fs=json.loads(r['findings']); counts={s:sum(f['status']==s for f in fs) for s in ('Pass','Fail','Not Evaluated')}; buff=BytesIO(); styles=getSampleStyleSheet(); doc=SimpleDocTemplate(buff,pagesize=letter,title=f"RepoGuard - {r['device']}")
 story=[Paragraph('RepoGuard AI — Network Compliance Audit',styles['Title']),Paragraph(f"Device: {r['device']} | Vendor: {r['vendor']} | Source: {r['filename']}",styles['Normal']),Paragraph(f"Audit: {r['created']}",styles['Normal']),Spacer(1,12),Paragraph('Summary',styles['Heading2']),Paragraph(' | '.join(f'{k}: {v}' for k,v in counts.items()),styles['Normal']),Spacer(1,10)]
 for f in fs:story.extend([Paragraph(f"{f['status']} — {f['framework']} / {f['control_id']} ({f['severity']})",styles['Heading3']),Paragraph(f['title'],styles['Normal']),Paragraph(f"Evidence (line {f['line'] or '—'}): {f['evidence']}",styles['Normal']),Paragraph(f"Detected: {f['detected_value']!r}; expected: {f['expected_value']!r}",styles['Normal']),Paragraph(f"Remediation: {f['remediation']}",styles['Normal']),Spacer(1,8)])
 story.append(Paragraph('Coverage is limited to the explicitly listed prototype checks. Not Evaluated is not a compliance pass.',styles['Italic']));doc.build(story)
 return Response(buff.getvalue(),media_type='application/pdf',headers={'Content-Disposition':f"attachment; filename=repoguard-{r['device']}.pdf"})
@app.get('/api/dashboard')
def dashboard():
 rows=get_audits(); fs=[f for r in rows for f in r['findings']]; passed=sum(f['status']=='Pass' for f in fs);failed=sum(f['status']=='Fail' for f in fs); evaluated=passed+failed
 return {'devices':len(rows),'compliance_percent':round(100*passed/evaluated) if evaluated else 0,'passed':passed,'failed':failed,'not_evaluated':len(fs)-evaluated,'severity':{s:sum(f['status']=='Fail' and f['severity']==s for f in fs) for s in ('critical','high','medium','low')},'vendors':{v:sum(a['vendor']==v for a in rows) for v in {a['vendor'] for a in rows}},'recent':rows[:10]}

# Open-source repository security workspace. Analysis is local/deterministic; no source is executed.
REPO_MAX_UPLOAD=20*1024*1024
REPO_MAX_EXPANDED=60*1024*1024
REPO_MAX_FILES=500
TEXT_SUFFIXES={'.py','.js','.jsx','.ts','.tsx','.java','.go','.rb','.php','.cs','.c','.h','.cpp','.yaml','.yml','.json','.toml','.ini','.sh','.ps1','.env','.md','.txt','.xml','.tf','.dockerfile'}
SECRET_PATTERNS=[('Private key',r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----','critical'),('AWS access key',r'\bAKIA[0-9A-Z]{16}\b','critical'),('Generic credential assignment',r'(?i)(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*["\'][^"\']{8,}["\']','high')]
CODE_RULES=[('SQL injection risk',r'(?i)(?:execute|query)\s*\(\s*f["\']|\+\s*(?:request|req\.|input\()','high','Use parameterized SQL queries and validate user input.'),('Unsafe deserialization',r'(?i)pickle\.loads?\s*\(|yaml\.load\s*\(','high','Use safe deserialization APIs and validate untrusted input.'),('Shell command construction',r'(?i)(?:shell\s*=\s*True|os\.system\s*\(|subprocess\.(?:run|Popen|call)\([^\n]*shell\s*=\s*True)','high','Avoid shell invocation; pass an argument array and validate inputs.'),('Disabled TLS verification',r'(?i)(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false)','high','Enable certificate and hostname verification.'),('Wildcard CORS',r'(?i)(?:allow_origins\s*=\s*\[\s*["\']\*["\']|Access-Control-Allow-Origin[^\n]*\*)','medium','Restrict cross-origin access to trusted origins.')]
def safe_repo_name(name):
 name=re.sub(r'[^A-Za-z0-9_.-]','-',name.strip())[:100]
 return name or 'repository'
def scan_repo(files):
 findings=[]; dependencies=[]; seen=set()
 for path,content in files.items():
  suffix=Path(path).suffix.lower(); name=Path(path).name.lower()
  if suffix in TEXT_SUFFIXES or name in {'dockerfile','.env','makefile','readme','license','changelog','gitignore','jenkinsfile'}:
   for line_no,line in enumerate(content.splitlines(),1):
    for title,pattern,severity in SECRET_PATTERNS:
     match=re.search(pattern,line)
     if match:
      secret=match.group(0); masked=(secret[:4]+'••••') if len(secret)>4 else '••••'
      findings.append({'id':str(uuid.uuid4()),'category':'secret','title':title,'severity':severity,'path':path,'line':line_no,'evidence':masked,'description':'Potential hard-coded secret. The matched value is masked in results.','recommendation':'Remove the credential from source, rotate it, and load it from a managed secret store.'});break
    for title,pattern,severity,fix in CODE_RULES:
     if re.search(pattern,line):
      safe_line=line
      for secret_title,secret_pattern,_ in SECRET_PATTERNS:
       safe_line=re.sub(secret_pattern,lambda m:(m.group(0)[:4]+'••••') if secret_title=='AWS access key' else '[redacted private key]' if secret_title=='Private key' else re.sub(r'(?i)^((?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*)["\'][^"\']*["\']',r'\1"••••"',m.group(0)),safe_line)
      findings.append({'id':str(uuid.uuid4()),'category':'code','title':title,'severity':severity,'path':path,'line':line_no,'evidence':safe_line.strip()[:180],'description':'Static pattern match; review context to confirm exploitability.','recommendation':fix})
  if name=='package.json':
   try:
    data=json.loads(content)
    for section in ('dependencies','devDependencies','optionalDependencies'):
     for n,v in data.get(section,{}).items():
      key=('npm',n,v)
      if key not in seen:dependencies.append({'name':n,'version':v,'ecosystem':'npm','direct':True,'source':path});seen.add(key)
   except Exception:findings.append({'id':str(uuid.uuid4()),'category':'dependency','title':'Invalid package.json','severity':'medium','path':path,'line':1,'evidence':'Unable to parse JSON','description':'Manifest could not be read.','recommendation':'Correct the manifest syntax and rerun the scan.'})
  elif name=='package-lock.json':
   try:
    lock=json.loads(content)
    for n,meta in lock.get('packages',{}).items():
     if not n or not meta.get('version'):continue
     package=n.split('node_modules/')[-1];key=('npm',package,meta['version'])
     if key not in seen:dependencies.append({'name':package,'version':meta['version'],'ecosystem':'npm','direct':False,'source':path});seen.add(key)
   except Exception:pass
  elif name in {'requirements.txt','requirements-dev.txt'}:
   for line in content.splitlines():
    m=re.match(r'\s*([A-Za-z0-9_.-]+)\s*(?:==|~=|>=|<=|>|<)\s*([^;\s]+)',line)
    if m:
     key=('pypi',m.group(1),m.group(2))
     if key not in seen:dependencies.append({'name':m.group(1),'version':m.group(2),'ecosystem':'PyPI','direct':True,'source':path});seen.add(key)
  elif name=='go.mod':
   for line in content.splitlines():
    m=re.match(r'\s*([^\s]+)\s+(v[0-9][^\s]+)',line)
    if m:
     key=('go',m.group(1),m.group(2))
     if key not in seen:dependencies.append({'name':m.group(1),'version':m.group(2),'ecosystem':'Go','direct':True,'source':path});seen.add(key)
  elif name=='cargo.toml':
   try:
    import tomllib
    cargo=tomllib.loads(content)
    for section in ('dependencies','dev-dependencies','build-dependencies'):
     for package,value in cargo.get(section,{}).items():
      version=value if isinstance(value,str) else value.get('version','unspecified')
      key=('cargo',package,version)
      if key not in seen:dependencies.append({'name':package,'version':version,'ecosystem':'crates.io','direct':True,'source':path});seen.add(key)
   except Exception:pass
 direct=set()
 for path,content in files.items():
  name=Path(path).name.lower()
  if name=='package.json':
   try:
    manifest=json.loads(content)
    for section in ('dependencies','devDependencies','optionalDependencies'):direct.update(('npm',n) for n in manifest.get(section,{}))
   except Exception:pass
  elif name in {'requirements.txt','requirements-dev.txt'}:
   direct.update(('PyPI',m.group(1)) for line in content.splitlines() if (m:=re.match(r'\s*([A-Za-z0-9_.-]+)\s*(?:==|~=|>=|<=|>|<)',line)))
  elif name=='go.mod':
   direct.update(('Go',m.group(1)) for line in content.splitlines() if (m:=re.match(r'\s*([^\s]+)\s+v[0-9]',line)))
 merged={}
 for d in dependencies:
  key=(d['ecosystem'],d['name']); old=merged.get(key)
  if old is None:merged[key]=d.copy();continue
  exact=bool(re.fullmatch(r'v?\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.-]+)?',d['version']))
  old_exact=bool(re.fullmatch(r'v?\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.-]+)?',old['version']))
  if exact and not old_exact:merged[key]=d.copy()
 for key,d in merged.items():d['direct']=key in direct or d.get('direct',False)
 return findings,list(merged.values())

def repo_summary(repo):
 findings=repo['findings']; counts={s:sum(f['severity']==s for f in findings) for s in ('critical','high','medium','low')}
 score=max(0,100-counts['critical']*35-counts['high']*18-counts['medium']*7-counts['low']*2)
 return {'score':score,'grade':'A' if score>=90 else 'B' if score>=75 else 'C' if score>=55 else 'D' if score>=35 else 'F','counts':counts,'total_findings':len(findings),'dependencies':len(repo['dependencies'])}
def repo_from_row(r):
 return {'id':r['id'],'name':r['name'],'source':r['source'],'created':r['created'],'files':json.loads(r['files']),'commits':json.loads(r['commits']),'findings':json.loads(r['findings']),'dependencies':json.loads(r['dependencies']),'approvals':json.loads(r['approvals'] or '[]')}
def store_repo(name,source,files,commits=None):
 findings,deps=scan_repo(files); repo={'id':str(uuid.uuid4()),'name':safe_repo_name(name),'source':source,'created':datetime.now(timezone.utc).isoformat(),'files':files,'commits':commits or [],'findings':findings,'dependencies':deps,'approvals':[]}
 with db() as c:c.execute('INSERT INTO repositories(id,name,source,created,files,commits,findings,dependencies,approvals) VALUES(?,?,?,?,?,?,?,?,?)',(repo['id'],repo['name'],source,repo['created'],json.dumps(files),json.dumps(repo['commits']),json.dumps(findings),json.dumps(deps),'[]'))
 return repo
def public_github_import(url,token=None):
 m=re.fullmatch(r'https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?',url.strip())
 if not m:raise HTTPException(400,'Enter a valid GitHub repository URL.')
 owner,repo=m.groups(); api=f'https://api.github.com/repos/{owner}/{repo}';headers={'User-Agent':'RepoGuard-AI','Accept':'application/vnd.github+json'}
 if token:headers['Authorization']=f'Bearer {token}'
 def get(url,max_bytes=REPO_MAX_UPLOAD):
  req=urllib.request.Request(url,headers=headers)
  try:
   with urllib.request.urlopen(req,timeout=15,context=ssl.create_default_context(cafile=certifi.where())) as response:
    data=response.read(max_bytes+1)
    if len(data)>max_bytes:raise HTTPException(413,'GitHub response exceeds allowed size')
    return data
  except urllib.error.HTTPError as e:
   if e.code==401:raise HTTPException(401,'GitHub rejected the access token. Check that it is valid and read-only access is enabled.')
   if e.code==403:raise HTTPException(403,'GitHub denied access. Check repository permissions and API rate limits.')
   if e.code==404:raise HTTPException(404,'Repository not found, or the token does not have access to this private repository.')
   raise HTTPException(502,f'GitHub request failed ({e.code}).')
  except (urllib.error.URLError,TimeoutError) as e:raise HTTPException(502,'Could not reach GitHub; check network connectivity.')
 try:meta=json.loads(get(api,500_000)); branch=meta.get('default_branch','main')
 except HTTPException:raise
 archive=get(f'{api}/zipball/{branch}',REPO_MAX_UPLOAD)
 commits_raw=json.loads(get(f'{api}/commits?per_page=30',3_000_000)); commits=[{'sha':c['sha'][:8],'author':(c.get('commit',{}).get('author') or {}).get('name','Unknown'),'date':(c.get('commit',{}).get('author') or {}).get('date',''),'message':c.get('commit',{}).get('message','').splitlines()[0][:200]} for c in commits_raw]
 return meta.get('name',repo),archive,commits

def files_from_zip(raw):
 try:z=zipfile.ZipFile(BytesIO(raw))
 except zipfile.BadZipFile:raise HTTPException(400,'Upload a valid ZIP repository archive')
 files={};total=0;entries=[x for x in z.infolist() if not x.is_dir()]
 if len(entries)>REPO_MAX_FILES:raise HTTPException(413,'Repository contains too many files (limit 500)')
 for info in entries:
  p=Path(info.filename)
  if p.is_absolute() or '..' in p.parts:continue
  if any(x in {'node_modules','.git','.venv','venv','dist','build','__pycache__'} for x in p.parts):continue
  if p.suffix.lower() not in TEXT_SUFFIXES and p.name.lower() not in {'.env','.npmrc','.pypirc','.gitignore','dockerfile','package-lock.json','package.json','requirements.txt','requirements-dev.txt','go.mod','cargo.toml','pom.xml','gemfile','pipfile.lock','poetry.lock','readme','license','changelog','makefile','jenkinsfile'}:continue
  total+=info.file_size
  if total>REPO_MAX_EXPANDED:raise HTTPException(413,'Expanded text files exceed 60 MB')
  if info.file_size>2_000_000:continue
  try:files[str(p)]=z.read(info).decode('utf-8')
  except (UnicodeDecodeError,RuntimeError):continue
 if not files:raise HTTPException(400,'No supported text source or dependency files found in ZIP')
 return files
class GithubRequest(BaseModel):
 url:str=Field(min_length=10,max_length=500)
 token:SecretStr|None=Field(default=None,repr=False)
@app.post('/api/repositories/github')
def import_github(req:GithubRequest):
 token=req.token.get_secret_value().strip() if req.token and req.token.get_secret_value().strip() else None
 name,archive,commits=public_github_import(req.url,token);files=files_from_zip(archive);repo=store_repo(name,req.url,files,commits);return {**{k:v for k,v in repo.items() if k!='files'},'file_count':len(files),'summary':repo_summary(repo)}
@app.post('/api/repositories/upload')
async def upload_repository(file:UploadFile=File(...)):
 data=await file.read(REPO_MAX_UPLOAD+1)
 if len(data)>REPO_MAX_UPLOAD:raise HTTPException(413,'ZIP upload limit is 20 MB')
 files=files_from_zip(data);repo=store_repo(Path(file.filename or 'repository.zip').stem,'Local ZIP upload',files);return {**{k:v for k,v in repo.items() if k!='files'},'file_count':len(files),'summary':repo_summary(repo)}
@app.get('/api/repositories')
def list_repositories():
 with db() as c:rows=c.execute('SELECT * FROM repositories ORDER BY created DESC').fetchall()
 return {'repositories':[{k:v for k,v in repo_from_row(r).items() if k not in ('files','commits','findings','dependencies','approvals')}|{'summary':repo_summary(repo_from_row(r))} for r in rows]}
@app.get('/api/repositories/{repo_id}')
def get_repository(repo_id:str):
 with db() as c:r=c.execute('SELECT * FROM repositories WHERE id=?',(repo_id,)).fetchone()
 if not r:raise HTTPException(404,'Repository not found')
 repo=repo_from_row(r);return {k:v for k,v in repo.items() if k!='files'}|{'file_count':len(repo['files']),'summary':repo_summary(repo)}
@app.get('/api/repositories/{repo_id}/files')
def repository_files(repo_id:str):
 with db() as c:r=c.execute('SELECT name,files FROM repositories WHERE id=?',(repo_id,)).fetchone()
 if not r:raise HTTPException(404,'Repository not found')
 return {'repository':r['name'],'files':[{'path':p,'lines':len(text.splitlines()),'size':len(text.encode())} for p,text in json.loads(r['files']).items()]}
@app.get('/api/repositories/{repo_id}/files/{file_path:path}')
def repository_file(repo_id:str,file_path:str):
 with db() as c:r=c.execute('SELECT files FROM repositories WHERE id=?',(repo_id,)).fetchone()
 if not r:raise HTTPException(404,'Repository not found')
 content=json.loads(r['files']).get(file_path)
 if content is None:raise HTTPException(404,'File not found')
 return {'path':file_path,'content':content}
@app.get('/api/repositories/{repo_id}/commits')
def repository_commits(repo_id:str):
 with db() as c:r=c.execute('SELECT commits FROM repositories WHERE id=?',(repo_id,)).fetchone()
 if not r:raise HTTPException(404,'Repository not found')
 return {'commits':json.loads(r['commits'])}
@app.get('/api/repositories/{repo_id}/dependencies')
def repository_dependencies(repo_id:str):
 with db() as c:r=c.execute('SELECT dependencies FROM repositories WHERE id=?',(repo_id,)).fetchone()
 if not r:raise HTTPException(404,'Repository not found')
 return {'dependencies':json.loads(r['dependencies'])}
@app.get('/api/repositories/{repo_id}/sbom')
def repository_sbom(repo_id:str):
 with db() as c:r=c.execute('SELECT name,dependencies FROM repositories WHERE id=?',(repo_id,)).fetchone()
 if not r:raise HTTPException(404,'Repository not found')
 deps=json.loads(r['dependencies']);components=[]
 for d in deps:
  ecosystem=d['ecosystem'];group,name=(d['name'].rsplit('/',1) if ecosystem=='Go' and '/' in d['name'] else ('',d['name']))
  components.append({'type':'library','name':name,'version':d['version'],'group':group,'purl':f"pkg:{'npm' if ecosystem=='npm' else 'pypi' if ecosystem=='PyPI' else 'golang' if ecosystem=='Go' else 'cargo'}/{d['name']}@{d['version']}"})
 payload={'bomFormat':'CycloneDX','specVersion':'1.5','serialNumber':'urn:uuid:'+str(uuid.uuid4()),'version':1,'metadata':{'timestamp':datetime.now(timezone.utc).isoformat(),'component':{'type':'application','name':r['name']}},'components':components}
 return Response(json.dumps(payload,indent=2),media_type='application/vnd.cyclonedx+json',headers={'Content-Disposition':f'attachment; filename={safe_repo_name(r["name"])}-sbom.json'})
@app.get('/api/repositories/{repo_id}/risk')
def repository_risk(repo_id:str):
 with db() as c:r=c.execute('SELECT * FROM repositories WHERE id=?',(repo_id,)).fetchone()
 if not r:raise HTTPException(404,'Repository not found')
 repo=repo_from_row(r);return repo_summary(repo)|{'findings':repo['findings'],'basis':'Deterministic weighted count of static findings. Not a vulnerability database or penetration test.'}
@app.get('/api/repositories/{repo_id}/recommendations')
def repository_recommendations(repo_id:str):
 with db() as c:r=c.execute('SELECT findings FROM repositories WHERE id=?',(repo_id,)).fetchone()
 if not r:raise HTTPException(404,'Repository not found')
 findings=json.loads(r['findings']);return {'mode':'deterministic heuristic recommendations; no external AI model used','recommendations':[{'finding_id':f['id'],'title':f['title'],'path':f['path'],'line':f['line'],'priority':f['severity'],'recommendation':f['recommendation']} for f in findings]}
@app.get('/api/repositories/{repo_id}/pull-requests')
def repository_pr_suggestions(repo_id:str):
 with db() as c:r=c.execute('SELECT findings,approvals FROM repositories WHERE id=?',(repo_id,)).fetchone()
 if not r:raise HTTPException(404,'Repository not found')
 fs=json.loads(r['findings']);approvals=json.loads(r['approvals'] or '[]');return {'suggestions':[{'id':f['id'],'title':'[Security] '+f['title'],'body':f"Finding in `{f['path']}:{f['line']}`. {f['recommendation']} Review the change in its full context.",'patch':'# Suggested remediation: '+f['recommendation']+'\n# Human-authored change required; no automatic patch is applied.','status':next((a['status'] for a in approvals if a['finding_id']==f['id']),'Pending human review'),'path':f['path'],'line':f['line']} for f in fs]}
class ApprovalRequest(BaseModel):finding_id:str;decision:str;reviewer:str=Field(min_length=1,max_length=100);notes:str=''
@app.post('/api/repositories/{repo_id}/approvals')
def approve_suggestion(repo_id:str,req:ApprovalRequest):
 if req.decision not in {'approved','rejected'}:raise HTTPException(400,'Decision must be approved or rejected')
 with db() as c:
  r=c.execute('SELECT findings,approvals FROM repositories WHERE id=?',(repo_id,)).fetchone()
  if not r:raise HTTPException(404,'Repository not found')
  findings=json.loads(r['findings'])
  if not any(f['id']==req.finding_id for f in findings):raise HTTPException(404,'Finding not found')
  approvals=json.loads(r['approvals'] or '[]');approvals=[a for a in approvals if a['finding_id']!=req.finding_id];approvals.append({'finding_id':req.finding_id,'status':req.decision.title(),'reviewer':req.reviewer,'notes':req.notes[:1000],'created':datetime.now(timezone.utc).isoformat()});c.execute('UPDATE repositories SET approvals=? WHERE id=?',(json.dumps(approvals),repo_id))
 return {'saved':True,'status':req.decision.title(),'note':'Decision recorded for human review. No pull request was created or code changed.'}
@app.get('/api/repositories/{repo_id}/report')
def repository_report(repo_id:str):
 with db() as c:r=c.execute('SELECT * FROM repositories WHERE id=?',(repo_id,)).fetchone()
 if not r:raise HTTPException(404,'Repository not found')
 repo=repo_from_row(r);report={'repository':repo['name'],'source':repo['source'],'created':repo['created'],'summary':repo_summary(repo),'findings':repo['findings'],'dependencies':repo['dependencies'],'commits':repo['commits'],'human_approvals':repo['approvals'],'limitations':'Static heuristic scan. No OSV or other vulnerability database query was performed.'}
 return Response(json.dumps(report,indent=2),media_type='application/json',headers={'Content-Disposition':f'attachment; filename={safe_repo_name(repo["name"])}-security-report.json'})

@app.post('/api/repositories/{repo_id}/osv')
def check_osv(repo_id:str):
 with db() as c:r=c.execute('SELECT dependencies FROM repositories WHERE id=?',(repo_id,)).fetchone()
 if not r:raise HTTPException(404,'Repository not found')
 deps=json.loads(r['dependencies']); ecosystem_map={'npm':'npm','PyPI':'PyPI','Go':'Go','crates.io':'crates.io'}; queries=[]; indexed=[]; skipped=[]
 for d in deps:
  eco=ecosystem_map.get(d['ecosystem']);version=d['version']
  if not eco or not re.fullmatch(r'v?\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.-]+)?',version):
   skipped.append({'name':d['name'],'version':version,'reason':'No exact pinned version or unsupported ecosystem'});continue
  queries.append({'package':{'name':d['name'],'ecosystem':eco},'version':version});indexed.append(d)
 if len(queries)>100:queries=queries[:100];indexed=indexed[:100]
 if not queries:return {'status':'partial' if skipped else 'complete','checked':0,'skipped':skipped,'vulnerabilities':[],'note':'No exact pinned dependency versions could be queried.'}
 req=urllib.request.Request('https://api.osv.dev/v1/querybatch',data=json.dumps({'queries':queries}).encode(),headers={'Content-Type':'application/json','User-Agent':'RepoGuard-AI'},method='POST')
 try:
	 with urllib.request.urlopen(req,timeout=25,context=ssl.create_default_context(cafile=certifi.where())) as response:payload=json.loads(response.read(5_000_001))
 except (urllib.error.URLError,TimeoutError,urllib.error.HTTPError) as e:raise HTTPException(502,'OSV lookup failed; retry when the backend has internet access.')
 results=[]
 for d,result in zip(indexed,payload.get('results',[])):
  for vuln in result.get('vulns',[]):results.append({'package':d['name'],'version':d['version'],'ecosystem':d['ecosystem'],'id':vuln.get('id'),'modified':vuln.get('modified'),'url':'https://osv.dev/vulnerability/'+str(vuln.get('id',''))})
 return {'status':'partial' if skipped or len(indexed)<len(deps) else 'complete','checked':len(indexed),'skipped':skipped,'vulnerabilities':results,'note':'OSV checks exact versions only. No result is not proof that a package is safe.'}
