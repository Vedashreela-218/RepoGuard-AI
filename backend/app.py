from __future__ import annotations
import json, os, re, sqlite3, uuid
from datetime import datetime, timezone
from pathlib import Path
from io import BytesIO
from typing import Any
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer

DB_PATH=Path(os.getenv('REPOGUARD_DB_PATH',str(Path(__file__).with_name('repoguard.db')))); MAX_BYTES=1_000_000
app=FastAPI(title='RepoGuard AI',version='0.1.0',description='Read-only network configuration compliance prototype')
app.add_middleware(CORSMiddleware,allow_origins=['http://localhost:5173','http://127.0.0.1:5173'],allow_methods=['*'],allow_headers=['*'])
def db():
 c=sqlite3.connect(DB_PATH); c.row_factory=sqlite3.Row; return c
@app.on_event('startup')
def startup():
 with db() as c: c.executescript('CREATE TABLE IF NOT EXISTS audits(id TEXT PRIMARY KEY,filename TEXT,vendor TEXT,device TEXT,created TEXT,raw TEXT,normalized TEXT,findings TEXT,unknown TEXT); CREATE TABLE IF NOT EXISTS mappings(id INTEGER PRIMARY KEY,vendor TEXT,pattern TEXT,parameter TEXT,value TEXT,approved INTEGER,created TEXT);')
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
