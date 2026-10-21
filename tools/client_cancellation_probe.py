#!/usr/bin/env python3
"""Opt-in authenticated client-control observations against route-free fixtures.

Usage: python3 tools/client_cancellation_probe.py claude|codex|cursor BINARY
Requires existing client authentication and passwordless sudo for disposable netns.
Model inference may incur account usage; no credentials are read or printed.
This probes client control APIs, not desktop buttons or terminal Escape keys.
"""
import sys,os,json,pathlib,subprocess,tempfile,time,threading,queue,shutil,hashlib,atexit
assert len(sys.argv)==3 and sys.argv[1] in ('claude','codex','cursor'), __doc__
binary=str(pathlib.Path(sys.argv[2]).resolve(strict=True))
script_dir=pathlib.Path(__file__).resolve().parent
root=pathlib.Path(tempfile.mkdtemp(prefix='outbound-cancel-'));root.chmod(0o700)
ns='outbound-client-cancel-'+str(os.getpid())
(root/'namespace').write_text(ns)
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
def sudo(*args,**kw):return subprocess.run(['sudo','-n',*args],check=True,stdout=subprocess.DEVNULL,**kw)
sudo('ip','netns','add',ns);owns_namespace=True
sudo('ip','-n',ns,'link','set','lo','up');sudo('ip','-n',ns,'address','add','11.0.0.1/32','dev','lo')
sudo('install','-d','-m','755','/etc/netns/'+ns)
sudo('tee','/etc/netns/'+ns+'/resolv.conf',input='nameserver 127.0.0.1\noptions timeout:1 attempts:1\n',text=True)
backend=subprocess.Popen(['sudo','-n','ip','netns','exec',ns,'python3',str(script_dir/'client_cancellation_fixture.py'),str(root)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
for _ in range(200):
 if (root/'ready').exists():break
 time.sleep(.02)
assert (root/'ready').exists() and backend.poll() is None, 'fixture startup failed'
bridge=[str(script_dir/'client_wire_bridge.py'),ns,binary,str(root/'wire.jsonl')]
config=root/'mcp.json';config.write_text(json.dumps({'mcpServers':{'outbound_guard':{'command':'python3','args':bridge}}}))
(root/'.cursor').mkdir()
(root/'.cursor/mcp.json').write_text(config.read_text())
print('ROOT='+str(root),flush=True)
prompt='Use ONLY the outbound_guard guarded_fetch MCP tool to GET http://allowed.test/cancel-drip once. Do not use any other tools or retry. Wait for its actual result.'
clienthome=root/'codex';clienthome.mkdir(mode=0o700)
auth=pathlib.Path.home()/'.codex/auth.json'
if auth.exists():(clienthome/'auth.json').symlink_to(auth)
(clienthome/'config.toml').write_text('approval_policy="never"\nsandbox_mode="read-only"\n[mcp_servers.outbound_guard]\ncommand="python3"\nargs='+json.dumps(bridge)+'\nenabled_tools=["guarded_fetch"]\nrequired=true\n[mcp_servers.outbound_guard.tools.guarded_fetch]\napproval_mode="approve"\n')
name=sys.argv[1]
cmd=['claude','-p','--restricted','--strict-mcp-config','--mcp-config',str(config),'--allowedTools','mcp__outbound_guard__guarded_fetch','--tools','','--permission-mode','dontAsk','--no-session-persistence','--output-format','stream-json','--input-format','stream-json','--verbose'] if name=='claude' else ([str(pathlib.Path.home()/'.local/bin/agent'),'--approve-mcps','--trust','acp'] if name=='cursor' else ['codex','app-server','--listen','stdio://'])
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
  send({'id':5,'method':'turn/start','params':{'threadId':tid,'input':[{'type':'text','text':recovery}]}});response(5)
 deadline=time.monotonic()+40
 while time.monotonic()<deadline:
  lines=(root/'wire.jsonl').read_text().splitlines()
  if any(json.loads(line).get('rule')=='EGRESS_ALLOWED' for line in lines):break
  time.sleep(.02)
 if name=='cursor':
  smoke='Use ONLY outbound_guard guarded_fetch. First GET http://127.0.0.1/ once; then HEAD http://allowed.test/head-ok once. No other tools or retries. Report both actual results.'
  send({'jsonrpc':'2.0','id':6,'method':'session/prompt','params':{'sessionId':sid,'prompt':[{'type':'text','text':smoke}]}})
  response(6)
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
 if name=='cursor':
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
