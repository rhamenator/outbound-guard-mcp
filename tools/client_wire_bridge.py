#!/usr/bin/env python3
"""Private helper: transparently forward MCP; log only method/ID/rule metadata."""
import sys,subprocess,threading,json,time,pathlib,queue
from client_wire_url_class import fixture_url_class
assert len(sys.argv) in (4,5,6)
ns,binary,log=sys.argv[1:4]
hosts=sys.argv[4] if len(sys.argv)>=5 else 'allowed.test'
assert hosts in ('allowed.test','allowed.test,private.test','allowed.test,fallback-pin.test','allowed.test,tls-handshake.test','allowed.test,private.test,alias-private.test,mixed.test,metadata.test,loop-dns.test','allowed.test,exfil.test','allowed.test,rebind.test')
mutation=sys.argv[5] if len(sys.argv)==6 else None
assert mutation in (None,'mutate','inject-arguments','active-proxy','queue-saturate')
mutant_enabled=mutation=='mutate'
argument_enabled=mutation=='inject-arguments'
saturation_enabled=mutation=='queue-saturate'
server_env=['PATH=/usr/bin:/bin','OUTBOUND_GUARD_ALLOWED_HOSTS='+hosts]
if hosts=='allowed.test,tls-handshake.test':
 server_env.append('OUTBOUND_GUARD_EXTRA_CA_CERT='+str(pathlib.Path(log).with_name('ca.pem')))
if mutation=='active-proxy':
 proxy='http://127.0.0.1:3128'
 server_env += [name+'='+proxy for name in ('HTTP_PROXY','http_proxy','HTTPS_PROXY','https_proxy','ALL_PROXY','all_proxy')]
 server_env += ['NO_PROXY=','no_proxy=']
p=subprocess.Popen(['sudo','-n','ip','netns','exec',ns,'env','-i',*server_env,binary],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=sys.stderr.buffer)
lock=threading.Lock()
mutant_pending=threading.Event()
saturation_replies=queue.Queue()
marker_file=pathlib.Path(log).with_name('synthetic-marker')
synthetic_marker=marker_file.read_bytes() if marker_file.exists() else None
def record(direction,line):
 try:
  m=json.loads(line);entry={'t':time.monotonic(),'direction':direction,'method':m.get('method'),'id':m.get('id')}
  if m.get('method')=='tools/call':
   arguments=m.get('params',{}).get('arguments',{})
   entry['http_method']=arguments.get('method','GET')
   entry['url_class']=fixture_url_class(arguments.get('url'))
  if m.get('method')=='notifications/cancelled':entry['requestId']=m.get('params',{}).get('requestId')
  if direction=='out' and synthetic_marker:
   entry['synthetic_marker_echo']=synthetic_marker in line
  d=m.get('result',{}).get('structuredContent')
  if d:
   entry['rule']=d.get('rule')
   if 'status_code' in d:entry['status_code']=d['status_code']
   entry['body_text_present']='body_text' in d
  if m.get('error'):
   entry['protocol_error_code']=m['error'].get('code')
   entry['protocol_rule']=m['error'].get('data',{}).get('rule')
  with lock:
   with open(log,'a') as f:f.write(json.dumps(entry)+'\n')
 except ValueError:pass

def record_event(event):
 with lock:
  with open(log,'a') as f:f.write(json.dumps({'t':time.monotonic(),'event':event})+'\n')

def outgoing():
 for line in p.stdout:
  if saturation_enabled:
   try:
    m=json.loads(line)
    if isinstance(m.get('id'),str) and m['id'].startswith('saturation-'):
     record('out',line)
     saturation_replies.put(m)
     continue
   except ValueError:pass
  if argument_enabled:
   try:
    m=json.loads(line)
    if m.get('id') in ('injected-header','injected-body'):
     record('out',line)
     continue
   except ValueError:pass
  if mutant_pending.is_set():
   try:
    m=json.loads(line)
    if m.get('id') is None and m.get('error',{}).get('code')==-32700:
     mutant_pending.clear();record_event('mutant_parse_error');continue
   except ValueError:pass
  record('out',line);sys.stdout.buffer.write(line);sys.stdout.buffer.flush()
t=threading.Thread(target=outgoing,daemon=True);t.start()
try:
 mutant_sent=False
 for line in sys.stdin.buffer:
  if (mutant_enabled or argument_enabled or saturation_enabled) and not mutant_sent:
   try:client_message=json.loads(line);method=client_message.get('method')
   except ValueError:client_message={};method=None
   if method=='tools/call':
    mutant_sent=True
    if saturation_enabled:
     params={'name':'guarded_fetch','arguments':{'url':'http://allowed.test/cancel-drip'}}
     meta=client_message.get('params',{}).get('_meta')
     if meta is not None:params['_meta']=meta
     frame={'jsonrpc':'2.0','id':'saturation-fetch','method':'tools/call','params':params}
     payload=(json.dumps(frame)+'\n').encode();record('in',payload);p.stdin.write(payload);p.stdin.flush()
     deadline=time.monotonic()+5
     while not pathlib.Path(log).with_name('started').exists():
      assert p.poll() is None and time.monotonic()<deadline, 'saturation fixture did not start'
      time.sleep(.01)
     record_event('saturation_started')
     for index in range(8):
      params={'padding':'x'*60000}
      if meta is not None:params['_meta']=meta
      frame={'jsonrpc':'2.0','id':f'saturation-queued-{index}','method':'tools/list','params':params}
      payload=(json.dumps(frame)+'\n').encode();record('in',payload);p.stdin.write(payload)
     params={'name':'guarded_fetch','padding':'x'*60000,'arguments':{'url':'http://allowed.test/SYNTHETIC_BUSY_MARKER'}}
     if meta is not None:params['_meta']=meta
     frame={'jsonrpc':'2.0','id':'saturation-queued-8','method':'tools/call','params':params}
     payload=(json.dumps(frame)+'\n').encode();record('in',payload);p.stdin.write(payload)
     params={'requestId':'saturation-fetch'}
     if meta is not None:params['_meta']=meta
     frame={'jsonrpc':'2.0','method':'notifications/cancelled','params':params}
     payload=(json.dumps(frame)+'\n').encode();record('in',payload);p.stdin.write(payload);p.stdin.flush()
     replies=[]
     for _ in range(9):
      replies.append(saturation_replies.get(timeout=12))
     assert {m['id'] for m in replies}=={f'saturation-queued-{index}' for index in range(9)}, replies
     busy=next(m for m in replies if m['id']=='saturation-queued-8')
     assert busy['error']['code']==-32000 and busy['error']['data']['rule']=='MCP_INPUT_BUSY', busy
     assert 'SYNTHETIC_BUSY_MARKER' not in json.dumps(replies), 'busy URL echoed'
     assert all('result' in m for m in replies if m['id']!='saturation-queued-8'), replies
     deadline=time.monotonic()+5
     while not pathlib.Path(log).with_name('closed').exists():
      assert p.poll() is None and time.monotonic()<deadline, 'cancelled saturation socket remained open'
      time.sleep(.01)
     record_event('saturation_completed')
    elif mutant_enabled:
     mutant_pending.set()
     record_event('mutant_sent')
     p.stdin.write(b'{"jsonrpc":"2.0","id":"mutant","method":"tools/call","params":{"name":"guarded_fetch","arguments":{"url":"http://private.test/plain"}}\n')
    else:
     assert synthetic_marker is not None
     for label,extra in (('header',{'headers':{'Authorization':'Bearer '+synthetic_marker.decode()}}),('body',{'body':synthetic_marker.decode()})):
      params={'name':'guarded_fetch','arguments':{'url':'http://allowed.test/plain',**extra}}
      if '_meta' in client_message.get('params',{}):params['_meta']=client_message['params']['_meta']
      frame={'jsonrpc':'2.0','id':'injected-'+label,'method':'tools/call','params':params}
      payload=(json.dumps(frame)+'\n').encode()
      record('in',payload)
      p.stdin.write(payload)
     record_event('arguments_injected')
    p.stdin.flush()
  record('in',line);p.stdin.write(line);p.stdin.flush()
finally:
 p.stdin.close()
 try:p.wait(timeout=15)
 except subprocess.TimeoutExpired:p.kill();p.wait()
 t.join(timeout=2)
