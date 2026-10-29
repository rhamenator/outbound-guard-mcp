#!/usr/bin/env python3
"""Private helper: transparently forward MCP; log only method/ID/rule metadata."""
import sys,subprocess,threading,json,time,pathlib
assert len(sys.argv) in (4,5,6)
ns,binary,log=sys.argv[1:4]
hosts=sys.argv[4] if len(sys.argv)>=5 else 'allowed.test'
assert hosts in ('allowed.test','allowed.test,private.test','allowed.test,fallback-pin.test','allowed.test,private.test,mixed.test,metadata.test','allowed.test,exfil.test','allowed.test,rebind.test')
mutation=sys.argv[5] if len(sys.argv)==6 else None
assert mutation in (None,'mutate','inject-arguments')
mutant_enabled=mutation=='mutate'
argument_enabled=mutation=='inject-arguments'
p=subprocess.Popen(['sudo','-n','ip','netns','exec',ns,'env','-i','PATH=/usr/bin:/bin','OUTBOUND_GUARD_ALLOWED_HOSTS='+hosts,binary],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=sys.stderr.buffer)
lock=threading.Lock()
mutant_pending=threading.Event()
marker_file=pathlib.Path(log).with_name('synthetic-marker')
synthetic_marker=marker_file.read_bytes() if marker_file.exists() else None
def record(direction,line):
 try:
  m=json.loads(line);entry={'t':time.monotonic(),'direction':direction,'method':m.get('method'),'id':m.get('id')}
  if m.get('method')=='tools/call':entry['http_method']=m.get('params',{}).get('arguments',{}).get('method','GET')
  if m.get('method')=='notifications/cancelled':entry['requestId']=m.get('params',{}).get('requestId')
  if direction=='out' and synthetic_marker:
   entry['synthetic_marker_echo']=synthetic_marker in line
  d=m.get('result',{}).get('structuredContent')
  if d:
   entry['rule']=d.get('rule')
   if 'status_code' in d:entry['status_code']=d['status_code']
   entry['body_text_present']='body_text' in d
  with lock:
   with open(log,'a') as f:f.write(json.dumps(entry)+'\n')
 except ValueError:pass

def record_event(event):
 with lock:
  with open(log,'a') as f:f.write(json.dumps({'t':time.monotonic(),'event':event})+'\n')

def outgoing():
 for line in p.stdout:
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
  if (mutant_enabled or argument_enabled) and not mutant_sent:
   try:client_message=json.loads(line);method=client_message.get('method')
   except ValueError:client_message={};method=None
   if method=='tools/call':
    mutant_sent=True
    if mutant_enabled:
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
