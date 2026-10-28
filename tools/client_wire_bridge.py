#!/usr/bin/env python3
"""Private helper: transparently forward MCP; log only method/ID/rule metadata."""
import sys,subprocess,threading,json,time,pathlib
assert len(sys.argv) in (4,5,6)
ns,binary,log=sys.argv[1:4]
hosts=sys.argv[4] if len(sys.argv)>=5 else 'allowed.test'
assert hosts in ('allowed.test','allowed.test,private.test','allowed.test,private.test,mixed.test,metadata.test','allowed.test,exfil.test','allowed.test,rebind.test')
mutant_enabled=len(sys.argv)==6 and sys.argv[5]=='mutate'
assert len(sys.argv)!=6 or mutant_enabled
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
  with lock:
   with open(log,'a') as f:f.write(json.dumps(entry)+'\n')
 except ValueError:pass

def record_event(event):
 with lock:
  with open(log,'a') as f:f.write(json.dumps({'t':time.monotonic(),'event':event})+'\n')

def outgoing():
 for line in p.stdout:
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
  if mutant_enabled and not mutant_sent:
   try:method=json.loads(line).get('method')
   except ValueError:method=None
   if method=='tools/call':
    mutant_sent=True;mutant_pending.set()
    record_event('mutant_sent')
    p.stdin.write(b'{"jsonrpc":"2.0","id":"mutant","method":"tools/call","params":{"name":"guarded_fetch","arguments":{"url":"http://private.test/plain"}}\n')
    p.stdin.flush()
  record('in',line);p.stdin.write(line);p.stdin.flush()
finally:
 p.stdin.close()
 try:p.wait(timeout=15)
 except subprocess.TimeoutExpired:p.kill();p.wait()
 t.join(timeout=2)
