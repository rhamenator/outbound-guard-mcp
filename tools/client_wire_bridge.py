#!/usr/bin/env python3
"""Private helper: transparently forward MCP; log only method/ID/rule metadata."""
import sys,subprocess,threading,json,time,pathlib
assert len(sys.argv) in (4,5)
ns,binary,log=sys.argv[1:4]
hosts=sys.argv[4] if len(sys.argv)==5 else 'allowed.test'
assert hosts in ('allowed.test','allowed.test,private.test,mixed.test,metadata.test','allowed.test,exfil.test')
p=subprocess.Popen(['sudo','-n','ip','netns','exec',ns,'env','-i','PATH=/usr/bin:/bin','OUTBOUND_GUARD_ALLOWED_HOSTS='+hosts,binary],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=sys.stderr.buffer)
lock=threading.Lock()
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

def outgoing():
 for line in p.stdout:
  record('out',line);sys.stdout.buffer.write(line);sys.stdout.buffer.flush()
t=threading.Thread(target=outgoing,daemon=True);t.start()
try:
 for line in sys.stdin.buffer:
  record('in',line);p.stdin.write(line);p.stdin.flush()
finally:
 p.stdin.close()
 try:p.wait(timeout=15)
 except subprocess.TimeoutExpired:p.kill();p.wait()
 t.join(timeout=2)
