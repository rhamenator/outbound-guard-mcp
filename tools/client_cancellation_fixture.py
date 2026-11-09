#!/usr/bin/env python3
"""Private helper: run only in the probe's disposable network namespace."""
import sys,threading,socketserver,http.server,time,pathlib,json,os,ssl,subprocess,struct,socket
from netns_adversarial_probe import DNS,HTTP,PUBLIC_FIXTURE,QuietTLSHTTP
root=pathlib.Path(sys.argv[1])
dns=socketserver.ThreadingUDPServer(('127.0.0.1',53),DNS)
http=http.server.ThreadingHTTPServer((PUBLIC_FIXTURE,80),HTTP);http.daemon_threads=True
for s in [dns,http]:threading.Thread(target=s.serve_forever,daemon=True).start()
tcp_dns_queries=[]
tcp_dns_mode=os.environ.get('OUTBOUND_GUARD_CLIENT_DNS_TCP_PRIVATE')
if tcp_dns_mode in ('1','mixed-v6'):
 class PrivateTCPDNS(socketserver.BaseRequestHandler):
  def handle(self):
   self.request.settimeout(3)
   def read_exact(size):
    result=b''
    while len(result)<size:
     try:part=self.request.recv(size-len(result))
     except (TimeoutError,ConnectionResetError):return b''
     if not part:return b''
     result+=part
    return result
   while True:
    prefix=read_exact(2)
    if len(prefix)!=2:return
    length=struct.unpack('!H',prefix)[0]
    if not 17<=length<=512:return
    data=read_exact(length)
    if len(data)!=length:return
    offset=12;labels=[]
    while offset<len(data) and data[offset]:
     size=data[offset];offset+=1
     if size>63 or offset+size>len(data):return
     labels.append(data[offset:offset+size].decode('ascii','ignore'));offset+=size
    if offset+5>len(data):return
    name='.'.join(labels).lower();qtype=struct.unpack('!H',data[offset+1:offset+3])[0]
    expected_name='truncated-mixed-v6.test' if tcp_dns_mode=='mixed-v6' else 'truncated-private.test'
    if name!=expected_name or qtype not in (1,28):return
    tcp_dns_queries.append((name,qtype))
    question=data[12:offset+5]
    if tcp_dns_mode=='mixed-v6':
     address='11.0.0.1' if qtype==1 else '::1'
     answer=(b'\xc0\x0c'+struct.pack('!HHIH',qtype,1,60,4 if qtype==1 else 16)+
             socket.inet_pton(socket.AF_INET if qtype==1 else socket.AF_INET6,address))
    else:
     answer=(b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+socket.inet_pton(socket.AF_INET,'127.0.0.1')) if qtype==1 else b''
    response=data[:2]+struct.pack('!HHHHH',0x8180,1,int(bool(answer)),0,0)+question+answer
    self.request.sendall(struct.pack('!H',len(response))+response)
 class ThreadedTCPDNS(socketserver.ThreadingMixIn,socketserver.TCPServer):
  daemon_threads=True
  allow_reuse_address=True
 tcp_dns=ThreadedTCPDNS(('127.0.0.1',53),PrivateTCPDNS)
 threading.Thread(target=tcp_dns.serve_forever,daemon=True).start()
tls_sni=[]
if os.environ.get('OUTBOUND_GUARD_CLIENT_TLS_HANDSHAKE')=='1':
 tls_slow=os.environ.get('OUTBOUND_GUARD_CLIENT_TLS_SLOW')=='1'
 def openssl(*args):subprocess.run(['openssl',*args],check=True,capture_output=True,timeout=10)
 openssl('req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',str(root/'ca.key'),'-out',str(root/'ca.pem'),'-subj','/CN=Fixture CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
 openssl('req','-new','-newkey','rsa:2048','-nodes','-keyout',str(root/'leaf.key'),'-out',str(root/'leaf.csr'),'-subj','/CN=Fixture Leaf')
 public_host='allowed.test' if tls_slow else 'tls-handshake.test'
 for serial,host,address in ((1,'wrong.test','11.0.0.2'),(2,public_host,PUBLIC_FIXTURE)):
  (root/'extensions').write_text(f'subjectAltName=DNS:{host}\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
  openssl('x509','-req','-in',str(root/'leaf.csr'),'-CA',str(root/'ca.pem'),'-CAkey',str(root/'ca.key'),'-set_serial',str(serial),'-days','1','-extfile',str(root/'extensions'),'-out',str(root/(host+'.pem')))
  context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
  context.load_cert_chain(str(root/(host+'.pem')),str(root/'leaf.key'))
  context.set_servername_callback(lambda _socket,name,_context,address=address:tls_sni.append((address,name)))
  server=QuietTLSHTTP((address,443),HTTP)
  server.socket=context.wrap_socket(server.socket,server_side=True)
  threading.Thread(target=server.serve_forever,daemon=True).start()
(root/'ready').touch()
def snapshot(name, value):
 tmp=root/(name+'.tmp')
 tmp.write_text(json.dumps(value))
 # The parent probe reads these root-written snapshots as its ordinary user.
 # The probe directory remains private (0700), even with a restrictive umask.
 tmp.chmod(0o644)
 os.replace(tmp,root/name)

last_hits=None
last_dns=None
last_dns_a=None
last_dns_all=None
last_rebind=None
last_fallback=None
last_tls_handshake=None
last_tls_sni=None
last_tcp_dns=None
while True:
 hits=list(HTTP.hits)
 if hits!=last_hits:
  snapshot('hits.json',hits)
  last_hits=hits
 names=[name for name in DNS.names if name in ('private.test','alias-private.test','mixed.test','metadata.test','loop-dns.test','exfil.test')]
 if names!=last_dns:
  snapshot('dns.json',names)
  last_dns=names
 a_names=list(DNS.a_names)
 if a_names!=last_dns_a:
  snapshot('dns-a.json',a_names)
  last_dns_a=a_names
 all_names=list(DNS.names)
 if all_names!=last_dns_all:
  snapshot('dns-all.json',all_names)
  last_dns_all=all_names
 rebind=DNS.rebind_a_queries
 if rebind!=last_rebind:
  snapshot('rebind.json',rebind)
  last_rebind=rebind
 fallback=DNS.fallback_a_queries
 if fallback!=last_fallback:
  snapshot('fallback.json',fallback)
  last_fallback=fallback
 tls_handshake=DNS.tls_handshake_a_queries
 if tls_handshake!=last_tls_handshake:
  snapshot('tls-handshake.json',tls_handshake)
  last_tls_handshake=tls_handshake
 if tls_sni!=last_tls_sni:
  snapshot('tls-sni.json',tls_sni)
  last_tls_sni=list(tls_sni)
 if tcp_dns_queries!=last_tcp_dns:
  snapshot('dns-tcp.json',tcp_dns_queries)
  last_tcp_dns=list(tcp_dns_queries)
 if HTTP.cancel_started.is_set() and not (root/'started').exists():(root/'started').touch()
 if HTTP.cancel_closed.is_set() and not (root/'closed').exists():(root/'closed').touch()
 if (root/'reset-cancel').exists():
  assert HTTP.cancel_closed.is_set(), 'cannot reset an open cancellation fixture'
  HTTP.cancel_started.clear();HTTP.cancel_closed.clear()
  (root/'started').unlink(missing_ok=True);(root/'closed').unlink(missing_ok=True)
  (root/'reset-cancel').unlink();(root/'reset-complete').touch()
 time.sleep(.01)
