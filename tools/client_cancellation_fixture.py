#!/usr/bin/env python3
"""Private helper: run only in the probe's disposable network namespace."""
import sys,threading,socketserver,http.server,time,pathlib,json,os,ssl,subprocess
from netns_adversarial_probe import DNS,HTTP,PUBLIC_FIXTURE,QuietTLSHTTP
root=pathlib.Path(sys.argv[1])
dns=socketserver.ThreadingUDPServer(('127.0.0.1',53),DNS)
http=http.server.ThreadingHTTPServer((PUBLIC_FIXTURE,80),HTTP);http.daemon_threads=True
for s in [dns,http]:threading.Thread(target=s.serve_forever,daemon=True).start()
tls_sni=[]
if os.environ.get('OUTBOUND_GUARD_CLIENT_TLS_HANDSHAKE')=='1':
 def openssl(*args):subprocess.run(['openssl',*args],check=True,capture_output=True,timeout=10)
 openssl('req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',str(root/'ca.key'),'-out',str(root/'ca.pem'),'-subj','/CN=Fixture CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
 openssl('req','-new','-newkey','rsa:2048','-nodes','-keyout',str(root/'leaf.key'),'-out',str(root/'leaf.csr'),'-subj','/CN=Fixture Leaf')
 for serial,host,address in ((1,'wrong.test','11.0.0.2'),(2,'tls-handshake.test',PUBLIC_FIXTURE)):
  (root/'extensions').write_text(f'subjectAltName=DNS:{host}\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
  openssl('x509','-req','-in',str(root/'leaf.csr'),'-CA',str(root/'ca.pem'),'-CAkey',str(root/'ca.key'),'-set_serial',str(serial),'-days','1','-extfile',str(root/'extensions'),'-out',str(root/(host+'.pem')))
  context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
  context.load_cert_chain(str(root/(host+'.pem')),str(root/'leaf.key'))
  context.set_servername_callback(lambda _socket,name,_context,address=address:tls_sni.append((address,name)))
  server=QuietTLSHTTP((address,443),HTTP)
  server.socket=context.wrap_socket(server.socket,server_side=True)
  threading.Thread(target=server.serve_forever,daemon=True).start()
(root/'ready').touch()
last_hits=None
last_dns=None
last_dns_a=None
last_dns_all=None
last_rebind=None
last_fallback=None
last_tls_handshake=None
last_tls_sni=None
while True:
 hits=list(HTTP.hits)
 if hits!=last_hits:
  hits_tmp=root/'hits.json.tmp'
  hits_tmp.write_text(json.dumps(hits))
  os.replace(hits_tmp,root/'hits.json')
  last_hits=hits
 names=[name for name in DNS.names if name in ('private.test','alias-private.test','mixed.test','metadata.test','loop-dns.test','exfil.test')]
 if names!=last_dns:
  dns_tmp=root/'dns.json.tmp'
  dns_tmp.write_text(json.dumps(names))
  os.replace(dns_tmp,root/'dns.json')
  last_dns=names
 a_names=list(DNS.a_names)
 if a_names!=last_dns_a:
  dns_a_tmp=root/'dns-a.json.tmp'
  dns_a_tmp.write_text(json.dumps(a_names))
  os.replace(dns_a_tmp,root/'dns-a.json')
  last_dns_a=a_names
 all_names=list(DNS.names)
 if all_names!=last_dns_all:
  dns_all_tmp=root/'dns-all.json.tmp'
  dns_all_tmp.write_text(json.dumps(all_names))
  os.replace(dns_all_tmp,root/'dns-all.json')
  last_dns_all=all_names
 rebind=DNS.rebind_a_queries
 if rebind!=last_rebind:
  rebind_tmp=root/'rebind.json.tmp'
  rebind_tmp.write_text(json.dumps(rebind))
  os.replace(rebind_tmp,root/'rebind.json')
  last_rebind=rebind
 fallback=DNS.fallback_a_queries
 if fallback!=last_fallback:
  fallback_tmp=root/'fallback.json.tmp'
  fallback_tmp.write_text(json.dumps(fallback))
  os.replace(fallback_tmp,root/'fallback.json')
  last_fallback=fallback
 tls_handshake=DNS.tls_handshake_a_queries
 if tls_handshake!=last_tls_handshake:
  tls_tmp=root/'tls-handshake.json.tmp'
  tls_tmp.write_text(json.dumps(tls_handshake))
  os.replace(tls_tmp,root/'tls-handshake.json')
  last_tls_handshake=tls_handshake
 if tls_sni!=last_tls_sni:
  sni_tmp=root/'tls-sni.json.tmp'
  sni_tmp.write_text(json.dumps(tls_sni))
  os.replace(sni_tmp,root/'tls-sni.json')
  last_tls_sni=list(tls_sni)
 if HTTP.cancel_started.is_set() and not (root/'started').exists():(root/'started').touch()
 if HTTP.cancel_closed.is_set() and not (root/'closed').exists():(root/'closed').touch()
 time.sleep(.01)
