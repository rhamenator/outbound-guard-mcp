#!/usr/bin/env python3
"""Private helper: run only in the probe's disposable network namespace."""
import sys,threading,socketserver,http.server,time,pathlib,json,os
from netns_adversarial_probe import DNS,HTTP,PUBLIC_FIXTURE
root=pathlib.Path(sys.argv[1])
dns=socketserver.ThreadingUDPServer(('127.0.0.1',53),DNS)
http=http.server.ThreadingHTTPServer((PUBLIC_FIXTURE,80),HTTP);http.daemon_threads=True
for s in [dns,http]:threading.Thread(target=s.serve_forever,daemon=True).start()
(root/'ready').touch()
last_hits=None
last_dns=None
while True:
 hits=list(HTTP.hits)
 if hits!=last_hits:
  hits_tmp=root/'hits.json.tmp'
  hits_tmp.write_text(json.dumps(hits))
  os.replace(hits_tmp,root/'hits.json')
  last_hits=hits
 names=[name for name in DNS.names if name in ('private.test','mixed.test','metadata.test')]
 if names!=last_dns:
  dns_tmp=root/'dns.json.tmp'
  dns_tmp.write_text(json.dumps(names))
  os.replace(dns_tmp,root/'dns.json')
  last_dns=names
 if HTTP.cancel_started.is_set() and not (root/'started').exists():(root/'started').touch()
 if HTTP.cancel_closed.is_set() and not (root/'closed').exists():(root/'closed').touch()
 time.sleep(.01)
