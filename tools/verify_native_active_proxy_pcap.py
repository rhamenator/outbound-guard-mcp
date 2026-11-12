#!/usr/bin/env python3
"""Independently inspect one retained route-free active-proxy capture."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys


def verify(capture: Path, digest: str, mode: str) -> dict:
    assert mode in ("tls", "exfil")
    assert hashlib.sha256(capture.read_bytes()).hexdigest() == digest

    def fields(display_filter: str, *names: str) -> list[list[str]]:
        command = ["tshark", "-n", "-r", str(capture), "-Y", display_filter,
                   "-T", "fields", "-E", "separator=;"]
        for name in names:
            command.extend(("-e", name))
        result = subprocess.run(command, capture_output=True, text=True, timeout=15, check=True)
        return [line.split(";") for line in result.stdout.splitlines()]

    syns = [(ip, port) for ip, port in fields(
        "tcp.flags.syn == 1 && tcp.flags.ack == 0", "ip.dst", "tcp.dstport")]
    proxy_syns = [row for row in syns if row == ("127.0.0.1", "3128")]
    direct_syns = [row for row in syns if row != ("127.0.0.1", "3128")]
    expected_direct = ([ ("11.0.0.1", "80"), ("11.0.0.2", "443"),
                         ("11.0.0.1", "80") ] if mode == "tls"
                       else [("11.0.0.1", "80")] * 4)
    assert len(proxy_syns) == 5 and direct_syns == expected_direct, syns

    proxy_requests = fields("tcp.dstport == 3128 && http.request",
                            "http.request.method", "http.host", "http.request.uri")
    assert proxy_requests == [["GET", "allowed.test", "http://allowed.test/proxy-control"]], proxy_requests
    direct_requests = fields("tcp.dstport == 80 && http.request",
                             "http.request.method", "http.host", "http.request.uri")
    expected_paths = (["/proxy-control", "/plain"] if mode == "tls"
                      else ["/proxy-control", "/plain", "/head-ok", "/plain"])
    assert [path for _, _, path in direct_requests] == expected_paths, direct_requests
    assert all(host == "allowed.test" for _, host, _ in direct_requests), direct_requests

    dns_destinations = fields("dns.flags.response == 0 && udp.dstport == 53",
                              "ip.dst", "udp.dstport")
    assert dns_destinations and set(map(tuple, dns_destinations)) == {("127.0.0.1", "53")}
    assert not fields('dns.flags.response == 0 && dns.qry.name == "exfil.test"',
                      "dns.qry.name")
    hello = fields("tls.handshake.type == 1 && tcp.dstport == 443",
                   "tls.handshake.extensions_server_name", "ip.dst")
    assert hello == ([ ["tls-handshake.test", "11.0.0.2"] ] if mode == "tls" else []), hello

    ip_destinations = {address for (ips,) in fields("ip", "ip.dst")
                       for address in ips.split(",") if address}
    allowed = {"127.0.0.1", "11.0.0.1"} | ({"11.0.0.2"} if mode == "tls" else set())
    assert ip_destinations == allowed, ip_destinations
    return {"tcp_syn_destinations": sorted({f"{ip}:{port}" for ip, port in syns}),
            "proxy_tcp_syn_count": len(proxy_syns), "direct_tcp_syn_count": len(direct_syns),
            "proxy_http_requests": proxy_requests,
            "approved_http_paths": expected_paths,
            "dns_query_destinations": ["127.0.0.1:53"],
            "exfil_dns_query_count": 0, "tls_client_hello": hello,
            "ip_destinations": sorted(ip_destinations)}


if __name__ == "__main__":
    print(json.dumps(verify(Path(sys.argv[1]), sys.argv[2], sys.argv[3]), sort_keys=True))
