# Real-client cancellation and queue-saturation evidence

Status: experimental candidate observations, not release approval or universal client/UI certification.

## Non-ASCII URL exfiltration regression, 2026-10-29

The [raw-URL regression record](evidence/non-ascii-url-exfil-2026-10-29.json)
captures a controlled failure on the preceding trusted-main executable:
Claude sent a fullwidth synthetic token-shaped path to an approved fixture
host. URL parsing percent-encoded it, and `guarded_fetch` returned
`EGRESS_ALLOWED`; the old probe deliberately failed its new denial
assertion. No real credential was used. A focused Rust test also failed
before the fix because non-ASCII input reached reservation.

The server now rejects non-ASCII raw URLs with `EGRESS_INVALID_URL` before
reservation and DNS. Authenticated Claude Code 2.1.301 and Codex CLI 0.151.0
each completed the revised five-call skill workflow: approved GET/HEAD
controls succeeded, the ASCII synthetic marker returned
`EGRESS_SECRET_DETECTED`, and the fullwidth marker returned
`EGRESS_INVALID_URL`. The fixture saw only approved HTTP paths and no query
for the exfiltration host.

```bash
OUTBOUND_GUARD_CLIENT_EXFIL=1 python3 tools/client_cancellation_probe.py claude /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Repeat with `codex`. This closes the demonstrated URL canonicalization
route; it does not recognize all transformed or ASCII-encoded secrets,
cover Cursor's current plan-gated MCP path, establish automatic skill
triggering, or guard traffic sent through other tools.

## Native-client malformed DNS compression loop, 2026-10-29

The [malformed DNS record](evidence/native-client-dns-compression-loop-2026-10-29.json)
extends the route-free DNS fixture with an answer whose CNAME RDATA
compression pointer targets itself. Authenticated Claude Code 2.1.301 and
Codex CLI 0.151.0 each completed eight ordered `guarded_fetch` calls through
the installed two-file skill and current executable. The fixture observed
an A query for `loop-dns.test`; the call returned `EGRESS_DNS_FAILURE`, and
the HTTP fixture saw only the two approved control paths. Four preceding
private, alias, mixed-answer and metadata DNS cases still returned
`EGRESS_FORBIDDEN_ADDRESS`.

```bash
OUTBOUND_GUARD_CLIENT_DNS_SSRF=1 python3 tools/client_cancellation_probe.py codex /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Repeat with `claude`. This is one malformed answer shape on the tested
resolver, not general DNS protocol conformance or a packet-level proof of
all destinations. Cursor remains gated before MCP calls; explicit skill
use does not cover automatic triggering or traffic sent through other tools.

## Native-client CNAME-to-private DNS denial, 2026-10-29

The [CNAME SSRF record](evidence/native-client-cname-ssrf-2026-10-29.json)
uses the current HTTP-upgrade-fixed executable and inspected two-file skill
ZIP. In a disposable route-free namespace, `alias-private.test` returns a
CNAME to `private.test` and a loopback A record. Authenticated Claude Code
2.1.301 and Codex CLI 0.151.0 each made seven ordered calls. Loopback URL
denial, approved GET/HEAD, and four DNS denials matched expectations; the
CNAME call returned `EGRESS_FORBIDDEN_ADDRESS`. The fixture observed an A
query for the alias and only the two approved HTTP paths. The mode now adds
this case to its earlier private, mixed-answer, and metadata replay:

```bash
OUTBOUND_GUARD_CLIENT_DNS_SSRF=1 python3 tools/client_cancellation_probe.py claude /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Repeat with `codex`. The linked seven-call record predates the malformed DNS
case; this command now makes eight calls. This one CNAME shape does not prove arbitrary DNS-chain
handling or absence of every forbidden socket. Cursor's native plan gate
still prevents MCP calls. Explicit skill use does not cover automatic
triggering or traffic sent through other tools.

## Native-client HTTP 101 denial and recovery, 2026-10-29

The [native HTTP 101 record](evidence/native-client-http-upgrade-2026-10-29.json)
uses executable SHA-256
`5bc6e89ef3faf05bb754f1ae51c8ea50a1a1368558aba6af89477e32519fe308`
and the inspected two-file skill ZIP in real Claude Code 2.1.301 and
Codex CLI 0.151.0 sessions. Each client requested approved `/plain`, then
a controlled HTTP/1.1 `101 Switching Protocols` response, then `/plain`
again. Both received `EGRESS_ALLOWED`/200 for the controls and
`EGRESS_PROTOCOL_UPGRADE_DENIED` without body text for the upgrade. The
route-free fixture recorded exactly those three paths per session.

```bash
OUTBOUND_GUARD_CLIENT_HTTP_UPGRADE=1 python3 tools/client_cancellation_probe.py claude /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Repeat with `codex` for the second client. This is one 101 response, not
broad upgraded-protocol, HTTP/2 or parser conformance. Fixture hits do not
prove every packet or syscall destination. Cursor was not rerun after its
native plan gate yielded zero MCP calls. Explicit skill use does not prove
automatic triggering or cover traffic sent through other tools.

The [current-binary HTTP 101 replay](evidence/native-client-http-upgrade-current-binary-2026-10-30.json)
repeats this exact native workflow after the Unicode URL fix. Claude Code
2.1.301 and Codex CLI 0.151.0 each loaded the inspected two-file skill ZIP
and made three guarded calls through the current executable. The approved
GETs returned `EGRESS_ALLOWED`/200 around a `101 Switching Protocols`
response denied as `EGRESS_PROTOCOL_UPGRADE_DENIED` without body text. The
route-free fixture saw only `/plain`, `/switch-protocols`, `/plain` per
session. The same finite-case and client limitations above still apply.

## Native interim-header flood and recovery, 2026-10-30

The [current-binary 103 flood record](evidence/native-client-interim-header-flood-2026-10-30.json)
replays the route-free `103 Early Hints` header flood through real Claude Code
2.1.301 and Codex CLI 0.151.0 skill sessions. Each client made three guarded
GETs in order: approved `/plain`, hostile `/interim-header-flood`, and
approved `/plain`. The middle call returned `EGRESS_RESPONSE_WIRE_LIMIT`
without body text; both controls returned `EGRESS_ALLOWED`/200. The fixture
saw exactly those paths. The original HTTP 101 mode also passed a Codex
regression after this harness extension.

```bash
OUTBOUND_GUARD_CLIENT_HTTP_UPGRADE=interim python3 tools/client_cancellation_probe.py claude /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Repeat with `codex`. This is one HTTP/1.1 interim-response pattern. Cursor
remains untested for this case after its native plan gate; explicit skill
use, fixture hits and successful recovery do not prove automatic triggering,
every packet destination, UI cancellation or traffic sent through other tools.

## Post-upgrade-fix native control replay, 2026-10-29

The [post-fix control record](evidence/native-client-control-post-upgrade-2026-10-29.json)
uses the executable SHA-256
`5bc6e89ef3faf05bb754f1ae51c8ea50a1a1368558aba6af89477e32519fe308`
from the HTTP 101 fix and the inspected two-file skill ZIP. Real Claude
Code 2.1.301 and Codex CLI 0.151.0 sessions each completed a loopback GET
with `EGRESS_INVALID_HOST`, then approved GET and HEAD controls with
`EGRESS_ALLOWED`/200 in a route-free fixture.

```bash
python3 tools/client_cancellation_probe.py claude /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Repeat with `codex` for the second client. This sequence does not deliver a
101 response through either native client; the 101 denial is established by
the separate direct MCP route-free regression. Cursor was not rerun after
its native plan gate yielded zero MCP calls. Explicit skill use does not
prove automatic triggering or cover traffic sent through other tools.

## Current-binary native pinned-address fallback, 2026-10-29

The [current-binary fallback record](evidence/native-client-fallback-current-binary-2026-10-29.json)
uses real Claude Code 2.1.301 and Codex CLI 0.151.0 skill sessions with
executable SHA-256 `1d7a3f0175d88cec717a7fe141be58562f619bcfd8dd8bdd1be3e8736dcb49c3`
and the inspected two-file skill ZIP. Each client first fetched approved
`allowed.test`, then `fallback-pin.test`. The latter's first A answer listed
a refused public-policy address followed by the locally served public-policy
address; a hypothetical second A answer would switch to loopback. Each
client completed two `EGRESS_ALLOWED`/200 calls, and the fixture recorded
two `/plain` hits and one A query for `fallback-pin.test`.

```bash
OUTBOUND_GUARD_CLIENT_PINNED_FALLBACK=1 python3 tools/client_cancellation_probe.py claude /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Repeat with `codex` for the second client. One observed A query shows no
application-visible retry in this path; it does not cover every OS resolver,
TLS or HTTP reconnect state. These native sessions did not trace packets or
connect syscalls. The earlier route-free syscall fixture is separate
evidence. Cursor was not rerun after its native plan gate yielded zero MCP
calls. Explicit skill use does not prove automatic triggering or cover
traffic sent through other tools.

## Current-binary native response-body limits and recovery, 2026-10-29

The [current-binary body-limit record](evidence/native-client-body-limits-current-binary-2026-10-29.json)
uses real Claude Code 2.1.301 and Codex CLI 0.151.0 skill sessions with
executable SHA-256 `1d7a3f0175d88cec717a7fe141be58562f619bcfd8dd8bdd1be3e8736dcb49c3`
and the inspected two-file skill ZIP. Each client made four ordered GETs to
a controlled route-free HTTP/1.1 fixture. Fixed-length `/large` and chunked
`/chunked-large` responses returned `EGRESS_RESPONSE_LIMIT`; approved
`/plain` controls before and after returned `EGRESS_ALLOWED`/200. The
fixture recorded exactly the four requested paths.

```bash
OUTBOUND_GUARD_CLIENT_RESPONSE_LIMIT=1 python3 tools/client_cancellation_probe.py claude /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Repeat with `codex` for the second client. These are two finite response-size
cases, not aggregate resource-exhaustion, all-stream or HTTP/2 proof. Fixture
hits are not packet or syscall tracing for every destination. Cursor was not
rerun after its native plan gate yielded zero MCP calls. Explicit skill use
does not prove automatic triggering or cover traffic sent through other
tools.

## Current-binary native response-header limits and recovery, 2026-10-29

The [current-binary header record](evidence/native-client-header-limits-current-binary-2026-10-29.json)
uses real Claude Code 2.1.301 and Codex CLI 0.151.0 skill sessions with the
same executable SHA-256 `1d7a3f0175d88cec717a7fe141be58562f619bcfd8dd8bdd1be3e8736dcb49c3`
and inspected two-file skill ZIP. Each client made five ordered GETs to the
controlled route-free HTTP/1.1 fixture. Approved `/plain` controls returned
`EGRESS_ALLOWED`/200 before and after three `EGRESS_INVALID_FRAMING` denials
for excess header count, an oversized header and a parser-ceiling response.
The fixture recorded exactly the five requested paths.

```bash
OUTBOUND_GUARD_CLIENT_HEADER_LIMIT=1 python3 tools/client_cancellation_probe.py claude /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Repeat with `codex` for the second client. These are three finite HTTP/1.1
header cases, not full parser, TLS or HTTP/2 coverage. Fixture hits are not
packet or syscall tracing for every destination. Cursor was not rerun after
its native plan gate yielded zero MCP calls. Explicit skill use does not
prove automatic triggering or cover traffic sent through other tools.

## Current-binary native JSON instruction and duplicate-key denials, 2026-10-29

The [current-binary JSON record](evidence/native-client-json-current-binary-2026-10-29.json)
replays two controlled responses through the installed skill in real Claude
Code 2.1.301 and Codex CLI 0.151.0 sessions. For each client, an explicit
instruction-like JSON key returned `EGRESS_UNTRUSTED_INSTRUCTION`, and a
duplicate-key response that shadows a nested instruction returned
`EGRESS_INVALID_JSON`. Each denial was followed by an approved `/plain`
GET returning `EGRESS_ALLOWED` and HTTP 200. The fixture recorded exactly
the attempted hostile path and `/plain` for each of the four sessions. The
controlled instruction string did not appear in either native-client
transcript. All sessions used executable SHA-256
`1d7a3f0175d88cec717a7fe141be58562f619bcfd8dd8bdd1be3e8736dcb49c3`
and the inspected two-file skill ZIP.

```bash
OUTBOUND_GUARD_CLIENT_JSON_INJECTION=1 python3 tools/client_cancellation_probe.py claude /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
OUTBOUND_GUARD_CLIENT_JSON_INJECTION=duplicate python3 tools/client_cancellation_probe.py codex /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Run both modes for each client to repeat the full record. The fixture used
synthetic instructions, not credentials or public targets. This proves the
two recognized JSON shapes were denied by this executable; instructions in
other fields, plaintext, and HTML can still pass. The marker check is not a
general prompt-injection quarantine or a proof of model resistance. Cursor
was not rerun after its native plan gate yielded zero MCP calls. Explicit
skill use does not prove automatic triggering or cover traffic sent through
other tools.

## Current-binary native session with injected header and body arguments, 2026-10-29

The [current-binary argument record](evidence/native-client-arguments-current-binary-2026-10-29.json)
replays two approved GETs through the installed skill in real Claude Code
2.1.301 and Codex CLI 0.151.0 sessions. A transparent test bridge first
sends separate MCP calls with a synthetic marker in unsupported
`Authorization` header and `body` arguments, copying the native call's
protocol metadata. Both injected calls returned `EGRESS_INVALID_INPUT`
without echoing the marker. Each client then completed its two approved
GETs; the fixture recorded only two `/plain` HTTP hits and two A plus two
AAAA queries for `allowed.test`. Both used executable SHA-256
`1d7a3f0175d88cec717a7fe141be58562f619bcfd8dd8bdd1be3e8736dcb49c3`
and the inspected two-file skill ZIP.

```bash
OUTBOUND_GUARD_CLIENT_ARGUMENT_INJECTION=1 python3 tools/client_cancellation_probe.py claude /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

The bridge generated and hid the injected calls; neither client supplied
unsupported arguments. Cursor was not rerun after its preceding native plan
gate yielded zero MCP calls. This checks rejection of fields outside the
advertised schema, not safe transmission of arbitrary headers or bodies.
The fixture oracle is not a packet/syscall trace for every destination.
Explicit skill use does not prove automatic triggering or cover traffic sent
through other tools.

## Current-binary native session with an injected malformed MCP frame, 2026-10-29

The [current-binary MCP frame record](evidence/native-client-mcp-frame-current-binary-2026-10-29.json)
replays two approved GETs through the installed skill in real Claude Code
2.1.301 and Codex CLI 0.151.0 sessions. A transparent test bridge inserts
one unterminated JSON-RPC `tools/call` object containing a controlled private
fixture URL before the first valid client call. The server returned `-32700`
with a null ID for the injected frame; the bridge recorded and withheld that
reply. Both native clients then completed their two valid `EGRESS_ALLOWED`
calls, and the private fixture saw no DNS query or HTTP hit. Both used
executable SHA-256
`1d7a3f0175d88cec717a7fe141be58562f619bcfd8dd8bdd1be3e8736dcb49c3`
and the inspected two-file skill ZIP.

```bash
OUTBOUND_GUARD_CLIENT_FRAME_MUTATION=1 python3 tools/client_cancellation_probe.py claude /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

The bridge generated the malformed frame; the clients did not. Cursor was
not rerun after its preceding native plan gate yielded zero MCP calls. This
is one parser-recovery case, not complete MCP protocol conformance. The
fixture oracle is not a packet/syscall trace for every destination. Explicit
skill use does not prove automatic triggering or cover traffic sent through
other tools.

## Current-binary native malformed HTTP chunk framing, 2026-10-29

The [current-binary malformed HTTP record](evidence/native-client-malformed-http-current-binary-2026-10-29.json)
replays four ordered calls through the installed skill in real Claude Code
2.1.301 and Codex CLI 0.151.0 clients. After approved GET and HEAD controls,
a route-free HTTP/1.1 fixture sends an invalid hexadecimal chunk size and a
truncated chunk. Both clients received `EGRESS_READ_FAILURE` for each
malformed response; only the controls returned 200. The HTTP fixture
recorded exactly `/plain`, `/head-ok`, `/chunked-bad-size`, and
`/chunked-truncated`. Both used executable SHA-256
`1d7a3f0175d88cec717a7fe141be58562f619bcfd8dd8bdd1be3e8736dcb49c3`
and the inspected two-file skill ZIP.

```bash
OUTBOUND_GUARD_CLIENT_MALFORMED=1 python3 tools/client_cancellation_probe.py claude /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Cursor was not rerun after its preceding native plan gate yielded zero MCP
calls. This tests two chunked-body malformations, not malformed MCP frames,
other HTTP parser states, TLS, or HTTP/2. Fixture hits are not packet or
syscall evidence for every possible destination. Explicit skill use does not
prove automatic triggering or cover traffic sent through other tools.

## Current-binary native slow HTTP denial and recovery, 2026-10-29

The [current-binary slow HTTP record](evidence/native-client-slow-http-current-binary-2026-10-29.json)
replays four ordered GETs through the installed skill in real Claude Code
2.1.301 and Codex CLI 0.151.0 clients: an approved control, a body sent one
byte per second, an eleven-second delay before headers, and a final approved
control. Both clients received `EGRESS_RESPONSE_TOO_SLOW` for the drip,
`EGRESS_NETWORK_FAILURE` for the delayed first byte, and `EGRESS_ALLOWED`
for the final recovery call. The route-free fixture recorded exactly
`/plain`, `/drip`, `/delayed`, `/plain`. Both used executable SHA-256
`1d7a3f0175d88cec717a7fe141be58562f619bcfd8dd8bdd1be3e8736dcb49c3`
and the inspected two-file skill ZIP.

```bash
OUTBOUND_GUARD_CLIENT_SLOW_HTTP=1 python3 tools/client_cancellation_probe.py claude /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Cursor was not rerun after its preceding native plan gate yielded zero MCP
calls. This records decisions and fixture hits for one drip rate and one
first-byte delay, not precise byte counts, packet timings, socket-close
latency, peak memory, concurrent slow requests, or other pacing patterns.
Explicit skill use does not prove automatic triggering or cover traffic sent
through other tools.

## Current-binary native redirect and encoded-response traps, 2026-10-29

The [current-binary trap record](evidence/native-client-traps-current-binary-2026-10-29.json)
replays five ordered calls through the installed skill in real Claude Code
2.1.301 and Codex CLI 0.151.0 clients. After a loopback denial and approved
GET/HEAD controls, the controlled host returns a redirect to a private name
and a gzip body that would expand from under 16 KiB to 8 MiB. Both clients
received `EGRESS_REDIRECT_DENIED` and `EGRESS_ENCODED_RESPONSE` for those
traps. The route-free HTTP fixture observed only `/plain`, `/head-ok`,
`/redirect`, and `/gzip-bomb`, with no private redirect-target hit. Both
used executable SHA-256
`1d7a3f0175d88cec717a7fe141be58562f619bcfd8dd8bdd1be3e8736dcb49c3`
and the inspected two-file skill ZIP.

```bash
OUTBOUND_GUARD_CLIENT_TRAPS=1 python3 tools/client_cancellation_probe.py claude /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Cursor was not rerun after its preceding native plan gate yielded zero MCP
calls. These are exact policy decisions and fixture hits, not a packet or
syscall proof for every destination. The encoded response was rejected, so
this run did not measure decompression or peak memory. Explicit skill use
does not prove automatic triggering or cover traffic sent through other tools.

## Current-binary native synthetic URL exfiltration denial, 2026-10-29

The [current-binary exfiltration record](evidence/native-client-exfil-current-binary-2026-10-29.json)
uses a harness-generated synthetic secret-shaped URL path and an approved
controlled host. Claude Code 2.1.301 and Codex CLI 0.151.0 each completed an
explicit four-call skill turn: loopback denial, approved GET and HEAD, then
`EGRESS_SECRET_DETECTED`. The controlled resolver saw no query for the
exfiltration host, HTTP saw only `/plain` and `/head-ok`, and the transparent
bridge observed no synthetic marker in server-to-client MCP results. Both
used executable SHA-256
`1d7a3f0175d88cec717a7fe141be58562f619bcfd8dd8bdd1be3e8736dcb49c3`
and the same inspected two-file skill ZIP. The marker was not a credential.
That four-call record predates the additional Unicode path; the command below
now makes five calls.

```bash
OUTBOUND_GUARD_CLIENT_EXFIL=1 python3 tools/client_cancellation_probe.py claude /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Cursor was not rerun after its preceding native plan gate yielded zero MCP
calls. This covers one synthetic URL path, not headers, bodies, arbitrary
secrets, provider-side transcripts, audit retention, or traffic sent through
other tools. The marker necessarily appears in the temporary client prompt.
DNS/HTTP fixture observations are not a packet or syscall trace.

## Current-binary native DNS rebinding between calls, 2026-10-29

The [current-binary rebinding record](evidence/native-client-rebind-current-binary-2026-10-29.json)
replays an approved control GET followed by two GETs to one operator-approved
fixture hostname through the installed skill and real Claude Code 2.1.301 and
Codex CLI 0.151.0 clients. The route-free namespace resolver returns the
locally served public-policy address for the first rebinding A query, then
loopback for the second. Both clients completed three ordered calls with two
`EGRESS_ALLOWED` decisions and a final `EGRESS_FORBIDDEN_ADDRESS`. Each run
recorded exactly two rebinding A queries and only the two approved `/plain`
HTTP fixture hits. Both used executable SHA-256
`1d7a3f0175d88cec717a7fe141be58562f619bcfd8dd8bdd1be3e8736dcb49c3`
and the inspected two-file skill ZIP.

```bash
OUTBOUND_GUARD_CLIENT_REBIND=1 python3 tools/client_cancellation_probe.py claude /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Cursor was not rerun after its immediately preceding native plan gate yielded
zero MCP calls. This checks changed A answers between separate guarded calls,
not an intra-call resolver race, every A/AAAA combination or every reconnect
path. Fixture hits are not a packet/syscall proof for every destination.
Explicit skill invocation does not prove automatic triggering or protect
traffic sent through other tools.

## Current-binary native DNS SSRF denials, 2026-10-29

The [exact-binary DNS record](evidence/native-client-dns-current-binary-2026-10-29.json)
replays six ordered calls through the installed clean skill and real Claude
Code 2.1.301 and Codex CLI 0.151.0 clients. Both completed loopback denial,
approved GET and HEAD controls, then three controlled DNS attacks: a private
address, a mixed public/private answer set, and a metadata-address answer.
Each attack returned `EGRESS_FORBIDDEN_ADDRESS`. The HTTP fixture observed
only the two approved control paths, `/plain` and `/head-ok`; none of the
three attack paths reached it. Both runs used executable SHA-256
`1d7a3f0175d88cec717a7fe141be58562f619bcfd8dd8bdd1be3e8736dcb49c3`
and the same inspected two-file skill ZIP. No public HTTP target or real
secret was involved.

```bash
OUTBOUND_GUARD_CLIENT_DNS_SSRF=1 python3 tools/client_cancellation_probe.py claude /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Cursor was not rerun because its current native plan gate prevented any MCP
call in the immediately preceding control replay. This finite evidence
checks policy decisions and controlled HTTP fixture hits, not packet or
syscall absence for every possible address or behavior of traffic sent
through other tools. Explicit skill invocation is not automatic triggering.

## Current-binary native control replay, 2026-10-29

The [exact-binary record](evidence/native-client-control-current-binary-2026-10-29.json)
replays the route-free held-HTTP cancellation control on the executable with
SHA-256 `1d7a3f0175d88cec717a7fe141be58562f619bcfd8dd8bdd1be3e8736dcb49c3`.
Claude Code 2.1.301 sent one matching MCP cancellation after its stream-JSON
interrupt, suppressed the cancelled tool reply, and the fixture observed
socket closure in 0.04 seconds in the retained run. Its subsequent approved
GET, loopback denial, and HEAD control passed. Codex CLI 0.151.0 acknowledged
an app-server turn interrupt but sent no MCP cancellation in its completed
run; the guarded fetch instead returned `EGRESS_RESPONSE_TOO_SLOW` and the
fixture socket closed in 2.997 seconds. Codex then passed the same recovery,
loopback-denial and HEAD controls. A later Codex repeat issued no MCP call
within 80 seconds and is inconclusive, not an additional passing run.

Cursor CLI 2026.10.19-6bbf2c4 made no MCP call in an 80-second attempt. A
second attempt returned its native plan-upgrade notice and ended before any
MCP call. The harness now recognizes that plan gate on the control path,
reports zero tool calls, and exits within ten seconds instead of waiting for
the fixture deadline. Cursor cancellation delivery remains untested on this
executable. These are authenticated client control APIs, not desktop Stop
buttons or terminal Escape keys; no native client ran inside the cgroup
quota probes. Traffic through other tools remains outside Outbound Guard.

## Native-client valid JSON instruction pass-through, 2026-10-28

The opt-in `OUTBOUND_GUARD_CLIENT_JSON_INJECTION=1` replay asks a real
client to GET a controlled `application/json` response containing an
adversarial instruction string, then GET an approved plain response. Claude
Code 2.1.301 and Codex CLI 0.151.0 each completed exactly those two guarded
calls in a route-free fixture. Both tool results were `EGRESS_ALLOWED`, and
the instruction string appeared in each native-client transcript. The
[redacted candidate record](evidence/native-client-json-injection-2026-10-28.json)
binds source, binary and skill hashes to the observation.

```bash
OUTBOUND_GUARD_CLIENT_JSON_INJECTION=1 python3 tools/client_cancellation_probe.py codex /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Run one authenticated client at a time with the existing development
prerequisites and a checksum-verified candidate. Model usage may incur cost.
The explicit prompt told each client to treat fetched text as data. These
finite sessions show the server passed a valid JSON instruction through;
they do not prove general model resistance. The `untrusted_content` flag is
not a sanitizer or quarantine. Cursor was not rerun under its separate plan
gate. No real secrets or public targets were used, and traffic through other
tools remains outside Outbound Guard.

This pass-through occurred on the earlier `8b76b439ca53` candidate binary.
The subsequent source change denies explicit instruction-like JSON keys;
local debug-client and route-free fixture replays passed for that narrow
case. A later [signed trusted-main candidate replay](evidence/native-client-json-signed-main-2026-10-28.json)
also passed with Claude Code and Codex CLI. Other prompt-injection forms
remain unquarantined.

A follow-up parser check rejects duplicate JSON object keys as
`EGRESS_INVALID_JSON`. Without that check, a later duplicate could overwrite
an object containing a blocked nested key during parsing while the original
raw body was still returned. The route-free fixture confirms denial without
`body_text`. An [unsigned exact-PR-artifact replay](evidence/native-client-json-duplicate-2026-10-28.json)
with Claude Code and Codex CLI returned `EGRESS_INVALID_JSON` then
`EGRESS_ALLOWED` on the two requested guarded GETs. Neither transcript
contained the controlled instruction string. This is finite evidence for
that PR artifact. The same denial and approved recovery GET passed in the
[signed trusted-main replay](evidence/native-client-json-signed-main-2026-10-28.json).

```bash
OUTBOUND_GUARD_CLIENT_JSON_INJECTION=duplicate python3 tools/client_cancellation_probe.py codex /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

## Native-client slow HTTP denial and recovery, 2026-10-28

The opt-in `OUTBOUND_GUARD_CLIENT_SLOW_HTTP=1` skill replay asks a real
client for an approved GET, a one-byte-per-second body, an eleven-second
delay before headers, and another approved GET. Claude Code and Codex CLI
each completed all four calls in order. The slow body returned
`EGRESS_RESPONSE_TOO_SLOW`; the delayed headers returned
`EGRESS_NETWORK_FAILURE`; the final approved GET succeeded. The [redacted
exact-candidate record](evidence/native-client-slow-http-2026-10-28.json)
binds source, binary and skill hashes to these observations.

```bash
OUTBOUND_GUARD_CLIENT_SLOW_HTTP=1 python3 tools/client_cancellation_probe.py codex /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Run one authenticated client at a time with the existing development
prerequisites and a checksum-verified candidate. Model usage may incur cost.
This records decisions and fixture hits, not a native-client packet trace or
peak resource use. Cursor was not rerun under its plan gate. Alternate
pacing, concurrent slow requests and traffic sent through other tools
remain outside this observation.

## Native-client pinned-address fallback under a DNS flip, 2026-10-28

The opt-in `OUTBOUND_GUARD_CLIENT_PINNED_FALLBACK=1` skill replay asks a real
client for an approved control GET and one GET to a controlled DNS name.
The first A answer lists a public-policy address with no HTTP listener,
then the public-policy fixture address. A hypothetical second A query
would return loopback. Claude Code and Codex CLI each completed both GETs
with HTTP 200, while the resolver saw exactly one A query for the fallback
name. The [redacted exact-candidate record](evidence/native-client-pinned-fallback-2026-10-28.json)
binds source, binary and skill hashes to these observations.

```bash
OUTBOUND_GUARD_CLIENT_PINNED_FALLBACK=1 python3 tools/client_cancellation_probe.py codex /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Run one authenticated client at a time with the existing development
prerequisites and a checksum-verified candidate. Model usage may incur cost.
This native-client fixture does not trace connect syscalls or packets; the
separate route-free TCP-refusal probe does, for its own run. Cursor was not
rerun under its plan gate. TLS/HTTP reconnects, other resolver behavior and
traffic sent through other tools remain outside this observation.

## Native-client session with one injected malformed MCP frame, 2026-10-28

The opt-in `OUTBOUND_GUARD_CLIENT_FRAME_MUTATION=1` replay asks a real
client for two approved GETs. A transparent test bridge inserts one
unterminated JSON-RPC `tools/call` frame, containing a controlled private
fixture URL, immediately before the first valid client call. The bridge
records and withholds the server's `-32700` parse-error reply for that
injected frame. Claude Code and Codex CLI each completed both valid calls;
the private fixture saw no DNS query or HTTP hit. The [redacted
exact-candidate record](evidence/native-client-mcp-frame-mutation-2026-10-28.json)
binds source, binary and skill hashes to these observations.

```bash
OUTBOUND_GUARD_CLIENT_FRAME_MUTATION=1 python3 tools/client_cancellation_probe.py codex /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Run one authenticated client at a time with the existing development
prerequisites and a checksum-verified candidate. Model usage may incur cost.
The bridge, rather than the clients, generates the malformed frame. Cursor
was not rerun because its separate plan gate prevents an MCP call. This is
one parser recovery case, not complete MCP conformance or proof about
traffic sent through other tools.

## Native-client session with injected header and body arguments, 2026-10-28

The opt-in `OUTBOUND_GUARD_CLIENT_ARGUMENT_INJECTION=1` replay asks a real
client for two approved GETs. A test bridge first sends separate MCP calls
with a synthetic secret marker in an unsupported `Authorization` header and
an unsupported `body` field, copying the native call's protocol metadata.
The bridge records and withholds only the injected replies. In Claude Code
2.1.301 and Codex CLI 0.151.0 sessions, both injected calls returned
`EGRESS_INVALID_INPUT` without echoing the marker; the clients then completed
their two GETs. Each run had exactly two approved HTTP hits and two A plus
two AAAA queries for `allowed.test`. The [redacted candidate record](evidence/native-client-argument-injection-2026-10-28.json)
binds these observations to the binary and skill hashes.

```bash
OUTBOUND_GUARD_CLIENT_ARGUMENT_INJECTION=1 python3 tools/client_cancellation_probe.py codex /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Run one authenticated client at a time with the existing development
prerequisites and a checksum-verified candidate. Model usage may incur cost.
The bridge generated the header/body frames and hid their replies; neither
client generated unsupported arguments. Cursor was not rerun under its
separate plan gate. This is rejection of fields outside the advertised tool
schema, not a test of sending arbitrary headers or bodies or proof about
traffic sent through other tools. No packet or syscall trace was taken in
these native-client sessions; the pre-DNS strace probe is separate.

## Native-client response header limits and recovery, 2026-10-28

The opt-in `OUTBOUND_GUARD_CLIENT_HEADER_LIMIT=1` skill replay asks a real
client for an approved GET, then three controlled HTTP responses with 70
extra headers, one 24 KiB header and one 1 MiB header, followed by another
approved GET. Claude Code 2.1.301 and Codex CLI 0.151.0 each completed all
five calls. The three hostile responses returned `EGRESS_INVALID_FRAMING`;
the final GET succeeded. The fixture observed the five requested HTTP hits
in order. The [redacted candidate record](evidence/native-client-header-limits-2026-10-28.json)
binds source, binary and skill hashes to these observations.

```bash
OUTBOUND_GUARD_CLIENT_HEADER_LIMIT=1 python3 tools/client_cancellation_probe.py codex /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Run one authenticated client at a time with the existing development
prerequisites and a checksum-verified candidate. Model usage may incur cost.
Cursor was not rerun under its separate plan gate. These finite header
parser cases do not establish aggregate memory, file descriptor or CPU
limits. No packet or syscall trace was taken in these native-client
sessions, and traffic sent through other tools remains outside this gate.

## Native-client response size limit and recovery, 2026-10-28

The opt-in `OUTBOUND_GUARD_CLIENT_RESPONSE_LIMIT=1` skill replay asks a real
client for an approved GET, two 70,000-byte responses from a controlled
HTTP fixture (fixed length and chunked), then another approved GET. Claude
Code and Codex CLI each completed all four ordered calls. Both large
responses returned `EGRESS_RESPONSE_LIMIT`, and the final GET succeeded.
Cursor CLI produced session updates but issued no MCP call within the
80-second deadline, so its result is inconclusive. The [redacted
exact-candidate record](evidence/native-client-response-limit-2026-10-28.json)
binds source, binary and skill hashes to these observations.
In a follow-up, Cursor returned a native plan-upgrade notice and ended its
turn before any MCP call. The harness now reports that condition promptly;
Cursor coverage remains open until an authenticated turn can run.

Run one authenticated client at a time with the existing development
prerequisites and a checksum-verified candidate:

```bash
OUTBOUND_GUARD_CLIENT_RESPONSE_LIMIT=1 python3 tools/client_cancellation_probe.py codex /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Model usage may incur cost. This covers two response size failures and
subsequent recovery. It does not measure peak memory, descriptor use,
aggregate process resource exhaustion, or traffic sent through other tools.

## Native-client malformed HTTP chunk framing, 2026-10-28

The opt-in `OUTBOUND_GUARD_CLIENT_MALFORMED=1` skill replay asks a real
client for an approved GET and HEAD, then GETs from a controlled HTTP/1.1
fixture with an invalid chunk size and a truncated chunk. Claude Code and
Codex CLI each completed all four ordered calls. Both malformed responses
returned `EGRESS_READ_FAILURE`; only the two control calls returned 200.
Cursor CLI issued no MCP call within the 80-second deadline in two attempts,
so its result is inconclusive. The [redacted exact-candidate record](evidence/native-client-malformed-http-2026-10-28.json)
binds source, binary and skill hashes to these observations.
A later response-limit replay found a Cursor plan gate, but the original
malformed-response attempts did not retain a plan notice; their cause is
therefore still unconfirmed.

Run one authenticated client at a time with the existing development
prerequisites and a checksum-verified candidate:

```bash
OUTBOUND_GUARD_CLIENT_MALFORMED=1 python3 tools/client_cancellation_probe.py codex /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Model usage may incur cost. This probes two malformed HTTP response bodies
through explicit skill turns. It does not cover malformed MCP framing, every
HTTP parser state, or traffic sent through other tools.

## Native-client DNS rebinding between calls, 2026-10-28

The opt-in `OUTBOUND_GUARD_CLIENT_REBIND=1` skill replay asks a real client
for an approved control GET followed by two GETs to the same exact
operator-approved fixture hostname. The controlled resolver returns the
locally served public-policy address for its first A query and loopback for
its second. Claude Code, Codex CLI and Cursor CLI each completed three
ordered calls: two HTTP 200 allows followed by `EGRESS_FORBIDDEN_ADDRESS`.
Each run recorded exactly two A queries for the rebinding name and only two
HTTP fixture hits. The [redacted exact-candidate record](evidence/native-client-rebind-2026-10-28.json)
binds source/artifact identity, client versions and results.

Run one authenticated client at a time with the existing development
prerequisites and a checksum-verified candidate:

```bash
OUTBOUND_GUARD_CLIENT_REBIND=1 python3 tools/client_cancellation_probe.py codex /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Replace `codex` with `claude` or `cursor` for the other clients. Model usage
may incur cost. This tests a changed A answer between separate calls, not an
intra-call resolver race, every A/AAAA combination or all reconnect paths.
The HTTP fixture-hit oracle is not a syscall trace proving no forbidden
socket opened; separate network trace probes cover that narrower claim.
Traffic sent through other tools remains outside Outbound Guard's boundary.

## Native-client synthetic exfiltration attempt, 2026-10-28

The opt-in `OUTBOUND_GUARD_CLIENT_EXFIL=1` skill replay asks each real client
to send a synthetic secret-shaped URL path to an operator-approved controlled
host. The marker is generated by the harness, is not a credential, and is
stored only in the temporary private fixture directory. Claude Code, Codex
CLI and Cursor CLI each completed an explicit four-call skill turn: loopback
denial, approved GET and HEAD, then `EGRESS_SECRET_DETECTED`. The controlled
resolver saw no query for the exfiltration host, HTTP saw only the approved
controls, and the transparent bridge found no marker in outbound MCP frames.
The [redacted exact-candidate record](evidence/native-client-exfil-2026-10-28.json)
includes source/artifact identity, client results and one inconclusive initial
Claude replay whose tool-call count differed from the assertion.
That historical record has four calls; the current command adds the
non-ASCII URL denial described above.

Run one authenticated client at a time with the existing development
prerequisites and a checksum-verified candidate:

```bash
OUTBOUND_GUARD_CLIENT_EXFIL=1 python3 tools/client_cancellation_probe.py codex /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Replace `codex` with `claude` or `cursor` for the other clients. Model usage
may incur cost. This covers one synthetic URL path, not headers, request
bodies, arbitrary secrets, client/provider-side transcripts, audit retention
or traffic sent through other tools. The marker is present in the ephemeral
client prompt. The fixture oracle is not a socket syscall trace; separate
network probes cover that narrower claim.

## Native-client DNS SSRF denials, 2026-10-28

The opt-in `OUTBOUND_GUARD_CLIENT_DNS_SSRF=1` skill replay grants the MCP
server four exact fixture hosts, then asks each real client to call
`guarded_fetch` for an approved control and three hostile DNS names.
`private.test` resolves to loopback, `mixed.test` returns a public-policy
address plus loopback, and `metadata.test` resolves to link-local metadata
space. Claude Code, Codex CLI and Cursor CLI each completed six ordered tool
calls: loopback URL denial, approved GET and HEAD, then three
`EGRESS_FORBIDDEN_ADDRESS` decisions. The controlled resolver observed all
three hostile names; the HTTP fixture saw only the approved control paths.
The [redacted exact-candidate record](evidence/native-client-dns-ssrf-2026-10-28.json)
contains source, artifact and binary hashes, client versions and results.
That record predates the additional CNAME and malformed DNS cases; the
command below now makes eight calls as described above.

Run one authenticated client at a time with the existing development
prerequisites and a checksum-verified candidate:

```bash
OUTBOUND_GUARD_CLIENT_DNS_SSRF=1 python3 tools/client_cancellation_probe.py codex /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Replace `codex` with `claude` or `cursor` for the other clients. Model usage
may incur cost. The fixture-hit oracle is not a syscall trace proving no
forbidden socket opened; separate network tracing probes cover that narrower
claim. These finite answers do not establish rebinding or every resolver
behavior through native clients. Exfiltration, malformed protocol, resource
exhaustion, native UI controls and traffic sent by other tools remain open.

## Native-client redirect and compression traps, 2026-10-28

The opt-in `OUTBOUND_GUARD_CLIENT_TRAPS=1` mode of
`tools/client_cancellation_probe.py` extends its explicit skill workflow with
two controlled hostile responses. After a loopback denial and approved
GET/HEAD controls, each client requests an allowed-host redirect to a private
name and a gzip body that expands from under 16 KiB to 8 MiB. Claude Code,
Codex CLI and Cursor CLI each made exactly five tool calls and received
`EGRESS_REDIRECT_DENIED` and `EGRESS_ENCODED_RESPONSE` for those traps. The
fixture observed the four expected allowed-host paths and no redirect-target
HTTP hit. The [machine-readable three-client record](evidence/native-client-traps-2026-10-28.json)
binds the installed executable, skill ZIP, client versions and exact results.

Run one authenticated client at a time with the already installed development
prerequisites and a checksum-verified candidate:

```bash
OUTBOUND_GUARD_CLIENT_TRAPS=1 python3 tools/client_cancellation_probe.py codex /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

Replace `codex` with `claude` or `cursor` for the other clients. This uses the
client account and may incur model usage.

This tests policy decisions through live clients, with only the MCP child in
a disposable route-free namespace. The fixture hit list is not a syscall or
packet trace proving no forbidden socket opened; existing network trace
probes address that separately. Compression is rejected, so no decompression
or peak-memory measurement occurs. Separate sections record later native-client
DNS rebinding, synthetic URL exfiltration, malformed protocol, and bounded
resource probes; those finite cases do not close their broader release gates.
The Debian installer is unsigned, with signed build provenance.

## Trusted-main Debian candidate replay, 2026-10-28

The independently rebuilt main candidate from source `8b76b439ca53`, with
signed GitHub build provenance, was extracted from the checksum-verified
archive and exercised through the
existing authenticated Claude Code 2.1.301, Codex CLI 0.151.0 and Cursor CLI
2026.10.19-6bbf2c4 clients. The executable SHA-256 is
`7bfe987a8b7a126488c3b17d4ec12ce57a5072f1a5ad6735f7ce62e1c8527407`.
Each client completed an explicit native skill path with a loopback denial and
controlled GET/HEAD successes. Each then completed a separate live-client
control-path replay and a successful recovery GET, loopback denial and HEAD.
The [redacted six-run record](evidence/native-client-replay-2026-10-28.json)
binds source, artifact, skill ZIP, executable, client versions and outcomes.

Claude delivered one matching MCP cancellation and the peer closed in 0.061s
without a cancelled tool reply. Codex and Cursor acknowledged their respective
turn controls but did not send MCP cancellation; their sockets closed after
the server's roughly three-second response deadline, with a bounded denial
reply. All three clients remained live. These observations cover explicit
skill and control API paths, not desktop/terminal Stop controls, native queue
saturation, automatic skill triggering, or traffic sent by other tools. The
broader hostile DNS/HTTP and release gates remain open. The Debian installer
itself is unsigned.

## Scope and results, 2026-10-21

The optimized Linux x86_64 GNU archive candidate `ec96881e4ca9` has binary SHA-256 `93882fb0e55073efda897e7d3f020d6ebe2c4cb62009a70be72e622008ec9b19`. A transparent stdio bridge recorded only MCP method/ID/rule metadata. The real clients used their existing authenticated model services on the host; only the MCP child ran in a disposable route-free network namespace with controlled DNS/HTTP. No VM, public attack target, or runtime dependency was added. Later source changes and candidate replays are recorded below and above this historical section.

| Client/version | Control tested | Matching MCP cancellation | Observed outcome |
| --- | --- | --- | --- |
| Claude Code 2.1.301 | Headless stream-JSON `interrupt` control request | Yes | Acknowledged interrupt, no cancelled-fetch reply, peer socket closed in about 1.01s while client remained live; subsequent guarded GET returned HTTP 200. |
| Codex CLI 0.151.0 | App-server `turn/interrupt` | No | The completed replay observed the fetch end via `EGRESS_RESPONSE_TOO_SLOW` at about 3.02s; recovery GET returned HTTP 200. Additional replays hit upstream HTTP 429 (one during recovery, another before the fixture started) and are inconclusive, not passing replays. |
| Cursor CLI 2026.10.19-6bbf2c4 | ACP `session/cancel` | No | Client reported a cancelled turn, but the fetch ended via `EGRESS_RESPONSE_TOO_SLOW` at about 3.01s; recovery GET, loopback denial and approved HEAD then passed. |

The socket timings are fixture-specific samples, not latency guarantees. For Codex and Cursor, a cancelled *agent turn* did not imply an MCP cancellation notification in these tested paths. The server continued its bounded request until its own policy ended it. This observation does not prove how every UI, other client version, transport or interrupt timing behaves. Desktop Stop buttons, terminal Escape keys, other DNS/TLS phases and saturated client-controlled queues remain separate tests. Do not claim prompt socket cancellation for these unverified paths.

Cursor was installed using the official HTTPS installer and the user completed browser login. The authenticated ACP client discovered the real MCP server. Its actual calls produced `EGRESS_INVALID_HOST` for loopback, and `EGRESS_ALLOWED` with HTTP 200 for controlled GET and HEAD. Private temporary MCP configuration and wire logs were removed after completed probes. Cursor may retain its own normal client history/settings; authentication remains installed for the user's other MCP chats.

The redacted [machine-readable record](evidence/client-cancellation-2026-10-21.json) distinguishes completed observations from inconclusive provider failures. No credentials or account identifiers are included.

## Reproduce an authenticated control-path observation

These optional **development** probes require Linux network namespaces, the source checkout, passwordless `sudo` for disposable network setup, an installed client, and existing normal client authentication. Model inference uses the client's account and may incur usage/cost. This is not a server-install or companion-skill requirement. No `sudo` is required for ordinary production stdio operation.

```bash
python3 tools/client_cancellation_probe.py claude /absolute/path/to/installed/outbound-guard-mcp
python3 tools/client_cancellation_probe.py codex /absolute/path/to/installed/outbound-guard-mcp
python3 tools/client_cancellation_probe.py cursor /absolute/path/to/installed/outbound-guard-mcp
```

Run one account-backed probe at a time when inference is throttled. The harness only approves the fixture's guarded-fetch permission, rejects other requested tool permissions, and uses an empty private workspace. It acknowledges the client's interrupt, observes the actual MCP wire behavior, checks peer closure while the client remains live, and attempts a recovery call. Cursor additionally exercises loopback denial and HEAD. A report with `matching_wire_cancellation: false` is an observed client limitation, **not a passing prompt-cancellation acceptance gate**. Provider errors must be recorded as inconclusive; do not equate them with a network guard defect. The harness removes its temporary namespace and private client/wire logs. Cleanup signals only PIDs belonging to that exact network namespace, never a host-wide process-name match.

## Historical queue saturation review (before the priority fix)

`test_saturated_cancellation` in the normal controlled network suite runs both protocol eras with one live fetch and nine ordinary requests, each carrying 60,000 padding bytes. Eight frames fill the channel; the ninth is reader-held, so a cancellation behind it cannot yet reach the control handler. In this fixture the fetch ends by its own slow-response rule. The test requires all nine queued replies, one correct audit decision, socket closure and a successful subsequent fetch; it checks sampled RSS below 64 MiB and descriptors below 64.

Debug samples were 8,792 KiB (legacy), 8,948 KiB (modern), and seven descriptors. These are finite sampled observations, **not proven upper bounds or OS process quotas**. Input frame bounds and queue capacity bound retained input, but saturation still delays control processing. The existing ten-second HTTP deadline and other phase/stream controls remain relevant even when clients omit cancellation. No claim is made that all queued work or process-wide memory/CPU has an aggregate deadline.

A separate Request Guard chat reviewed the new saturation test without edits/builds/VMs and found no actionable issue in this bounded interpretation. It specifically required that measured RSS/FD figures remain labeled samples. Strict control priority at queue saturation and client UI cancellation remain open in issue #65; this milestone adds evidence without silently waiving them.

## References

- [MCP stdio cancellation](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio)
- [Codex app-server interruption](https://developers.openai.com/codex/app-server)
- [Cursor ACP control and MCP support](https://prod.cursor.com/docs/cli/acp)
- [Claude Agent SDK interrupt example](https://github.com/anthropics/claude-agent-sdk-python/blob/main/examples/streaming_mode.py)

The [current priority admission implementation](cancellation-priority.md) replaces the historical saturation behavior above. The dated client-control observations and JSON records remain historical evidence; they do not automatically certify a later release candidate or its client UI behavior.

## Fresh CI archive replay — 2026-10-22

All three authenticated control probes were rerun sequentially against a fresh extraction of the signed CI archive for source `5c937811120a865564240b693f8bf558fd909ab3`. The archive and skill ZIP passed their checksum manifest; executable SHA-256 was `6549e77a5b450c630a3909f43d9bdf2521f820ec599ad9528c5df8e74d9e8388`. See the [redacted replay record](evidence/client-cancellation-2026-10-22.json) for archive/skill hashes and CI/provenance links.

| Client/version | Wire cancellation | Sample socket closure after interrupt | Recovery |
| --- | --- | --- | --- |
| Claude Code 2.1.301 stream-JSON interrupt | Matching notification; cancelled reply suppressed | 0.061s | Guarded GET HTTP200 |
| Codex CLI0.151.0 app-server turn/interrupt | No notification; tool returned its own slow-response denial | 3.019s | Guarded GET HTTP200 |
| Cursor CLI2026.10.19-6bbf2c4 ACP session/cancel | No notification; tool returned its own slow-response denial | 3.015s | Guarded GET HTTP200; loopback denied; HEAD HTTP200 |

Each client acknowledged its control interrupt and remained live. These are single fixture-specific timing samples. The server's new cancellation handling does not make Codex or Cursor deliver notifications in those tested paths; their prompt-cancellation acceptance remains unmet. The fresh extraction and temporary MCP configuration exercise an installed archive, while normal existing account authentication is reused. Desktop/terminal controls, saturated client queues and all network phases remain untested by this client replay. Historical records above remain dated evidence; no later artifact or production-readiness approval is implied.

## TLS-patched installed archive replay — 2026-10-22

After the WebPKI/root advisory correction, all three control probes were rerun sequentially against a fresh extraction of source `174a2d0d3ba9393f6ffa35aa9e2db15330093509`'s signed CI archive. Its executable hash is `ca4912a67ab4e1c3509508fc7e9ac46824715e742d153f166431f74019770046`. The archive/skill checksum manifest passed, installed inventory identifies `rustls-webpki`0.103.16 and `webpki-roots`1.0.10, and the skill ZIP contains exactly the top-level skill's SKILL.md and GPL license with required frontmatter. The [redacted patched-candidate record](evidence/client-cancellation-2026-10-22-tls-patched.json) retains exact hashes and client results.

Claude Code2.1.301 emitted matching cancellation, suppressed the cancelled reply and closed its socket in0.061s; recovery GET returned200. Codex CLI0.151.0 still omitted cancellation and reached the guard's slow-response denial in3.014s, then recovered with GET200. Cursor CLI2026.10.19-6bbf2c4 likewise omitted cancellation and ended in3.015s; recovery GET200, loopback denial and HEAD200 passed. All acknowledged the client control interrupt and remained live; no provider failures occurred in these completed replays.

These are single control-path samples, not latency guarantees or desktop/terminal control coverage. Only Cursor ran the extra denial/HEAD sequence here. Existing authentication was reused, while MCP configuration and extraction were fresh. The historical pre-patch records above do not establish the patched binary's behavior; conversely, this replay does not waive remaining client/UI, implementation or human review gates. Older archives with the disclosed affected dependencies should be rebuilt, not selected merely because their historical tests passed.


## Replay after the framing harness candidate

The [2026-10-22 installed-candidate replay](evidence/client-cancellation-2026-10-22-frame-candidate.json) uses source23b9cdc6c350, binary SHA256 `9c12b359928f78f2f855e8c3cd4ae5137c40060e03155af34d30e6e28f73e8d1`, and a fresh checksum-verified CI archive extraction. The clean skill ZIP contains only SKILL.md and LICENSE; native skill activation was not tested. All three clients now ran recovery GET, loopback denial and HEAD200 controls through the same live client after interrupt acknowledgment.

Claude Code2.1.301 sent matching MCP cancellation, closed the fixture socket in0.061s and suppressed the cancelled reply. Codex CLI0.151.0 and Cursor CLI2026.10.19-6bbf2c4 acknowledged their control interrupts but sent no MCP cancellation; their calls ended with `EGRESS_RESPONSE_TOO_SLOW` in3.012s and2.994s respectively. Both then passed all three recovery/denial/HEAD controls. These remain missing client-cancellation delivery observations, not passing prompt-cancellation gates or server failures to honor a delivered notification.

The probe waits for Codex's recovery turn to complete and Cursor's prompt result before sending their next control sequence, then requires exact four-fetch/two-HTTP200 outcomes for every client. Only redacted metadata is retained; private configs/transcripts and owned namespaces are cleaned up. These are finite control-API samples, not desktop/terminal UI coverage, saturated queues, all network phases or stable-release approval. Older candidate results are not automatically transferred to this binary.

## RPC-fuzz candidate replay, 2026-10-23

The separately installed signed candidate from source `96ef82ca08f1` was replayed after its executable identity changed. [Exact package/binary/skill/client evidence](evidence/native-client-replay-2026-10-23.json) records the six successful probe runs and limitations. Claude Code2.1.301 delivered one matching MCP cancellation, suppressed the cancelled reply and closed the peer in0.061seconds. Codex CLI0.151.0 and Cursor2026.10.19-6bbf2c4 acknowledged their app-server/ACP turn controls but sent no MCP cancellation; each slow response closed under the server's own deadline in about3.02seconds and its denial reply remained present. These are not passing prompt-cancellation delivery cases. Each client remained live and completed recovery GET200, loopback denial and HEAD200.

Each also completed its explicit clean-ZIP skill workflow against this executable: Claude's native Skill invocation succeeded, Codex discovered the enabled installed skill and completed an explicit skill-input turn, and Cursor completed a native read of the installed project skill. All three then made the expected denial/GET/HEAD calls. These distinct observations establish the exercised explicit loading paths, not automatic triggering, adherence to every instruction or equivalent Skill-tool acknowledgments across clients.

The existing opt-in helper, controlled route-free DNS/HTTP fixtures and normal client authentication were reused. Only one client ran at a time. The archive/extracted binary hashes matched the exact CI-verified signed candidate; this records checksum binding to that evidence, not a separate local cryptographic attestation-verifier run. The ZIP still contains only top-level `outbound-guard/SKILL.md` and LICENSE. Private workspaces and owned fixture namespaces/processes were removed. Client authentication/configuration, skills and server runtime were unchanged. Desktop/terminal controls, native saturated queues and other release gates remain unproven.

## Native TLS certificate-failure and rebinding replay — 2026-10-30

Claude Code 2.1.301 and Codex CLI 0.151.0 each loaded the clean two-file skill ZIP in a fresh temporary project and made three explicit `guarded_fetch` calls through the current debug executable: HTTPS to `tls-handshake.test` twice, then HTTP to `allowed.test`. The controlled CA signed a wrong-host certificate at the first pinned public address and a matching certificate at the second. Both clients observed `EGRESS_NETWORK_FAILURE`, then `EGRESS_FORBIDDEN_ADDRESS` after the next DNS answer became private, then `EGRESS_ALLOWED` for recovery. The fixture recorded exactly two A queries, SNI only at the first address, and one HTTP hit for recovery. Denials contained no body. The [redacted replay record](evidence/native-client-tls-handshake-2026-10-30.json) binds the executable, skill ZIP, harness and fixture hashes.

This is an explicit native skill workflow for those two client versions using a route-free Linux namespace. It does not prove automatic skill triggering, UI cancellation, every TLS alert, all clients or traffic sent through other tools. Cursor was not replayed in this slice; its later native workflows remain blocked by the recorded plan gate. The executable is a local debug build from the stated source, not an installed candidate package or owner-approved release.

## Exact archive native TLS replay — 2026-10-30

The same Claude Code and Codex CLI workflows were repeated with the executable and two-file skill ZIP extracted from trusted-main CI run `41052316927` for source `9a4731e9f448`. The downloaded artifact's `SHA256SUMS` validated the archive, ZIP and Debian package; the extracted executable matched the CI independent-rebuild comparison. Both clients again produced `EGRESS_NETWORK_FAILURE`, `EGRESS_FORBIDDEN_ADDRESS`, then `EGRESS_ALLOWED`. The route-free fixture recorded SNI only at the wrong-host first pinned address, exactly two A queries and only the approved recovery HTTP hit. [The exact-archive record](evidence/native-client-tls-handshake-archive-2026-10-30.json) retains artifact and executable hashes, client versions, results and limits.

This verifies a freshly extracted optimized archive and skill, not installation or upgrade of the Debian package. The CI package gate separately tests disposable Debian installation, launch and removal; these native client calls do not substitute for that gate or an exact-candidate owner decision. Cursor, UI cancellation, automatic triggering and other tools' traffic remain outside this replay.

## Active ambient-proxy trap with native clients — 2026-10-30

Claude Code 2.1.301 and Codex CLI 0.151.0 repeated that three-call TLS/DNS/recovery workflow with the same checksum-verified archive and skill. The MCP server's environment contained live `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` values, including lowercase variants, all pointing to mitmdump 8.1.1 inside the disposable route-free namespace. A separate curl positive control first reached the same HTTP fixture through mitmdump and produced one recorded proxy flow. The native guarded calls then produced the expected certificate denial, private-address denial and approved recovery without adding a proxy flow. The only proxy record remained the positive control; the fixture recorded first-address-only TLS SNI, two A queries and the approved recovery hit. See the [redacted active-proxy record](evidence/native-client-active-proxy-2026-10-30.json).

This directly observes one active ambient proxy trap with two native clients and an instrumented positive control. It does not prove every proxy scheme/configuration, arbitrary exfiltration resistance, desktop/terminal controls or traffic sent through other tools. The mitmdump addon records only method, hostname and path; the generated namespace and temporary proxy profile are removed after each run. The executable remains archive-extracted, not installed from the Debian package.

## Synthetic exfiltration with an active proxy — 2026-10-30

The same checksum-verified archive binary and skill were replayed with `OUTBOUND_GUARD_CLIENT_EXFIL=1 OUTBOUND_GUARD_CLIENT_ACTIVE_PROXY=1`. Each native Claude Code 2.1.301 and Codex CLI 0.151.0 skill session made five guarded calls: loopback denial, approved GET and HEAD, a synthetic secret-shaped path on an approved test host, and a non-ASCII lookalike path. The last two returned `EGRESS_SECRET_DETECTED` and `EGRESS_INVALID_URL`; no DNS query reached the exfiltration host and no synthetic marker appeared in outbound MCP results. A curl positive control generated one mitmdump flow before the client calls; neither client added a flow. The HTTP fixture saw only the positive control and two approved calls. [Exact replay evidence](evidence/native-client-active-proxy-exfil-2026-10-30.json) records hashes, outcomes and limits.

This tests two synthetic URL shapes, one live local HTTP proxy and two explicit native skill workflows. It does not certify arbitrary secret detection, proxy configurations, automatic skill triggering, traffic through other tools or a Debian package installation.
