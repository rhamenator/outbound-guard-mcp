# Cancellation priority and bounded admission

Status: experimental implementation and regression evidence; not release approval.

## Policy

The stdio reader applies valid cancellation notifications before ordinary admission. Eight ordinary input frames may queue. Instead of blocking when that queue is full, the reader removes the rejected request's pending-cancellation registration and queues a small correlated JSON-RPC error:

```json
{"jsonrpc":"2.0","id":"request-id","error":{"code":-32000,"message":"Server input capacity reached","data":{"rule":"MCP_INPUT_BUSY","remediation":"Wait for outstanding replies, then retry this request. This request was not executed."}}}
```

No tool/policy execution, DNS, socket, rate reservation or audit entry is performed for that rejected request. The request ID is preserved; no arguments, URL, credentials, client identity or cancellation reason are reflected. Clients must correlate responses by ID, since busy errors may overtake queued responses. Wait for outstanding replies before retrying and never bypass a denial through another tool.

Busy replies have their own eight-entry bound and are flushed by the existing single writer, retaining its three-second deadline. If that queue fills, or overflow input cannot be safely correlated (malformed frame or notification), the reader publishes a fixed input-overload error and cancels all admitted fetches. The dispatcher exits rather than processing more queued work. This is intentional overload disconnection, not a promise to deliver a reply for every request after transport failure. Reconnect and retry only work known not to have executed; previously admitted requests may have consumed budgets or produced audit events.

EOF alone may wait for queue space because no later control bytes exist; admitted work and pending busy replies drain before graceful shutdown. Other ordinary sends never wait on input queue capacity. Retained input, busy responses and registered IDs stay bounded; this does not establish process-wide CPU/RSS quotas. At most ten tool IDs can be transiently registered (executing, eight queued and the current admission attempt); rejected IDs are removed before busy admission.

## Regression evidence

The controlled HTTP/DNS suite runs the following in both modern and legacy modes:

- A live drip fetch, eight ordinary requests with 60,000-byte padding, one excess fetch, then cancellation. The eight admitted list replies and one correlated busy reply arrive; no cancelled-fetch reply appears. Audit contains only `EGRESS_CANCELLED`; the rejected marker never appears in results. A late cancellation for the rejected ID cannot poison its successful subsequent reuse. Peer socket closes while the process remains live.
- Flooding beyond both bounded queues during a live fetch terminates with fixed `Input overload limit exceeded` diagnostic and closes that socket. Sensitive request IDs are not echoed on stderr.
- Existing raw/SDK typed cancellation, redacted audit, ordinary interleaving, resource limits, slow/oversized input, and blocked/closed stdout tests remain.

Normal non-overload corpora use `tools/stdio_exchange.py` to pace actual requests/responses, preserving every existing case and asserting the same results without retries, hidden busy handling or suppression of errors. Its own tests cover notifications, a final frame delimited by EOF, and killing an unresponsive child at the deadline. Dedicated concurrent admission/overload probes remain unpaced. This separates ordinary conformance testing from deliberate overload testing rather than relying on scheduler-dependent acceptance of arbitrarily large bursts.

## Remaining boundaries

Cancellation cannot be processed until its bytes arrive as a complete frame. Frame size/time limits still apply; a partial frame ahead of cancellation cannot be bypassed safely. Network cancellation remains cooperative, and spent reservations remain counted. Clients that stop their agent turn without sending MCP cancellation are unchanged by this server fix. The dated Codex/Cursor control-path limitations and untested desktop/terminal UI behavior remain open, as do independent review and the other release gates in issue #65. Traffic through other tools is outside this server's enforcement boundary.
