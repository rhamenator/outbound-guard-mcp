# Optional Linux process limits and recovery

The server's queues, timers and byte limits apply per process. Operators running several MCP instances should place them under an aggregate OS resource boundary. This optional recipe requires Linux cgroup v2, a working user systemd manager, Python3 for the probe, and delegated memory/CPU/PID controllers. It needs no root access and changes no host firewall or other services. It is not a portable server requirement or a passing OOM test.

From a source checkout after building the server:

```sh
python3 tools/systemd_deployment_probe.py target/debug/outbound-guard-mcp
```

The probe creates one uniquely named transient user service using `systemd-run --user --pipe --wait --collect`. Only that service's Python supervisor and server children receive aggregate `MemoryMax=64M`, `TasksMax=16`, `CPUQuota=50%`, and inherited hard/soft `LimitNOFILE=64`. It checks the actual cgroup files and both servers' membership/descriptor limits, exercises MCP ping and a pre-network denial, kills exactly one owned server, verifies the sibling still responds, then starts a replacement with an empty audit log. Cleanup kills owned children on failure; systemd collects the transient unit. No public target is contacted.

A local run on Linux 7.0.0-38-generic with systemd 259.5 passed on 2026-10-22: `memory.max=67108864`, `pids.max=16`, `cpu.max=50000 100000`. This proves configuration and the exercised manual process-replacement path. It does not prove behavior at memory/PID exhaustion, CPU saturation, or during an active network call. The ordinary hosted CI runner does not supply this user-manager environment; this remains a separately run deployment test, not an implied CI result. The 64 MiB figure covers the probe supervisor and two idle/denied server instances, not every workload; size limits for your actual installation before relying on them.

For one independently installed stdio server, an operator can adapt this command in their MCP client's process configuration:

```sh
systemd-run --user --quiet --wait --pipe --collect \
  --property=MemoryMax=64M --property=TasksMax=16 \
  --property=CPUQuota=50% --property=LimitNOFILE=64 \
  --setenv=OUTBOUND_GUARD_ALLOWED_HOSTS=api.example.com \
  /absolute/path/to/outbound-guard-mcp
```

Replace the binary path and approved host. Each invocation creates a separate group; sharing aggregate quotas across multiple client invocations requires an operator-managed common slice. This example does not install such a slice, authenticate a client, or add a network firewall. A lower CPU quota can delay cooperative timeout observation. Hitting a hard OS limit may terminate the process before it returns structured JSON. Require clients to treat disconnects as failures; never retry through an unguarded tool.

After process failure, close the failed MCP session and launch a replacement through the same limits and host configuration, then repeat discovery and a known denial/allow control. Do not configure automatic replay of tool calls: a failed response does not establish whether a remote operation occurred. Audit history, rate budgets and correlation IDs are process-local and reset on restart; there is no shared cross-process rate governor or durable audit. External supervision/logging and a shared egress governor are required if those are deployment requirements. A restart can replace a permanently stuck native DNS worker, but this probe does not induce that failure or certify a resolver recovery policy.
