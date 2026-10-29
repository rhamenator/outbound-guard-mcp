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


## Deliberate memory exhaustion control

An additional optional host test exercises actual cgroup OOM behavior:

```sh
python3 tools/systemd_memory_pressure_probe.py target/debug/outbound-guard-mcp
```

The outer supervisor creates one randomly named transient user service with aggregate 64 MiB memory, zero swap, 16 tasks, 50% CPU and 64 descriptors per process. `OOMPolicy=kill` must set `memory.oom.group=1`. Inside that group, a live server first answers modern MCP ping. A Python helper then touches at most 128 MiB in one-MiB chunks. The outer supervisor, which remains outside that group, requires systemd's `Result=oom-kill`, failed state, and no remaining group processes. It stops/resets only its exact owned unit on success, failure or timeout. Finally it runs the ordinary deployment probe in a fresh limited group to demonstrate MCP service after this failure.

On 2026-10-22, Linux 7.0.0-38-generic/systemd 259.5 produced the required OOM result and fresh-group recovery. This is deliberate helper-induced aggregate exhaustion, not an exploit that makes the server allocate unbounded memory. The result is process termination/disconnect, **not a structured MCP error**. It does not establish active-request completion, automatic recovery, durable state, every OOM victim-selection policy, PID exhaustion or CPU-saturation behavior. The hard no-swap 64 MiB limit applies only to that test group; no host memory limit or global OOM policy is changed. This test is separate from hosted CI and requires the same user-manager/controller permissions as the first probe.

## Deliberate task exhaustion control

```sh
python3 tools/systemd_task_pressure_probe.py /absolute/path/to/outbound-guard-mcp
```

This opt-in Linux test requires the same user systemd manager and delegated cgroup-v2 controllers as the probes above; it uses only Python's standard library and needs no root access. Its uniquely named unit has `MemoryMax=64M`, `MemorySwapMax=0`, `TasksMax=16`, `CPUQuota=50%` and `LimitNOFILE=64`. After a real server answers modern MCP ping, a helper creates at most 16 sleeping threads. The probe requires thread creation to fail, `pids.current` to equal 16 and the kernel's `pids.events` max counter to increase. It then attempts exactly one additional server process and requires `EAGAIN`. No fork bomb, public target or host-wide resource setting is involved.

While the group is saturated, the existing server must still answer ping and return `EGRESS_INVALID_HOST` for a loopback fetch before DNS. An allowlisted request to `pressure.invalid` must fail closed with `EGRESS_DNS_FAILURE` when the kernel refuses the resolver worker; the task count must stay at its ceiling and the server must still answer ping. The test does not resolve that name or open an HTTP socket. Releasing and joining the helper threads must reduce the group's task count, after which a new server must answer ping and the original must remain responsive. All owned children are killed/reaped on success or failure; the outer supervisor stops/resets only its randomly named unit, with a 20-second overall deadline.

The [2026-10-23 local evidence](evidence/cgroup-task-exhaustion-2026-10-23.json) records 12 sleeping helper threads, task count 16 at saturation and 4 after release, two kernel max-counter events, `EAGAIN`, both MCP controls and manual replacement. The initial harness run used the wrong JSON field name for the denial assertion; the corrected run passed. The [2026-10-29 resolver-worker extension](evidence/cgroup-dns-worker-ceiling-2026-10-29.json) found that a thread-creation `WouldBlock` was misreported as `EGRESS_DNS_BUSY`, whose remediation incorrectly said a prior lookup was running. The server now maps worker-creation failure to `EGRESS_DNS_FAILURE`, retains `EGRESS_DNS_BUSY` for an occupied gate, and answers a following ping at the task ceiling. This is helper-induced task exhaustion before lookup, not an active HTTP/DNS exchange. It proves neither CPU-saturation behavior, automatic recovery, new-worker success after release, nor response guarantees for every possible resource failure. It remains a separate host deployment test; hosted CI does not provide this user-manager environment.

## Deliberate CPU saturation control

```sh
python3 tools/systemd_cpu_pressure_probe.py /absolute/path/to/outbound-guard-mcp
```

This additional optional Linux/user-systemd probe starts a real server and one bounded Python CPU helper in the same unique cgroup. It verifies membership and reads back `cpu.max` at 50% of one CPU, alongside the same 64 MiB/no-swap, 16-task and 64-descriptor limits. The helper spins for at most four wall-clock seconds. After observing an actual kernel throttling event, the supervisor issues ten modern MCP pings and ten loopback fetches that must return `EGRESS_INVALID_HOST` before DNS. It paces these controls across quota periods and requires at least five additional `nr_throttled` events and increased `throttled_usec`, with a three-second deadline for each response. After the helper exits, another ping must succeed. The outer 20-second deadline and exact-unit cleanup bound failure cases. No VM, root permission, public network target or host-wide CPU setting is needed.

The [2026-10-23 local evidence](evidence/cgroup-cpu-pressure-2026-10-23.json) records 11 throttled periods and 557612 throttled microseconds over the measured controls, with all twenty controls and post-pressure ping passing. The recorded maximum reply time is a finite observation, **not a latency SLA**. The first trial finished its controls within one throttled period; the final probe deliberately spreads them out and requires multiple kernel throttling events. This tests helper-induced CPU pressure and continued pre-network MCP service. It does not certify active HTTP/DNS deadline accuracy under CPU pressure, combined memory/task/CPU exhaustion, automatic recovery or all scheduler configurations. Hosted CI does not run this user-manager test. Owned helper/server processes are killed and reaped on failure, and only the uniquely named transient unit is stopped/reset.

## Aggregate oversized-frame control

```sh
python3 tools/systemd_aggregate_frame_probe.py /absolute/path/to/outbound-guard-mcp
```

This optional local probe runs two server processes in one uniquely named user cgroup with 64 MiB memory, no swap, 16 tasks, 50% CPU quota and 64 descriptors per process. It concurrently sends each server an 8 MiB newline-terminated stdio frame, then a valid ping. Each process must reject the oversized frame and answer its following ping. The probe checks cgroup membership, `memory.peak`, and unchanged `oom`/`oom_kill` counters. It kills and reaps its children and stops/resets only its owned transient unit on exit. The outer deadline is 25 seconds.

The [2026-10-28 local evidence](evidence/cgroup-aggregate-frame-2026-10-28.json) records both rejection/recovery sequences under the shared limit, an 11,259,904-byte peak and no OOM events on Linux 7.0.0-38-generic/systemd 259. This is a finite stdio framing and process-memory observation. It does not test active HTTP/DNS, native clients, sustained load or aggregate CPU/kernel memory. Hosted CI lacks this user-manager setup, so the probe is separate from CI.
