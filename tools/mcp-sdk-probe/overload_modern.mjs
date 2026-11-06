// Development-only official SDK client: send the overload frames itself.
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

const input = createInterface({ input: process.stdin });
const hourlyHosts = Array.from({ length: 12 }, (_, index) => `hour-failure-${index + 1}.test`);
const client = new Client({ name: 'outbound-guard-overload-probe', version: '1' },
  { versionNegotiation: { mode: { pin: '2026-07-28' } } });
const transport = new StdioClientTransport({ command: process.argv[2],
  env: { ...process.env, OUTBOUND_GUARD_ALLOWED_HOSTS:
    ['allowed.test', 'budget-failure.test', 'audit-failure-1.test',
      'audit-failure-2.test', 'audit-failure-3.test', ...hourlyHosts,
      'hour-denied.test'].join(',') }, stderr: 'pipe' });
let stderr = '';
transport.stderr?.on('data', chunk => { stderr += chunk.toString(); });
try {
  await client.connect(transport);
  assert.equal(client.getNegotiatedProtocolVersion(), '2026-07-28');
  const cycles = 12;
  for (let cycle = 0; cycle < cycles; cycle++) {
    const controller = new AbortController();
    const held = client.callTool({ name: 'guarded_fetch', arguments: {
      url: 'http://allowed.test/cancel-drip',
    } }, { signal: controller.signal, timeout: 15000 }).then(
      () => { throw new Error('cancelled fetch unexpectedly resolved'); },
      error => { assert.ok(controller.signal.aborted && error); },
    );
    console.log('FETCH_STARTED');
    assert.equal((await once(input, 'line'))[0], 'flood');
    const padding = 'x'.repeat(60000);
    const queued = Array.from({ length: 8 }, () => client.request({
      method: 'tools/list', params: { padding },
    }).then(value => ({ ok: true, value }), error => ({ ok: false, error })));
    const busy = client.request({ method: 'tools/call', params: {
      name: 'guarded_fetch', padding, arguments: {
        url: 'http://allowed.test/SYNTHETIC_BUSY_MARKER',
      },
    } }).then(value => ({ ok: true, value }), error => ({ ok: false, error }));
    controller.abort(new Error('synthetic-sdk-overload-abort'));
    const results = await Promise.all(queued);
    const denied = await busy;
    await held;
    assert.ok(results.every(result => result.ok && result.value.tools?.length > 0), results);
    assert.equal(denied.ok, false, denied);
    assert.equal(denied.error.code, -32000);
    assert.equal(denied.error.data?.rule, 'MCP_INPUT_BUSY');
    const audit = await client.readResource({ uri: 'outbound-guard://logs/audit.json' });
    assert.deepEqual(JSON.parse(audit.contents[0].text).events.map(event => event.rule),
      Array.from({ length: cycle }, () => ['EGRESS_CANCELLED', 'EGRESS_ALLOWED'])
        .flat().concat('EGRESS_CANCELLED'));
    const recovery = await client.callTool({ name: 'guarded_fetch', arguments: {
      url: 'http://allowed.test/plain',
    } });
    assert.equal(recovery.structuredContent.rule, 'EGRESS_ALLOWED');
    assert.equal(recovery.structuredContent.body_text, 'fixture-ok');
    console.log('SDK_OVERLOAD_RECOVERED');
    if (cycle + 1 < cycles) {
      assert.equal((await once(input, 'line'))[0], 'continue');
    }
  }
  const finalAudit = await client.readResource({ uri: 'outbound-guard://logs/audit.json' });
  assert.deepEqual(JSON.parse(finalAudit.contents[0].text).events.map(event => event.rule),
    Array.from({ length: cycles }, () => ['EGRESS_CANCELLED', 'EGRESS_ALLOWED']).flat());
  console.log('SDK_OVERLOAD_AUDIT_DONE');
  assert.equal((await once(input, 'line'))[0], 'budget');
  for (let call = 0; call < 36; call++) {
    const result = await client.callTool({ name: 'guarded_fetch', arguments: {
      url: 'http://allowed.test/plain',
    } });
    assert.equal(result.structuredContent.rule, 'EGRESS_ALLOWED');
    assert.equal(result.structuredContent.body_text, 'fixture-ok');
  }
  console.log('SDK_BUDGET_FILLED');
  assert.equal((await once(input, 'line'))[0], 'deny');
  const denied = await client.callTool({ name: 'guarded_fetch', arguments: {
    url: 'http://allowed.test/SYNTHETIC_RATE_MARKER',
  } });
  assert.equal(denied.isError, true);
  assert.equal(denied.structuredContent.rule, 'EGRESS_RATE_LIMIT');
  assert.equal('body_text' in denied.structuredContent, false);
  const budgetAudit = await client.readResource({ uri: 'outbound-guard://logs/audit.json' });
  assert.deepEqual(JSON.parse(budgetAudit.contents[0].text).events.map(event => event.rule),
    Array.from({ length: cycles }, () => ['EGRESS_CANCELLED', 'EGRESS_ALLOWED'])
      .flat().concat(Array(36).fill('EGRESS_ALLOWED'), 'EGRESS_RATE_LIMIT'));
  assert.ok((await client.listTools()).tools.length > 0);
  console.log('SDK_RATE_BUDGET_DENIED');
  assert.equal((await once(input, 'line'))[0], 'dnsbudget');
  for (let call = 0; call < 60; call++) {
    const result = await client.callTool({ name: 'guarded_fetch', arguments: {
      url: 'http://budget-failure.test/plain',
    } });
    assert.equal(result.isError, true);
    assert.equal(result.structuredContent.rule, 'EGRESS_DNS_FAILURE');
    assert.equal('body_text' in result.structuredContent, false);
  }
  console.log('SDK_DNS_BUDGET_FILLED');
  assert.equal((await once(input, 'line'))[0], 'dnsdeny');
  const dnsDenied = await client.callTool({ name: 'guarded_fetch', arguments: {
    url: 'http://budget-failure.test/SYNTHETIC_DNS_BUDGET_MARKER',
  } });
  assert.equal(dnsDenied.isError, true);
  assert.equal(dnsDenied.structuredContent.rule, 'EGRESS_RATE_LIMIT');
  assert.equal('body_text' in dnsDenied.structuredContent, false);
  const dnsAudit = await client.readResource({ uri: 'outbound-guard://logs/audit.json' });
  assert.deepEqual(JSON.parse(dnsAudit.contents[0].text).events.map(event => event.rule),
    Array.from({ length: cycles }, () => ['EGRESS_CANCELLED', 'EGRESS_ALLOWED'])
      .flat().concat(Array(36).fill('EGRESS_ALLOWED'), 'EGRESS_RATE_LIMIT',
        Array(60).fill('EGRESS_DNS_FAILURE'), 'EGRESS_RATE_LIMIT'));
  assert.ok((await client.listTools()).tools.length > 0);
  console.log('SDK_DNS_RATE_BUDGET_DENIED');
  assert.equal((await once(input, 'line'))[0], 'auditfill');
  for (const host of ['audit-failure-1.test', 'audit-failure-2.test', 'audit-failure-3.test']) {
    for (let call = 0; call < 60; call++) {
      const result = await client.callTool({ name: 'guarded_fetch', arguments: {
        url: `http://${host}/plain`,
      } });
      assert.equal(result.isError, true);
      assert.equal(result.structuredContent.rule, 'EGRESS_DNS_FAILURE');
      assert.equal('body_text' in result.structuredContent, false);
    }
  }
  const ringResource = await client.readResource({ uri: 'outbound-guard://logs/audit.json' });
  const ring = JSON.parse(ringResource.contents[0].text);
  const allRules = Array.from({ length: cycles }, () => ['EGRESS_CANCELLED', 'EGRESS_ALLOWED'])
    .flat().concat(Array(36).fill('EGRESS_ALLOWED'), 'EGRESS_RATE_LIMIT',
      Array(60).fill('EGRESS_DNS_FAILURE'), 'EGRESS_RATE_LIMIT',
      Array(180).fill('EGRESS_DNS_FAILURE'));
  assert.equal(ring.capacity, 256);
  assert.equal(ring.events.length, 256);
  assert.deepEqual(ring.events.map(event => event.rule), allRules.slice(-256));
  assert.ok(ring.events.every(event =>
    Object.keys(event).sort().join(',') === 'correlation_id,rule,status'));
  assert.equal(ringResource.contents[0].text.includes('audit-failure-'), false);
  assert.ok((await client.listTools()).tools.length > 0);
  console.log('SDK_AUDIT_CAPACITY_FILLED');
  assert.equal((await once(input, 'line'))[0], 'reset');
  const recovered = await client.callTool({ name: 'guarded_fetch', arguments: {
    url: 'http://allowed.test/plain',
  } });
  assert.equal(recovered.structuredContent.rule, 'EGRESS_ALLOWED');
  assert.equal(recovered.structuredContent.body_text, 'fixture-ok');
  const failedAgain = await client.callTool({ name: 'guarded_fetch', arguments: {
    url: 'http://budget-failure.test/plain',
  } });
  assert.equal(failedAgain.isError, true);
  assert.equal(failedAgain.structuredContent.rule, 'EGRESS_DNS_FAILURE');
  const resetAudit = JSON.parse((await client.readResource({
    uri: 'outbound-guard://logs/audit.json',
  })).contents[0].text);
  assert.equal(resetAudit.events.length, 256);
  assert.deepEqual(resetAudit.events.slice(-2).map(event => event.rule),
    ['EGRESS_ALLOWED', 'EGRESS_DNS_FAILURE']);
  assert.ok((await client.listTools()).tools.length > 0);
  console.log('SDK_RATE_WINDOW_RESET');
  assert.equal((await once(input, 'line'))[0], 'hourfill');
  const hourDecisions = [];
  for (const [index, host] of hourlyHosts.entries()) {
    for (let call = 0; call < (index === 11 ? 38 : 60); call++) {
      const result = await client.callTool({ name: 'guarded_fetch', arguments: {
        url: `http://${host}/plain`,
      } });
      assert.equal(result.isError, true);
      assert.equal(result.structuredContent.rule, 'EGRESS_DNS_FAILURE');
      const { correlation_id, status, rule } = result.structuredContent;
      assert.match(correlation_id, /^egress-[1-9]\d*$/);
      hourDecisions.push({ correlation_id, status, rule });
    }
  }
  console.log('SDK_HOUR_BUDGET_FILLED');
  assert.equal((await once(input, 'line'))[0], 'hourdeny');
  const hourDenied = await client.callTool({ name: 'guarded_fetch', arguments: {
    url: 'http://hour-denied.test/SYNTHETIC_HOUR_BUDGET_MARKER',
  } });
  assert.equal(hourDenied.isError, true);
  assert.equal(hourDenied.structuredContent.rule, 'EGRESS_RATE_LIMIT');
  assert.equal('body_text' in hourDenied.structuredContent, false);
  const { correlation_id, status, rule } = hourDenied.structuredContent;
  assert.match(correlation_id, /^egress-[1-9]\d*$/);
  hourDecisions.push({ correlation_id, status, rule });
  assert.equal(hourDecisions.length, 699);
  assert.equal(new Set(hourDecisions.map(event => event.correlation_id)).size, 699);
  for (let index = 1; index < hourDecisions.length; index++) {
    assert.equal(Number(hourDecisions[index].correlation_id.split('-')[1]),
      Number(hourDecisions[index - 1].correlation_id.split('-')[1]) + 1);
  }
  const hourAudit = JSON.parse((await client.readResource({
    uri: 'outbound-guard://logs/audit.json',
  })).contents[0].text);
  assert.equal(hourAudit.events.length, 256);
  assert.deepEqual(hourAudit.events, hourDecisions.slice(-256));
  assert.ok(hourAudit.events.every(event =>
    Object.keys(event).sort().join(',') === 'correlation_id,rule,status'));
  assert.equal(JSON.stringify(hourAudit).includes('hour-failure-'), false);
  assert.equal(JSON.stringify(hourAudit).includes('hour-denied.test'), false);
  assert.ok((await client.listTools()).tools.length > 0);
  console.log('SDK_HOUR_BUDGET_DENIED');
  assert.equal((await once(input, 'line'))[0], 'finish');
} finally {
  await client.close();
  input.close();
}
assert.equal(stderr, '');
