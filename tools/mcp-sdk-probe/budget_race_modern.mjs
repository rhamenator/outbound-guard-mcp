// Official SDK concurrent submissions at the per-host reservation boundary.
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

const client = new Client({ name: 'outbound-guard-budget-race-probe', version: '1' },
  { versionNegotiation: { mode: { pin: '2026-07-28' } } });
const transport = new StdioClientTransport({ command: process.argv[2],
  env: { ...process.env, OUTBOUND_GUARD_ALLOWED_HOSTS: 'allowed.test' }, stderr: 'pipe' });
let stderr = '';
transport.stderr?.on('data', chunk => { stderr += chunk.toString(); });
const fetch = () => client.callTool({ name: 'guarded_fetch', arguments: {
  url: 'http://allowed.test/plain',
} });
try {
  await client.connect(transport);
  assert.equal(client.getNegotiatedProtocolVersion(), '2026-07-28');
  for (let index = 0; index < 52; index++) {
    const result = await fetch();
    assert.equal(result.structuredContent.rule, 'EGRESS_ALLOWED');
    assert.equal(result.structuredContent.body_text, 'fixture-ok');
  }
  const burst = await Promise.all(Array.from({ length: 16 }, () =>
    fetch().then(result => ({ result }), error => ({ error }))));
  let allowed = 0;
  let rateDenied = 0;
  let busy = 0;
  for (const item of burst) {
    if (item.error) {
      assert.equal(item.error.code, -32000);
      assert.equal(item.error.data?.rule, 'MCP_INPUT_BUSY');
      busy++;
    } else if (item.result.structuredContent.rule === 'EGRESS_ALLOWED') {
      assert.equal(item.result.structuredContent.body_text, 'fixture-ok');
      allowed++;
    } else {
      assert.equal(item.result.isError, true);
      assert.equal(item.result.structuredContent.rule, 'EGRESS_RATE_LIMIT');
      assert.equal('body_text' in item.result.structuredContent, false);
      rateDenied++;
    }
  }
  assert.equal(allowed + rateDenied + busy, 16);
  assert.ok(allowed > 0 && allowed <= 8, { allowed, rateDenied, busy });
  for (let index = allowed; index < 8; index++) {
    const result = await fetch();
    assert.equal(result.structuredContent.rule, 'EGRESS_ALLOWED');
    assert.equal(result.structuredContent.body_text, 'fixture-ok');
  }
  const final = await client.callTool({ name: 'guarded_fetch', arguments: {
    url: 'http://allowed.test/SYNTHETIC_BUDGET_RACE_MARKER',
  } });
  assert.equal(final.isError, true);
  assert.equal(final.structuredContent.rule, 'EGRESS_RATE_LIMIT');
  assert.equal('body_text' in final.structuredContent, false);
  const audit = JSON.parse((await client.readResource({
    uri: 'outbound-guard://logs/audit.json',
  })).contents[0].text);
  assert.equal(audit.events.filter(event => event.rule === 'EGRESS_ALLOWED').length, 60);
  assert.equal(audit.events.filter(event => event.rule === 'EGRESS_RATE_LIMIT').length,
    rateDenied + 1);
  assert.equal(audit.events.length, 61 + rateDenied);
  assert.equal(new Set(audit.events.map(event => event.correlation_id)).size,
    audit.events.length);
  assert.equal(JSON.stringify(audit).includes('SYNTHETIC_BUDGET_RACE_MARKER'), false);
  assert.ok((await client.listTools()).tools.length > 0);
  console.log(`SDK_BUDGET_RACE:${allowed}:${rateDenied}:${busy}`);
} finally {
  await client.close();
}
assert.equal(stderr, '');
