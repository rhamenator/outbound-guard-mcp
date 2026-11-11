// Demonstrate that the advertised per-host budget belongs to each server process.
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

const sessions = [];
try {
  for (let index = 0; index < 2; index++) {
    const client = new Client({ name: `outbound-guard-process-budget-${index}`, version: '1' },
      { versionNegotiation: { mode: { pin: '2026-07-28' } } });
    const transport = new StdioClientTransport({ command: process.argv[2],
      env: { ...process.env, OUTBOUND_GUARD_ALLOWED_HOSTS: 'allowed.test' }, stderr: 'pipe' });
    let stderr = '';
    transport.stderr?.on('data', chunk => { stderr += chunk.toString(); });
    sessions.push({ client, stderr: () => stderr });
    await client.connect(transport);
    assert.equal(client.getNegotiatedProtocolVersion(), '2026-07-28');
  }
  const fetch = client => client.callTool({ name: 'guarded_fetch', arguments: {
    url: 'http://allowed.test/plain',
  } });
  // Alternate the two live server processes to expose any shared accounting.
  for (let index = 0; index < 60; index++) {
    for (const { client } of sessions) {
      const result = await fetch(client);
      assert.equal(result.structuredContent.rule, 'EGRESS_ALLOWED');
      assert.equal(result.structuredContent.body_text, 'fixture-ok');
    }
  }
  for (const { client } of sessions) {
    const result = await client.callTool({ name: 'guarded_fetch', arguments: {
      url: 'http://allowed.test/SYNTHETIC_TWO_PROCESS_BUDGET_MARKER',
    } });
    assert.equal(result.isError, true);
    assert.equal(result.structuredContent.rule, 'EGRESS_RATE_LIMIT');
    assert.equal('body_text' in result.structuredContent, false);
    const audit = JSON.parse((await client.readResource({
      uri: 'outbound-guard://logs/audit.json',
    })).contents[0].text);
    assert.equal(audit.events.length, 61);
    assert.equal(audit.events.filter(event => event.rule === 'EGRESS_ALLOWED').length, 60);
    assert.equal(audit.events.filter(event => event.rule === 'EGRESS_RATE_LIMIT').length, 1);
    assert.equal(JSON.stringify(audit).includes('SYNTHETIC_TWO_PROCESS_BUDGET_MARKER'), false);
  }
  console.log('SDK_TWO_PROCESS_BUDGET:120:2');
} finally {
  await Promise.all(sessions.map(async ({ client, stderr }) => {
    await client.close();
    assert.equal(stderr(), '');
  }));
}
