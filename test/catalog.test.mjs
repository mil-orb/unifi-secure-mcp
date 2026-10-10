import test from 'node:test';
import assert from 'node:assert/strict';
import { operations, spec, byId, validateInput, buildRequest, normalize } from '../src/catalog.mjs';
import { parseOrigin } from '../src/config.mjs';
import { redact, assertBoundedJson } from '../src/security.mjs';
import { renderInventory } from '../src/mermaid.mjs';
const siteId = '00000000-0000-4000-8000-000000000001';
test('every documented operation is represented exactly once without executing it', () => {
  const ids = Object.values(spec.paths).flatMap((p) =>
    Object.values(p)
      .filter((o) => o.operationId)
      .map((o) => o.operationId),
  );
  assert.deepEqual(operations.map((o) => o.id).sort(), ids.sort());
  assert.equal(ids.length, 73);
  assert.equal(operations.filter((o) => o.readOnly).length, 41);
  assert.equal(new Set(operations.map((o) => o.name)).size, 73);
});
test('origin and path validation reject alternate protocols, credentials and traversal', () => {
  for (const u of [
    'http://router',
    'https://u:p@router',
    'https://router/x',
    'https://router/?x=1',
    'https://router/#x',
  ])
    assert.throws(() => parseOrigin(u));
  const op = byId.get('getNetworksOverviewPage');
  for (const bad of ['../login', '%2f', 'https://evil.invalid'])
    assert.throws(() => buildRequest(op, { path: { siteId: bad } }, 'https://router'));
  assert.equal(
    buildRequest(op, { path: { siteId }, query: { filter: "name.eq('Lab')" } }, 'https://router')
      .url.origin,
    'https://router',
  );
});
test('query validation rejects unknown parameters and unbounded pagination', () => {
  for (const query of [
    { limit: 0 },
    { limit: 201 },
    { offset: 1000001 },
    { redirect: 'https://evil.invalid' },
  ])
    assert.throws(() =>
      validateInput(byId.get('getNetworksOverviewPage'), { path: { siteId }, query }),
    );
});
test('discriminator inheritance validates required subtype fields and unknown fields', () => {
  const op = byId.get('updateNetwork'),
    base = {
      path: { siteId, networkId: siteId },
      body: { management: 'UNMANAGED', name: 'Lab', enabled: false, vlanId: 20 },
    };
  assert.doesNotThrow(() => validateInput(op, base));
  assert.throws(() =>
    validateInput(op, { ...base, body: { ...base.body, management: 'GATEWAY' } }),
  );
  assert.throws(() => validateInput(op, { ...base, body: { ...base.body, unknown: true } }));
  assert.throws(() =>
    validateInput(op, { ...base, body: { ...base.body, management: 'UNKNOWN' } }),
  );
});
test('redaction and structural limits resist secret echoes and prototype keys', () => {
  assert.deepEqual(redact({ passphrase: 'pw', data: 'key leaked' }, ['key']), {
    passphrase: '[REDACTED]',
    data: '[REDACTED] leaked',
  });
  assert.throws(() => assertBoundedJson(JSON.parse('{"__proto__":{"x":1}}')));
  let deep = {};
  for (let i = 0; i < 40; i++) deep = { child: deep };
  assert.throws(() => assertBoundedJson(deep));
});
test('Mermaid labels cannot add directives, HTML, commands or graph statements', () => {
  const name = 'x\"]\nclick n0 "https://evil.invalid"\n%%{init:xx}%%<script>`';
  const result = renderInventory({ devices: { data: [{ id: name, name }], totalCount: 1 } });
  assert.ok(!/[<%`{}]/.test(result.mermaid));
  assert.equal(result.mermaid.split('\n').filter((l) => l.includes('["x')).length, 1);
  assert.ok(!result.mermaid.includes('https:'));
});
