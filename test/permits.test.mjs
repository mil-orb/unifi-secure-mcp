import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { grant, revoke, policy, authorize, lock, record } from '../src/permits.mjs';
import { writePrivate } from '../src/storage.mjs';
import { byId } from '../src/catalog.mjs';
test('permit scope, expiry, malformed storage, lock and audit gates fail closed', () => {
  const directory = mkdtempSync(join(tmpdir(), 'unifi-permit-test-'));
  const id = '00000000-0000-4000-8000-000000000001',
    other = '00000000-0000-4000-8000-000000000002';
  const config = { configured: true, writeEnabled: true, dataDir: directory };
  const op = byId.get('updateNetwork'),
    input = { path: { siteId: id } };
  try {
    assert.equal(policy(config).mode, 'read-only');
    assert.throws(() => authorize(config, op, input), /READ_ONLY/);
    const permit = grant(config, { sites: [id], operations: [op.id], minutes: 1 });
    assert.doesNotThrow(() => authorize(config, op, input));
    assert.throws(() => authorize(config, op, { path: { siteId: other } }), /READ_ONLY/);
    assert.throws(() => authorize(config, byId.get('deleteNetwork'), input), /READ_ONLY/);
    assert.equal(policy(config, Date.parse(permit.expiresAt) + 1).mode, 'read-only');
    assert.equal(policy({ ...config, writeEnabled: false }).mode, 'read-only');
    const release = lock(config);
    assert.throws(() => lock(config), /WRITE_BUSY/);
    release();
    record(config, { outcome: 'synthetic' });
    writePrivate(join(directory, 'permit.json'), 'malformed');
    assert.equal(policy(config).mode, 'read-only');
    revoke(config);
    assert.equal(policy(config).mode, 'read-only');
  } finally {
    assert.ok(
      resolve(directory).startsWith(resolve(tmpdir())) && directory.includes('unifi-permit-test-'),
    );
    rmSync(directory, { recursive: true, force: true });
  }
});
