import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { bundledSpecs, compileSpec, byId, validateInput } from '../src/catalog.mjs';
import { Plans } from '../src/plans.mjs';
import { UniFiClient } from '../src/client.mjs';
import { redact, safeError } from '../src/security.mjs';
import { reservedSecretName } from '../src/storage.mjs';
import { collect, readOperations } from '../src/pathfinder.mjs';
import { inventory, inventoryOperations } from '../src/mermaid.mjs';
// Synthetic identifiers and documentation-range addresses, built at runtime.
const siteId = '00000000-0000-4000-8000-000000000001';
const otherId = '00000000-0000-4000-8000-000000000002';
const subnet = `192.0.2.${0}/24`;
const host = `192.0.2.${10}`;
const aclBody = {
  type: 'IPV4',
  enabled: true,
  name: 'Lab',
  action: 'BLOCK',
  sourceFilter: { type: 'IP_ADDRESSES_OR_SUBNETS', ipAddressesOrSubnets: [subnet] },
};
const wifiBody = (securityConfiguration) => ({
  type: 'STANDARD',
  name: 'Synthetic',
  enabled: true,
  hideName: false,
  clientIsolationEnabled: false,
  channel2gLockedTo6: false,
  dtimPeriod2gLockedTo3: false,
  multicastToUnicastConversionEnabled: false,
  uapsdEnabled: false,
  advertiseDeviceName: false,
  arpProxyEnabled: false,
  bssTransitionEnabled: false,
  broadcastingFrequenciesGHz: [2.4, 5],
  securityConfiguration,
});

test('allOf placeholders no longer disable validation (ACL filters, RADIUS, DNS domain) on every spec', () => {
  for (const version of bundledSpecs) {
    const { byId: ops } = compileSpec(version);
    const acl = ops.get('createAclRule');
    assert.ok(acl.validate({ path: { siteId }, body: aclBody }), `${version}: real ACL body`);
    for (const sourceFilter of [{ anything: 'goes' }, 'text', { type: 'UNKNOWN' }])
      assert.equal(
        acl.validate({ path: { siteId }, body: { ...aclBody, sourceFilter } }),
        false,
        `${version}: garbage sourceFilter`,
      );
    const wifi = ops.get('updateWifiBroadcast');
    const path = { siteId, wifiBroadcastId: otherId };
    assert.ok(wifi.validate({ path, body: wifiBody({ type: 'WPA2_PERSONAL' }) }), version);
    assert.equal(
      wifi.validate({
        path,
        body: wifiBody({ type: 'WPA2_PERSONAL', radiusConfiguration: { anything: 'goes' } }),
      }),
      false,
      `${version}: garbage radiusConfiguration`,
    );
    const dns = ops.get('createDnsPolicy');
    const record = (domain) => ({
      path: { siteId },
      body: { type: 'A_RECORD', enabled: true, domain, ipv4Address: host, ttlSeconds: 60 },
    });
    assert.ok(dns.validate(record('example.com')), `${version}: valid domain`);
    assert.equal(dns.validate(record('')), false, `${version}: empty domain`);
    assert.equal(dns.validate(record('a'.repeat(128))), false, `${version}: long domain`);
  }
});

test('no request-body property of any bundled spec normalizes to an accept-anything schema', () => {
  const empty = [];
  const walk = (s, at) => {
    if (!s || typeof s !== 'object' || Array.isArray(s)) return;
    if (!Object.keys(s).length) empty.push(at);
    for (const [k, v] of Object.entries(s))
      if (!['const', 'enum', 'default'].includes(k))
        Array.isArray(v) ? v.forEach((x, i) => walk(x, `${at}/${k}/${i}`)) : walk(v, `${at}/${k}`);
  };
  for (const version of bundledSpecs)
    for (const op of compileSpec(version).operations)
      if (!op.readOnly) walk(op.inputSchema, `${version} ${op.id}`);
  assert.deepEqual(empty, []);
});

test('a [REDACTED] marker in a request body is refused before any read or write', async () => {
  const op = byId.get('updateWifiBroadcast');
  const calls = [];
  const client = {
    clean: (x) => redact(x),
    resolveInput: (x) => x,
    call: async (o) => {
      calls.push(o.id);
      return {};
    },
  };
  const plans = new Plans({}, client, {
    auth: () => {},
    audit: () => {},
    acquire: () => () => {},
  });
  const path = { siteId, wifiBroadcastId: otherId };
  for (const securityConfiguration of [
    { type: 'WPA2_PERSONAL', passphrase: '[REDACTED]' },
    { type: 'WPA2_PERSONAL', passphrase: 'x[REDACTED]x' },
  ])
    await assert.rejects(
      plans.preview(op, { path, body: wifiBody(securityConfiguration) }),
      /REDACTED_VALUE/,
    );
  assert.deepEqual(calls, []);
  assert.match(safeError(new Error('REDACTED_VALUE')), /@secret:NAME/);
  // An ordinary passphrase still validates; query and path are unaffected.
  assert.doesNotThrow(() =>
    validateInput(op, {
      path,
      body: wifiBody({ type: 'WPA2_PERSONAL', passphrase: 'synthetic-pass' }),
    }),
  );
});

test('@secret:api-key (any case) cannot be resolved into a request body', () => {
  const dir = mkdtempSync(join(tmpdir(), 'unifi-mcp-test-'));
  try {
    const client = new UniFiClient({ configured: true, credentialStore: 'file', dataDir: dir });
    for (const name of ['api-key', 'API-KEY', 'Api-Key'])
      assert.throws(
        () => client.resolveInput({ path: { siteId }, body: { description: `@secret:${name}` } }),
        /INPUT_INVALID/,
      );
    assert.equal(client.secrets.size, 0);
    assert.ok(reservedSecretName('API-key'));
    assert.ok(!reservedSecretName('wifi_password'));
    // Other names still go to the secret store (missing here, so unavailable).
    assert.throws(
      () =>
        client.resolveInput({ path: { siteId }, body: { description: '@secret:wifi_password' } }),
      /SECRET_UNAVAILABLE/,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('redaction keeps guest-authorization metadata and network references readable', () => {
  const out = redact({
    grantedAuthorization: { authorizedAt: 't', authorizationMethod: 'API' },
    revokedAuthorization: { authorizationMethod: 'VOUCHER' },
    presharedKeyNetworkIds: [{ networkId: otherId }],
    presharedKeys: [{ key: 'synthetic' }],
    authorization: { authorizationMethod: 'API' },
    passphrase: 'synthetic',
  });
  assert.equal(out.grantedAuthorization.authorizationMethod, 'API');
  assert.equal(out.revokedAuthorization.authorizationMethod, 'VOUCHER');
  assert.deepEqual(out.presharedKeyNetworkIds, [{ networkId: otherId }]);
  assert.equal(out.presharedKeys, '[REDACTED]');
  assert.equal(out.authorization, '[REDACTED]');
  assert.equal(out.passphrase, '[REDACTED]');
});

test('helper tools read only the operations they declare for toolset gating', async () => {
  const seen = new Set();
  const stub = {
    call: async (id) => {
      seen.add(typeof id === 'string' ? id : id.id);
      return { data: [], totalCount: 0 };
    },
  };
  await inventory(stub, siteId);
  assert.deepEqual([...seen].sort(), [...inventoryOperations].sort());
  seen.clear();
  // Zone-to-zone and same-network queries together reach every collect() branch
  // that does not need data; each read must be declared.
  for (const query of [
    {
      source: { kind: 'zoneId', value: siteId },
      destination: { kind: 'zoneId', value: otherId },
    },
    {
      source: { kind: 'clientId', value: siteId },
      destination: { kind: 'clientId', value: otherId },
    },
  ])
    await collect(stub, siteId, query).catch(() => {});
  for (const id of seen) assert.ok(readOperations.includes(id), id);
  for (const id of [...readOperations, ...inventoryOperations])
    assert.equal(byId.get(id)?.readOnly, true, id);
});
