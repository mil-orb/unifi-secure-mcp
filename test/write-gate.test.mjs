// Review R1 Batch C: write gate. M2 plan-bound permits, L6 not-sent failures, H1 item 4
// secret-aware previews, I1 permit schema. Synthetic data only.
import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID, createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { Plans } from '../src/plans.mjs';
import {
  grant,
  grantPlan,
  authorize,
  policy,
  sharePreview,
  readPreview,
  removePreview,
} from '../src/permits.mjs';
import { byId, activeSpec, bundledSpecs } from '../src/catalog.mjs';
import { redact, hash, secretFields, messages } from '../src/security.mjs';
import { writePrivate, secureDirectory, lastActiveSpec } from '../src/storage.mjs';
import { UniFiClient } from '../src/client.mjs';
import { id, original, openssl, withSimulator } from './simulator.mjs';
const uid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const sha = (text) => createHash('sha256').update(text).digest('hex');
const temp = (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'unifi-mcp-test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
};
const op = byId.get('updateNetwork');
const networkInput = (name) => ({
  path: { siteId: uid(1), networkId: uid(2) },
  body: { management: 'UNMANAGED', name, enabled: false, vlanId: 20 },
});

test('M2: a plan-bound permit authorizes only its plan; operation/site permits are unchanged', (t) => {
  const config = { configured: true, writeEnabled: true, dataDir: temp(t) };
  const planId = randomUUID(),
    requestHash = sha('request'),
    input = networkInput('Lab');
  const shared = {
    planId,
    operation: op.id,
    method: op.method,
    path: op.path,
    siteId: uid(1),
    request: input,
    sensitiveFields: [],
    requestHash,
    expiresAt: new Date(Date.now() + 300000).toISOString(),
    specVersion: activeSpec.loaded,
  };
  sharePreview(config, shared);
  assert.deepEqual(readPreview(config, planId), shared);
  assert.throws(() => grantPlan(config, planId, sha('other')), /STALE_PLAN/);
  assert.throws(
    () => grantPlan({ ...config, writeEnabled: false }, planId, requestHash),
    /INPUT_INVALID/,
  );
  assert.throws(() => grantPlan(config, uid(9), requestHash), /PLAN_EXPIRED/);
  const permit = grantPlan(config, planId, requestHash);
  assert.deepEqual(permit.plan, { id: planId, requestHash });
  assert.deepEqual([permit.sites, permit.operations], [[uid(1)], [op.id]]);
  assert.equal(permit.expiresAt, shared.expiresAt, 'expires with the preview');
  const binding = { id: planId, requestHash };
  assert.doesNotThrow(() => authorize(config, op, input, binding));
  for (const other of [
    undefined,
    { id: randomUUID(), requestHash },
    { id: planId, requestHash: sha('x') },
  ])
    assert.throws(() => authorize(config, op, input, other), /READ_ONLY/);
  assert.throws(() => authorize(config, op, { path: { siteId: uid(3) } }, binding), /READ_ONLY/);
  assert.throws(() => authorize(config, byId.get('deleteNetwork'), input, binding), /READ_ONLY/);
  // A malformed binding makes the whole permit read-only.
  const file = join(config.dataDir, 'permit.json');
  for (const bad of [
    { ...permit, plan: { id: 'not-a-uuid', requestHash } },
    { ...permit, plan: { id: planId, requestHash: 'short' } },
    { ...permit, plan: null },
    { ...permit, sites: [uid(1), uid(3)] },
  ]) {
    writePrivate(file, JSON.stringify(bad));
    assert.equal(policy(config).mode, 'read-only');
  }
  // Without --plan: unchanged operation/site semantics, whatever binding apply passes.
  grant(config, { sites: [uid(1)], operations: [op.id], minutes: 1 });
  assert.equal(policy(config).plan, undefined);
  for (const any of [undefined, binding, { id: randomUUID(), requestHash: sha('y') }])
    assert.doesNotThrow(() => authorize(config, op, input, any));
  // Expired previews are refused and pruned; removed previews are gone.
  const stale = randomUUID();
  sharePreview(config, {
    ...shared,
    planId: stale,
    expiresAt: new Date(Date.now() - 1).toISOString(),
  });
  assert.throws(() => readPreview(config, stale), /PLAN_EXPIRED/);
  sharePreview(config, { ...shared, planId: randomUUID() });
  assert.ok(!readdirSync(config.dataDir).includes(`preview-${stale}.json`));
  removePreview(config, planId);
  assert.throws(() => readPreview(config, planId), /PLAN_EXPIRED/);
  assert.throws(() => readPreview(config, '../permit'), /PLAN_EXPIRED/);
});

test('M2: Plans shares each preview and applies only the one its permit names', async (t) => {
  const config = { configured: true, writeEnabled: true, dataDir: temp(t) };
  const writes = [];
  const client = {
    clean: (x) => redact(x),
    resolveInput: (x) => x,
    call: async (o, input, opts) => {
      if (o.readOnly) return { name: 'Before' };
      writes.push({ name: input.body.name, plan: opts?.plan });
      return {};
    },
  };
  const plans = new Plans(config, client, { audit: () => {}, acquire: () => () => {} });
  const a = await plans.preview(op, networkInput('Intended'));
  const b = await plans.preview(op, networkInput('Injected'));
  assert.equal(a.localPermit, `unifi-secure-mcp permit --plan ${a.planId}`);
  const shared = readPreview(config, a.planId);
  assert.equal(shared.requestHash, hash(networkInput('Intended')));
  assert.deepEqual(shared.request, a.request);
  assert.equal(shared.specVersion, activeSpec.loaded);
  grantPlan(config, a.planId, shared.requestHash);
  await assert.rejects(plans.apply(b.planId, b.confirmation), /READ_ONLY/);
  assert.equal(writes.length, 0);
  await plans.apply(a.planId, a.confirmation);
  assert.deepEqual(writes, [
    { name: 'Intended', plan: { id: a.planId, requestHash: shared.requestHash } },
  ]);
  assert.throws(() => readPreview(config, a.planId), /PLAN_EXPIRED/, 'consumed');
  plans.discard(b.planId);
  assert.throws(() => readPreview(config, b.planId), /PLAN_EXPIRED/, 'discarded');
  // Read-only configuration: nothing is shared, and no permit command is offered.
  const readOnly = new Plans({ ...config, writeEnabled: false }, client);
  const c = await readOnly.preview(op, networkInput('Other'));
  assert.equal(c.localPermit, undefined);
  assert.throws(() => readPreview(config, c.planId), /PLAN_EXPIRED/);
});

test('M2: end to end, a plan-bound permit applies one previewed request through the server', async () => {
  await withSimulator(
    { info: { applicationVersion: '11.0.97' } },
    async ({ config, sim, call, result }) => {
      const path = { siteId: id, networkId: id };
      const preview = async (name) =>
        result(await call('unifi_api_update_network', { path, body: { ...original, name } }));
      const apply = (p) =>
        call('unifi_apply_plan', { planId: p.planId, confirmation: p.confirmation });
      const intended = await preview('Changed lab');
      const injected = await preview('Injected lab');
      assert.match(intended.localPermit, /permit --plan /);
      grantPlan(config, intended.planId, readPreview(config, intended.planId).requestHash);
      // The server process checks issuedAt against its own clock (see integration test).
      await new Promise((r) => setTimeout(r, 100));
      assert.equal((await apply(injected)).isError, true);
      assert.equal(sim.writes, 0);
      assert.equal((await apply(intended)).isError, undefined);
      assert.equal(sim.state.name, 'Changed lab');
      const restore = await preview(original.name);
      assert.equal((await apply(restore)).isError, true, 'the permit named one plan only');
      assert.equal(sim.writes, 1);
      // Restore the synthetic state with an ordinary operation/site permit.
      grant(config, { sites: [id], operations: ['updateNetwork'], minutes: 1 });
      await new Promise((r) => setTimeout(r, 100));
      const back = await preview(original.name);
      assert.equal((await apply(back)).isError, undefined);
      assert.deepEqual(sim.state, original);
      // I1: the server recorded the schema it loaded for the permit command.
      assert.equal(lastActiveSpec(config), '11.0.97');
    },
  );
});

// Old behaviour of apply with a stub client whose write fails with `error`.
function harness(error) {
  const events = [];
  let writes = 0;
  const plans = new Plans(
    {},
    {
      clean: (x) => x,
      resolveInput: (x) => x,
      call: async (o) => {
        if (o.readOnly) return { name: 'Before' };
        writes++;
        throw error;
      },
    },
    { auth: () => {}, audit: (e) => events.push(e.outcome), acquire: () => () => {} },
  );
  return { plans, events, writes: () => writes };
}

test('L6: a write that failed before sending is blocked, not uncertain; others are unchanged', async () => {
  for (const [error, expected, outcome] of [
    [Object.assign(new Error('TLS_PIN_CHANGED'), { notSent: true }), /TLS_PIN_CHANGED/, 'blocked'],
    [Object.assign(new Error('READ_ONLY'), { notSent: true }), /READ_ONLY/, 'blocked'],
    [new Error('TIMEOUT'), /WRITE_UNCERTAIN/, 'uncertain'],
    [new Error('UPSTREAM_500'), /WRITE_UNCERTAIN/, 'uncertain'],
    [new Error('TLS_FAILED'), /WRITE_UNCERTAIN/, 'uncertain'],
  ]) {
    const h = harness(error);
    const p = await h.plans.preview(op, networkInput('Lab'));
    await assert.rejects(h.plans.apply(p.planId, p.confirmation), expected);
    assert.deepEqual(h.events, ['attempt', outcome], error.message);
    await assert.rejects(h.plans.apply(p.planId, p.confirmation), /PLAN_EXPIRED/, 'consumed');
    assert.equal(h.writes(), 1, 'never retried');
  }
});

test('L6: the client marks only failures before the TLS handshake completes as notSent', async (t) => {
  const dir = temp(t);
  const cert = (name) =>
    execFileSync(
      openssl,
      [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-keyout',
        join(dir, `${name}.key`),
        '-out',
        join(dir, `${name}.pem`),
        '-days',
        '1',
        '-subj',
        '/CN=localhost',
      ],
      { stdio: 'ignore', windowsHide: true },
    );
  cert('router');
  cert('other');
  const data = join(dir, 'data');
  writePrivate(join(data, 'router.pem'), readFileSync(join(dir, 'router.pem')));
  writePrivate(join(data, 'api-key.secret'), 'synthetic-key');
  const serve = (name, handler) =>
    new Promise((resolve) => {
      const server = https.createServer(
        {
          key: readFileSync(join(dir, `${name}.key`)),
          cert: readFileSync(join(dir, `${name}.pem`)),
        },
        handler,
      );
      server.listen(0, '127.0.0.1', () => resolve(server));
      t.after(() => new Promise((r) => server.close(r)));
    });
  const client = (port, authorize = () => {}) =>
    new UniFiClient(
      {
        configured: true,
        baseUrl: `https://127.0.0.1:${port}`,
        dataDir: data,
        credentialStore: 'file',
      },
      { authorize },
    );
  const write = (c) => c.call(op, networkInput('Lab'));
  const failure = async (promise) => {
    try {
      await promise;
    } catch (error) {
      return { message: error.message, notSent: error.notSent === true };
    }
    assert.fail('expected a failure');
  };
  // Refused by the local permit check: nothing sent.
  assert.deepEqual(
    await failure(
      new UniFiClient({
        configured: true,
        dataDir: data,
        baseUrl: 'https://127.0.0.1:1',
        credentialStore: 'file',
      }).call(op, networkInput('Lab')),
    ),
    {
      message: 'READ_ONLY',
      notSent: true,
    },
  );
  // Nothing listening: nothing sent.
  const closed = await serve('router', () => {});
  const port = closed.address().port;
  await new Promise((r) => closed.close(r));
  assert.deepEqual(await failure(write(client(port))), { message: 'TLS_FAILED', notSent: true });
  // A different certificate: nothing sent.
  const impostor = await serve('other', () => assert.fail('no request may arrive'));
  assert.deepEqual(await failure(write(client(impostor.address().port))), {
    message: 'TLS_PIN_CHANGED',
    notSent: true,
  });
  // The request reached the router: the outcome is unknown or a server error.
  const dropping = await serve('router', (req) => req.on('data', () => req.socket.destroy()));
  assert.deepEqual(await failure(write(client(dropping.address().port))), {
    message: 'TLS_FAILED',
    notSent: false,
  });
  const failing = await serve('router', (req, res) => {
    res.statusCode = 500;
    res.end('{}');
  });
  assert.deepEqual(await failure(write(client(failing.address().port))), {
    message: 'UPSTREAM_500',
    notSent: false,
  });
});

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

test('H1 item 4: previews say whether each secret is a reference, a new literal or omitted', async () => {
  const before = {
    name: 'Synthetic',
    securityConfiguration: { type: 'WPA2_PERSONAL', passphrase: 'old-value' },
  };
  const describe = (security) => secretFields(wifiBody(security), before);
  assert.deepEqual(describe({ type: 'WPA2_PERSONAL', passphrase: '@secret:wifi_password' }), [
    { field: 'securityConfiguration.passphrase', value: '@secret:wifi_password' },
  ]);
  assert.deepEqual(describe({ type: 'WPA2_PERSONAL', passphrase: 'new-literal' }), [
    { field: 'securityConfiguration.passphrase', value: 'literal (hidden)' },
  ]);
  assert.deepEqual(describe({ type: 'OPEN' }), [
    { field: 'securityConfiguration.passphrase', value: 'omitted' },
  ]);
  const { securityConfiguration, ...withoutSecurity } = wifiBody({});
  assert.deepEqual(secretFields(withoutSecurity, before), [
    { field: 'securityConfiguration.passphrase', value: 'omitted' },
  ]);
  assert.deepEqual(secretFields(withoutSecurity, undefined), []);
  // In a preview: the request and before stay redacted exactly as before, plus sensitiveFields.
  const wifi = byId.get('updateWifiBroadcast');
  const plans = new Plans(
    {},
    {
      clean: (x) => redact(x),
      resolveInput: (x) => structuredClone(x),
      call: async () => structuredClone(before),
    },
    { auth: () => {}, audit: () => {}, acquire: () => () => {} },
  );
  const path = { siteId: uid(1), wifiBroadcastId: uid(2) };
  for (const [passphrase, value] of [
    ['@secret:wifi_password', '@secret:wifi_password'],
    ['synthetic-literal', 'literal (hidden)'],
  ]) {
    const p = await plans.preview(wifi, {
      path,
      body: wifiBody({ type: 'WPA2_PERSONAL', passphrase }),
    });
    assert.deepEqual(Object.keys(p), [
      'planId',
      'operation',
      'method',
      'path',
      'request',
      'sensitiveFields',
      'before',
      'expiresAt',
      'confirmation',
      'risk',
      'precondition',
      'rollback',
    ]);
    assert.equal(p.request.body.securityConfiguration.passphrase, '[REDACTED]');
    assert.equal(p.before.securityConfiguration.passphrase, '[REDACTED]');
    assert.deepEqual(p.sensitiveFields, [{ field: 'securityConfiguration.passphrase', value }]);
    assert.ok(!JSON.stringify(p).includes('synthetic-literal'));
    assert.ok(!JSON.stringify(p).includes('old-value'));
  }
});

test('I1: permit checks operation IDs against the pinned or last-loaded schema', (t) => {
  const dir = temp(t);
  secureDirectory(dir);
  const configPath = join(dir, 'config.json');
  const save = (extra = {}) =>
    writePrivate(
      configPath,
      JSON.stringify({
        version: 1,
        baseUrl: 'https://127.0.0.1',
        dataDir: dir,
        credentialStore: 'file',
        writeEnabled: true,
        ...extra,
      }),
    );
  const cli = fileURLToPath(new URL('../src/cli.mjs', import.meta.url));
  const run = (...args) =>
    spawnSync(process.execPath, [cli, ...args, '--config', configPath], { encoding: 'utf8' });
  const permit = () =>
    run('permit', '--site', uid(1), '--operation', 'updateNetwork', '--minutes', '1');
  save();
  let r = permit();
  assert.equal(r.status, 0, r.stderr);
  assert.ok(
    r.stderr.includes(`${bundledSpecs.at(-1)} (newest bundled; no server start recorded yet)`),
  );
  writePrivate(join(dir, 'active-spec.json'), JSON.stringify({ loaded: '10.6.106' }));
  r = permit();
  assert.ok(r.stderr.includes('10.6.106 (loaded by the last server start)'), r.stderr);
  save({ specVersion: '11.0.97' });
  r = permit();
  assert.ok(r.stderr.includes('11.0.97 (pinned in config)'), r.stderr);
  // permit --plan needs an interactive terminal and no other scope flags.
  r = run('permit', '--plan', uid(5));
  assert.equal(r.status, 1);
  assert.ok(r.stderr.includes(messages.INPUT_INVALID));
});
