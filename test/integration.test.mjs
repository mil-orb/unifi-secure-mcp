import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { writePrivate, secureDirectory, storeSecret } from '../src/storage.mjs';
import { grant, revoke } from '../src/permits.mjs';
import { UniFiClient } from '../src/client.mjs';
import { messages } from '../src/security.mjs';
const id = '00000000-0000-4000-8000-000000000001';
const original = { management: 'UNMANAGED', name: 'Example lab', enabled: false, vlanId: 20 };
const openssl =
  process.platform === 'win32' ? 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe' : 'openssl';
// Starts a synthetic pinned-HTTPS router plus a real stdio MCP server process.
// `info` is the /v1/info response body, or a number to answer with that HTTP status.
async function withSimulator({ info, specVersion }, run) {
  const dir = mkdtempSync(join(tmpdir(), 'unifi-mcp-test-'));
  let server, client;
  const sim = { writes: 0, requests: [], state: { ...original } };
  try {
    secureDirectory(dir);
    execFileSync(
      openssl,
      [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-keyout',
        join(dir, 'server.key'),
        '-out',
        join(dir, 'router.pem'),
        '-days',
        '1',
        '-subj',
        '/CN=localhost',
        '-addext',
        'subjectAltName=DNS:localhost,IP:127.0.0.1',
      ],
      { stdio: 'ignore', windowsHide: true },
    );
    // OpenSSL creates public certificates with the process umask. The runtime
    // deliberately requires owner-only storage even for its enrolled certificate.
    if (process.platform !== 'win32') chmodSync(join(dir, 'router.pem'), 0o600);
    writePrivate(join(dir, 'router.pem'), readFileSync(join(dir, 'router.pem')));
    server = https.createServer(
      { key: readFileSync(join(dir, 'server.key')), cert: readFileSync(join(dir, 'router.pem')) },
      (req, res) => {
        sim.requests.push({ method: req.method, url: req.url });
        assert.equal(req.headers['x-api-key'], 'synthetic-test-value');
        res.setHeader('Content-Type', 'application/json');
        let body = '';
        req.on('data', (c) => (body += c));
        req.on('end', () => {
          if (req.url === '/proxy/network/integration/v1/info') {
            if (typeof info === 'number') res.statusCode = info;
            return res.end(JSON.stringify(typeof info === 'number' ? {} : info));
          }
          if (req.url === `/proxy/network/integration/v1/sites/${id}/networks/${id}`) {
            if (req.method === 'PUT') {
              sim.writes++;
              sim.state = JSON.parse(body);
            }
            return res.end(JSON.stringify(sim.state));
          }
          res.statusCode = 404;
          res.end('{}');
        });
      },
    );
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const config = {
      version: 1,
      baseUrl: `https://127.0.0.1:${server.address().port}`,
      dataDir: dir,
      credentialStore: process.platform === 'win32' ? 'dpapi' : 'file',
      writeEnabled: true,
      ...(specVersion ? { specVersion } : {}),
      configured: true,
    };
    storeSecret(config, 'synthetic-test-value');
    const { configured, ...saved } = config;
    writePrivate(join(dir, 'config.json'), JSON.stringify(saved));
    client = new Client({ name: 'integration-test', version: '1' });
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [
        fileURLToPath(new URL('../src/cli.mjs', import.meta.url)),
        'serve',
        '--config',
        join(dir, 'config.json'),
      ],
      stderr: 'pipe',
    });
    let diagnostics = '';
    transport.stderr?.on('data', (chunk) => {
      diagnostics = (diagnostics + chunk.toString()).slice(-4096);
    });
    try {
      await client.connect(transport);
    } catch {
      throw new Error(
        Object.values(messages).find((message) => diagnostics.includes(message)) ||
          'MCP simulator startup failed; no raw diagnostics returned.',
      );
    }
    const call = (name, args = {}) => client.callTool({ name, arguments: args });
    await run({ client, config, sim, dir, call, result: (r) => r.structuredContent.result });
  } finally {
    await client?.close();
    if (server) await new Promise((r) => server.close(r));
    const root = resolve(tmpdir());
    assert.ok(resolve(dir).startsWith(root + '\\') || resolve(dir).startsWith(root + '/'));
    assert.ok(dir.includes('unifi-mcp-test-'));
    rmSync(dir, { recursive: true, force: true });
  }
}
test('real stdio MCP and pinned HTTPS: read, preview, permit, apply, restore, reject replay', async () => {
  await withSimulator(
    { info: { applicationVersion: '11.0.97', apiKey: 'synthetic-test-value' } },
    async ({ client, config, sim, dir, call, result }) => {
      const tools = await client.listTools();
      assert.equal(tools.tools.length, 77);
      assert.equal(client.getServerVersion().icons[0].mimeType, 'image/x-icon');
      const status = result(await call('unifi_status'));
      assert.equal(status.access.mode, 'read-only');
      assert.equal(status.history.outageEvents, false);
      assert.deepEqual(status.spec, {
        loaded: '11.0.97',
        detected: '11.0.97',
        match: 'exact',
        bundled: ['10.6.106', '11.0.97', '11.1.47'],
      });
      assert.equal(status.schemaVersion, '11.0.97');
      const capabilities = JSON.parse(
        (await client.readResource({ uri: 'unifi://capabilities' })).contents[0].text,
      );
      assert.equal(capabilities.spec.match, 'exact');
      assert.match(client.getInstructions(), /Loaded API schema 11\.0\.97 .*match: exact/);
      assert.match(client.getInstructions(), /reportFlowEnabled/);
      assert.equal((await client.listResources()).resources.length, 2);
      assert.equal((await client.listPrompts()).prompts.length, 2);
      assert.equal(result(await call('unifi_api_get_info')).apiKey, '[REDACTED]');
      const invalid = await call('unifi_api_get_info', { url: 'https://example.org' });
      assert.equal(invalid.isError, true);
      const input = {
        path: { siteId: id, networkId: id },
        body: { ...original, name: 'Changed lab' },
      };
      const preview = result(await call('unifi_api_update_network', input));
      assert.equal(sim.writes, 0);
      assert.equal(
        (
          await call('unifi_apply_plan', {
            planId: preview.planId,
            confirmation: preview.confirmation,
          })
        ).isError,
        true,
      );
      assert.equal(sim.writes, 0);
      grant(config, { sites: [id], operations: ['updateNetwork'], minutes: 1 });
      // The permit is stamped by this process but checked by the long-lived server
      // process, whose clock can trail by a millisecond on Windows; permits.mjs
      // rejects issuedAt in its future. Wait so the test does not race that check.
      await new Promise((r) => setTimeout(r, 100));
      assert.equal(
        (
          await call('unifi_apply_plan', {
            planId: preview.planId,
            confirmation: preview.confirmation,
          })
        ).isError,
        undefined,
      );
      assert.equal(sim.writes, 1);
      assert.equal(
        (
          await call('unifi_apply_plan', {
            planId: preview.planId,
            confirmation: preview.confirmation,
          })
        ).isError,
        true,
      );
      assert.equal(sim.writes, 1);
      const restore = result(await call('unifi_api_update_network', { ...input, body: original }));
      await call('unifi_apply_plan', {
        planId: restore.planId,
        confirmation: restore.confirmation,
      });
      assert.deepEqual(sim.state, original);
      assert.equal(sim.writes, 2);
      revoke(config);
      assert.equal(result(await call('unifi_status')).access.mode, 'read-only');
      assert.ok(sim.requests.every((r) => r.url.startsWith('/proxy/network/integration/v1/')));
      // A different certificate must fail before sending the API key to the peer.
      execFileSync(
        openssl,
        [
          'req',
          '-x509',
          '-newkey',
          'rsa:2048',
          '-nodes',
          '-keyout',
          join(dir, 'other.key'),
          '-out',
          join(dir, 'other.pem'),
          '-days',
          '1',
          '-subj',
          '/CN=localhost',
        ],
        { stdio: 'ignore', windowsHide: true },
      );
      const before = sim.requests.length;
      writePrivate(join(dir, 'router.pem'), readFileSync(join(dir, 'other.pem')));
      await assert.rejects(new UniFiClient(config).call('getInfo', {}), /TLS_FAILED/);
      assert.equal(sim.requests.length, before);
    },
  );
});
test('failed version detection still starts, lists tools and falls back to the pin', async () => {
  await withSimulator(
    { info: 500, specVersion: '11.0.97' },
    async ({ client, sim, call, result }) => {
      assert.equal((await client.listTools()).tools.length, 77);
      const status = result(await call('unifi_status'));
      assert.deepEqual(status.spec, {
        loaded: '11.0.97',
        detected: null,
        match: 'not-detected',
        bundled: ['10.6.106', '11.0.97', '11.1.47'],
      });
      assert.match(client.getInstructions(), /detection failed/);
      assert.deepEqual(
        sim.requests.map((r) => `${r.method} ${r.url}`),
        ['GET /proxy/network/integration/v1/info'],
      );
    },
  );
});
