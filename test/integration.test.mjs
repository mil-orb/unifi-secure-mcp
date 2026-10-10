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
const id = '00000000-0000-4000-8000-000000000001';
test('real stdio MCP and pinned HTTPS: read, preview, permit, apply, restore, reject replay', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'unifi-mcp-test-'));
  let server, client;
  let writes = 0;
  const requests = [];
  const original = { management: 'UNMANAGED', name: 'Example lab', enabled: false, vlanId: 20 };
  let state = { ...original };
  try {
    secureDirectory(dir);
    const openssl =
      process.platform === 'win32' ? 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe' : 'openssl';
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
        requests.push({ method: req.method, url: req.url });
        assert.equal(req.headers['x-api-key'], 'synthetic-test-value');
        res.setHeader('Content-Type', 'application/json');
        let body = '';
        req.on('data', (c) => (body += c));
        req.on('end', () => {
          if (req.url === '/proxy/network/integration/v1/info')
            return res.end(
              JSON.stringify({ applicationVersion: 'test', apiKey: 'synthetic-test-value' }),
            );
          if (req.url === `/proxy/network/integration/v1/sites/${id}/networks/${id}`) {
            if (req.method === 'PUT') {
              writes++;
              state = JSON.parse(body);
            }
            return res.end(JSON.stringify(state));
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
    transport.stderr?.on('data', () => {});
    await client.connect(transport);
    const call = (name, args = {}) => client.callTool({ name, arguments: args });
    const result = (r) => r.structuredContent.result;
    const tools = await client.listTools();
    assert.equal(tools.tools.length, 77);
    assert.equal(client.getServerVersion().icons[0].mimeType, 'image/x-icon');
    assert.equal(result(await call('unifi_status')).access.mode, 'read-only');
    assert.equal(result(await call('unifi_status')).history.outageEvents, false);
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
    assert.equal(writes, 0);
    assert.equal(
      (
        await call('unifi_apply_plan', {
          planId: preview.planId,
          confirmation: preview.confirmation,
        })
      ).isError,
      true,
    );
    assert.equal(writes, 0);
    grant(config, { sites: [id], operations: ['updateNetwork'], minutes: 1 });
    assert.equal(
      (
        await call('unifi_apply_plan', {
          planId: preview.planId,
          confirmation: preview.confirmation,
        })
      ).isError,
      undefined,
    );
    assert.equal(writes, 1);
    assert.equal(
      (
        await call('unifi_apply_plan', {
          planId: preview.planId,
          confirmation: preview.confirmation,
        })
      ).isError,
      true,
    );
    assert.equal(writes, 1);
    const restore = result(await call('unifi_api_update_network', { ...input, body: original }));
    await call('unifi_apply_plan', { planId: restore.planId, confirmation: restore.confirmation });
    assert.deepEqual(state, original);
    assert.equal(writes, 2);
    revoke(config);
    assert.equal(result(await call('unifi_status')).access.mode, 'read-only');
    assert.ok(requests.every((r) => r.url.startsWith('/proxy/network/integration/v1/')));
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
    const before = requests.length;
    writePrivate(join(dir, 'router.pem'), readFileSync(join(dir, 'other.pem')));
    await assert.rejects(new UniFiClient(config).call('getInfo', {}), /TLS_FAILED/);
    assert.equal(requests.length, before);
  } finally {
    await client?.close();
    if (server) await new Promise((r) => server.close(r));
    const root = resolve(tmpdir());
    assert.ok(resolve(dir).startsWith(root + '\\') || resolve(dir).startsWith(root + '/'));
    assert.ok(dir.includes('unifi-mcp-test-'));
    rmSync(dir, { recursive: true, force: true });
  }
});
