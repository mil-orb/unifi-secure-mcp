// Shared synthetic router simulator: pinned HTTPS plus a real stdio MCP server process.
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
import { messages } from '../src/security.mjs';
export const id = '00000000-0000-4000-8000-000000000001';
export const original = {
  management: 'UNMANAGED',
  name: 'Example lab',
  enabled: false,
  vlanId: 20,
};
export const openssl =
  process.platform === 'win32' ? 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe' : 'openssl';
// Starts a synthetic pinned-HTTPS router plus a real stdio MCP server process.
// `info` is the /v1/info response body, or a number to answer with that HTTP status.
// `routes` maps extra GET pathnames to synthetic JSON bodies.
export async function withSimulator(
  { info, specVersion, toolsets, serveArgs = [], routes = {} },
  run,
) {
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
          const route = routes[new URL(req.url, 'https://simulator.invalid').pathname];
          if (req.method === 'GET' && route !== undefined) return res.end(JSON.stringify(route));
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
      ...(toolsets ? { toolsets } : {}),
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
        ...serveArgs,
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
