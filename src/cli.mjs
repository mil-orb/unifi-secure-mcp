#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { createInterface } from 'node:readline/promises';
import { Writable } from 'node:stream';
import tls from 'node:tls';
import { X509Certificate, randomUUID } from 'node:crypto';
import { resolve, dirname } from 'node:path';
import { readFileSync, existsSync } from 'node:fs';
import { defaultConfigPath, loadConfig, parseOrigin, dataFile } from './config.mjs';
import { secureDirectory, writePrivate, storeSecret } from './storage.mjs';
import { grant, revoke, policy } from './permits.mjs';
import { safeError } from './security.mjs';
import { operations, spec } from './catalog.mjs';
import { UniFiClient } from './client.mjs';
import { serve } from './server.mjs';
const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    config: { type: 'string' },
    site: { type: 'string', multiple: true },
    operation: { type: 'string', multiple: true },
    minutes: { type: 'string' },
    name: { type: 'string' },
    help: { type: 'boolean' },
    version: { type: 'boolean' },
  },
});
const configPath = resolve(values.config || process.env.UNIFI_MCP_CONFIG || defaultConfigPath());
async function prompts() {
  let muted = false;
  const output = new Writable({
    write(chunk, _encoding, callback) {
      if (!muted) process.stdout.write(chunk);
      callback();
    },
  });
  const rl = createInterface({
    input: process.stdin,
    output,
    terminal: Boolean(process.stdin.isTTY),
  });
  return {
    async ask(question, { secret = false, fallback } = {}) {
      process.stdout.write(question + (fallback !== undefined ? ` [${fallback}]` : '') + ': ');
      muted = secret;
      const answer = await rl.question('');
      muted = false;
      if (secret) process.stdout.write('\n');
      return answer.trim() || fallback || '';
    },
    close() {
      rl.close();
    },
  };
}
async function enroll(origin) {
  const url = new URL(origin);
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host: url.hostname.replace(/^\[|\]$/g, ''),
        port: Number(url.port || 443),
        rejectUnauthorized: false,
        minVersion: 'TLSv1.2',
      },
      () => {
        try {
          const cert = new X509Certificate(socket.getPeerCertificate().raw);
          socket.end();
          resolve(cert);
        } catch {
          reject(new Error('TLS_FAILED'));
        }
      },
    );
    socket.setTimeout(10000, () => {
      socket.destroy();
      reject(new Error('TIMEOUT'));
    });
    socket.on('error', () => reject(new Error('TLS_FAILED')));
  });
}
async function setup() {
  if (!process.stdin.isTTY) throw new Error('SETUP_REQUIRED');
  const p = await prompts();
  try {
    console.log(
      'UniFi Secure MCP · local setup · unofficial Ubiquiti integration\nDesigned and verified with UDR7 / Network 10.6.106. No remote MCP listener is installed.\nNever paste credentials into a chat. Setup accepts your key only through hidden local input.',
    );
    let existing;
    if (existsSync(configPath)) {
      existing = loadConfig(configPath);
      if ((await p.ask('Replace the existing local configuration? Type YES')) !== 'YES') return;
    }
    const baseUrl = parseOrigin(
      await p.ask('Local UDR7 HTTPS origin', {
        fallback: existing?.baseUrl || 'https://192.168.1.1',
      }),
    );
    const dataDir = resolve(
      await p.ask('Dedicated private data directory', {
        fallback: existing?.dataDir || resolve(dirname(configPath), 'private'),
      }),
    );
    const cert = await enroll(baseUrl);
    console.log(
      `\nRouter certificate SHA-256: ${cert.fingerprint256}\nExpires: ${cert.validTo}\nThis public-certificate probe sends NO API key. Compare the fingerprint with the certificate shown by your trusted UniFi browser session.`,
    );
    const expected = (await p.ask('Paste the verified SHA-256 fingerprint'))
      .replace(/[^a-f0-9]/gi, '')
      .toUpperCase();
    if (
      expected !== cert.fingerprint256.replaceAll(':', '') ||
      Date.parse(cert.validTo) <= Date.now() ||
      Date.parse(cert.validFrom) > Date.now()
    )
      throw new Error('TLS_FAILED');
    const mode = await p.ask(
      'Access: readonly or write-capable (writes still require a short-lived permit)',
      { fallback: 'readonly' },
    );
    if (!['readonly', 'write-capable'].includes(mode)) throw new Error('INPUT_INVALID');
    console.log(
      '\nIn UniFi Network > Integrations, create a dedicated limited-life API key. Prefer restricted permissions if your firmware offers them. A broad API key remains powerful even when this MCP enforces read-only.',
    );
    const key = await p.ask('API key (hidden)', { secret: true });
    if (!key || /[\s]/.test(key) || key.length > 8192) throw new Error('INPUT_INVALID');
    // Verify a fresh credential generation before atomically switching the config
    // pointer. Failed enrollment cannot overwrite working credentials or permits.
    const config = {
      version: 1,
      baseUrl,
      dataDir: resolve(dataDir, 'enrollment-' + randomUUID()),
      credentialStore: process.platform === 'win32' ? 'dpapi' : 'file',
      writeEnabled: mode === 'write-capable',
    };
    secureDirectory(dataDir);
    secureDirectory(config.dataDir);
    secureDirectory(dirname(configPath));
    writePrivate(dataFile(config, 'router.pem'), cert.toString());
    storeSecret(config, key);
    revoke(config);
    const info = await new UniFiClient({ ...config, configured: true }).call('getInfo', {});
    writePrivate(configPath, JSON.stringify(config, null, 2));
    console.log(
      `\nSetup verified. Network ${info.applicationVersion || 'connected'}. Mode: read-only${config.writeEnabled ? ' (write tool available; no permit active)' : ''}.\nConfig: ${configPath}\n${process.platform === 'win32' ? 'Key storage: Windows DPAPI, current user.' : 'Key storage: local owner-only file (not encrypted); use an encrypted volume/OS key management for stronger at-rest protection.'}\nRestart your MCP host after registering the server. See docs/SETUP.md for Codex and standard MCP configuration.`,
    );
  } finally {
    p.close();
  }
}
try {
  if (values.version) {
    console.log('unifi-secure-mcp 0.2.0');
  } else if (values.help || positionals[0] === 'help') {
    console.log(
      'unifi-secure-mcp <serve|setup|status|operations|permit|revoke|secret> [--config ABSOLUTE_PATH]\n\nsetup       Guided certificate/key/access setup (interactive terminal)\nserve       MCP over STDIO; protocol output only\nstatus      Local access and readiness information\noperations  All operations in the pinned API schema\npermit      --site UUID --operation OPERATION_ID [--minutes 15] (flags repeatable)\nrevoke      Disable all writes immediately\nsecret      --name NAME (hidden local input; use @secret:NAME in request bodies)\n\nDefault: read-only. No insecure TLS flag or credential command-line option.',
    );
  } else if (positionals[0] === 'setup') await setup();
  else if (positionals[0] === 'operations')
    console.log(
      JSON.stringify(
        {
          version: spec.info.version,
          operations: operations.map(({ id, name, method, path, tag }) => ({
            id,
            name,
            method,
            path,
            tag,
          })),
        },
        null,
        2,
      ),
    );
  else {
    const config = loadConfig(configPath);
    switch (positionals[0] || 'serve') {
      case 'serve':
        await serve(config);
        break;
      case 'status':
        console.log(
          JSON.stringify(
            {
              configured: config.configured,
              configPath,
              writeEnabled: config.writeEnabled || false,
              access: policy(config),
            },
            null,
            2,
          ),
        );
        break;
      case 'permit':
        if (!config.configured) throw new Error('SETUP_REQUIRED');
        console.log(
          JSON.stringify(
            grant(config, {
              sites: values.site,
              operations: values.operation,
              minutes: values.minutes === undefined ? 15 : Number(values.minutes),
            }),
            null,
            2,
          ),
        );
        break;
      case 'revoke':
        if (!config.configured) throw new Error('SETUP_REQUIRED');
        revoke(config);
        console.log('Read-only: all local write permits revoked.');
        break;
      case 'secret': {
        if (!config.configured || !process.stdin.isTTY) throw new Error('SETUP_REQUIRED');
        if (!values.name || values.name === 'api-key') throw new Error('INPUT_INVALID');
        const p = await prompts();
        try {
          const value = await p.ask('Secret value (hidden)', { secret: true });
          storeSecret(config, value, values.name);
          console.log('Stored locally. Reference it as @secret:' + values.name);
        } finally {
          p.close();
        }
        break;
      }
      default:
        throw new Error('INPUT_INVALID');
    }
  }
} catch (e) {
  console.error(safeError(e));
  process.exitCode = 1;
}
