#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { createInterface } from 'node:readline/promises';
import { Writable } from 'node:stream';
import tls from 'node:tls';
import { X509Certificate, randomUUID } from 'node:crypto';
import { resolve, dirname, basename } from 'node:path';
import { readFileSync, existsSync } from 'node:fs';
import { defaultConfigPath, loadConfig, parseOrigin, dataFile } from './config.mjs';
import {
  secureDirectory,
  writePrivate,
  storeSecret,
  reservedSecretName,
  lastActiveSpec,
} from './storage.mjs';
import { grant, grantPlan, readPreview, revoke, policy } from './permits.mjs';
import { safeError } from './security.mjs';
import { operations, spec, bundledSpecs, activateSpec } from './catalog.mjs';
import { version } from './version.mjs';
import { UniFiClient } from './client.mjs';
import { serve } from './server.mjs';
import { confirmFingerprint, enrollments, removeEnrollment } from './enrollment.mjs';
const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    config: { type: 'string' },
    site: { type: 'string', multiple: true },
    operation: { type: 'string', multiple: true },
    minutes: { type: 'string' },
    plan: { type: 'string' },
    name: { type: 'string' },
    help: { type: 'boolean' },
    'no-detect': { type: 'boolean' },
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
      // readline draws the prompt itself: in terminal mode it clears the current
      // line first, which would erase a question written separately to stdout.
      // question() draws synchronously, so muting starts after the prompt is shown.
      const pending = rl.question(
        question + (fallback !== undefined ? ` [${fallback}]` : '') + ': ',
      );
      muted = secret;
      const answer = await pending;
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
      `UniFi Secure MCP ${version} · local setup · unofficial Ubiquiti integration\nBundled Network API schemas: ${bundledSpecs.join(', ')}; the closest match to the router's reported version is selected at startup. No remote MCP listener is installed.\nNever paste credentials into a chat. Setup accepts your key only through hidden local input.`,
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
    await confirmFingerprint(cert, (q) => p.ask(q), console.log);
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
    // Only new, empty or application-created folders are restricted (see secureDirectory).
    const configDir = dirname(configPath);
    secureDirectory(configDir, {
      known: [basename(configPath), ...(dirname(dataDir) === configDir ? [basename(dataDir)] : [])],
    });
    secureDirectory(dataDir);
    let info;
    try {
      secureDirectory(config.dataDir);
      writePrivate(dataFile(config, 'router.pem'), cert.toString());
      storeSecret(config, key);
      revoke(config);
      info = await new UniFiClient({ ...config, configured: true }).call('getInfo', {});
    } catch (error) {
      // A failed generation must not leave an API key behind.
      try {
        removeEnrollment(dataDir, config.dataDir);
      } catch {}
      throw error;
    }
    writePrivate(configPath, JSON.stringify(config, null, 2));
    console.log(
      `\nSetup verified. Network ${info.applicationVersion || 'connected'}. Mode: read-only${config.writeEnabled ? ' (write tool available; no permit active)' : ''}.\nConfig: ${configPath}\n${process.platform === 'win32' ? 'Key storage: Windows DPAPI, current user.' : 'Key storage: local owner-only file (not encrypted); use an encrypted volume/OS key management for stronger at-rest protection.'}\nRestart your MCP host after registering the server. See docs/SETUP.md for Codex and standard MCP configuration.`,
    );
    const older = enrollments(dataDir).filter((path) => path !== resolve(config.dataDir));
    if (older.length) {
      console.log(
        `\n${older.length} older enrollment folder(s) remain in ${dataDir}. Each holds a previous API key (encrypted), certificate, permits and audit log. MCP processes still running with the old configuration stop working once they are deleted; restart them.`,
      );
      if ((await p.ask('Delete them now? Type DELETE to confirm')) === 'DELETE') {
        for (const path of older) removeEnrollment(dataDir, path);
        console.log(`Deleted ${older.length} older enrollment folder(s).`);
      } else console.log('Kept. Setup offers this again the next time it runs.');
      console.log('Also revoke the old API keys in UniFi Network > Integrations.');
    }
  } finally {
    p.close();
  }
}
// permit --plan: the human reads the exact previewed request in their own terminal and
// authorizes only that request, once, until the preview expires.
async function permitPlan(config, planId) {
  if (values.site || values.operation || values.minutes !== undefined || !process.stdin.isTTY)
    throw new Error('INPUT_INVALID');
  const shared = readPreview(config, planId);
  if (bundledSpecs.includes(shared.specVersion)) activateSpec(shared.specVersion);
  const { operation, method, path, siteId, request, sensitiveFields, requestHash } = shared;
  console.log(
    JSON.stringify(
      {
        planId: shared.planId,
        operation,
        method,
        path,
        siteId,
        request,
        sensitiveFields,
        requestHash,
      },
      null,
      2,
    ),
  );
  console.log(
    `\nThis permit authorizes exactly the request above, once, until ${shared.expiresAt}. [REDACTED] hides secret values; sensitiveFields says whether each is a @secret reference, a new literal or omitted. Grant it only if this is the change you asked for.`,
  );
  const p = await prompts();
  let answer;
  try {
    answer = await p.ask('Grant a one-time permit for this request? Type YES');
  } finally {
    p.close();
  }
  if (answer !== 'YES') {
    console.log('No permit granted.');
    return;
  }
  console.log(JSON.stringify(grantPlan(config, planId, requestHash), null, 2));
}
try {
  if (values.version) {
    console.log(`unifi-secure-mcp ${version}`);
  } else if (values.help || positionals[0] === 'help') {
    console.log(
      'unifi-secure-mcp <serve|setup|status|operations|permit|revoke|secret> [--config ABSOLUTE_PATH]\n\nsetup       Guided certificate/key/access setup (interactive terminal)\nserve       MCP over STDIO; protocol output only (--no-detect: skip the startup version read)\nstatus      Local access and readiness information\noperations  All operations in the pinned API schema\npermit      --plan PLAN_ID (interactive: shows that preview, authorizes only it, once)\n            --site UUID --operation OPERATION_ID [--minutes 15] (flags repeatable)\nrevoke      Disable all writes immediately\nsecret      --name NAME (hidden local input; use @secret:NAME in request bodies)\n\nDefault: read-only. No insecure TLS flag or credential command-line option.',
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
        await serve(config, { detect: !values['no-detect'] });
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
        if (values.plan !== undefined) {
          await permitPlan(config, values.plan);
          break;
        }
        {
          // Validate operation IDs against the schema the server uses: the pin, else the
          // one the last server start loaded, else the newest bundled one.
          const last = lastActiveSpec(config);
          const version = config.specVersion ?? (bundledSpecs.includes(last) ? last : undefined);
          if (version) activateSpec(version);
          console.error(
            `Operation IDs checked against Network API schema ${spec.info.version} (${config.specVersion ? 'pinned in config' : version ? 'loaded by the last server start' : 'newest bundled; no server start recorded yet'}).`,
          );
        }
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
        if (!values.name || reservedSecretName(values.name)) throw new Error('INPUT_INVALID');
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
