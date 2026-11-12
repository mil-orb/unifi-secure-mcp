import https from 'node:https';
import { readFileSync } from 'node:fs';
import { buildRequest, byId } from './catalog.mjs';
import { assertPrivateFile, dataFile } from './config.mjs';
import { certificateOptions, redact, tlsError } from './security.mjs';
import { readSecret, reservedSecretName } from './storage.mjs';
import { version } from './version.mjs';
// Marks a failure that happened before any request byte reached the router, so a write
// that failed this way is known not to have been sent.
const notSent = (error) =>
  Object.assign(error instanceof Error ? error : new Error('TLS_FAILED'), { notSent: true });
export class UniFiClient {
  // The decrypted API key, read once per process (on Windows each read spawns
  // PowerShell). It is already held in this.secrets for redaction, so caching adds no
  // exposure. Cleared after 401/403 so a replaced key is picked up on the next call.
  #key;
  constructor(
    config,
    {
      authorize = () => {
        throw new Error('READ_ONLY');
      },
      request = https.request,
    } = {},
  ) {
    this.config = config;
    this.authorize = authorize;
    this.request = request;
    this.secrets = new Set();
  }
  clean(value) {
    return redact(value, [...this.secrets]);
  }
  resolveSecrets(value) {
    if (Array.isArray(value)) return value.map((v) => this.resolveSecrets(v));
    if (value && typeof value === 'object')
      return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, this.resolveSecrets(v)]));
    if (typeof value === 'string' && value.startsWith('@secret:')) {
      // The UniFi API key must never be copied into router configuration.
      if (reservedSecretName(value.slice(8))) throw new Error('INPUT_INVALID');
      const secret = readSecret(this.config, value.slice(8));
      this.secrets.add(secret);
      return secret;
    }
    return value;
  }
  resolveInput(input) {
    if (JSON.stringify({ path: input.path, query: input.query }).includes('@secret:'))
      throw new Error('INPUT_INVALID');
    return {
      ...input,
      ...(input.body === undefined ? {} : { body: this.resolveSecrets(input.body) }),
    };
  }
  // plan: the { id, requestHash } binding passed to authorize for a plan-bound permit.
  async call(operation, input, { raw = false, plan } = {}) {
    let op, url, method, tls, key, payload;
    try {
      if (!this.config.configured) throw new Error('SETUP_REQUIRED');
      op = typeof operation === 'string' ? byId.get(operation) : operation;
      if (!op || byId.get(op.id) !== op) throw new Error('OPERATION_UNAVAILABLE');
      const resolved = this.resolveInput(input),
        built = buildRequest(op, resolved, this.config.baseUrl);
      ({ url, method } = built);
      const cert = dataFile(this.config, 'router.pem');
      assertPrivateFile(cert);
      tls = certificateOptions(readFileSync(cert, 'utf8'));
      if (this.#key === undefined) {
        const read = readSecret(this.config);
        if (/[\r\n]/.test(read)) throw new Error('CREDENTIAL_UNAVAILABLE');
        this.secrets.add(read);
        this.#key = read;
      }
      key = this.#key;
      payload = built.body === undefined ? undefined : JSON.stringify(built.body);
      if (!op.readOnly) this.authorize(op, resolved, plan);
    } catch (error) {
      throw notSent(error);
    }
    // Until the TLS handshake with the pinned router completes, no request byte has left.
    let connected = false;
    const failure = (code) => (connected ? new Error(code) : notSent(new Error(code)));
    const result = await new Promise((resolve, reject) => {
      let settled = false;
      const finish = (error, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(deadline);
        error ? reject(error) : resolve(value);
      };
      let req;
      const deadline = setTimeout(() => {
        req?.destroy();
        finish(failure('TIMEOUT'));
      }, 15000);
      try {
        req = this.request(
          url,
          {
            ...tls,
            method,
            agent: false,
            headers: {
              Accept: 'application/json',
              'X-API-Key': key,
              'User-Agent': `unifi-secure-mcp/${version}`,
              ...(payload === undefined
                ? {}
                : {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(payload),
                  }),
            },
          },
          (res) => {
            if (res.statusCode < 200 || res.statusCode >= 300) {
              if (res.statusCode === 401 || res.statusCode === 403) this.#key = undefined;
              res.destroy();
              finish(new Error(`UPSTREAM_${res.statusCode}`));
              return;
            }
            if (res.statusCode === 204) {
              res.resume();
              finish(null, null);
              return;
            }
            if (!/^application\/json(?:;|$)/i.test(res.headers['content-type'] || '')) {
              res.destroy();
              finish(new Error('RESPONSE_INVALID'));
              return;
            }
            let size = 0;
            const chunks = [];
            res.on('data', (chunk) => {
              size += chunk.length;
              if (size > 2 * 1024 * 1024) {
                res.destroy();
                finish(new Error('RESPONSE_INVALID'));
              } else chunks.push(chunk);
            });
            res.on('error', () => finish(new Error('TLS_FAILED')));
            res.on('aborted', () => finish(new Error('TLS_FAILED')));
            res.on('end', () => {
              try {
                finish(null, JSON.parse(Buffer.concat(chunks).toString('utf8')));
              } catch {
                finish(new Error('RESPONSE_INVALID'));
              }
            });
          },
        );
        req.on('socket', (socket) => socket.once?.('secureConnect', () => (connected = true)));
        req.on('error', (error) => finish(failure(tlsError(error))));
        req.end(payload);
      } catch {
        finish(failure('TLS_FAILED'));
      }
    });
    return raw ? result : this.clean(result);
  }
}
