import https from 'node:https';
import { readFileSync } from 'node:fs';
import { buildRequest, byId } from './catalog.mjs';
import { assertPrivateFile, dataFile } from './config.mjs';
import { certificateOptions, redact } from './security.mjs';
import { readSecret } from './storage.mjs';
export class UniFiClient {
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
  async call(operation, input, { raw = false } = {}) {
    if (!this.config.configured) throw new Error('SETUP_REQUIRED');
    const op = typeof operation === 'string' ? byId.get(operation) : operation;
    if (!op || byId.get(op.id) !== op) throw new Error('OPERATION_UNAVAILABLE');
    const resolved = this.resolveInput(input),
      { url, method, body } = buildRequest(op, resolved, this.config.baseUrl);
    const cert = dataFile(this.config, 'router.pem');
    assertPrivateFile(cert);
    const tls = certificateOptions(readFileSync(cert, 'utf8'));
    const key = readSecret(this.config);
    if (/[\r\n]/.test(key)) throw new Error('CREDENTIAL_UNAVAILABLE');
    this.secrets.add(key);
    const payload = body === undefined ? undefined : JSON.stringify(body);
    if (!op.readOnly) this.authorize(op, resolved);
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
        finish(new Error('TIMEOUT'));
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
              'User-Agent': 'unifi-secure-mcp/0.2.0',
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
        req.on('error', () => finish(new Error('TLS_FAILED')));
        req.end(payload);
      } catch {
        finish(new Error('TLS_FAILED'));
      }
    });
    return raw ? result : this.clean(result);
  }
}
