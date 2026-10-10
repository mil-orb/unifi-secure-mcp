import { X509Certificate, timingSafeEqual, createHash } from 'node:crypto';
const secretKey =
  /password|passphrase|preshared|privatekey|secret|token|credential|certificate|authorization|apikey|psk|^key$|^pin$/i;
export function redact(value, secrets = []) {
  if (Array.isArray(value)) return value.map((v) => redact(v, secrets));
  if (value && typeof value === 'object')
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [
        k,
        secretKey.test(k.replace(/[^a-z0-9]/gi, '')) ? '[REDACTED]' : redact(v, secrets),
      ]),
    );
  if (typeof value === 'string')
    for (const key of secrets) if (key) value = value.replaceAll(key, '[REDACTED]');
  return value;
}
export function assertBoundedJson(value, depth = 0) {
  if (depth > 30) throw new Error('INPUT_INVALID');
  if (value && typeof value === 'object')
    for (const [k, v] of Object.entries(value)) {
      if (['__proto__', 'prototype', 'constructor'].includes(k)) throw new Error('INPUT_INVALID');
      assertBoundedJson(v, depth + 1);
    }
  if (typeof value === 'number' && !Number.isFinite(value)) throw new Error('INPUT_INVALID');
}
export function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object')
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((k) => [k, canonical(value[k])]),
    );
  return value;
}
export const hash = (value) =>
  createHash('sha256')
    .update(JSON.stringify(canonical(value)))
    .digest('hex');
export function certificateOptions(pem) {
  const pinned = new X509Certificate(pem).raw;
  return {
    ca: pem,
    rejectUnauthorized: true,
    minVersion: 'TLSv1.2',
    checkServerIdentity(_host, peer) {
      if (!peer.raw || peer.raw.length !== pinned.length || !timingSafeEqual(peer.raw, pinned))
        return new Error('TLS_PIN_CHANGED');
    },
  };
}
export const messages = {
  CONFIG_INVALID:
    'Configuration is invalid. Run the local setup command or review the config file.',
  SETUP_REQUIRED: 'Run unifi-secure-mcp setup locally first. Never paste credentials into chat.',
  INSECURE_FILE:
    'A private file has unsafe permissions or is a symbolic link. Repair local permissions before continuing.',
  CREDENTIAL_UNAVAILABLE:
    'The credential cannot be loaded. Run setup with the owning OS account; never print the key.',
  TLS_FAILED:
    'Secure connection failed. Check the router address and enrolled certificate; do not disable verification.',
  TIMEOUT: 'The router request timed out.',
  INPUT_INVALID: 'Input does not match the documented operation schema or safety limits.',
  RESPONSE_INVALID: 'The router returned an invalid or oversized response.',
  READ_ONLY:
    'Write execution is disabled or this operation/site is outside the active local permit.',
  PLAN_EXPIRED: 'The preview is missing, expired, or already consumed. Create a new preview.',
  PLAN_CONFIRMATION:
    'Confirmation must exactly match the preview. Obtain user approval for its actual effects first.',
  STALE_PLAN: 'The target changed since preview. No update was sent. Preview again.',
  WRITE_BUSY:
    'Another write is active, or a previous process left a lock. Review it locally; never remove a live writer lock.',
  AUDIT_UNAVAILABLE: 'Cannot persist the audit record. A new write will not start.',
  WRITE_UNCERTAIN:
    'The write was attempted but its outcome could not be confirmed. Inspect current state; never automatically retry.',
  SECRET_UNAVAILABLE:
    'A referenced local secret is missing or unsafe. Configure it locally without pasting it into chat.',
  SPEC_INVALID: 'The bundled API schema is invalid or incompatible.',
  OPERATION_UNAVAILABLE: 'The operation is disabled or absent from the bundled API version.',
};
export function safeError(e) {
  if (/^UPSTREAM_\d+$/.test(e?.message))
    return `UniFi returned HTTP ${e.message.slice(9)}. No upstream error body is exposed.`;
  return (
    messages[e?.message] ||
    'Request failed. No credential or upstream error body has been returned.'
  );
}
