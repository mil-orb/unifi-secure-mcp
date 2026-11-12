import { X509Certificate, timingSafeEqual, createHash } from 'node:crypto';
export const REDACTED = '[REDACTED]';
const secretKey =
  /password|passphrase|preshared|privatekey|secret|token|credential|certificate|authorization|apikey|psk|^key$|^pin$/i;
// Documented non-secret fields that secretKey would otherwise hide: guest-authorization
// metadata (timestamps, limits, usage) and Wi-Fi network references.
const notSecret = new Set([
  'authorizationmethod',
  'grantedauthorization',
  'revokedauthorization',
  'presharedkeynetworkids',
]);
export const isSecretKey = (k) => {
  const name = k.replace(/[^a-z0-9]/gi, '');
  return secretKey.test(name) && !notSecret.has(name.toLowerCase());
};
// Preview aid: every secret-named field of a request body, described without its value
// as a @secret:NAME reference, a hidden literal, or omitted (set in `before`, absent from
// the body). Both the body and `before` are redacted in a preview, so one shared marker
// could not tell these apart.
export function secretFields(body, before) {
  const out = [];
  const join = (at, k) => (at ? `${at}.${k}` : k);
  const omitted = (prior, at) => {
    if (!prior || typeof prior !== 'object') return;
    for (const [k, v] of Object.entries(prior))
      if (isSecretKey(k)) {
        if (v !== null && v !== undefined) out.push({ field: join(at, k), value: 'omitted' });
      } else omitted(v, join(at, k));
  };
  const walk = (value, prior, at) => {
    if (!value || typeof value !== 'object') return;
    for (const [k, v] of Object.entries(value))
      if (isSecretKey(k))
        out.push({
          field: join(at, k),
          value: typeof v === 'string' && v.startsWith('@secret:') ? v : 'literal (hidden)',
        });
      else walk(v, prior?.[k], join(at, k));
    if (prior && typeof prior === 'object' && Array.isArray(prior) === Array.isArray(value))
      for (const [k, v] of Object.entries(prior))
        if (!Object.hasOwn(value, k)) omitted({ [k]: v }, at);
  };
  walk(body, before, '');
  return out;
}
// Router JSON is parsed without a depth limit, but these walks recurse. Far deeper than
// any documented response, and far below the stack limit.
const maxDepth = 64;
export function redact(value, secrets = [], depth = 0) {
  if (depth > maxDepth) throw new Error('RESPONSE_INVALID');
  if (Array.isArray(value)) return value.map((v) => redact(v, secrets, depth + 1));
  if (value && typeof value === 'object')
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [
        k,
        isSecretKey(k) ||
        (k === 'code' &&
          ['authorizedGuestCount', 'authorizedGuestLimit', 'timeLimitMinutes'].some((field) =>
            Object.hasOwn(value, field),
          ))
          ? REDACTED
          : redact(v, secrets, depth + 1),
      ]),
    );
  if (typeof value === 'string')
    for (const key of secrets) if (key) value = value.replaceAll(key, REDACTED);
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
export function canonical(value, depth = 0) {
  if (depth > maxDepth) throw new Error('RESPONSE_INVALID');
  if (Array.isArray(value)) return value.map((v) => canonical(v, depth + 1));
  if (value && typeof value === 'object')
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((k) => [k, canonical(value[k], depth + 1)]),
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
    // The enrolled leaf is the only trust anchor, even when it was issued by a CA
    // (custom or ACME certificate) whose root is not trusted here. Validity dates are
    // still checked, and checkServerIdentity below pins the exact bytes.
    allowPartialTrustChain: true,
    rejectUnauthorized: true,
    minVersion: 'TLSv1.2',
    checkServerIdentity(_host, peer) {
      if (!peer.raw || peer.raw.length !== pinned.length || !timingSafeEqual(peer.raw, pinned))
        return new Error('TLS_PIN_CHANGED');
    },
  };
}
// OpenSSL codes meaning the peer did not present the enrolled certificate.
const otherCertificate = new Set([
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'CERT_SIGNATURE_FAILURE',
]);
export function tlsError(error) {
  if (error?.message === 'TLS_PIN_CHANGED' || otherCertificate.has(error?.code))
    return 'TLS_PIN_CHANGED';
  if (['CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'].includes(error?.code)) return 'TLS_CERT_EXPIRED';
  return 'TLS_FAILED';
}
export const messages = {
  PERMISSION_CHECK_TIMEOUT:
    'Local permission validation timed out. Retry when the OS is responsive; do not bypass permission checks.',
  CONFIG_INVALID:
    'Configuration is invalid. Run the local setup command or review the config file.',
  SETUP_REQUIRED: 'Run unifi-secure-mcp setup locally first. Never paste credentials into chat.',
  INSECURE_FILE:
    'A private file has unsafe permissions or is a symbolic link. Repair local permissions before continuing.',
  CREDENTIAL_UNAVAILABLE:
    'The credential cannot be loaded. Run setup with the owning OS account; never print the key.',
  TLS_FAILED:
    'Secure connection failed. Check the router address and enrolled certificate; do not disable verification.',
  TLS_PIN_CHANGED:
    'The router presented a certificate other than the enrolled one. Do not bypass this: verify the new certificate independently, then re-run setup.',
  TLS_CERT_EXPIRED:
    'The router certificate has expired or is not yet valid. Renew it on the router, verify the new fingerprint independently, then re-run setup.',
  TLS_FINGERPRINT_MISMATCH:
    'The fingerprint you entered does not match the certificate the router presented. Setup stopped; nothing was stored.',
  POWERSHELL_BLOCKED:
    'Windows PowerShell could not run a bundled helper script (for example, execution policy set by Group Policy, or a downloaded copy that Windows blocked). See Troubleshooting in docs/SETUP.md; do not weaken private-storage permissions.',
  PRIVATE_DIR_NOT_DEDICATED:
    'Choose a new or empty folder used only by this MCP. Setup restricts the folder and everything inside it to your account, so it refuses a folder that already holds other files.',
  TIMEOUT: 'The router request timed out.',
  INPUT_INVALID: 'Input does not match the documented operation schema or safety limits.',
  REDACTED_VALUE:
    'A redacted value ([REDACTED]) cannot be sent. Omit the field if the API allows it, or reference a locally stored secret as @secret:NAME.',
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
