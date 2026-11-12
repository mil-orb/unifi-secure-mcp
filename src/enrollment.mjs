import { readdirSync, lstatSync, rmSync } from 'node:fs';
import { resolve, dirname, basename } from 'node:path';
const generation = /^enrollment-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const hex = (value) =>
  String(value)
    .replace(/[^a-f0-9]/gi, '')
    .toUpperCase();
// Asks for the fingerprint the user sees in a trusted browser session BEFORE showing the
// probe's value, so pasting back what setup printed cannot pass the check. The probe's
// fingerprint is shown only after a mismatch, to help diagnose it.
export async function confirmFingerprint(cert, ask, log, now = Date.now()) {
  if (Date.parse(cert.validTo) <= now || Date.parse(cert.validFrom) > now)
    throw new Error('TLS_CERT_EXPIRED');
  log(
    `\nRouter certificate received (valid until ${cert.validTo}). This probe sent NO API key.\nOpen the router's web interface in a browser session you already trust, view its certificate, and copy the SHA-256 fingerprint shown there. Setup does not display the fingerprint first, so your entry is an independent check.`,
  );
  const entered = hex(await ask('SHA-256 fingerprint from your browser'));
  if (!entered || entered !== hex(cert.fingerprint256)) {
    log(
      `\nMismatch. The router presented SHA-256 ${cert.fingerprint256}. If your trusted browser shows a different value, do not continue: something may be intercepting the connection.`,
    );
    throw new Error('TLS_FINGERPRINT_MISMATCH');
  }
}
// Credential generations (enrollment-<uuid>) directly inside the data directory.
export function enrollments(dataDir) {
  return readdirSync(dataDir, { withFileTypes: true })
    .filter((d) => d.isDirectory() && generation.test(d.name))
    .map((d) => resolve(dataDir, d.name));
}
// Deletes one generation folder: its router.pem, encrypted API key, permits and audit log.
export function removeEnrollment(dataDir, path) {
  path = resolve(path);
  if (
    dirname(path) !== resolve(dataDir) ||
    !generation.test(basename(path)) ||
    !lstatSync(path).isDirectory()
  )
    throw new Error('INPUT_INVALID');
  rmSync(path, { recursive: true, force: true });
}
