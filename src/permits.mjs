import {
  readFileSync,
  openSync,
  closeSync,
  writeSync,
  fsyncSync,
  unlinkSync,
  existsSync,
  readdirSync,
} from 'node:fs';
import { randomUUID } from 'node:crypto';
import { dataFile, assertPrivateFile } from './config.mjs';
import { writePrivate } from './storage.mjs';
import { byId } from './catalog.mjs';
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const sha256 = /^[0-9a-f]{64}$/;
// A plan-bound permit (permit --plan) names exactly one previewed request.
const validBinding = (p) =>
  p.plan === undefined ||
  (Boolean(p.plan) &&
    uuid.test(p.plan.id) &&
    sha256.test(p.plan.requestHash) &&
    p.sites.length === 1 &&
    p.operations.length === 1);
export function policy(config, now = Date.now()) {
  if (!config.configured || !config.writeEnabled) return { mode: 'read-only' };
  try {
    const path = dataFile(config, 'permit.json');
    assertPrivateFile(path);
    const p = JSON.parse(readFileSync(path, 'utf8'));
    const issued = Date.parse(p.issuedAt),
      expiry = Date.parse(p.expiresAt);
    if (
      !Number.isFinite(issued) ||
      !Number.isFinite(expiry) ||
      issued > now ||
      expiry <= now ||
      expiry - issued > 3600000 ||
      expiry <= issued ||
      !uuid.test(p.id) ||
      !Array.isArray(p.sites) ||
      !p.sites.length ||
      !p.sites.every((s) => uuid.test(s)) ||
      !Array.isArray(p.operations) ||
      !p.operations.length ||
      !p.operations.every((id) => byId.has(id) && !byId.get(id).readOnly) ||
      !validBinding(p)
    )
      return { mode: 'read-only' };
    return { ...p, mode: 'read-write' };
  } catch {
    return { mode: 'read-only' };
  }
}
// plan: { id, requestHash } of the plan being applied. Operation/site permits ignore it;
// a plan-bound permit accepts only that exact plan.
export function authorize(config, op, input, plan) {
  const p = policy(config);
  if (
    p.mode !== 'read-write' ||
    !p.operations.includes(op.id) ||
    !p.sites.includes(input.path?.siteId) ||
    (p.plan && (plan?.id !== p.plan.id || plan?.requestHash !== p.plan.requestHash))
  )
    throw new Error('READ_ONLY');
}
// Previews are shared with the local `permit --plan` command through private files, so
// the human sees the exact request in their own terminal before authorizing it.
const previewName = /^preview-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.json$/;
const previewFile = (config, id) => {
  if (!uuid.test(id)) throw new Error('INPUT_INVALID');
  return dataFile(config, `preview-${id.toLowerCase()}.json`);
};
export function sharePreview(config, preview, now = Date.now()) {
  for (const name of readdirSync(config.dataDir))
    if (previewName.test(name))
      try {
        const old = JSON.parse(readFileSync(dataFile(config, name), 'utf8'));
        if (!(Date.parse(old.expiresAt) > now)) unlinkSync(dataFile(config, name));
      } catch {}
  writePrivate(previewFile(config, preview.planId), JSON.stringify(preview, null, 2));
}
export function readPreview(config, id, now = Date.now()) {
  let p;
  try {
    const path = previewFile(config, id);
    assertPrivateFile(path);
    p = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    throw new Error('PLAN_EXPIRED');
  }
  if (
    p?.planId?.toLowerCase() !== id.toLowerCase() ||
    typeof p.operation !== 'string' ||
    !uuid.test(p.siteId) ||
    !sha256.test(p.requestHash) ||
    !(Date.parse(p.expiresAt) > now)
  )
    throw new Error('PLAN_EXPIRED');
  return p;
}
export function removePreview(config, id) {
  try {
    unlinkSync(previewFile(config, id));
  } catch {}
}
// One-time permit for exactly one previewed request. requestHash is the value the user
// was shown; a preview that changed since then is refused. Expires with the preview.
export function grantPlan(config, id, requestHash, now = Date.now()) {
  if (!config.writeEnabled) throw new Error('INPUT_INVALID');
  const shared = readPreview(config, id, now);
  if (shared.requestHash !== requestHash) throw new Error('STALE_PLAN');
  if (!byId.has(shared.operation) || byId.get(shared.operation).readOnly)
    throw new Error('INPUT_INVALID');
  const p = {
    id: randomUUID(),
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(Math.min(Date.parse(shared.expiresAt), now + 3600000)).toISOString(),
    sites: [shared.siteId],
    operations: [shared.operation],
    plan: { id: shared.planId, requestHash },
  };
  writePrivate(dataFile(config, 'permit.json'), JSON.stringify(p, null, 2));
  return p;
}
export function grant(config, { sites, operations, minutes = 15 }) {
  if (
    !config.writeEnabled ||
    !Number.isInteger(minutes) ||
    minutes < 1 ||
    minutes > 60 ||
    !sites?.length ||
    !sites.every((s) => uuid.test(s)) ||
    !operations?.length ||
    !operations.every((id) => byId.has(id) && !byId.get(id).readOnly)
  )
    throw new Error('INPUT_INVALID');
  const now = Date.now();
  const p = {
    id: randomUUID(),
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + minutes * 60000).toISOString(),
    sites,
    operations,
  };
  writePrivate(dataFile(config, 'permit.json'), JSON.stringify(p, null, 2));
  return p;
}
export function revoke(config) {
  writePrivate(dataFile(config, 'permit.json'), '{}');
}
export function lock(config) {
  const path = dataFile(config, 'write.lock');
  let fd;
  try {
    fd = openSync(path, 'wx', 0o600);
    writeSync(fd, JSON.stringify({ pid: process.pid, at: new Date().toISOString() }));
    closeSync(fd);
  } catch {
    if (fd !== undefined)
      try {
        closeSync(fd);
      } catch {}
    throw new Error('WRITE_BUSY');
  }
  return () => {
    try {
      unlinkSync(path);
    } catch {}
  };
}
export function record(config, event) {
  let fd;
  try {
    const path = dataFile(config, 'audit.jsonl');
    if (existsSync(path)) assertPrivateFile(path);
    fd = openSync(path, 'a', 0o600);
    writeSync(
      fd,
      JSON.stringify({ at: new Date().toISOString(), pid: process.pid, ...event }) + '\n',
    );
    fsyncSync(fd);
  } catch {
    throw new Error('AUDIT_UNAVAILABLE');
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}
