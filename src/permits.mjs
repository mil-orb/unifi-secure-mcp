import {
  readFileSync,
  openSync,
  closeSync,
  writeSync,
  fsyncSync,
  unlinkSync,
  existsSync,
} from 'node:fs';
import { randomUUID } from 'node:crypto';
import { dataFile, assertPrivateFile } from './config.mjs';
import { writePrivate } from './storage.mjs';
import { byId } from './catalog.mjs';
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
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
      !p.operations.every((id) => byId.has(id) && !byId.get(id).readOnly)
    )
      return { mode: 'read-only' };
    return { ...p, mode: 'read-write' };
  } catch {
    return { mode: 'read-only' };
  }
}
export function authorize(config, op, input) {
  const p = policy(config);
  if (
    p.mode !== 'read-write' ||
    !p.operations.includes(op.id) ||
    !p.sites.includes(input.path?.siteId)
  )
    throw new Error('READ_ONLY');
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
