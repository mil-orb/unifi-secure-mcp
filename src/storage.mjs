import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  chmodSync,
  existsSync,
  renameSync,
  unlinkSync,
  lstatSync,
  readdirSync,
} from 'node:fs';
import { randomUUID } from 'node:crypto';
import { dirname, resolve, parse, join, sep } from 'node:path';
import { homedir } from 'node:os';
import { assertPrivateFile, dataFile } from './config.mjs';
import { runPowerShell } from './powershell.mjs';
// The UniFi API key's slot. Case-insensitive because Windows file names are.
export const reservedSecretName = (name) =>
  typeof name === 'string' && name.toLowerCase() === 'api-key';
// Written into every folder this application restricts. Securing a folder replaces the
// ACLs of everything inside it, so only new, empty, marked or application-created
// folders qualify.
export const privateMarker = '.unifi-secure-mcp-private';
// Names this application creates. Folders from 0.3.0 and earlier carry no marker.
const ownEntry =
  /^(?:\.unifi-secure-mcp-private|enrollment-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|router\.pem|permit\.json|audit\.jsonl|write\.lock|active-spec\.json|preview-[0-9a-f-]{36}\.json|[a-z0-9_-]{1,64}\.(?:dpapi|secret)|.+\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.tmp)$/i;
const pathKey = (p) => (process.platform === 'win32' ? p.toLowerCase() : p);
// known: extra entry names the caller expects (the config file, the data directory).
export function secureDirectory(path, { known = [] } = {}) {
  path = resolve(path);
  const home = pathKey(resolve(homedir())),
    target = pathKey(path).replace(/[\\/]+$/, '');
  // Never the drive root, the home directory or any ancestor of it, in any letter case.
  if (path === parse(path).root || home === target || home.startsWith(target + sep))
    throw new Error('INSECURE_FILE');
  let entries = [];
  try {
    if (!lstatSync(path).isDirectory()) throw new Error('INSECURE_FILE');
    entries = readdirSync(path);
  } catch (error) {
    if (error.code !== 'ENOENT') throw new Error('INSECURE_FILE');
  }
  if (
    entries.length &&
    !entries.includes(privateMarker) &&
    !entries.every((name) => ownEntry.test(name) || known.includes(name))
  )
    throw new Error('PRIVATE_DIR_NOT_DEDICATED');
  mkdirSync(path, { recursive: true, mode: 0o700 });
  if (!entries.includes(privateMarker))
    writeFileSync(
      join(path, privateMarker),
      'Private folder of unifi-secure-mcp. Setup restricts it and everything inside to one account.\n',
      { mode: 0o600 },
    );
  if (process.platform !== 'win32') chmodSync(path, 0o700);
  else
    runPowerShell(
      'protect-data.ps1',
      ['-Path', path],
      { stdio: ['ignore', 'pipe', 'pipe'], timeout: 15000 },
      'INSECURE_FILE',
    );
}
export function writePrivate(path, contents) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  if (existsSync(path)) assertPrivateFile(path);
  const temporary = path + '.' + randomUUID() + '.tmp';
  try {
    writeFileSync(temporary, contents, { mode: 0o600, flag: 'wx' });
    renameSync(temporary, path);
  } finally {
    if (existsSync(temporary)) unlinkSync(temporary);
  }
}
export function storeSecret(config, value, name = 'api-key') {
  if (
    !/^[a-zA-Z0-9_-]{1,64}$/.test(name) ||
    typeof value !== 'string' ||
    !value ||
    value.length > 8192
  )
    throw new Error('SECRET_UNAVAILABLE');
  const suffix = config.credentialStore === 'dpapi' ? '.dpapi' : '.secret';
  const path = dataFile(config, name + suffix);
  secureDirectory(config.dataDir);
  if (existsSync(path)) assertPrivateFile(path);
  if (config.credentialStore === 'dpapi')
    runPowerShell(
      'secret.ps1',
      ['-Mode', 'Store', '-Path', path],
      { input: value, stdio: ['pipe', 'pipe', 'pipe'], timeout: 10000, maxBuffer: 16384 },
      'SECRET_UNAVAILABLE',
    );
  else writePrivate(path, value);
}
export function readSecret(config, name = 'api-key') {
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(name)) throw new Error('SECRET_UNAVAILABLE');
  try {
    const path = dataFile(
      config,
      name + (config.credentialStore === 'dpapi' ? '.dpapi' : '.secret'),
    );
    assertPrivateFile(path);
    const value =
      config.credentialStore === 'dpapi'
        ? runPowerShell(
            'secret.ps1',
            ['-Mode', 'Read', '-Path', path],
            {
              encoding: 'utf8',
              stdio: ['ignore', 'pipe', 'pipe'],
              timeout: 10000,
              maxBuffer: 16384,
            },
            'SECRET_UNAVAILABLE',
          )
        : readFileSync(path, 'utf8');
    if (!value || value.length > 8192) throw new Error();
    return value;
  } catch (error) {
    // A script PowerShell refused to run is reported as such, not as a missing key.
    if (error.message === 'POWERSHELL_BLOCKED') throw error;
    throw new Error(name === 'api-key' ? 'CREDENTIAL_UNAVAILABLE' : 'SECRET_UNAVAILABLE');
  }
}
export function ready(config) {
  return Boolean(
    config.configured &&
      existsSync(dataFile(config, 'router.pem')) &&
      existsSync(
        dataFile(config, 'api-key' + (config.credentialStore === 'dpapi' ? '.dpapi' : '.secret')),
      ),
  );
}
// The schema the last server start loaded for this enrollment (best effort), so the
// local permit command validates operation IDs against the same schema.
export function recordActiveSpec(config, active) {
  try {
    writePrivate(
      dataFile(config, 'active-spec.json'),
      JSON.stringify({ loaded: active.loaded, detected: active.detected, match: active.match }),
    );
  } catch {}
}
export function lastActiveSpec(config) {
  try {
    const path = dataFile(config, 'active-spec.json');
    assertPrivateFile(path);
    return JSON.parse(readFileSync(path, 'utf8'))?.loaded;
  } catch {
    return undefined;
  }
}
