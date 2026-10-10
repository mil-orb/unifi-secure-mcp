import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  chmodSync,
  existsSync,
  renameSync,
  unlinkSync,
  lstatSync,
} from 'node:fs';
import { randomUUID } from 'node:crypto';
import { dirname, resolve, parse } from 'node:path';
import { homedir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { assertPrivateFile, dataFile } from './config.mjs';
const powershell = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
export function secureDirectory(path) {
  path = resolve(path);
  if (path === parse(path).root || path === homedir()) throw new Error('INSECURE_FILE');
  mkdirSync(path, { recursive: true, mode: 0o700 });
  if (process.platform !== 'win32') chmodSync(path, 0o700);
  else
    execFileSync(
      powershell,
      [
        '-NoProfile',
        '-NonInteractive',
        '-File',
        fileURLToPath(new URL('../scripts/protect-data.ps1', import.meta.url)),
        '-Path',
        path,
      ],
      { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'], timeout: 15000 },
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
    execFileSync(
      powershell,
      [
        '-NoProfile',
        '-NonInteractive',
        '-File',
        fileURLToPath(new URL('../scripts/secret.ps1', import.meta.url)),
        '-Mode',
        'Store',
        '-Path',
        path,
      ],
      {
        input: value,
        windowsHide: true,
        stdio: ['pipe', 'pipe', 'pipe'],
        timeout: 10000,
        maxBuffer: 16384,
      },
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
        ? execFileSync(
            powershell,
            [
              '-NoProfile',
              '-NonInteractive',
              '-File',
              fileURLToPath(new URL('../scripts/secret.ps1', import.meta.url)),
              '-Mode',
              'Read',
              '-Path',
              path,
            ],
            {
              encoding: 'utf8',
              windowsHide: true,
              stdio: ['ignore', 'pipe', 'pipe'],
              timeout: 10000,
              maxBuffer: 16384,
            },
          )
        : readFileSync(path, 'utf8');
    if (!value || value.length > 8192) throw new Error();
    return value;
  } catch {
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
