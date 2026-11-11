import { homedir } from 'node:os';
import { resolve, dirname, isAbsolute } from 'node:path';
import { readFileSync, existsSync, lstatSync } from 'node:fs';
import { bundledSpecs } from './catalog.mjs';
import { runPowerShell } from './powershell.mjs';
export const defaultConfigPath = () => resolve(homedir(), '.unifi-secure-mcp', 'config.json');
export function parseOrigin(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error('CONFIG_INVALID');
  }
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.pathname !== '/' ||
    url.search ||
    url.hash
  )
    throw new Error('CONFIG_INVALID');
  return url.origin;
}
export function loadConfig(path = process.env.UNIFI_MCP_CONFIG || defaultConfigPath()) {
  path = resolve(path);
  if (!existsSync(path)) return { configured: false, path };
  assertPrivateFile(path);
  let data;
  try {
    data = JSON.parse(readFileSync(path, 'utf8').replace(/^\uFEFF/, ''));
  } catch {
    throw new Error('CONFIG_INVALID');
  }
  // A config file holding null, an array or a scalar is invalid, not a TypeError.
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('CONFIG_INVALID');
  const allowed = [
    'version',
    'baseUrl',
    'dataDir',
    'credentialStore',
    'writeEnabled',
    'toolsets',
    'specVersion',
  ];
  if (
    Object.keys(data).some((k) => !allowed.includes(k)) ||
    data.version !== 1 ||
    !isAbsolute(data.dataDir || '') ||
    !['dpapi', 'file'].includes(data.credentialStore) ||
    typeof data.writeEnabled !== 'boolean' ||
    (data.toolsets !== undefined &&
      (!Array.isArray(data.toolsets) || !data.toolsets.every((t) => typeof t === 'string'))) ||
    (data.specVersion !== undefined && !bundledSpecs.includes(data.specVersion))
  )
    throw new Error('CONFIG_INVALID');
  if (data.credentialStore === 'dpapi' && process.platform !== 'win32')
    throw new Error('CONFIG_INVALID');
  if (process.platform === 'win32')
    runPowerShell(
      'check-private.ps1',
      ['-ConfigPath', path, '-DataDirectory', data.dataDir],
      { stdio: ['ignore', 'pipe', 'pipe'], timeout: 30000 },
      'INSECURE_FILE',
      'PERMISSION_CHECK_TIMEOUT',
    );
  return Object.freeze({
    ...data,
    path,
    baseUrl: parseOrigin(data.baseUrl),
    dataDir: resolve(data.dataDir),
    configured: true,
  });
}
export function assertPrivateFile(path) {
  const st = lstatSync(path);
  if (
    st.isSymbolicLink() ||
    !st.isFile() ||
    (process.platform !== 'win32' &&
      ((st.mode & 0o077) !== 0 || (process.getuid && st.uid !== process.getuid())))
  )
    throw new Error('INSECURE_FILE');
}
export const dataFile = (config, name) => resolve(config.dataDir, name);
export const configDirectory = (path) => dirname(resolve(path));
