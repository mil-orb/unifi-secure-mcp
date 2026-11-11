// Review R1 Batch B: Windows, setup and runtime robustness. Synthetic data only;
// addresses, MACs and fingerprints are built at runtime.
import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  mkdtempSync,
  mkdirSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
  copyFileSync,
} from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { secureDirectory, writePrivate, privateMarker } from '../src/storage.mjs';
import { loadConfig } from '../src/config.mjs';
import { UniFiClient } from '../src/client.mjs';
import { redact, hash, canonical, tlsError, safeError, messages } from '../src/security.mjs';
import {
  powershell,
  powershellPath,
  powershellArgs,
  powershellError,
  runPowerShell,
} from '../src/powershell.mjs';
import { confirmFingerprint, enrollments, removeEnrollment } from '../src/enrollment.mjs';
const root = fileURLToPath(new URL('../', import.meta.url));
const openssl =
  process.platform === 'win32' ? 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe' : 'openssl';
const uid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const temp = (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'unifi-mcp-test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
};

test('M3: privacy scans unstaged edits, untracked files and the index', (t) => {
  const repo = temp(t);
  const git = (...args) =>
    execFileSync(
      'git',
      ['-C', repo, '-c', 'user.name=t', '-c', 'user.email=t@example.invalid', ...args],
      { stdio: 'ignore' },
    );
  mkdirSync(join(repo, 'scripts'));
  copyFileSync(join(root, 'scripts/privacy.mjs'), join(repo, 'scripts/privacy.mjs'));
  writeFileSync(join(repo, 'README.md'), 'clean\n');
  writeFileSync(join(repo, '.gitignore'), 'ignored.md\n');
  git('init', '-q');
  git('add', '.');
  git('-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'init');
  const scan = () => {
    const r = spawnSync(process.execPath, [join(repo, 'scripts/privacy.mjs')], {
      encoding: 'utf8',
    });
    return { status: r.status, out: r.stdout + r.stderr };
  };
  assert.equal(scan().status, 0);
  const address = [192, 0, 2, 7].join('.');
  const mac = Array(6).fill('0a').join(':');
  writeFileSync(join(repo, 'ignored.md'), address);
  assert.equal(scan().status, 0, 'git-ignored files are not publishable');
  writeFileSync(join(repo, 'README.md'), `clean\n${address}\n`);
  let r = scan();
  assert.equal(r.status, 1, 'unstaged edit');
  assert.match(r.out, /README\.md: possible deployment address/);
  git('add', 'README.md');
  writeFileSync(join(repo, 'README.md'), 'clean\n');
  r = scan();
  assert.equal(r.status, 1, 'staged bytes are still scanned after the working tree is cleaned');
  git('reset', '-q', 'README.md');
  assert.equal(scan().status, 0);
  mkdirSync(join(repo, 'src'));
  writeFileSync(join(repo, 'src/new.mjs'), `// ${mac}\n`);
  r = scan();
  assert.equal(r.status, 1, 'untracked file');
  assert.match(r.out, /src\/new\.mjs: possible deployment address/);
});

test('M4: setup restricts only new, empty, marked or application-created folders', (t) => {
  const base = temp(t);
  const unrelated = join(base, 'Documents');
  mkdirSync(unrelated);
  writeFileSync(join(unrelated, 'notes.md'), 'mine');
  assert.throws(() => secureDirectory(unrelated), /PRIVATE_DIR_NOT_DEDICATED/);
  assert.ok(!existsSync(join(unrelated, privateMarker)), 'refused before any change');
  assert.match(safeError(new Error('PRIVATE_DIR_NOT_DEDICATED')), /new or empty folder/);
  // A config file the caller expects does not make an unrelated folder acceptable.
  writeFileSync(join(unrelated, 'config.json'), '{}');
  assert.throws(
    () => secureDirectory(unrelated, { known: ['config.json'] }),
    /PRIVATE_DIR_NOT_DEDICATED/,
  );
  const fresh = join(base, 'fresh');
  secureDirectory(fresh);
  assert.ok(existsSync(join(fresh, privateMarker)));
  writeFileSync(join(fresh, 'anything.txt'), 'x');
  secureDirectory(fresh); // the marker makes it ours
  // A pre-marker (0.3.0) layout is recognised by the names this application creates.
  const legacy = join(base, 'legacy');
  mkdirSync(join(legacy, `enrollment-${uid(1)}`), { recursive: true });
  for (const name of ['router.pem', 'api-key.dpapi', 'wifi_password.secret', 'permit.json'])
    writeFileSync(join(legacy, name), 'synthetic');
  secureDirectory(legacy);
  const configDir = join(base, 'config');
  mkdirSync(join(configDir, 'private'), { recursive: true });
  writeFileSync(join(configDir, 'unifi.json'), '{}');
  secureDirectory(configDir, { known: ['unifi.json', 'private'] });
  // Home, any ancestor of home, and any letter-case variant are always refused.
  const home = homedir();
  for (const path of [home, dirname(home), home.toUpperCase(), home.toLowerCase()])
    if (process.platform === 'win32' || path === home || path === dirname(home))
      assert.throws(() => secureDirectory(path), /INSECURE_FILE/, path);
});

test('L1/I4: PowerShell is found under SystemRoot and its failures are told apart', (t) => {
  const exe = ['System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'].join('\\');
  assert.equal(powershellPath({ SystemRoot: 'D:\\Windows' }), `D:\\Windows\\${exe}`);
  assert.equal(powershellPath({ SYSTEMROOT: 'E:\\WINNT' }), `E:\\WINNT\\${exe}`);
  for (const SystemRoot of [undefined, 'Windows', 'C:\\x;y', 'C:\\..\\x', '\\\\server\\share'])
    assert.equal(powershellPath({ SystemRoot }), `C:\\Windows\\${exe}`, String(SystemRoot));
  const args = powershellArgs('secret.ps1', ['-Mode', 'Store']);
  assert.deepEqual(args.slice(0, 5), [
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy',
    'Bypass',
    '-File',
  ]);
  assert.deepEqual(args.slice(-2), ['-Mode', 'Store']);
  assert.equal(powershellError({ status: 2 }, 'INSECURE_FILE'), 'INSECURE_FILE');
  assert.equal(powershellError({ status: 1 }, 'INSECURE_FILE'), 'POWERSHELL_BLOCKED');
  assert.equal(powershellError({ code: 'ENOENT' }, 'INSECURE_FILE'), 'POWERSHELL_BLOCKED');
  assert.equal(
    powershellError({ code: 'ETIMEDOUT' }, 'INSECURE_FILE', 'PERMISSION_CHECK_TIMEOUT'),
    'PERMISSION_CHECK_TIMEOUT',
  );
  assert.match(messages.POWERSHELL_BLOCKED, /docs\/SETUP\.md/);
  for (const script of ['check-private.ps1', 'protect-data.ps1', 'secret.ps1'])
    assert.match(readFileSync(join(root, 'scripts', script), 'utf8'), /exit 2\s*\}\s*$/);
  if (process.platform !== 'win32') return;
  // Real Windows PowerShell: a failure the script detects is exit 2; a policy block is not.
  const missing = join(temp(t), 'missing');
  const params = ['-ConfigPath', missing, '-DataDirectory', missing];
  const opts = { stdio: ['ignore', 'pipe', 'pipe'], timeout: 30000 };
  assert.throws(
    () => runPowerShell('check-private.ps1', params, opts, 'INSECURE_FILE'),
    /INSECURE_FILE/,
  );
  const blocked = [...powershellArgs('check-private.ps1', params)];
  blocked[blocked.indexOf('Bypass')] = 'Restricted';
  let error;
  try {
    execFileSync(powershell, blocked, { windowsHide: true, ...opts });
  } catch (e) {
    error = e;
  }
  assert.equal(powershellError(error, 'INSECURE_FILE'), 'POWERSHELL_BLOCKED');
});

test('L11: the DPAPI pipe uses UTF-8 byte streams, not the console code page', () => {
  // Static check only. Fixed, not runtime-verified with a non-ASCII secret.
  const script = readFileSync(join(root, 'scripts/secret.ps1'), 'utf8');
  for (const needle of ['UTF8Encoding', 'OpenStandardInput()', 'OpenStandardOutput()'])
    assert.ok(script.includes(needle), needle);
  assert.ok(!/\[Console\]::(?:In|Out)\./.test(script));
});

// One synthetic CA, a leaf it issued (served with the chain), and a pinned client.
async function withChainServer(t, run) {
  const dir = temp(t);
  const ssl = (...args) => execFileSync(openssl, args, { stdio: 'ignore', windowsHide: true });
  const at = (name) => join(dir, name);
  ssl(
    'req',
    '-x509',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-keyout',
    at('ca.key'),
    '-out',
    at('ca.pem'),
    '-days',
    '1',
    '-subj',
    '/CN=Synthetic Test CA',
    '-addext',
    'basicConstraints=critical,CA:TRUE',
    '-addext',
    'keyUsage=critical,keyCertSign',
  );
  ssl(
    'req',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-keyout',
    at('leaf.key'),
    '-out',
    at('leaf.csr'),
    '-subj',
    '/CN=localhost',
  );
  ssl(
    'x509',
    '-req',
    '-in',
    at('leaf.csr'),
    '-CA',
    at('ca.pem'),
    '-CAkey',
    at('ca.key'),
    '-set_serial',
    '2',
    '-days',
    '1',
    '-out',
    at('leaf.pem'),
  );
  const seen = { keys: [], status: 200 };
  const server = https.createServer(
    {
      key: readFileSync(at('leaf.key')),
      cert: readFileSync(at('leaf.pem'), 'utf8') + readFileSync(at('ca.pem'), 'utf8'),
    },
    (req, res) => {
      seen.keys.push(req.headers['x-api-key']);
      res.statusCode = seen.status;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ applicationVersion: '11.0.97' }));
    },
  );
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise((r) => server.close(r)));
  const data = join(dir, 'data');
  const config = {
    configured: true,
    baseUrl: `https://127.0.0.1:${server.address().port}`,
    dataDir: data,
    credentialStore: 'file',
  };
  const pin = (name) => writePrivate(join(data, 'router.pem'), readFileSync(at(name)));
  const key = (value) => writePrivate(join(data, 'api-key.secret'), value);
  await run({ config, seen, pin, key });
}

test('L5: a CA-issued router certificate can be pinned; only the exact leaf passes', async (t) => {
  await withChainServer(t, async ({ config, pin, key }) => {
    key('synthetic-key-1');
    pin('leaf.pem');
    const info = await new UniFiClient(config).call('getInfo', {});
    assert.equal(info.applicationVersion, '11.0.97');
    // Pinning the issuing CA instead of the leaf must not be enough.
    pin('ca.pem');
    await assert.rejects(new UniFiClient(config).call('getInfo', {}), /TLS_PIN_CHANGED/);
  });
  assert.equal(tlsError({ code: 'CERT_HAS_EXPIRED' }), 'TLS_CERT_EXPIRED');
  assert.equal(tlsError({ code: 'CERT_NOT_YET_VALID' }), 'TLS_CERT_EXPIRED');
  assert.equal(tlsError({ code: 'DEPTH_ZERO_SELF_SIGNED_CERT' }), 'TLS_PIN_CHANGED');
  assert.equal(tlsError(new Error('TLS_PIN_CHANGED')), 'TLS_PIN_CHANGED');
  assert.equal(tlsError({ code: 'ECONNREFUSED' }), 'TLS_FAILED');
  for (const code of ['TLS_PIN_CHANGED', 'TLS_CERT_EXPIRED'])
    assert.match(safeError(new Error(code)), /re-run setup/);
});

test('L2: the API key is read once per process and re-read after 401', async (t) => {
  await withChainServer(t, async ({ config, seen, pin, key }) => {
    pin('leaf.pem');
    key('synthetic-key-1');
    const client = new UniFiClient(config);
    await client.call('getInfo', {});
    key('synthetic-key-2'); // a replaced file is not re-read while the key works
    await client.call('getInfo', {});
    seen.status = 401;
    await assert.rejects(client.call('getInfo', {}), /UPSTREAM_401/);
    seen.status = 200;
    await client.call('getInfo', {});
    assert.deepEqual(seen.keys, [
      'synthetic-key-1',
      'synthetic-key-1',
      'synthetic-key-1',
      'synthetic-key-2',
    ]);
  });
});

test('L7: setup asks for the browser fingerprint before showing the probe value', async () => {
  const fingerprint256 = Array.from({ length: 32 }, (_, i) =>
    (i * 7 + 16).toString(16).padStart(2, '0').toUpperCase(),
  ).join(':');
  const hex = fingerprint256.replaceAll(':', '');
  const cert = {
    fingerprint256,
    validFrom: new Date(Date.now() - 86400000).toUTCString(),
    validTo: new Date(Date.now() + 86400000).toUTCString(),
  };
  const run = async (answer, c = cert) => {
    const log = [];
    let shownBeforeAsk;
    const ask = async () => {
      shownBeforeAsk = log.join('\n');
      return answer;
    };
    const error = await confirmFingerprint(c, ask, (m) => log.push(m)).catch((e) => e);
    return { error, shownBeforeAsk, log: log.join('\n') };
  };
  const ok = await run(hex.toLowerCase());
  assert.equal(ok.error, undefined);
  assert.ok(!ok.shownBeforeAsk.toUpperCase().replaceAll(':', '').includes(hex.slice(0, 16)));
  assert.equal((await run(fingerprint256)).error, undefined);
  for (const wrong of ['', 'AB'.repeat(32)]) {
    const r = await run(wrong);
    assert.match(r.error.message, /TLS_FINGERPRINT_MISMATCH/);
    assert.ok(r.log.includes(fingerprint256), 'shown only after a mismatch');
  }
  const expired = await run(hex, { ...cert, validTo: new Date(Date.now() - 1000).toUTCString() });
  assert.match(expired.error.message, /TLS_CERT_EXPIRED/);
  assert.equal(expired.shownBeforeAsk, undefined, 'not asked at all');
});

test('L8: enrollment generations are listed and removed only inside the data directory', (t) => {
  const data = temp(t);
  for (const n of [1, 2]) mkdirSync(join(data, `enrollment-${uid(n)}`));
  mkdirSync(join(data, 'enrollment-other'));
  mkdirSync(join(data, 'notes'));
  writeFileSync(join(data, `enrollment-${uid(3)}`), 'a file, not a generation');
  assert.deepEqual(
    enrollments(data).sort(),
    [join(data, `enrollment-${uid(1)}`), join(data, `enrollment-${uid(2)}`)].sort(),
  );
  for (const bad of [
    join(data, 'notes'),
    join(data, 'enrollment-other'),
    join(data, `enrollment-${uid(3)}`),
    join(dirname(data), `enrollment-${uid(1)}`),
    join(data, 'notes', `enrollment-${uid(1)}`),
  ])
    assert.throws(() => removeEnrollment(data, bad), /INPUT_INVALID|ENOENT/, bad);
  writeFileSync(join(data, `enrollment-${uid(1)}`, 'api-key.secret'), 'synthetic');
  removeEnrollment(data, join(data, `enrollment-${uid(1)}`));
  assert.deepEqual(enrollments(data), [join(data, `enrollment-${uid(2)}`)]);
  assert.ok(existsSync(join(data, 'notes')));
});

test('L9: deeply nested router JSON fails as RESPONSE_INVALID, not a stack overflow', () => {
  let deep = 0;
  for (let i = 0; i < 100000; i++) deep = [deep];
  assert.throws(() => redact(deep), /RESPONSE_INVALID/);
  assert.throws(() => hash(deep), /RESPONSE_INVALID/);
  let ok = { v: 1 };
  for (let i = 0; i < 60; i++) ok = { child: ok, list: [i] };
  assert.doesNotThrow(() => redact(ok));
  assert.doesNotThrow(() => hash(ok));
  // Canonical form (and so every plan hash) is unchanged for ordinary input.
  assert.deepEqual(
    JSON.stringify(canonical({ b: 1, a: [{ d: 2, c: 3 }] })),
    '{"a":[{"c":3,"d":2}],"b":1}',
  );
});

test('L10: a config file that is not a JSON object is CONFIG_INVALID', (t) => {
  const dir = temp(t);
  for (const body of ['null', '[]', '5', '"text"', 'true']) {
    const path = join(dir, 'config.json');
    writePrivate(path, body);
    assert.throws(() => loadConfig(path), /CONFIG_INVALID/, body);
  }
});
