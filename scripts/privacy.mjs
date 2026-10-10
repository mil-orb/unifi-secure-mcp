// Defense in depth, not a guarantee. Review staged changes before publishing.
import { readdirSync, readFileSync } from 'node:fs';
import { resolve, relative, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
const root = fileURLToPath(new URL('../', import.meta.url));
const roots = new Set(['.github', 'assets', 'docs', 'examples', 'scripts', 'spec', 'src', 'test']);
const top = new Set([
  '.gitignore',
  '.gitattributes',
  '.prettierignore',
  '.prettierrc.json',
  'AGENTS.md',
  'README.md',
  'SECURITY.md',
  'LICENSE',
  'THIRD-PARTY-NOTICES.md',
  'CONTRIBUTING.md',
  'CHANGELOG.md',
  'config.example.json',
  'package.json',
  'package-lock.json',
]);
function walk(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((d) => {
    if (['.git', 'node_modules'].includes(d.name)) return [];
    if (d.isSymbolicLink()) throw new Error('Symlinks are not permitted in publishable source');
    const p = resolve(dir, d.name);
    return d.isDirectory() ? walk(p) : [relative(root, p).replaceAll('\\', '/')];
  });
}
let files,
  staged = false;
try {
  files = execFileSync('git', ['-C', root, 'ls-files', '--cached', '-z'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  })
    .split('\0')
    .filter(Boolean);
  staged = true;
} catch {
  files = walk(root);
}
if (!files.length) throw new Error('No source files selected for scanning');
const findings = [];
for (const path of files) {
  if (!(top.has(path) || roots.has(path.split('/')[0])))
    findings.push(`${path}: outside source allowlist`);
  if (
    /(?:^|\/)(?:private|node_modules|local-[^/]*)(?:\/|$)|\.(?:dpapi|secret|pem|key|pfx|p12|har|pcap|pcapng|log|bak|tmp)$/i.test(
      path,
    )
  )
    findings.push(`${path}: private artifact type`);
  const bytes = staged
    ? execFileSync('git', ['-C', root, 'show', ':' + path], { maxBuffer: 20 * 1024 * 1024 })
    : readFileSync(resolve(root, path));
  if (path === 'assets/mcp-demo-redacted.png') {
    if (
      createHash('sha256').update(bytes).digest('hex') !==
      'cb401c2bcee9a8a742adb0d0e7ac24c564dfed2ff30fc78c5e18e12574967b17'
    )
      findings.push(`${path}: unreviewed image content`);
    continue;
  }
  if (path === 'assets/unifi.ico') {
    if (bytes.readUInt32LE(0) !== 65536) findings.push(`${path}: unexpected icon format`);
    continue;
  }
  if (
    !['.mjs', '.ps1', '.json', '.md', '.toml', '.yml', '.yaml', ''].includes(extname(path)) &&
    !['.gitignore', '.prettierignore'].includes(path)
  )
    findings.push(`${path}: unreviewed format`);
  const value = bytes.toString('utf8');
  if (
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bgh[pousr]_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}\b|\bAKIA[A-Z0-9]{16}\b/.test(
      value,
    )
  )
    findings.push(`${path}: possible credential`);
  // The upstream schema legitimately contains vendor-authored example values.
  if (path.startsWith('spec/')) continue;
  const addresses = value.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  if (
    addresses.some((a) => !['127.0.0.1', '192.168.1.1'].includes(a)) ||
    /\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b/.test(value)
  )
    findings.push(`${path}: possible deployment address`);
}
if (findings.length) {
  console.error(findings.join('\n'));
  process.exitCode = 1;
} else
  console.log(
    JSON.stringify({
      filesScanned: files.length,
      source: staged ? 'git index' : 'source tree',
      findings: 0,
      limitation:
        'Also review for private identifiers and scan exact deployment values locally before publishing.',
    }),
  );
