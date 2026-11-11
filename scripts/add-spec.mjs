// Adds a downloaded UniFi Network OpenAPI file to spec/. Local files only: no network access.
//
//   node scripts/add-spec.mjs <openapi.json> [--source https://URL] [--replace] [--prune]
//   node scripts/add-spec.mjs --prune
//
// Validates openapi 3.1.x, info.version, the schema keyword guard and compilation, copies the
// file to spec/unifi-network-<version>.json, updates spec/manifest.json, and (re)writes
// docs/spec-changes/<previous>-to-<next>.md for every consecutive pair of bundled specs.
// Re-running with an already bundled, identical file only refreshes the reports. A different
// file for a bundled version needs --replace. --prune lists specs outside the retention rule
// and deletes them only after confirmation. --root DIR (tests) works on another checkout layout.
import { readFileSync, writeFileSync, renameSync, mkdirSync, unlinkSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve, join } from 'node:path';
import { createInterface } from 'node:readline';
import { readManifest } from '../src/catalog.mjs';
import {
  repoRoot,
  dirUrl,
  serializeManifest,
  specProblems,
  counts,
  verifySpecSet,
  retention,
  expectedReports,
} from './spec-lib.mjs';

const usage =
  'Usage: node scripts/add-spec.mjs <openapi.json> [--source https://URL] [--replace] [--prune]\n' +
  '       node scripts/add-spec.mjs --prune';
const die = (message, code = 1) => {
  console.error(message);
  process.exit(code);
};
const opts = { file: null, source: null, replace: false, prune: false, root: repoRoot };
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--replace') opts.replace = true;
  else if (a === '--prune') opts.prune = true;
  else if (a === '--source' || a === '--root') {
    if (argv[i + 1] === undefined) die(usage, 2);
    opts[a.slice(2)] = argv[++i];
  } else if (a.startsWith('--') || opts.file) die(usage, 2);
  else opts.file = a;
}
if (!opts.file && !opts.prune) die(usage, 2);
if (opts.source !== null) {
  let url;
  try {
    url = new URL(opts.source);
  } catch {}
  if (url?.protocol !== 'https:' || url.username || url.password)
    die(
      '--source must be an https:// URL without credentials (it is only recorded, never fetched)',
    );
}
const specDir = join(resolve(opts.root), 'spec');
const docsDir = join(resolve(opts.root), 'docs', 'spec-changes');
try {
  readManifest(dirUrl(specDir));
} catch {
  die(`No valid spec/manifest.json under ${resolve(opts.root)}`);
}
const writeAtomic = (path, data) => {
  writeFileSync(path + '.tmp', data);
  renameSync(path + '.tmp', path);
};
const ask = (question) =>
  new Promise((done) => {
    process.stdout.write(question);
    const rl = createInterface({ input: process.stdin });
    let answered = false;
    rl.once('line', (line) => {
      answered = true;
      rl.close();
      done(line.trim().toLowerCase());
    });
    rl.once('close', () => answered || done(''));
  });

let changed = false;
if (opts.file) {
  if (/^[a-z][a-z0-9+.-]*:/i.test(opts.file) && !/^[a-z]:[\\/]/i.test(opts.file))
    die('Give a local file path. This tool never downloads; fetch the spec yourself first.');
  const path = resolve(opts.file);
  let bytes;
  try {
    if (statSync(path).size > 32 * 1024 * 1024) die('Spec file is larger than 32 MiB');
    bytes = readFileSync(path);
  } catch {
    die('Cannot read the spec file');
  }
  // Store LF-only UTF-8 without BOM so the committed bytes match the recorded SHA-256.
  let text = bytes.toString('utf8').replace(/^﻿/, '');
  if (text.includes('\r')) {
    text = text.replace(/\r\n?/g, '\n');
    console.log('Note: converted line endings to LF before hashing.');
  }
  let spec;
  try {
    spec = JSON.parse(text);
  } catch {
    die('The file is not valid JSON');
  }
  const catalog = {};
  const problems = specProblems(spec, catalog);
  if (problems.length)
    die(`Refusing to add this spec:\n${problems.map((p) => `  ${p}`).join('\n')}`);
  const version = spec.info.version;
  const data = Buffer.from(text, 'utf8');
  const sha256 = createHash('sha256').update(data).digest('hex');
  const entries = readManifest(dirUrl(specDir)).map((e) => ({ ...e }));
  const existing = entries.find((e) => e.version === version);
  if (existing && existing.sha256 === sha256 && opts.source === null)
    console.log(`${version} is already bundled with this exact content; refreshing reports only.`);
  else {
    if (existing && existing.sha256 !== sha256 && !opts.replace)
      die(
        `${version} is already bundled with different content. Re-run with --replace if you intend to swap it (for example, an official copy for a mirror copy).`,
      );
    const source = opts.source ?? existing?.source ?? 'unrecorded (added from a local file)';
    const entry = {
      version,
      file: `unifi-network-${version}.json`,
      sha256,
      source,
      official: source.startsWith('https://developer.ui.com/'),
      ...counts(catalog),
    };
    writeAtomic(join(specDir, entry.file), data);
    const next = [...entries.filter((e) => e.version !== version), entry];
    writeAtomic(join(specDir, 'manifest.json'), serializeManifest(next));
    console.log(
      `${existing ? 'Replaced' : 'Added'} ${entry.file}: ${entry.operations} operations (${entry.reads} reads, ${entry.mutations} mutations), sha256 ${sha256}, official: ${entry.official}.`,
    );
  }
  changed = true;
}

if (opts.prune) {
  const entries = readManifest(dirUrl(specDir)).map((e) => ({ ...e }));
  const { keep, remove } = retention(entries.map((e) => e.version));
  console.log(`Retention keeps: ${keep.join(', ')}`);
  if (!remove.length) console.log('Nothing to prune.');
  else {
    console.log('Would delete:');
    for (const v of remove) console.log(`  spec/unifi-network-${v}.json`);
    console.log(
      'Tests that name a deleted version, and any local config pinning specVersion to it, must be updated afterwards.',
    );
    const answer = await ask(`Delete these ${remove.length} spec file(s)? Type "yes" to confirm: `);
    process.stdout.write('\n');
    if (answer !== 'yes' && answer !== 'y') console.log('Not deleted.');
    else {
      writeAtomic(
        join(specDir, 'manifest.json'),
        serializeManifest(entries.filter((e) => !remove.includes(e.version))),
      );
      for (const v of remove) unlinkSync(join(specDir, `unifi-network-${v}.json`));
      console.log(`Deleted ${remove.length} spec file(s).`);
      changed = true;
    }
  }
}

if (changed) {
  const { errors, catalogs } = verifySpecSet(dirUrl(specDir));
  if (errors.length) die(`Spec directory failed verification:\n  ${errors.join('\n  ')}`);
  mkdirSync(docsDir, { recursive: true });
  for (const report of expectedReports(catalogs)) {
    writeAtomic(join(docsDir, report.file), report.content);
    console.log(`Wrote docs/spec-changes/${report.file}`);
  }
  console.log(
    'Next: review the reports, run node scripts/check.mjs --write (docs/OPERATIONS.md), then npm run check, npm test and npm run privacy.',
  );
}
