import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  existsSync,
  readdirSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { auditSpec, buildCatalog, manifest, loadSpec } from '../src/catalog.mjs';
import { serializeManifest, counts, retention } from '../scripts/spec-lib.mjs';

const script = (name) => fileURLToPath(new URL(`../scripts/${name}`, import.meta.url));
const fixture = (name) => fileURLToPath(new URL(`./fixtures/specs/${name}`, import.meta.url));
const readJson = (path) => JSON.parse(readFileSync(path, 'utf8'));
const run = (name, args, input = '') =>
  spawnSync(process.execPath, [script(name), ...args], { encoding: 'utf8', input });
const scratch = [];
const tempRoot = () => {
  const dir = mkdtempSync(join(tmpdir(), 'unifi-mcp-spec-'));
  scratch.push(dir);
  mkdirSync(join(dir, 'spec'));
  return dir;
};
test.after(() => {
  for (const dir of scratch)
    if (resolve(dir).startsWith(resolve(tmpdir()) + sep)) rmSync(dir, { recursive: true });
});
// A spec/ directory holding the base fixture re-versioned as each requested version.
// Items are versions, or [version, parsed spec] pairs.
function bundle(root, versions) {
  const entries = versions.map((item) => {
    const [version, base] = Array.isArray(item)
      ? item
      : [item, readJson(fixture('synthetic-11.1.0.json'))];
    const text = JSON.stringify({ ...base, info: { ...base.info, version } }, null, 2) + '\n';
    const file = `unifi-network-${version}.json`;
    writeFileSync(join(root, 'spec', file), text);
    return {
      version,
      file,
      sha256: createHash('sha256').update(text).digest('hex'),
      source: 'https://example.invalid/synthetic.json',
      official: false,
      ...counts(buildCatalog(JSON.parse(text))),
    };
  });
  writeFileSync(join(root, 'spec', 'manifest.json'), serializeManifest(entries));
}

test('every bundled spec passes the schema keyword guard', () => {
  for (const entry of manifest) assert.deepEqual(auditSpec(loadSpec(entry)), [], entry.version);
});

test('the keyword guard reports unsupported constructs with JSON paths', () => {
  const findings = auditSpec(readJson(fixture('synthetic-unknown-keyword.json')));
  assert.ok(findings.includes('#/components/schemas/Widget/if: unsupported schema keyword "if"'));
  assert.ok(
    findings.includes('#/components/schemas/Widget/then: unsupported schema keyword "then"'),
  );
  const spec = readJson(fixture('synthetic-11.1.0.json'));
  const widget = spec.components.schemas.Widget;
  widget.properties.name.format = 'hostname-ish';
  widget.properties.enabled.not = { const: true };
  spec.components.schemas.PortWidgetFilter.allOf[1].minProperties = 1;
  spec.paths['/v1/sites/{siteId}/widgets'].get.parameters.push({
    name: 'X-Trace',
    in: 'header',
    schema: { type: 'string' },
  });
  const more = auditSpec(spec);
  for (const expected of [
    '#/components/schemas/Widget/properties/name/format: unsupported format "hostname-ish"',
    '#/components/schemas/Widget/properties/enabled/not: unsupported schema keyword "not"',
    '#/components/schemas/PortWidgetFilter/allOf/1/minProperties: unsupported schema keyword "minProperties"',
    '#/components/schemas/PortWidgetFilter/allOf/1: keyword "minProperties" inside an allOf member is dropped by normalize()',
    '#/paths/~1v1~1sites~1{siteId}~1widgets/get/parameters/2: parameter must be an inline path/query parameter with a schema',
  ])
    assert.ok(more.includes(expected), `${expected}\n${more.join('\n')}`);
  assert.equal(more.length, 5, more.join('\n'));
});

test('an 11.1.99 fixture is added cleanly with one command and a review report', () => {
  const root = tempRoot();
  bundle(root, ['11.1.0']);
  const added = run('add-spec.mjs', [
    fixture('synthetic-11.1.99.json'),
    '--source',
    'https://developer.ui.com/network/v11.1.99/openapi.json',
    '--root',
    root,
  ]);
  assert.equal(added.status, 0, added.stderr);
  const entries = readJson(join(root, 'spec', 'manifest.json')).specs;
  assert.deepEqual(
    entries.map((e) => [e.version, e.official, e.operations, e.reads, e.mutations]),
    [
      ['11.1.0', false, 3, 1, 2],
      ['11.1.99', true, 4, 1, 3],
    ],
  );
  const stored = readFileSync(join(root, 'spec', 'unifi-network-11.1.99.json'));
  assert.equal(createHash('sha256').update(stored).digest('hex'), entries[1].sha256);
  const report = readFileSync(join(root, 'docs', 'spec-changes', '11.1.0-to-11.1.99.md'), 'utf8');
  for (const expected of [
    '- `deleteWidget`: `DELETE /v1/sites/{siteId}/widgets/{widgetId}`',
    '- `createWidget`: `body.zoneId`',
    '- `updateWidget`: `body.zoneId`',
    '- **`updateWidget`: `body.reportActivity`**: "Report widget activity in Insights. Defaults to true when omitted."',
    '- `WidgetFilter.type`: added `RANGE`',
    '- Added: `RangeWidgetFilter`',
    '- Changed: `Widget`, `WidgetFilter`',
  ])
    assert.ok(report.includes(expected), `${expected}\n---\n${report}`);
  // A new discriminator branch's own required fields are not reported as breaking.
  assert.doesNotMatch(report, /RANGE\}\.start/);
  const check = run('check.mjs', ['--spec-dir', join(root, 'spec')]);
  assert.equal(check.status, 0, check.stderr);
  assert.equal(JSON.parse(check.stdout).schemaVersion, '11.1.99');

  const again = run('add-spec.mjs', [fixture('synthetic-11.1.99.json'), '--root', root]);
  assert.equal(again.status, 0, again.stderr);
  assert.match(again.stdout, /refreshing reports only/);
  const altered = join(root, 'altered.json');
  const changed = readJson(fixture('synthetic-11.1.99.json'));
  changed.components.schemas.Widget.properties.name.maxLength = 32;
  writeFileSync(altered, JSON.stringify(changed));
  const conflict = run('add-spec.mjs', [altered, '--root', root]);
  assert.equal(conflict.status, 1);
  assert.match(conflict.stderr, /--replace/);
  const replaced = run('add-spec.mjs', [altered, '--replace', '--root', root]);
  assert.equal(replaced.status, 0, replaced.stderr);
  assert.equal(readJson(join(root, 'spec', 'manifest.json')).specs[1].official, true);
  assert.equal(run('check.mjs', ['--spec-dir', join(root, 'spec')]).status, 0);
});

test('a spec with an unknown keyword is refused by add-spec and fails the check', () => {
  const root = tempRoot();
  bundle(root, ['11.1.0']);
  const before = readFileSync(join(root, 'spec', 'manifest.json'), 'utf8');
  const refused = run('add-spec.mjs', [fixture('synthetic-unknown-keyword.json'), '--root', root]);
  assert.equal(refused.status, 1);
  assert.match(
    refused.stderr,
    /#\/components\/schemas\/Widget\/if: unsupported schema keyword "if"/,
  );
  assert.equal(readFileSync(join(root, 'spec', 'manifest.json'), 'utf8'), before);
  assert.deepEqual(readdirSync(join(root, 'spec')).sort(), [
    'manifest.json',
    'unifi-network-11.1.0.json',
  ]);

  // Bypassing add-spec (hand-edited manifest) still fails npm run check's guard.
  bundle(root, ['11.1.0', ['11.1.100', readJson(fixture('synthetic-unknown-keyword.json'))]]);
  const check = run('check.mjs', ['--spec-dir', join(root, 'spec')]);
  assert.equal(check.status, 1);
  assert.match(
    check.stderr,
    /unifi-network-11\.1\.100\.json #\/components\/schemas\/Widget\/if: unsupported schema keyword "if"/,
  );
});

test('add-spec accepts only local OpenAPI 3.1 files', () => {
  const root = tempRoot();
  bundle(root, ['11.1.0']);
  const url = run('add-spec.mjs', [
    'https://developer.ui.com/network/v11.1.99/openapi.json',
    '--root',
    root,
  ]);
  assert.equal(url.status, 1);
  assert.match(url.stderr, /local file/);
  const old = join(root, 'old.json');
  writeFileSync(
    old,
    JSON.stringify({ ...readJson(fixture('synthetic-11.1.99.json')), openapi: '3.0.3' }),
  );
  const refused = run('add-spec.mjs', [old, '--root', root]);
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /openapi must be 3\.1\.x/);
  const badSource = run('add-spec.mjs', [
    fixture('synthetic-11.1.99.json'),
    '--source',
    'http://x.invalid/a',
    '--root',
    root,
  ]);
  assert.equal(badSource.status, 1);
  assert.equal(readJson(join(root, 'spec', 'manifest.json')).specs.length, 1);
});

test('retention keeps the newest patch per minor line plus the previous major newest', () => {
  assert.deepEqual(retention(['10.6.106', '11.0.97', '11.1.47']), {
    keep: ['10.6.106', '11.0.97', '11.1.47'],
    remove: [],
  });
  assert.deepEqual(retention(['9.5.1', '10.0.1', '10.1.0', '11.0.1', '11.0.2', '11.1.0']), {
    keep: ['10.1.0', '11.0.2', '11.1.0'],
    remove: ['9.5.1', '10.0.1', '11.0.1'],
  });
});

test('--prune lists candidates and deletes only after confirmation', () => {
  const root = tempRoot();
  bundle(root, ['10.0.1', '10.1.0', '11.0.1', '11.0.2', '11.1.0']);
  const declined = run('add-spec.mjs', ['--prune', '--root', root], 'no\n');
  assert.equal(declined.status, 0, declined.stderr);
  assert.match(declined.stdout, /spec\/unifi-network-10\.0\.1\.json/);
  assert.match(declined.stdout, /spec\/unifi-network-11\.0\.1\.json/);
  assert.match(declined.stdout, /Not deleted/);
  assert.equal(readJson(join(root, 'spec', 'manifest.json')).specs.length, 5);
  const silent = run('add-spec.mjs', ['--prune', '--root', root], '');
  assert.match(silent.stdout, /Not deleted/);
  const confirmed = run('add-spec.mjs', ['--prune', '--root', root], 'yes\n');
  assert.equal(confirmed.status, 0, confirmed.stderr);
  assert.deepEqual(
    readJson(join(root, 'spec', 'manifest.json')).specs.map((e) => e.version),
    ['10.1.0', '11.0.2', '11.1.0'],
  );
  assert.equal(existsSync(join(root, 'spec', 'unifi-network-10.0.1.json')), false);
  assert.ok(existsSync(join(root, 'docs', 'spec-changes', '10.1.0-to-11.0.2.md')));
  assert.equal(run('check.mjs', ['--spec-dir', join(root, 'spec')]).status, 0);
});
