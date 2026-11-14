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

test('the guard rejects path keys that could leave the integration API', () => {
  const spec = readJson(fixture('synthetic-11.1.0.json'));
  const item = spec.paths['/v1/sites/{siteId}/widgets'];
  const escaping = [
    '/../../../api/foo',
    '/v1/./sites',
    '/v1/%2e%2e/api',
    '/v1\\..\\api',
    'v1/sites',
    '/v1//sites',
  ];
  for (const path of escaping) spec.paths[path] = item;
  const findings = auditSpec(spec);
  for (const path of escaping)
    assert.ok(
      findings.some(
        (f) =>
          f.endsWith(': path must be plain "/segment" or "/{param}" parts') &&
          f.includes(path.replace(/~/g, '~0').replace(/\//g, '~1')),
      ),
      `${path}\n${findings.join('\n')}`,
    );
  assert.equal(
    new URL('/proxy/network/integration' + escaping[0], 'https://example.invalid').pathname,
    '/api/foo',
    'URL parsing normalizes the escape that the guard prevents',
  );
});

test('the guard rejects documented operations the catalog cannot register', () => {
  const spec = readJson(fixture('synthetic-11.1.0.json'));
  const item = spec.paths['/v1/sites/{siteId}/widgets'];
  item.head = { ...item.get, operationId: 'headWidgetPage' };
  item.options = { ...item.get, operationId: 'optionsWidgetPage' };
  const findings = auditSpec(spec);
  for (const method of ['head', 'options'])
    assert.ok(
      findings.includes(
        `#/paths/~1v1~1sites~1{siteId}~1widgets/${method}: HTTP method "${method}" is not supported`,
      ),
      findings.join('\n'),
    );
  // Without an operationId nothing would be registered or claimed; it stays allowed.
  delete item.head.operationId;
  delete item.options.operationId;
  assert.deepEqual(auditSpec(spec), []);
});

test('an operation-level parameter overrides the path-level one with the same name', () => {
  const spec = readJson(fixture('synthetic-11.1.0.json'));
  const item = spec.paths['/v1/sites/{siteId}/widgets'];
  item.parameters = [
    { name: 'limit', in: 'query', required: true, schema: { type: 'integer', minimum: 1 } },
  ];
  const op = buildCatalog(spec).operations.find((o) => o.id === 'getWidgetPage');
  const siteId = '00000000-0000-4000-8000-000000000001';
  assert.ok(op.validate({ path: { siteId } }), 'the operation made limit optional');
  assert.ok(op.validate({ path: { siteId }, query: { limit: 5 } }));
  assert.ok(!op.validate({ path: { siteId }, query: { limit: 500 } }), 'operation maximum applies');
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
  // New bytes without a new --source do not inherit the old copy's provenance.
  let entry = readJson(join(root, 'spec', 'manifest.json')).specs[1];
  assert.equal(entry.official, false);
  assert.match(entry.source, /^unrecorded/);
  assert.equal(run('check.mjs', ['--spec-dir', join(root, 'spec')]).status, 0);
  const restored = run('add-spec.mjs', [
    fixture('synthetic-11.1.99.json'),
    '--replace',
    '--source',
    'https://developer.ui.com/network/v11.1.99/openapi.json',
    '--root',
    root,
  ]);
  assert.equal(restored.status, 0, restored.stderr);
  entry = readJson(join(root, 'spec', 'manifest.json')).specs[1];
  assert.equal(entry.official, true);
  // Same bytes again without --source keep the recorded provenance.
  assert.equal(run('add-spec.mjs', [fixture('synthetic-11.1.99.json'), '--root', root]).status, 0);
  assert.equal(readJson(join(root, 'spec', 'manifest.json')).specs[1].official, true);
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
