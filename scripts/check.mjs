import { operations, spec } from '../src/catalog.mjs';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
for (const directory of ['src', 'scripts', 'test'])
  for (const file of readdirSync(new URL(`../${directory}/`, import.meta.url)))
    if (file.endsWith('.mjs'))
      execFileSync(
        process.execPath,
        ['--check', fileURLToPath(new URL(`../${directory}/${file}`, import.meta.url))],
        { stdio: 'pipe' },
      );
const documented = Object.values(spec.paths).flatMap((path) =>
  Object.values(path)
    .filter((o) => o.operationId)
    .map((o) => o.operationId),
);
assert.deepEqual(operations.map((o) => o.id).sort(), documented.sort());
assert.equal(new Set(operations.map((o) => o.name)).size, operations.length);
assert.ok(
  operations.every((o) => o.name.length <= 64 && o.inputSchema.additionalProperties === false),
);
assert.equal(operations.length, 73);
assert.equal(operations.filter((o) => o.readOnly).length, 41);
const rows = operations
  .map(
    (o) =>
      `| \`${o.id}\` | ${o.method} | \`${o.path}\` | ${o.readOnly ? 'Read' : 'Preview → permitted apply'} |`,
  )
  .join('\n');
const content = `# API operation coverage\n\nGenerated from Ubiquiti's Network ${spec.info.version} OpenAPI specification. All ${operations.length} operation IDs are registered: 41 reads and 32 mutations. Coverage means implementation/registration, not that every endpoint was executed against a router. Hardware and firmware can limit individual operations.\n\n| Official operation ID | Method | API path | MCP behavior |\n| --- | --- | --- | --- |\n${rows}\n`;
const path = new URL('../docs/OPERATIONS.md', import.meta.url);
if (process.argv.includes('--write')) {
  mkdirSync(new URL('../docs/', import.meta.url), { recursive: true });
  writeFileSync(path, content);
} else
  assert.equal(
    readFileSync(path, 'utf8'),
    content,
    'Operation documentation drift: node scripts/check.mjs --write',
  );
console.log(
  JSON.stringify({
    schemaVersion: spec.info.version,
    documented: 73,
    implemented: operations.length,
    reads: 41,
    mutations: 32,
    invokedOperations: 0,
  }),
);
