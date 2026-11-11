// Shared by scripts/check.mjs and scripts/add-spec.mjs. Reads local files only.
import { readFileSync, readdirSync } from 'node:fs';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import {
  readManifest,
  loadSpec,
  auditSpec,
  buildCatalog,
  compareVersions,
  parseVersion,
} from '../src/catalog.mjs';

export const repoRoot = fileURLToPath(new URL('../', import.meta.url));
export const dirUrl = (path) => {
  const url = pathToFileURL(resolve(path));
  if (!url.href.endsWith('/')) url.href += '/';
  return url;
};
const KEYS = [
  'version',
  'file',
  'sha256',
  'source',
  'official',
  'operations',
  'reads',
  'mutations',
];
// The only accepted on-disk form of spec/manifest.json: sorted by version, fixed key order.
export function serializeManifest(entries) {
  const specs = [...entries]
    .sort((a, b) => compareVersions(a.version, b.version))
    .map((e) => Object.fromEntries(KEYS.map((k) => [k, e[k]])));
  return JSON.stringify({ specs }, null, 2) + '\n';
}
export const counts = (catalog) => {
  const reads = catalog.operations.filter((o) => o.readOnly).length;
  return {
    operations: catalog.operations.length,
    reads,
    mutations: catalog.operations.length - reads,
  };
};
// Checks one parsed spec as add-spec/check require. Returns error strings.
export function specProblems(spec, catalogOut = {}) {
  const errors = [];
  if (typeof spec?.openapi !== 'string' || !/^3\.1\.\d+$/.test(spec.openapi))
    errors.push('openapi must be 3.1.x');
  if (!parseVersion(spec?.info?.version)) errors.push('info.version must be MAJOR.MINOR.PATCH');
  if (!spec?.paths || typeof spec.paths !== 'object') errors.push('paths missing');
  if (errors.length) return errors;
  const findings = auditSpec(spec);
  if (findings.length) return findings;
  let catalog;
  try {
    catalog = buildCatalog(spec);
  } catch (error) {
    return [`operation schemas failed to compile: ${error.message}`];
  }
  const documented = Object.values(spec.paths).flatMap((p) =>
    Object.values(p)
      .filter((o) => o?.operationId)
      .map((o) => o.operationId),
  );
  if (new Set(documented).size !== documented.length) errors.push('duplicate operationId');
  if (catalog.byName.size !== catalog.operations.length) errors.push('duplicate tool name');
  for (const o of catalog.operations)
    if (o.name.length > 64) errors.push(`${o.id}: tool name longer than 64 characters`);
  Object.assign(catalogOut, catalog);
  return errors;
}
// Verifies a spec directory: canonical manifest, no stray files, hashes, keyword guard, counts.
export function verifySpecSet(dir) {
  const errors = [];
  let entries;
  try {
    entries = readManifest(dir);
  } catch {
    return { errors: ['manifest.json: missing or invalid'], catalogs: [] };
  }
  if (readFileSync(new URL('manifest.json', dir), 'utf8') !== serializeManifest(entries))
    errors.push('manifest.json: not in canonical form (use scripts/add-spec.mjs to change it)');
  const listed = new Set(entries.map((e) => e.file));
  for (const file of readdirSync(dir))
    if (file !== 'manifest.json' && !listed.has(file))
      errors.push(`${file}: present in spec/ but not listed in manifest.json`);
  const catalogs = [];
  for (const entry of entries) {
    let spec;
    try {
      spec = loadSpec(entry, dir);
    } catch {
      errors.push(`${entry.file}: missing, or SHA-256/info.version does not match manifest.json`);
      continue;
    }
    const catalog = {};
    const problems = specProblems(spec, catalog);
    if (problems.length) {
      errors.push(...problems.map((p) => `${entry.file} ${p}`));
      continue;
    }
    const actual = counts(catalog);
    for (const k of ['operations', 'reads', 'mutations'])
      if (actual[k] !== entry[k])
        errors.push(`${entry.file}: ${k} is ${actual[k]} but manifest.json says ${entry[k]}`);
    catalogs.push({ entry, spec, ...catalog });
  }
  return { errors, catalogs };
}

// Keep the newest patch of each minor line of the newest major, plus the newest spec of
// the previous major present. Everything else is a prune candidate.
export function retention(versions) {
  const sorted = [...versions].sort(compareVersions);
  const major = (v) => parseVersion(v)[0];
  const top = major(sorted.at(-1));
  const previous = Math.max(-1, ...sorted.map(major).filter((m) => m < top));
  const keep = new Set();
  for (const v of sorted) {
    const [M, m] = parseVersion(v);
    if (M === top) {
      const newest = sorted.filter((x) => major(x) === M && parseVersion(x)[1] === m).at(-1);
      keep.add(newest);
    } else if (M === previous) keep.add(sorted.filter((x) => major(x) === M).at(-1));
  }
  return { keep: sorted.filter((v) => keep.has(v)), remove: sorted.filter((v) => !keep.has(v)) };
}

// ---- Change report ----
const canonical = (value, key) => {
  if (Array.isArray(value)) {
    const items = value.map((v) => canonical(v));
    if (['oneOf', 'anyOf'].includes(key))
      return items.sort((x, y) => JSON.stringify(x).localeCompare(JSON.stringify(y)));
    return ['required', 'enum'].includes(key) ? items.sort() : items;
  }
  if (value && typeof value === 'object')
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((k) => [k, canonical(value[k], k)]),
    );
  return value;
};
const same = (a, b) => JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
const STRUCTURE = ['properties', 'items', 'oneOf', 'anyOf', 'additionalProperties', 'required'];
// A field's own constraints, without its children.
const local = (schema) =>
  Object.fromEntries(Object.entries(schema).filter(([k]) => !STRUCTURE.includes(k)));
// Flattens a normalized input schema into field paths: a.b, a[] (items), a{type=X} (branch).
function fields(schema, prefix = '', out = new Map()) {
  if (!schema || typeof schema !== 'object') return out;
  for (const key of ['oneOf', 'anyOf'])
    (schema[key] || []).forEach((branch, i) => {
      const tag = Object.entries(branch.properties || {}).find(([, v]) => v.const !== undefined);
      const path = `${prefix}{${tag ? `${tag[0]}=${tag[1].const}` : `#${i + 1}`}}`;
      out.set(path, { required: true, branch: true, local: local(branch) });
      fields(branch, path, out);
    });
  for (const [name, child] of Object.entries(schema.properties || {})) {
    const path = prefix ? `${prefix}.${name}` : name;
    out.set(path, {
      required: (schema.required || []).includes(name),
      description: typeof child.description === 'string' ? child.description : '',
      hasDefault: child.default !== undefined,
      default: child.default,
      local: local(child),
    });
    fields(child, path, out);
  }
  if (schema.items) fields(schema.items, `${prefix}[]`, out);
  if (schema.additionalProperties && typeof schema.additionalProperties === 'object')
    fields(schema.additionalProperties, `${prefix}{*}`, out);
  return out;
}
const parent = (path) => {
  const m = /^(.*?)(?:\.[^.{}[\]]+|\[\]|\{[^{}]*\})$/.exec(path);
  return m ? m[1] : '';
};
const code = (s) => '`' + String(s).replace(/`/g, "'") + '`';
const cell = (s) => String(s).replace(/\s+/g, ' ').replace(/\|/g, '\\|').trim();
const defaultSentence = (info) => {
  const text = cell(info.description).slice(0, 240);
  const value = info.hasDefault ? `schema default ${code(JSON.stringify(info.default))}` : '';
  return [text && `"${text}"`, value].filter(Boolean).join('; ');
};
const list = (items, empty = 'None.') => (items.length ? items.join('\n') : empty);
const capped = (items, n = 15) =>
  items.length > n ? [...items.slice(0, n), `and ${items.length - n} more`] : items;

export function changeReport(prev, next) {
  const a = prev.catalog,
    b = next.catalog;
  const opLine = (o) => `- ${code(o.id)}: ${code(`${o.method} ${o.path}`)}`;
  const added = b.operations.filter((o) => !a.byId.has(o.id));
  const removed = a.operations.filter((o) => !b.byId.has(o.id));
  const changed = [],
    newRequired = [],
    defaulted = [];
  for (const o of b.operations) {
    const old = a.byId.get(o.id);
    if (!old) continue;
    const before = fields(old.inputSchema),
      after = fields(o.inputSchema);
    const notes = [];
    if (old.method !== o.method || old.path !== o.path)
      notes.push(
        `endpoint ${code(`${old.method} ${old.path}`)} → ${code(`${o.method} ${o.path}`)}`,
      );
    // Only the root of each new or removed subtree.
    const gained = [...after.keys()].filter(
      (k) => !before.has(k) && (!parent(k) || before.has(parent(k))),
    );
    const lost = [...before.keys()].filter(
      (k) => !after.has(k) && (!parent(k) || after.has(parent(k))),
    );
    const constraints = [],
      described = [],
      loosened = [];
    for (const [path, info] of after) {
      const was = before.get(path);
      if (!was) continue;
      if (was.required && !info.required) loosened.push(code(path));
      const keys = [...new Set([...Object.keys(was.local), ...Object.keys(info.local)])]
        .filter((k) => !same(was.local[k], info.local[k]))
        .sort();
      if (keys.length === 1 && keys[0] === 'description') described.push(path);
      else if (keys.length)
        constraints.push(`${code(path)} (${keys.filter((k) => k !== 'description').join(', ')})`);
    }
    if (gained.length) notes.push(`fields added: ${capped(gained.map(code)).join(', ')}`);
    if (lost.length) notes.push(`fields removed: ${capped(lost.map(code)).join(', ')}`);
    if (loosened.length) notes.push(`now optional: ${capped(loosened).join(', ')}`);
    if (constraints.length) notes.push(`constraints changed: ${capped(constraints).join(', ')}`);
    if (described.length)
      notes.push(
        `description text changed on ${described.length} field${described.length > 1 ? 's' : ''}`,
      );
    for (const [path, info] of after) {
      if (info.branch) continue;
      const was = before.get(path);
      const parentExisted = !parent(path) || before.has(parent(path));
      if (info.required && (was ? !was.required : parentExisted))
        newRequired.push(`- ${code(o.id)}: ${code(path)}${was ? ' (was optional)' : ''}`);
      if (
        !was &&
        !info.required &&
        parentExisted &&
        (/\bdefault/i.test(info.description) || info.hasDefault)
      )
        defaulted.push(`- **${code(o.id)}: ${code(path)}**: ${defaultSentence(info)}`);
    }
    if (!notes.length && !same(old.inputSchema, o.inputSchema))
      notes.push('other input schema differences');
    if (notes.length) changed.push(`- ${code(o.id)}: ${notes.join('; ')}`);
  }
  const sa = prev.spec.components.schemas,
    sb = next.spec.components.schemas;
  const schemaAdded = Object.keys(sb).filter((k) => !Object.hasOwn(sa, k));
  const schemaRemoved = Object.keys(sa).filter((k) => !Object.hasOwn(sb, k));
  const schemaChanged = Object.keys(sb).filter((k) => Object.hasOwn(sa, k) && !same(sa[k], sb[k]));
  const discriminators = [];
  for (const [name, schema] of Object.entries(sb)) {
    const mapping = schema.discriminator?.mapping;
    if (!mapping) continue;
    const oldMapping = sa[name]?.discriminator?.mapping || {};
    const values = Object.keys(mapping).filter((v) => !Object.hasOwn(oldMapping, v));
    const gone = Object.keys(oldMapping).filter((v) => !Object.hasOwn(mapping, v));
    if (values.length || gone.length)
      discriminators.push(
        `- ${code(`${name}.${schema.discriminator.propertyName}`)}${Object.hasOwn(sa, name) ? '' : ' (new schema)'}: ` +
          [
            values.length && `added ${values.map(code).join(', ')}`,
            gone.length && `removed ${gone.map(code).join(', ')}`,
          ]
            .filter(Boolean)
            .join('; '),
      );
  }
  const names = (xs) => (xs.length ? xs.map(code).join(', ') : 'None.');
  const v1 = prev.spec.info.version,
    v2 = next.spec.info.version;
  return `# Network ${v1} → ${v2} specification changes

Generated by \`scripts/add-spec.mjs\` from the bundled specifications; \`npm run check\` fails if it drifts. It compares operation input schemas as this MCP validates them, plus the raw component schemas. Review it before trusting a new version, especially the last two sections. Field paths are relative to the tool input: \`[]\` marks array items and \`{type=X}\` a discriminator branch.

| Change | Count |
| --- | --- |
| Operations added | ${added.length} |
| Operations removed | ${removed.length} |
| Operations with changed input | ${changed.length} |
| Schemas added / removed / changed | ${schemaAdded.length} / ${schemaRemoved.length} / ${schemaChanged.length} |
| Discriminators with new or removed values | ${discriminators.length} |
| New required request fields | ${newRequired.length} |
| New optional request fields that mention a default | ${defaulted.length} |

## Operations added

${list(added.map(opLine))}

## Operations removed

${list(removed.map(opLine))}

## Operations with changed input

${list(changed)}

## Schemas

- Added: ${names(schemaAdded)}
- Removed: ${names(schemaRemoved)}
- Changed: ${names(schemaChanged)}

## Discriminator values

${list(discriminators)}

## New required request fields

These break existing callers that omit them. A field is listed only when its parent object already existed.

${list(newRequired)}

## New optional request fields that mention a default

**Hazard:** a full-object update (PUT) built from an older shape omits these fields, and the router may then reset them to their default. Carry them over from the preview's \`before\` snapshot.

${list(defaulted)}
`;
}
export const reportName = (v1, v2) => `${v1}-to-${v2}.md`;
// One report per consecutive pair of bundled specs.
export function expectedReports(catalogs) {
  const sorted = [...catalogs].sort((x, y) => compareVersions(x.entry.version, y.entry.version));
  return sorted.slice(1).map((next, i) => ({
    file: reportName(sorted[i].entry.version, next.entry.version),
    content: changeReport(
      { spec: sorted[i].spec, catalog: sorted[i] },
      { spec: next.spec, catalog: next },
    ),
  }));
}
