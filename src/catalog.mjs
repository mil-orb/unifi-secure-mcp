import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import Ajv from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { assertBoundedJson } from './security.mjs';
const fail = () => {
  throw new Error('SPEC_INVALID');
};
const semver = /^(\d{1,4})\.(\d{1,4})\.(\d{1,6})$/;
const parseVersion = (v) => {
  const m = typeof v === 'string' && semver.exec(v);
  return m ? m.slice(1).map(Number) : null;
};
function compareVersions(a, b) {
  const x = parseVersion(a),
    y = parseVersion(b);
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i];
  return 0;
}
// Extract only a numeric major.minor.patch from untrusted router text.
export function versionFrom(value) {
  const m = typeof value === 'string' && /^(\d{1,4}\.\d{1,4}\.\d{1,6})(?!\d)/.exec(value);
  return m ? m[1] : null;
}
function readManifest() {
  let data;
  try {
    data = JSON.parse(readFileSync(new URL('../spec/manifest.json', import.meta.url), 'utf8'));
  } catch {
    fail();
  }
  if (!Array.isArray(data?.specs) || !data.specs.length) fail();
  for (const e of data.specs)
    if (
      !parseVersion(e?.version) ||
      e.file !== `unifi-network-${e.version}.json` ||
      !/^[0-9a-f]{64}$/.test(e.sha256) ||
      typeof e.source !== 'string' ||
      typeof e.official !== 'boolean' ||
      !['operations', 'reads', 'mutations'].every((k) => Number.isSafeInteger(e[k]) && e[k] >= 0) ||
      e.reads + e.mutations !== e.operations
    )
      fail();
  if (new Set(data.specs.map((e) => e.version)).size !== data.specs.length) fail();
  return Object.freeze(
    [...data.specs]
      .sort((a, b) => compareVersions(a.version, b.version))
      .map((e) => Object.freeze({ ...e })),
  );
}
export const manifest = readManifest();
export const bundledSpecs = Object.freeze(manifest.map((e) => e.version));
// Reads a bundled spec only from spec/, verifying the manifest SHA-256 before parsing.
export function loadSpec(entry) {
  if (!parseVersion(entry?.version) || entry.file !== `unifi-network-${entry.version}.json`) fail();
  let bytes, parsed;
  try {
    bytes = readFileSync(new URL(`../spec/${entry.file}`, import.meta.url));
  } catch {
    fail();
  }
  if (createHash('sha256').update(bytes).digest('hex') !== entry.sha256) fail();
  try {
    parsed = JSON.parse(bytes.toString('utf8'));
  } catch {
    fail();
  }
  if (parsed?.info?.version !== entry.version || !parsed.paths || !parsed.components?.schemas)
    fail();
  return parsed;
}
let activeSchemas;
function dereference(ref, schemas) {
  const prefix = '#/components/schemas/';
  if (!ref.startsWith(prefix)) throw new Error('SPEC_INVALID');
  const name = decodeURIComponent(ref.slice(prefix.length)).replace(/~1/g, '/').replace(/~0/g, '~');
  if (!Object.hasOwn(schemas, name)) throw new Error('SPEC_INVALID');
  return schemas[name];
}
// UniFi uses OpenAPI discriminator mappings plus allOf inheritance. Expand each
// mapping into an explicit JSON-Schema union, merging inherited object fields.
function flatten(schema, schemas, seen = new Set()) {
  if (schema.$ref) {
    if (seen.has(schema.$ref)) throw new Error('SPEC_INVALID');
    return flatten(
      {
        ...dereference(schema.$ref, schemas),
        ...Object.fromEntries(Object.entries(schema).filter(([k]) => k !== '$ref')),
      },
      schemas,
      new Set([...seen, schema.$ref]),
    );
  }
  const own = { ...schema };
  delete own.allOf;
  if (schema.allOf) {
    for (const part of schema.allOf) {
      const p = flatten(part, schemas, seen);
      own.properties = { ...p.properties, ...own.properties };
      own.required = [...new Set([...(p.required || []), ...(own.required || [])])];
      own.type = own.type || p.type;
    }
  }
  return own;
}
export function normalize(schema, depth = 0, schemas = activeSchemas) {
  if (depth > 40) throw new Error('SPEC_INVALID');
  const flat = flatten(schema, schemas);
  if (flat.discriminator?.mapping) {
    const { propertyName, mapping } = flat.discriminator;
    return {
      oneOf: Object.entries(mapping).map(([value, ref]) => {
        const child = flatten({ $ref: ref }, schemas);
        delete child.discriminator;
        child.properties = {
          ...flat.properties,
          ...child.properties,
          [propertyName]: { type: 'string', const: value },
        };
        child.required = [
          ...new Set([...(flat.required || []), ...(child.required || []), propertyName]),
        ];
        return normalize(child, depth + 1, schemas);
      }),
    };
  }
  const out = {};
  for (const key of [
    'type',
    'enum',
    'const',
    'minimum',
    'maximum',
    'exclusiveMinimum',
    'exclusiveMaximum',
    'minLength',
    'maxLength',
    'pattern',
    'format',
    'minItems',
    'maxItems',
    'uniqueItems',
    'required',
    'description',
    'default',
  ])
    if (flat[key] !== undefined) out[key] = flat[key];
  if (flat.properties) {
    out.type = 'object';
    out.properties = Object.fromEntries(
      Object.entries(flat.properties)
        .filter(([, v]) => !v.readOnly)
        .map(([k, v]) => [k, normalize(v, depth + 1, schemas)]),
    );
    out.additionalProperties =
      flat.additionalProperties === undefined
        ? false
        : typeof flat.additionalProperties === 'object'
          ? normalize(flat.additionalProperties, depth + 1, schemas)
          : flat.additionalProperties;
  } else if (flat.additionalProperties !== undefined)
    out.additionalProperties =
      typeof flat.additionalProperties === 'object'
        ? normalize(flat.additionalProperties, depth + 1, schemas)
        : flat.additionalProperties;
  if (flat.items) out.items = normalize(flat.items, depth + 1, schemas);
  for (const key of ['oneOf', 'anyOf'])
    if (flat[key]) out[key] = flat[key].map((v) => normalize(v, depth + 1, schemas));
  if (flat.nullable)
    out.type = Array.isArray(out.type) ? [...out.type, 'null'] : [out.type, 'null'];
  return out;
}
const ajv = new Ajv({
  strict: false,
  allErrors: false,
  validateFormats: true,
  coerceTypes: false,
  useDefaults: false,
});
addFormats(ajv);
ajv.addFormat('int32', {
  type: 'number',
  validate: (n) => Number.isInteger(n) && n >= -2147483648 && n <= 2147483647,
});
ajv.addFormat('int64', { type: 'number', validate: Number.isSafeInteger });
ajv.addFormat('double', { type: 'number', validate: Number.isFinite });
const snake = (s) => s.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
export function buildCatalog(source) {
  const schemas = source.components.schemas;
  const operations = Object.entries(source.paths).flatMap(([path, item]) =>
    Object.entries(item)
      .filter(([m, o]) => ['get', 'post', 'put', 'patch', 'delete'].includes(m) && o.operationId)
      .map(([method, op]) => {
        const parameters = [...(item.parameters || []), ...(op.parameters || [])];
        const properties = {},
          required = [];
        for (const place of ['path', 'query']) {
          const list = parameters.filter((p) => p.in === place);
          if (list.length) {
            properties[place] = {
              type: 'object',
              properties: Object.fromEntries(
                list.map((p) => [p.name, normalize(p.schema, 0, schemas)]),
              ),
              required: list.filter((p) => p.required).map((p) => p.name),
              additionalProperties: false,
            };
            if (properties[place].required.length) required.push(place);
          }
        }
        if (op.requestBody) {
          properties.body = normalize(
            op.requestBody.content['application/json'].schema,
            0,
            schemas,
          );
          if (op.requestBody.required) required.push('body');
        }
        const inputSchema = { type: 'object', properties, required, additionalProperties: false };
        return {
          id: op.operationId,
          name: `unifi_api_${snake(op.operationId)}`,
          method: method.toUpperCase(),
          path,
          tag: op.tags?.[0] || 'Other',
          summary: op.summary || op.operationId,
          description: op.description || '',
          inputSchema,
          parameters,
          readOnly: method === 'get',
          responses: Object.keys(op.responses),
          validate: ajv.compile(inputSchema),
        };
      }),
  );
  return {
    operations,
    byId: new Map(operations.map((o) => [o.id, o])),
    byName: new Map(operations.map((o) => [o.name, o])),
  };
}
// Compile one bundled spec without changing the active catalog.
export function compileSpec(version) {
  const entry = manifest.find((e) => e.version === version);
  if (!entry) fail();
  const loaded = loadSpec(entry);
  const catalog = buildCatalog(loaded);
  const reads = catalog.operations.filter((o) => o.readOnly).length;
  if (
    catalog.operations.length !== entry.operations ||
    reads !== entry.reads ||
    catalog.operations.length - reads !== entry.mutations ||
    catalog.byId.size !== entry.operations ||
    catalog.byName.size !== entry.operations
  )
    fail();
  return { spec: loaded, entry, ...catalog };
}
// Live ES-module bindings: importers always see the active catalog.
export let spec, operations, byId, byName, activeSpec;
function install(version, detected, match) {
  const c = compileSpec(version);
  activeSchemas = c.spec.components.schemas;
  spec = c.spec;
  operations = c.operations;
  byId = c.byId;
  byName = c.byName;
  activeSpec = Object.freeze({ loaded: version, detected, match, bundled: bundledSpecs });
}
install(bundledSpecs.at(-1), null, 'not-detected');
let activated = false;
// Once per process: operation objects from an earlier catalog fail client identity checks.
export function activateSpec(version, { detected = null, match = 'not-detected' } = {}) {
  if (activated || !bundledSpecs.includes(version)) fail();
  if (detected !== null && !parseVersion(detected)) fail();
  activated = true;
  install(version, detected, match);
  return activeSpec;
}
// Pure. An older spec is a subset the router accepts; a newer one may permit request
// shapes the router rejects. A configured pin always wins.
export function selectSpecVersion(detected, pinned, bundled = bundledSpecs) {
  const list = [...bundled].sort(compareVersions);
  if (!list.length || !list.every(parseVersion)) fail();
  if (pinned != null && !list.includes(pinned)) fail();
  const d = parseVersion(detected) ? detected : null;
  if (pinned != null)
    return {
      version: pinned,
      match: !d ? 'not-detected' : compareVersions(d, pinned) === 0 ? 'exact' : 'pinned',
    };
  if (!d) return { version: list.at(-1), match: 'not-detected' };
  const exact = list.find((v) => compareVersions(v, d) === 0);
  if (exact) return { version: exact, match: 'exact' };
  const same = list.filter((v) => parseVersion(v)[0] === parseVersion(d)[0]);
  const older = same.filter((v) => compareVersions(v, d) < 0);
  if (older.length) {
    const version = older.at(-1);
    return { version, match: version === same.at(-1) ? 'newer-than-bundled' : 'nearest-older' };
  }
  if (same.length) return { version: same[0], match: 'older-than-bundled' };
  return { version: list.at(-1), match: 'major-mismatch' };
}
export function validateInput(op, input) {
  assertBoundedJson(input);
  if (Buffer.byteLength(JSON.stringify(input)) > 128 * 1024 || !op.validate(input))
    throw new Error('INPUT_INVALID');
  if (input.query?.limit !== undefined && (input.query.limit < 1 || input.query.limit > 200))
    throw new Error('INPUT_INVALID');
  if (input.query?.offset > 1000000 || (input.query?.filter?.length || 0) > 4096)
    throw new Error('INPUT_INVALID');
  for (const [k, v] of Object.entries(input.path || {})) {
    if (typeof v === 'string' && (!/^[a-zA-Z0-9_-]+$/.test(v) || v.length > 128))
      throw new Error('INPUT_INVALID');
    if (typeof v === 'number' && (!Number.isSafeInteger(v) || v < 0))
      throw new Error('INPUT_INVALID');
  }
  return input;
}
export function buildRequest(op, input, baseUrl) {
  validateInput(op, input);
  let path = op.path.replace(/\{([^}]+)\}/g, (_, key) =>
    encodeURIComponent(String(input.path[key])),
  );
  const url = new URL('/proxy/network/integration' + path, baseUrl);
  for (const [k, v] of Object.entries(input.query || {})) url.searchParams.set(k, String(v));
  return { url, method: op.method, body: input.body };
}
