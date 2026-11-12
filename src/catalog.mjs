import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import Ajv from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { assertBoundedJson, REDACTED } from './security.mjs';
const fail = () => {
  throw new Error('SPEC_INVALID');
};
const semver = /^(\d{1,4})\.(\d{1,4})\.(\d{1,6})$/;
export const parseVersion = (v) => {
  const m = typeof v === 'string' && semver.exec(v);
  return m ? m.slice(1).map(Number) : null;
};
export function compareVersions(a, b) {
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
// Bundled specs live only here; tooling may pass another directory URL (with a trailing slash).
export const SPEC_DIR = new URL('../spec/', import.meta.url);
export function readManifest(dir = SPEC_DIR) {
  let data;
  try {
    data = JSON.parse(readFileSync(new URL('manifest.json', dir), 'utf8'));
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
export function loadSpec(entry, dir = SPEC_DIR) {
  if (!parseVersion(entry?.version) || entry.file !== `unifi-network-${entry.version}.json`) fail();
  let bytes, parsed;
  try {
    bytes = readFileSync(new URL(entry.file, dir));
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
// A property declared by several allOf members must satisfy every declaration.
// UniFi bases often declare a placeholder ({} or a description) that a later member
// refines, so a constraint-free declaration yields to the other one; two object
// declarations merge as allOf (recursively); two other declarations are intersected.
const constraintFree = (s) => Object.keys(s).every((k) => k.startsWith('x-') || ANNOTATIONS.has(k));
function mergeProperty(a, b, schemas) {
  if (JSON.stringify(a) === JSON.stringify(b) || constraintFree(b)) return a;
  if (constraintFree(a)) return b;
  const merged =
    flatten(a, schemas).properties || flatten(b, schemas).properties
      ? { allOf: [a, b] }
      : { 'x-intersection': [a, b] };
  if (a.readOnly || b.readOnly) merged.readOnly = true;
  return merged;
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
    const parts = schema.allOf.map((part) => flatten(part, schemas, seen));
    if (schema.properties) parts.push({ properties: schema.properties });
    own.properties = {};
    for (const p of parts) {
      for (const [k, v] of Object.entries(p.properties || {}))
        own.properties[k] = Object.hasOwn(own.properties, k)
          ? mergeProperty(own.properties[k], v, schemas)
          : v;
      own.required = [...new Set([...(p.required || []), ...(own.required || [])])];
      own.type = own.type || p.type;
    }
  }
  return own;
}
export function normalize(schema, depth = 0, schemas = activeSchemas) {
  if (depth > 40) throw new Error('SPEC_INVALID');
  if (schema['x-intersection'])
    return { allOf: schema['x-intersection'].map((s) => normalize(s, depth + 1, schemas)) };
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
// Schema keywords normalize() implements, and annotations it may safely drop.
const UNDERSTOOD = new Set([
  '$ref',
  'allOf',
  'oneOf',
  'anyOf',
  'discriminator',
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
  'default',
  'properties',
  'additionalProperties',
  'items',
  'nullable',
  'readOnly',
]);
const ANNOTATIONS = new Set([
  'title',
  'description',
  'example',
  'examples',
  'deprecated',
  'writeOnly',
  'externalDocs',
  '$comment',
]);
// flatten() merges only these from an allOf member; anything else would be dropped.
const ALLOF_MERGED = new Set(['$ref', 'allOf', 'type', 'properties', 'required', 'discriminator']);
const TYPES = new Set(['object', 'array', 'string', 'number', 'integer', 'boolean', 'null']);
const SCHEMA_REF = '#/components/schemas/';
const pointer = (parts) =>
  '#/' + parts.map((p) => String(p).replace(/~/g, '~0').replace(/\//g, '~1')).join('/');
// Lists every construct buildCatalog()/normalize() would not enforce faithfully, as
// "JSON-pointer: reason". An empty list means the spec is safe to compile.
export function auditSpec(source) {
  const findings = [];
  const add = (parts, reason) => findings.push(`${pointer(parts)}: ${reason}`);
  const schemas = source?.components?.schemas;
  if (!schemas || typeof schemas !== 'object') return ['#/components/schemas: missing'];
  const target = (ref) => {
    if (typeof ref !== 'string' || !ref.startsWith(SCHEMA_REF)) return undefined;
    const name = decodeURIComponent(ref.slice(SCHEMA_REF.length))
      .replace(/~1/g, '/')
      .replace(/~0/g, '~');
    return Object.hasOwn(schemas, name) ? schemas[name] : undefined;
  };
  const ignorable = (k) => k.startsWith('x-') || ANNOTATIONS.has(k);
  const allOfMember = (member, parts) => {
    const seen = new Set();
    for (let m = member; m && typeof m === 'object'; m = target(m.$ref)) {
      for (const k of Object.keys(m))
        if (!ignorable(k) && !ALLOF_MERGED.has(k))
          add(parts, `keyword "${k}" inside an allOf member is dropped by normalize()`);
      if (!m.$ref || seen.has(m.$ref)) break;
      seen.add(m.$ref);
    }
  };
  const visit = (schema, parts) => {
    if (!schema || typeof schema !== 'object' || Array.isArray(schema))
      return add(parts, 'schema must be an object');
    for (const [k, v] of Object.entries(schema)) {
      const at = [...parts, k];
      if (ignorable(k)) continue;
      if (!UNDERSTOOD.has(k)) {
        add(at, `unsupported schema keyword "${k}"`);
        continue;
      }
      if (k === '$ref' && !target(v)) add(at, 'unresolvable or non-schema $ref');
      else if (k === 'type' && ![v].flat().every((t) => TYPES.has(t))) add(at, 'unknown type');
      else if (k === 'format' && (typeof v !== 'string' || !Object.hasOwn(ajv.formats, v)))
        add(at, `unsupported format "${v}"`);
      else if (k === 'discriminator') {
        if (!v || typeof v.propertyName !== 'string' || !v.mapping || typeof v.mapping !== 'object')
          add(at, 'discriminator needs propertyName and mapping');
        else {
          for (const dk of Object.keys(v))
            if (!['propertyName', 'mapping'].includes(dk) && !dk.startsWith('x-'))
              add([...at, dk], `unsupported discriminator keyword "${dk}"`);
          for (const [value, ref] of Object.entries(v.mapping))
            if (!target(ref)) add([...at, 'mapping', value], 'unresolvable mapping $ref');
        }
      } else if (k === 'properties') {
        if (!v || typeof v !== 'object') add(at, 'properties must be an object');
        else for (const [name, child] of Object.entries(v)) visit(child, [...at, name]);
      } else if (k === 'items') visit(v, at);
      else if (k === 'additionalProperties' && typeof v !== 'boolean') visit(v, at);
      else if (['allOf', 'oneOf', 'anyOf'].includes(k)) {
        if (!Array.isArray(v)) add(at, `${k} must be an array`);
        else
          v.forEach((child, i) => {
            visit(child, [...at, i]);
            if (k === 'allOf') allOfMember(child, [...at, i]);
          });
      }
    }
  };
  for (const [name, schema] of Object.entries(schemas))
    visit(schema, ['components', 'schemas', name]);
  for (const [path, item] of Object.entries(source.paths || {})) {
    const params = (list, parts) =>
      (list || []).forEach((p, i) => {
        if (!p || !['path', 'query'].includes(p.in) || typeof p.name !== 'string' || !p.schema)
          add([...parts, i], 'parameter must be an inline path/query parameter with a schema');
        else visit(p.schema, [...parts, i, 'schema']);
      });
    params(item.parameters, ['paths', path, 'parameters']);
    for (const [method, op] of Object.entries(item)) {
      if (!['get', 'post', 'put', 'patch', 'delete'].includes(method) || !op?.operationId) continue;
      params(op.parameters, ['paths', path, method, 'parameters']);
      if (op.requestBody) {
        const schema = op.requestBody.content?.['application/json']?.schema;
        if (!schema)
          add(
            ['paths', path, method, 'requestBody'],
            'request body must be inline application/json',
          );
        else
          visit(schema, [
            'paths',
            path,
            method,
            'requestBody',
            'content',
            'application/json',
            'schema',
          ]);
      }
    }
  }
  return findings;
}
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
  if (auditSpec(loaded).length) fail();
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
// The redaction marker is never a real value: sending it would overwrite a secret.
const hasRedactionMarker = (v) =>
  typeof v === 'string'
    ? v.includes(REDACTED)
    : Boolean(v && typeof v === 'object' && Object.values(v).some(hasRedactionMarker));
export function validateInput(op, input) {
  assertBoundedJson(input);
  if (hasRedactionMarker(input.body)) throw new Error('REDACTED_VALUE');
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
