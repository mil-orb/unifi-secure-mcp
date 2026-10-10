import { readFileSync } from 'node:fs';
import Ajv from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { assertBoundedJson } from './security.mjs';
export const spec = JSON.parse(
  readFileSync(new URL('../spec/unifi-network-10.6.106.json', import.meta.url), 'utf8'),
);
const schemas = spec.components.schemas;
function dereference(ref) {
  const prefix = '#/components/schemas/';
  if (!ref.startsWith(prefix)) throw new Error('SPEC_INVALID');
  const name = decodeURIComponent(ref.slice(prefix.length)).replace(/~1/g, '/').replace(/~0/g, '~');
  if (!schemas[name]) throw new Error('SPEC_INVALID');
  return schemas[name];
}
// UniFi uses OpenAPI discriminator mappings plus allOf inheritance. Expand each
// mapping into an explicit JSON-Schema union, merging inherited object fields.
function flatten(schema, seen = new Set()) {
  if (schema.$ref) {
    if (seen.has(schema.$ref)) throw new Error('SPEC_INVALID');
    return flatten(
      {
        ...dereference(schema.$ref),
        ...Object.fromEntries(Object.entries(schema).filter(([k]) => k !== '$ref')),
      },
      new Set([...seen, schema.$ref]),
    );
  }
  const own = { ...schema };
  delete own.allOf;
  if (schema.allOf) {
    for (const part of schema.allOf) {
      const p = flatten(part, seen);
      own.properties = { ...p.properties, ...own.properties };
      own.required = [...new Set([...(p.required || []), ...(own.required || [])])];
      own.type = own.type || p.type;
    }
  }
  return own;
}
export function normalize(schema, depth = 0) {
  if (depth > 40) throw new Error('SPEC_INVALID');
  const flat = flatten(schema);
  if (flat.discriminator?.mapping) {
    const { propertyName, mapping } = flat.discriminator;
    return {
      oneOf: Object.entries(mapping).map(([value, ref]) => {
        const child = flatten({ $ref: ref });
        delete child.discriminator;
        child.properties = {
          ...flat.properties,
          ...child.properties,
          [propertyName]: { type: 'string', const: value },
        };
        child.required = [
          ...new Set([...(flat.required || []), ...(child.required || []), propertyName]),
        ];
        return normalize(child, depth + 1);
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
        .map(([k, v]) => [k, normalize(v, depth + 1)]),
    );
    out.additionalProperties =
      flat.additionalProperties === undefined
        ? false
        : typeof flat.additionalProperties === 'object'
          ? normalize(flat.additionalProperties, depth + 1)
          : flat.additionalProperties;
  } else if (flat.additionalProperties !== undefined)
    out.additionalProperties =
      typeof flat.additionalProperties === 'object'
        ? normalize(flat.additionalProperties, depth + 1)
        : flat.additionalProperties;
  if (flat.items) out.items = normalize(flat.items, depth + 1);
  for (const key of ['oneOf', 'anyOf'])
    if (flat[key]) out[key] = flat[key].map((v) => normalize(v, depth + 1));
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
export const operations = Object.entries(spec.paths).flatMap(([path, item]) =>
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
            properties: Object.fromEntries(list.map((p) => [p.name, normalize(p.schema)])),
            required: list.filter((p) => p.required).map((p) => p.name),
            additionalProperties: false,
          };
          if (properties[place].required.length) required.push(place);
        }
      }
      if (op.requestBody) {
        properties.body = normalize(op.requestBody.content['application/json'].schema);
        if (op.requestBody.required) required.push('body');
      }
      const inputSchema = { type: 'object', properties, required, additionalProperties: false };
      const operation = {
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
      return operation;
    }),
);
export const byId = new Map(operations.map((o) => [o.id, o]));
export const byName = new Map(operations.map((o) => [o.name, o]));
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
