// Read-only firewall path explainer. collect() performs GET operations only through
// client.call; explain() is pure so it can be tested without a router. The result is a
// configuration model, not a packet trace.
import { label } from './mermaid.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const OCTET = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
const IPV4 = new RegExp(`^(?:${OCTET}\\.){3}${OCTET}$`);
const PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'ANY'];
const STATES = ['NEW', 'ESTABLISHED', 'RELATED', 'INVALID'];
const PROTOCOL_NUMBERS = { TCP: 6, UDP: 17, ICMP: 1 };
const PAGE = 200;
const POLICY_CAP = 1000;
const LIST_CAP = 200;
const EVALUATED_CAP = 100;
// Every operation collect() may read; the server offers unifi_explain_path only when
// all are exposed by toolsets. A test checks collect() stays within this list.
export const readOperations = Object.freeze([
  'getFirewallZones',
  'getNetworksOverviewPage',
  'getNetworkDetails',
  'getConnectedClientDetails',
  'getFirewallPolicies',
  'getTrafficMatchingLists',
  'getWifiBroadcastPage',
  'getWifiBroadcastDetails',
  'getAclRulePage',
  'getFirewallPolicyOrdering',
]);
const RUNTIME_FILTERS = {
  APPLICATION: 'application (DPI)',
  APPLICATION_CATEGORY: 'application category (DPI)',
  DOMAIN: 'domain',
  REGION: 'region (GeoIP)',
  VPN_SERVER: 'VPN server',
  SITE_TO_SITE_VPN_TUNNEL: 'site-to-site VPN tunnel',
};
export const ORDER = {
  rule: 'beforeSystemDefined user policies, then system-defined and derived policies by index, then afterSystemDefined user policies',
  note: 'This evaluation order was verified against the policy list in the UniFi UI.',
};
export const CAVEATS = [
  'Configuration model, not a packet trace: no traffic was observed.',
  'Multicast and broadcast discovery (mDNS, SSDP, vendor UDP broadcast) is not decided by these policies.',
  'Confirm the result in UniFi Insights > Flows.',
  'IPv4 only.',
];

const uuidSchema = { type: 'string', format: 'uuid' };
const one = (key, schema) => ({
  type: 'object',
  properties: { [key]: schema },
  required: [key],
  additionalProperties: false,
});
const endpointSchemas = [
  one('clientId', uuidSchema),
  one('ipAddress', { type: 'string', format: 'ipv4', maxLength: 15 }),
  one('networkId', uuidSchema),
  one('zoneId', uuidSchema),
];
export const inputSchema = {
  type: 'object',
  properties: {
    siteId: uuidSchema,
    source: { oneOf: endpointSchemas },
    destination: { oneOf: [...endpointSchemas, one('external', { const: true })] },
    protocol: { type: 'string', enum: PROTOCOLS, default: 'ANY' },
    port: { type: 'integer', minimum: 1, maximum: 65535, description: 'Destination port.' },
    connectionState: { type: 'string', enum: STATES, default: 'NEW' },
  },
  required: ['siteId', 'source', 'destination'],
  additionalProperties: false,
};

const invalid = () => {
  throw new Error('INPUT_INVALID');
};
const plain = (v) =>
  v !== null &&
  typeof v === 'object' &&
  !Array.isArray(v) &&
  Object.getPrototypeOf(v) === Object.prototype;
function parseEndpoint(value, allowExternal) {
  if (!plain(value)) invalid();
  const keys = Object.keys(value);
  if (keys.length !== 1) invalid();
  const [kind] = keys,
    v = value[kind];
  if (['clientId', 'networkId', 'zoneId'].includes(kind) && typeof v === 'string' && UUID.test(v))
    return { kind, value: v };
  if (kind === 'ipAddress' && typeof v === 'string' && IPV4.test(v)) return { kind, value: v };
  if (kind === 'external' && allowExternal && v === true) return { kind };
  return invalid();
}
// Strict, hand-written validation: the MCP server does not validate inputSchema itself.
export function parseQuery(args) {
  if (!plain(args)) invalid();
  const allowed = ['siteId', 'source', 'destination', 'protocol', 'port', 'connectionState'];
  if (Object.keys(args).some((k) => !allowed.includes(k))) invalid();
  if (typeof args.siteId !== 'string' || !UUID.test(args.siteId)) invalid();
  const source = parseEndpoint(args.source, false),
    destination = parseEndpoint(args.destination, true);
  const protocol = Object.hasOwn(args, 'protocol') ? args.protocol : 'ANY';
  const connectionState = Object.hasOwn(args, 'connectionState') ? args.connectionState : 'NEW';
  if (!PROTOCOLS.includes(protocol) || !STATES.includes(connectionState)) invalid();
  const port = Object.hasOwn(args, 'port') ? args.port : null;
  if (port !== null && (!Number.isInteger(port) || port < 1 || port > 65535 || protocol === 'ICMP'))
    invalid();
  return { siteId: args.siteId, source, destination, protocol, port, connectionState };
}

// IPv4 arithmetic on unsigned integers.
export const ipToInt = (ip) =>
  typeof ip === 'string' && IPV4.test(ip)
    ? ip.split('.').reduce((a, o) => a * 256 + Number(o), 0)
    : null;
export function cidr(value) {
  if (typeof value !== 'string') return null;
  const parts = value.split('/');
  if (parts.length > 2 || (parts.length === 2 && !/^\d{1,2}$/.test(parts[1]))) return null;
  const base = ipToInt(parts[0]),
    bits = parts.length === 2 ? Number(parts[1]) : 32;
  if (base === null || bits > 32) return null;
  const size = 2 ** (32 - bits),
    start = Math.floor(base / size) * size;
  return { start, stop: start + size - 1 };
}
const within = (ip, range) => range !== null && ip >= range.start && ip <= range.stop;
function subnets(network) {
  const c = network?.ipv4Configuration;
  if (!c) return [];
  return [
    Number.isInteger(c.prefixLength) ? cidr(`${c.hostIpAddress}/${c.prefixLength}`) : null,
    ...(Array.isArray(c.additionalHostIpSubnets) ? c.additionalHostIpSubnets.map(cidr) : []),
  ].filter(Boolean);
}
function ipItemRange(item) {
  if (item?.type === 'IP_ADDRESS')
    return String(item.value).includes('/') ? null : cidr(item.value);
  if (item?.type === 'SUBNET') return String(item.value).includes('/') ? cidr(item.value) : null;
  if (item?.type === 'IP_ADDRESS_RANGE') {
    const start = ipToInt(item.start),
      stop = ipToInt(item.stop);
    return start === null || stop === null ? null : { start, stop };
  }
  return null;
}

const systemZone = (snapshot, name) =>
  (snapshot.zones || []).find(
    (z) => z?.metadata?.origin === 'SYSTEM_DEFINED' && String(z.name).toLowerCase() === name,
  ) || null;
const zoneOfNetwork = (snapshot, network) =>
  (snapshot.zones || []).find((z) => network.zoneId && z.id === network.zoneId) ||
  (snapshot.zones || []).find(
    (z) => Array.isArray(z.networkIds) && z.networkIds.includes(network.id),
  ) ||
  null;
function resolveOne(snapshot, endpoint) {
  const out = {
    kind: endpoint.kind,
    ip: null,
    mac: null,
    network: null,
    zone: null,
    gateway: false,
    external: false,
    unresolved: [],
  };
  const networks = snapshot.networks || [];
  if (endpoint.kind === 'external') {
    out.external = true;
    out.zone = systemZone(snapshot, 'external');
    if (!out.zone) out.unresolved.push('no system-defined External zone was found');
    return out;
  }
  if (endpoint.kind === 'zoneId') {
    out.zone = (snapshot.zones || []).find((z) => z.id === endpoint.value) || null;
    if (!out.zone) out.unresolved.push('zone not found');
    return out;
  }
  if (endpoint.kind === 'networkId') {
    out.network = networks.find((n) => n.id === endpoint.value) || null;
    if (!out.network) out.unresolved.push('network not found');
  }
  if (endpoint.kind === 'clientId') {
    const client = snapshot.clients?.[endpoint.value];
    if (!client) out.unresolved.push('client not found or not connected');
    else {
      out.ip = IPV4.test(client.ipAddress ?? '') ? client.ipAddress : null;
      out.mac = typeof client.macAddress === 'string' ? client.macAddress.toLowerCase() : null;
      if (!out.ip) out.unresolved.push('client has no IPv4 address');
    }
  }
  if (endpoint.kind === 'ipAddress') out.ip = endpoint.value;
  if (out.ip && !out.network) {
    if (networks.some((n) => n.ipv4Configuration?.hostIpAddress === out.ip)) {
      out.gateway = true;
      out.zone = systemZone(snapshot, 'gateway');
      if (!out.zone) out.unresolved.push('no system-defined Gateway zone was found');
      return out;
    }
    const ip = ipToInt(out.ip);
    out.network = networks.find((n) => subnets(n).some((r) => within(ip, r))) || null;
    if (!out.network) out.unresolved.push('IP address is not inside any network subnet');
  }
  if (out.network) {
    out.zone = zoneOfNetwork(snapshot, out.network);
    if (!out.zone) out.unresolved.push('network has no firewall zone');
  }
  return out;
}
export function resolveEndpoints(snapshot, query) {
  return {
    source: resolveOne(snapshot, query.source),
    destination: resolveOne(snapshot, query.destination),
  };
}
const sameNetwork = (src, dst) =>
  Boolean(src.network && dst.network && src.network.id === dst.network.id);

// Order: beforeSystemDefined, system-defined/derived by index, afterSystemDefined.
export function effectiveOrder(policies, ordering, sourceZoneId, destinationZoneId) {
  const pair = (policies || []).filter(
    (p) => p?.source?.zoneId === sourceZoneId && p?.destination?.zoneId === destinationZoneId,
  );
  const byId = new Map(pair.map((p) => [p.id, p])),
    used = new Set(),
    rows = [];
  const take = (id, stage) => {
    if (byId.has(id) && !used.has(id)) {
      used.add(id);
      rows.push({ policy: byId.get(id), stage });
    }
  };
  const index = (p) => (Number.isSafeInteger(p.index) ? p.index : Number.MAX_SAFE_INTEGER);
  for (const id of ordering?.beforeSystemDefined || []) take(id, 'beforeSystemDefined');
  pair
    .filter((p) => !used.has(p.id) && p.metadata?.origin !== 'USER_DEFINED')
    .sort((a, b) => index(a) - index(b))
    .forEach((p) => take(p.id, 'systemDefined'));
  for (const id of ordering?.afterSystemDefined || []) take(id, 'afterSystemDefined');
  pair.filter((p) => !used.has(p.id)).forEach((p) => take(p.id, 'unordered'));
  return rows;
}

const yes = () => ({ r: true });
const no = (why) => ({ r: false, why });
const maybe = (why) => ({ r: null, why });
const opposite = (hit, f, why) => (hit !== Boolean(f.matchOpposite) ? yes() : no(why));
function protocolCheck(f, q) {
  if (!f) return yes();
  if (f.type === 'PRESET') {
    if (f.preset?.name !== 'TCP_UDP')
      return maybe(`unrecognised protocol preset ${label(f.preset?.name)}`);
    if (q === 'ANY') return maybe('policy matches TCP/UDP only; query protocol is ANY');
    return q === 'TCP' || q === 'UDP' ? yes() : no('protocol is not TCP or UDP');
  }
  let hit;
  if (f.type === 'NAMED_PROTOCOL' && typeof f.protocol?.name === 'string')
    hit = (x) => x === f.protocol.name;
  else if (f.type === 'PROTOCOL_NUMBER' && Number.isInteger(f.protocolNumber))
    hit = (x) => PROTOCOL_NUMBERS[x] === f.protocolNumber;
  else return maybe(`unrecognised protocol filter ${label(f.type)}`);
  if (q === 'ANY') return maybe('policy filters by protocol; query protocol is ANY');
  return opposite(hit(q), f, 'protocol does not match');
}
function scopeCheck(p, { query }) {
  const scope = p.ipProtocolScope;
  if (scope?.ipVersion === 'IPV6') return no('IPv6-only policy; query is IPv4');
  if (scope?.ipVersion !== 'IPV4' && scope?.ipVersion !== 'IPV4_AND_IPV6')
    return maybe(`unrecognised IP version ${label(scope?.ipVersion)}`);
  return protocolCheck(scope.protocolFilter, query.protocol);
}
function networkCheck(f, ep, side) {
  if (!Array.isArray(f?.networkIds)) return maybe(`${side} network filter is malformed`);
  if (ep.external)
    return f.matchOpposite
      ? maybe(`${side} is external; inverted network filter`)
      : no(`${side} is external, not a local network`);
  if (ep.gateway) return maybe(`${side} is a gateway address`);
  if (!ep.network) return maybe(`${side} network is unknown`);
  return opposite(f.networkIds.includes(ep.network.id), f, `${side} network not matched`);
}
function ipCheck(f, ep, side, ctx) {
  let items;
  if (f?.type === 'IP_ADDRESSES') items = f.items;
  else if (f?.type === 'TRAFFIC_MATCHING_LIST') {
    const list = ctx.lists.get(f.trafficMatchingListId);
    if (!list) return maybe(`${side} traffic matching list was not found`);
    if (list.type !== 'IPV4_ADDRESSES')
      return maybe(`${side} traffic matching list type ${label(list.type)} is not IPv4 addresses`);
    items = list.items;
  } else return maybe(`unrecognised ${side} IP address filter ${label(f?.type)}`);
  if (!Array.isArray(items)) return maybe(`${side} IP address filter is malformed`);
  if (!ep.ip) return maybe(`${side} IP address is unknown`);
  const ip = ipToInt(ep.ip);
  let hit = false,
    unknown = false;
  for (const item of items) {
    if (String(item?.value ?? item?.start ?? '').includes(':')) continue; // IPv6 never matches
    const range = ipItemRange(item);
    if (!range) unknown = true;
    else if (within(ip, range)) hit = true;
  }
  if (!hit && unknown)
    return maybe(`${side} IP address filter has an item that cannot be evaluated`);
  return opposite(hit, f, `${side} IP address not matched`);
}
function macCheck(macs, ep, side) {
  if (!ep.mac) return maybe(`${side} MAC address is unknown`);
  return macs.some((m) => String(m).toLowerCase() === ep.mac)
    ? yes()
    : no(`${side} MAC address not matched`);
}
function portCheck(f, side, ctx) {
  if (ctx.query.protocol === 'ICMP') return no('port filter cannot match ICMP');
  if (side === 'source') return maybe('source port is not part of the query');
  if (ctx.query.port === null) return maybe('destination port not given in the query');
  let items;
  if (f?.type === 'PORTS') items = f.items;
  else if (f?.type === 'TRAFFIC_MATCHING_LIST') {
    const list = ctx.lists.get(f.trafficMatchingListId);
    if (!list) return maybe('port traffic matching list was not found');
    if (list.type !== 'PORTS')
      return maybe(`traffic matching list type ${label(list.type)} is not ports`);
    items = list.items;
  } else return maybe(`unrecognised port filter ${label(f?.type)}`);
  if (!Array.isArray(items)) return maybe('port filter is malformed');
  const port = ctx.query.port;
  let hit = false,
    unknown = false;
  for (const item of items) {
    if (item?.type === 'PORT_NUMBER') hit ||= item.value === port;
    else if (item?.type === 'PORT_NUMBER_RANGE') hit ||= port >= item.start && port <= item.stop;
    else unknown = true;
  }
  if (!hit && unknown) return maybe('port filter has an item that cannot be evaluated');
  return opposite(hit, f, 'destination port not matched');
}
function filterChecks(tf, side, ctx) {
  if (tf === undefined || tf === null) return [yes()];
  const ep = side === 'source' ? ctx.src : ctx.dst,
    out = [];
  switch (tf.type) {
    case 'NETWORK':
      out.push(networkCheck(tf.networkFilter, ep, side));
      break;
    case 'IP_ADDRESS':
      out.push(ipCheck(tf.ipAddressFilter, ep, side, ctx));
      break;
    case 'MAC_ADDRESS':
      out.push(
        Array.isArray(tf.macAddressFilter?.macAddresses)
          ? macCheck(tf.macAddressFilter.macAddresses, ep, side)
          : maybe(`${side} MAC address filter is malformed`),
      );
      break;
    case 'PORT':
      break;
    case 'IPV6_IID':
      return [no(`${side} IPv6 interface-identifier filter; query is IPv4`)];
    default:
      return [
        maybe(
          RUNTIME_FILTERS[tf.type]
            ? `${side} ${RUNTIME_FILTERS[tf.type]} filter is decided at runtime`
            : `unrecognised ${side} filter type ${label(tf.type)}`,
        ),
      ];
  }
  if (tf.type !== 'MAC_ADDRESS' && typeof tf.macAddressFilter === 'string')
    out.push(macCheck([tf.macAddressFilter], ep, side));
  if (tf.portFilter) out.push(portCheck(tf.portFilter, side, ctx));
  return out;
}
export function evaluatePolicy(policy, ctx) {
  if (policy.enabled !== true) return { result: 'skipped', reasons: ['policy is disabled'] };
  const states = policy.connectionStateFilter;
  const checks = [
    scopeCheck(policy, ctx),
    !Array.isArray(states) || !states.length || states.includes(ctx.query.connectionState)
      ? yes()
      : no(`connection state ${ctx.query.connectionState} is not in the filter`),
    policy.schedule ? maybe(`schedule ${label(policy.schedule.mode)} depends on the time`) : yes(),
    policy.ipsecFilter ? maybe('IPsec filter is decided at runtime') : yes(),
    ...filterChecks(policy.source?.trafficFilter, 'source', ctx),
    ...filterChecks(policy.destination?.trafficFilter, 'destination', ctx),
  ];
  const miss = checks.find((c) => c.r === false);
  if (miss) return { result: 'no-match', reasons: [miss.why] };
  const unknown = checks.filter((c) => c.r === null);
  if (unknown.length) return { result: 'indeterminate', reasons: unknown.map((c) => c.why) };
  return { result: 'match', reasons: [] };
}

const safeId = (v) => (typeof v === 'string' && UUID.test(v) ? v : null);
const flag = (v) => (typeof v === 'boolean' ? v : null);
const summary = (e) => ({
  kind: e.kind,
  ipAddress: e.ip,
  macKnown: Boolean(e.mac),
  gateway: e.gateway,
  external: e.external,
  network: e.network
    ? {
        id: safeId(e.network.id),
        name: label(e.network.name),
        vlanId: Number.isInteger(e.network.vlanId) ? e.network.vlanId : null,
        isolationEnabled: flag(e.network.isolationEnabled),
        internetAccessEnabled: flag(e.network.internetAccessEnabled),
      }
    : null,
  zone: e.zone
    ? { id: safeId(e.zone.id), name: label(e.zone.name), origin: label(e.zone.metadata?.origin) }
    : null,
});
const setting = (network, name, reason) => ({
  verdict: 'BLOCK',
  decidedBy: {
    type: 'NETWORK_SETTING',
    setting: name,
    networkId: safeId(network.id),
    networkName: label(network.name),
  },
  shortCircuit: {
    type: name === 'internetAccessEnabled' ? 'INTERNET_ACCESS_DISABLED' : 'NETWORK_ISOLATED',
    reason,
  },
});
export function explain(snapshot, query) {
  const { source: src, destination: dst } = resolveEndpoints(snapshot, query);
  const result = {
    query: {
      protocol: query.protocol,
      port: query.port,
      connectionState: query.connectionState,
      ipVersion: 'IPV4',
    },
    source: summary(src),
    destination: summary(dst),
    verdict: 'UNDETERMINED',
    decidedBy: null,
    shortCircuit: null,
    unresolved: [],
    indeterminateAbove: [],
    evaluated: [],
    evaluatedTruncated: false,
    order: ORDER,
    policiesComplete: snapshot.policiesComplete !== false,
    caveats: [...CAVEATS],
  };
  if (!result.policiesComplete)
    result.caveats.push(
      `Only the first ${POLICY_CAP} firewall policies were read; later ones were not evaluated.`,
    );
  result.unresolved = [
    ...src.unresolved.map((r) => `source: ${r}`),
    ...dst.unresolved.map((r) => `destination: ${r}`),
  ];
  if (result.unresolved.length) return result;
  if (sameNetwork(src, dst)) {
    result.shortCircuit = {
      type: 'SAME_NETWORK',
      reason:
        'Both ends are on the same network, so traffic is switched at layer 2 and zone firewall policies do not apply. Wi-Fi client isolation and ACL rules govern it.',
      wifiBroadcasts: (snapshot.wifi || []).slice(0, 20).map((w) => ({
        id: safeId(w.id),
        name: label(w.name),
        enabled: flag(w.enabled),
        clientIsolationEnabled: flag(w.clientIsolationEnabled),
      })),
      aclRules: (snapshot.acl || [])
        .filter((r) => r?.enabled === true)
        .slice(0, 50)
        .map((r) => ({
          id: safeId(r.id),
          name: label(r.name),
          type: label(r.type),
          action: label(r.action),
          index: Number.isSafeInteger(r.index) ? r.index : null,
        })),
    };
    return result;
  }
  if (dst.external && src.network?.internetAccessEnabled === false)
    return Object.assign(
      result,
      setting(
        src.network,
        'internetAccessEnabled',
        'The source network has internet access disabled.',
      ),
    );
  const isolated = [src, dst].find((e) => e.network?.isolationEnabled === true);
  if (isolated && src.network && dst.network)
    return Object.assign(
      result,
      setting(
        isolated.network,
        'isolationEnabled',
        'A network on this path has isolation enabled. This verdict is inferred from the network setting, not from a listed policy (assumption).',
      ),
    );
  const lists = new Map((snapshot.trafficMatchingLists || []).map((l) => [l.id, l]));
  const ctx = { query, src, dst, lists };
  const rows = effectiveOrder(snapshot.policies, snapshot.ordering, src.zone.id, dst.zone.id);
  let decided = null;
  for (const [i, { policy, stage }] of rows.entries()) {
    const { result: outcome, reasons } = evaluatePolicy(policy, ctx);
    const row = {
      order: i + 1,
      stage,
      id: safeId(policy.id),
      name: label(policy.name),
      origin: label(policy.metadata?.origin),
      action: label(policy.action?.type),
      result: outcome,
      reasons,
    };
    result.evaluated.push(row);
    if (outcome === 'indeterminate') result.indeterminateAbove.push(row);
    if (outcome === 'match') {
      decided = row;
      break;
    }
  }
  result.evaluatedTruncated = result.evaluated.length > EVALUATED_CAP;
  result.evaluated = result.evaluated.slice(0, EVALUATED_CAP);
  result.indeterminateAbove = result.indeterminateAbove.slice(0, 50);
  if (decided) {
    result.verdict = ['ALLOW', 'BLOCK', 'REJECT'].includes(decided.action)
      ? decided.action
      : 'UNDETERMINED';
    result.decidedBy = { type: 'POLICY', ...decided };
    if (result.indeterminateAbove.length)
      result.caveats.push(
        'Policies listed in indeterminateAbove could match first at runtime and change this verdict.',
      );
  } else
    result.caveats.push(
      rows.length
        ? 'No policy for this zone pair definitely matched.'
        : 'No firewall policy was found for this zone pair.',
    );
  return result;
}

async function page(client, operationId, path, cap) {
  const data = [];
  let offset = 0,
    more = false;
  for (;;) {
    const res = await client.call(operationId, { path, query: { offset, limit: PAGE } });
    const items = Array.isArray(res?.data) ? res.data : [];
    data.push(...items);
    const total = Number.isSafeInteger(res?.totalCount) ? res.totalCount : null;
    if (items.length < PAGE || (total !== null && offset + items.length >= total)) break;
    if (data.length >= cap) {
      more = true;
      break;
    }
    offset += PAGE;
  }
  return { data: data.slice(0, cap), complete: !more && data.length <= cap };
}
export async function collect(client, siteId, query) {
  const path = { siteId };
  const snapshot = { zones: (await page(client, 'getFirewallZones', path, LIST_CAP)).data };
  snapshot.networks = [];
  for (const overview of (await page(client, 'getNetworksOverviewPage', path, LIST_CAP)).data) {
    if (!safeId(overview?.id)) continue;
    const details = await client.call('getNetworkDetails', {
      path: { siteId, networkId: overview.id },
    });
    snapshot.networks.push({ ...overview, ...details });
  }
  snapshot.clients = {};
  for (const endpoint of [query.source, query.destination])
    if (endpoint.kind === 'clientId' && !(endpoint.value in snapshot.clients))
      try {
        snapshot.clients[endpoint.value] = await client.call('getConnectedClientDetails', {
          path: { siteId, clientId: endpoint.value },
        });
      } catch (e) {
        if (e?.message !== 'UPSTREAM_404') throw e;
        snapshot.clients[endpoint.value] = null;
      }
  const policies = await page(client, 'getFirewallPolicies', path, POLICY_CAP);
  snapshot.policies = policies.data;
  snapshot.policiesComplete = policies.complete;
  snapshot.trafficMatchingLists = (
    await page(client, 'getTrafficMatchingLists', path, LIST_CAP)
  ).data;
  snapshot.ordering = null;
  const { source: src, destination: dst } = resolveEndpoints(snapshot, query);
  if (src.unresolved.length || dst.unresolved.length) return snapshot;
  if (sameNetwork(src, dst)) {
    const network = src.network;
    snapshot.wifi = [];
    const carried = (await page(client, 'getWifiBroadcastPage', path, LIST_CAP)).data.filter(
      (w) =>
        safeId(w?.id) &&
        ((w.network?.type === 'SPECIFIC' && w.network.networkId === network.id) ||
          (w.network?.type === 'NATIVE' && network.default === true)),
    );
    for (const w of carried.slice(0, 20))
      snapshot.wifi.push(
        await client.call('getWifiBroadcastDetails', {
          path: { siteId, wifiBroadcastId: w.id },
        }),
      );
    snapshot.acl = (await page(client, 'getAclRulePage', path, LIST_CAP)).data;
    return snapshot;
  }
  const ordering = await client.call('getFirewallPolicyOrdering', {
    path,
    query: { sourceFirewallZoneId: src.zone.id, destinationFirewallZoneId: dst.zone.id },
  });
  snapshot.ordering = ordering?.orderedFirewallPolicyIds ?? null;
  return snapshot;
}
export async function explainPath(client, args) {
  const query = parseQuery(args);
  return explain(await collect(client, query.siteId, query), query);
}
