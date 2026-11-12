import test from 'node:test';
import assert from 'node:assert/strict';
import { byId } from '../src/catalog.mjs';
import { parseQuery, explain, collect, explainPath } from '../src/pathfinder.mjs';

// Synthetic data only. Addresses are documentation ranges built at runtime so no
// literal address appears in source (the privacy checker rejects literals).
const internalIp = (n) => `192.0.2.${n}`;
const iotIp = (n) => `198.51.100.${n}`;
const mac = (last) => ['02', '00', '00', '00', '00', last].join(':');
const uid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const site = uid(1);
const Z = { internal: uid(11), iot: uid(12), gateway: uid(13), external: uid(14) };
const N = { internal: uid(21), iot: uid(22) };
const C = { hub: uid(31), bulb: uid(32) };
const scope = { ipVersion: 'IPV4' };
const policy = (n, from, to, action, extra = {}) => ({
  id: uid(n),
  enabled: true,
  name: `Policy ${n}`,
  index: n,
  action: { type: action },
  source: { zoneId: from },
  destination: { zoneId: to },
  ipProtocolScope: scope,
  loggingEnabled: false,
  reportFlowEnabled: true,
  metadata: { origin: 'USER_DEFINED' },
  ...extra,
});
const system = { metadata: { origin: 'SYSTEM_DEFINED' } };
function fixture() {
  return {
    zones: [
      { id: Z.internal, name: 'Internal', networkIds: [N.internal], ...system },
      { id: Z.iot, name: 'IoT', networkIds: [N.iot], metadata: { origin: 'USER_DEFINED' } },
      { id: Z.gateway, name: 'Gateway', networkIds: [], ...system },
      { id: Z.external, name: 'External', networkIds: [], ...system },
    ],
    networks: [
      {
        id: N.internal,
        management: 'GATEWAY',
        name: 'Internal',
        vlanId: 1,
        default: true,
        zoneId: Z.internal,
        isolationEnabled: false,
        internetAccessEnabled: true,
        ipv4Configuration: { hostIpAddress: internalIp(1), prefixLength: 25 },
      },
      {
        // No zoneId: the zone is found through the zone's networkIds.
        id: N.iot,
        management: 'GATEWAY',
        name: 'IoT',
        vlanId: 20,
        default: false,
        isolationEnabled: false,
        internetAccessEnabled: true,
        ipv4Configuration: { hostIpAddress: iotIp(1), prefixLength: 24 },
      },
    ],
    clients: {
      [C.hub]: { id: C.hub, ipAddress: internalIp(10), macAddress: mac('0a') },
      [C.bulb]: { id: C.bulb, ipAddress: iotIp(20), macAddress: mac('14') },
    },
    policies: [
      policy(41, Z.internal, Z.iot, 'ALLOW'),
      policy(43, Z.iot, Z.internal, 'ALLOW', {
        ...system,
        index: 20000,
        name: 'Allow Return Traffic',
        connectionStateFilter: ['ESTABLISHED', 'RELATED'],
      }),
      policy(42, Z.iot, Z.internal, 'BLOCK', { ...system, index: 30000, name: 'Block All' }),
      policy(44, Z.internal, Z.iot, 'BLOCK', { ...system, index: 30000, name: 'Block All' }),
      policy(48, Z.iot, Z.external, 'ALLOW', { ...system, index: 30000, name: 'Allow All' }),
    ],
    policiesComplete: true,
    trafficMatchingLists: [],
    ordering: { beforeSystemDefined: [uid(41)], afterSystemDefined: [] },
  };
}
const q = (args) => parseQuery({ siteId: site, ...args });
const run = (snapshot, args) => explain(snapshot, q(args));
const hub = { clientId: C.hub },
  bulb = { clientId: C.bulb };

test('Internal -> IoT is allowed by a user policy ordered before system policies', () => {
  const r = run(fixture(), { source: hub, destination: bulb, protocol: 'TCP', port: 443 });
  assert.equal(r.verdict, 'ALLOW');
  assert.equal(r.decidedBy.type, 'POLICY');
  assert.equal(r.decidedBy.id, uid(41));
  assert.equal(r.decidedBy.stage, 'beforeSystemDefined');
  assert.equal(r.decidedBy.origin, 'USER_DEFINED');
  assert.equal(r.source.zone.name, 'Internal');
  assert.equal(r.destination.zone.name, 'IoT');
  assert.equal(r.destination.network.vlanId, 20);
  assert.deepEqual(r.indeterminateAbove, []);
  assert.equal('assumption' in r.order, false);
  assert.match(r.order.rule, /beforeSystemDefined/);
  assert.ok(r.caveats.some((c) => /not a packet trace/.test(c)));
  assert.ok(r.caveats.some((c) => /mDNS, SSDP/.test(c)));
  assert.ok(r.caveats.some((c) => /Flows/.test(c)));
});

test('IoT -> Internal NEW is blocked by a system policy; ESTABLISHED is allowed', () => {
  const s = fixture();
  s.ordering = { beforeSystemDefined: [], afterSystemDefined: [] };
  const blocked = run(s, { source: bulb, destination: hub, protocol: 'TCP', port: 8123 });
  assert.equal(blocked.verdict, 'BLOCK');
  assert.equal(blocked.decidedBy.id, uid(42));
  assert.equal(blocked.decidedBy.origin, 'SYSTEM_DEFINED');
  assert.equal(blocked.evaluated[0].id, uid(43));
  assert.equal(blocked.evaluated[0].result, 'no-match');
  assert.match(blocked.evaluated[0].reasons[0], /connection state NEW/);
  const established = run(s, {
    source: bulb,
    destination: hub,
    protocol: 'TCP',
    port: 8123,
    connectionState: 'ESTABLISHED',
  });
  assert.equal(established.verdict, 'ALLOW');
  assert.equal(established.decidedBy.id, uid(43));
});

test('same network short-circuits to layer 2 with Wi-Fi isolation and ACL context', () => {
  const s = fixture();
  s.wifi = [{ id: uid(61), name: 'Lab <b>"x"</b>', enabled: true, clientIsolationEnabled: true }];
  s.acl = [
    { id: uid(71), name: 'ACL one', enabled: true, type: 'IPV4', action: 'BLOCK', index: 1 },
    { id: uid(72), name: 'ACL off', enabled: false, type: 'MAC', action: 'ALLOW', index: 2 },
  ];
  const r = run(s, { source: { ipAddress: iotIp(20) }, destination: { ipAddress: iotIp(21) } });
  assert.equal(r.verdict, 'UNDETERMINED');
  assert.equal(r.shortCircuit.type, 'SAME_NETWORK');
  assert.deepEqual(r.evaluated, []);
  assert.equal(r.shortCircuit.wifiBroadcasts[0].clientIsolationEnabled, true);
  assert.doesNotMatch(r.shortCircuit.wifiBroadcasts[0].name, /[<>"]/);
  assert.deepEqual(
    r.shortCircuit.aclRules.map((a) => a.id),
    [uid(71)],
  );
});

test('a port mismatch is skipped and a later port range match decides', () => {
  const s = fixture();
  s.policies.push(
    policy(45, Z.internal, Z.iot, 'BLOCK', {
      destination: {
        zoneId: Z.iot,
        trafficFilter: {
          type: 'PORT',
          portFilter: {
            type: 'PORTS',
            matchOpposite: false,
            items: [{ type: 'PORT_NUMBER', value: 22 }],
          },
        },
      },
    }),
    policy(46, Z.internal, Z.iot, 'REJECT', {
      destination: {
        zoneId: Z.iot,
        trafficFilter: {
          type: 'NETWORK',
          networkFilter: { networkIds: [N.iot], matchOpposite: false },
          portFilter: {
            type: 'PORTS',
            matchOpposite: false,
            items: [{ type: 'PORT_NUMBER_RANGE', start: 400, stop: 500 }],
          },
        },
      },
    }),
  );
  s.ordering = { beforeSystemDefined: [uid(45), uid(46), uid(41)], afterSystemDefined: [] };
  const r = run(s, { source: hub, destination: bulb, protocol: 'TCP', port: 443 });
  assert.equal(r.evaluated[0].id, uid(45));
  assert.equal(r.evaluated[0].result, 'no-match');
  assert.match(r.evaluated[0].reasons[0], /destination port not matched/);
  assert.equal(r.verdict, 'REJECT');
  assert.equal(r.decidedBy.id, uid(46));
  const noPort = run(s, { source: hub, destination: bulb, protocol: 'TCP' });
  assert.equal(noPort.evaluated[0].result, 'indeterminate');
  assert.match(noPort.evaluated[0].reasons[0], /port not given/);
});

test('a DOMAIN filter is indeterminate and reported above the deciding block', () => {
  const s = fixture();
  s.policies = s.policies.filter((p) => p.id !== uid(48));
  s.policies.push(
    policy(47, Z.iot, Z.external, 'ALLOW', {
      destination: {
        zoneId: Z.external,
        trafficFilter: {
          type: 'DOMAIN',
          domainFilter: { type: 'DOMAINS', domains: ['example.com'] },
        },
      },
    }),
    policy(49, Z.iot, Z.external, 'BLOCK', { ...system, index: 30000 }),
  );
  s.ordering = { beforeSystemDefined: [uid(47)], afterSystemDefined: [] };
  const r = run(s, { source: bulb, destination: { external: true }, protocol: 'TCP', port: 443 });
  assert.equal(r.destination.zone.name, 'External');
  assert.equal(r.verdict, 'BLOCK');
  assert.equal(r.decidedBy.id, uid(49));
  assert.deepEqual(
    r.indeterminateAbove.map((p) => p.id),
    [uid(47)],
  );
  assert.match(r.indeterminateAbove[0].reasons[0], /domain filter is decided at runtime/);
  assert.ok(r.caveats.some((c) => /indeterminateAbove/.test(c)));
});

test('a disabled policy is skipped', () => {
  const s = fixture();
  s.policies.push(policy(50, Z.internal, Z.iot, 'BLOCK', { enabled: false }));
  s.ordering = { beforeSystemDefined: [uid(50), uid(41)], afterSystemDefined: [] };
  const r = run(s, { source: hub, destination: bulb });
  assert.equal(r.evaluated[0].id, uid(50));
  assert.equal(r.evaluated[0].result, 'skipped');
  assert.equal(r.verdict, 'ALLOW');
  assert.equal(r.decidedBy.id, uid(41));
});

test('an unrecognised filter type is indeterminate, never a match or a miss', () => {
  const s = fixture();
  s.policies.push(
    policy(51, Z.internal, Z.iot, 'BLOCK', {
      source: { zoneId: Z.internal, trafficFilter: { type: 'FUTURE_FILTER', futureFilter: {} } },
    }),
    policy(52, Z.internal, Z.iot, 'BLOCK', {
      ipProtocolScope: { ipVersion: 'IPV4', protocolFilter: { type: 'FUTURE_PROTOCOL' } },
    }),
  );
  s.ordering = { beforeSystemDefined: [uid(51), uid(52), uid(41)], afterSystemDefined: [] };
  const r = run(s, { source: hub, destination: bulb, protocol: 'UDP', port: 5353 });
  assert.equal(r.evaluated[0].result, 'indeterminate');
  assert.match(r.evaluated[0].reasons[0], /unrecognised source filter type FUTURE_FILTER/);
  assert.equal(r.evaluated[1].result, 'indeterminate');
  assert.match(r.evaluated[1].reasons[0], /unrecognised protocol filter/);
  assert.equal(r.verdict, 'ALLOW');
  assert.equal(r.indeterminateAbove.length, 2);
});

test('external destination with internetAccessEnabled=false is blocked by the network setting', () => {
  const s = fixture();
  s.networks[1].internetAccessEnabled = false;
  const r = run(s, { source: bulb, destination: { external: true } });
  assert.equal(r.verdict, 'BLOCK');
  assert.equal(r.decidedBy.type, 'NETWORK_SETTING');
  assert.equal(r.decidedBy.setting, 'internetAccessEnabled');
  assert.equal(r.decidedBy.networkId, N.iot);
  assert.equal(r.shortCircuit.type, 'INTERNET_ACCESS_DISABLED');
  assert.deepEqual(r.evaluated, []);
});

test('network isolation blocks traffic between local networks, labelled as inferred', () => {
  const s = fixture();
  s.networks[1].isolationEnabled = true;
  const r = run(s, { source: hub, destination: bulb });
  assert.equal(r.verdict, 'BLOCK');
  assert.equal(r.decidedBy.setting, 'isolationEnabled');
  assert.match(r.shortCircuit.reason, /assumption/);
  const toGateway = run(s, {
    source: bulb,
    destination: { ipAddress: iotIp(1) },
    protocol: 'UDP',
    port: 53,
  });
  assert.notEqual(toGateway.shortCircuit?.type, 'NETWORK_ISOLATED');
});

test('a network gateway address resolves to the Gateway zone', () => {
  const r = run(fixture(), {
    source: bulb,
    destination: { ipAddress: iotIp(1) },
    protocol: 'UDP',
    port: 53,
  });
  assert.equal(r.destination.gateway, true);
  assert.equal(r.destination.zone.name, 'Gateway');
  assert.equal(r.verdict, 'UNDETERMINED');
  assert.ok(r.caveats.some((c) => /No firewall policy was found/.test(c)));
});

test('unresolvable endpoints are reported, not guessed', () => {
  const s = fixture();
  const r = run(s, { source: { ipAddress: internalIp(200) }, destination: bulb });
  assert.equal(r.verdict, 'UNDETERMINED');
  assert.deepEqual(r.unresolved, ['source: IP address is not inside any network subnet']);
  s.zones = s.zones.filter((z) => z.name !== 'External');
  const ext = run(s, { source: bulb, destination: { external: true } });
  assert.deepEqual(ext.unresolved, ['destination: no system-defined External zone was found']);
  s.clients[C.hub] = null;
  assert.deepEqual(run(s, { source: hub, destination: bulb }).unresolved, [
    'source: client not found or not connected',
  ]);
});

test('IP, MAC, network and traffic matching list filters are evaluated with matchOpposite', () => {
  const s = fixture();
  s.trafficMatchingLists = [
    {
      id: uid(81),
      type: 'IPV4_ADDRESSES',
      name: 'Hubs',
      items: [{ type: 'SUBNET', value: `${internalIp(8)}/29` }],
    },
  ];
  s.policies.push(
    policy(53, Z.internal, Z.iot, 'BLOCK', {
      source: {
        zoneId: Z.internal,
        trafficFilter: {
          type: 'IP_ADDRESS',
          ipAddressFilter: {
            type: 'TRAFFIC_MATCHING_LIST',
            matchOpposite: true,
            trafficMatchingListId: uid(81),
          },
        },
      },
    }),
    policy(54, Z.internal, Z.iot, 'BLOCK', {
      source: {
        zoneId: Z.internal,
        trafficFilter: { type: 'MAC_ADDRESS', macAddressFilter: { macAddresses: [mac('ff')] } },
      },
    }),
    policy(55, Z.internal, Z.iot, 'REJECT', {
      destination: {
        zoneId: Z.iot,
        trafficFilter: {
          type: 'IP_ADDRESS',
          ipAddressFilter: {
            type: 'IP_ADDRESSES',
            matchOpposite: false,
            items: [{ type: 'IP_ADDRESS_RANGE', start: iotIp(10), stop: iotIp(30) }],
          },
        },
      },
    }),
  );
  s.ordering = {
    beforeSystemDefined: [uid(53), uid(54), uid(55), uid(41)],
    afterSystemDefined: [],
  };
  const r = run(s, { source: hub, destination: bulb, protocol: 'TCP', port: 80 });
  assert.deepEqual(
    r.evaluated.map((e) => e.result),
    ['no-match', 'no-match', 'match'],
  );
  assert.equal(r.verdict, 'REJECT');
  const byIp = run(s, { source: { ipAddress: internalIp(10) }, destination: bulb });
  assert.equal(byIp.evaluated[1].result, 'indeterminate');
  assert.match(byIp.evaluated[1].reasons[0], /MAC address is unknown/);
});

test('untrusted names are sanitised with the Mermaid label function', () => {
  const s = fixture();
  s.policies[0].name = '<script>alert("x")</script>\n[[evil]]';
  const r = run(s, { source: hub, destination: bulb });
  assert.doesNotMatch(r.decidedBy.name, /[<>"\n[\]()]/);
});

test('parseQuery is strict and applies defaults', () => {
  const ok = q({ source: hub, destination: { external: true } });
  assert.equal(ok.protocol, 'ANY');
  assert.equal(ok.connectionState, 'NEW');
  assert.equal(ok.port, null);
  const bad = [
    { source: hub, destination: bulb, extra: true },
    { source: { ...hub, zoneId: Z.iot }, destination: bulb },
    { source: { clientId: C.hub, note: 'x' }, destination: bulb },
    { source: { external: true }, destination: bulb },
    { source: { ipAddress: ['999', '1', '1', '1'].join('.') }, destination: bulb },
    { source: { ipAddress: ['10', '01', '1', '1'].join('.') }, destination: bulb },
    { source: hub, destination: bulb, protocol: 'ICMP', port: 1 },
    { source: hub, destination: bulb, port: 0 },
    { source: hub, destination: bulb, port: 70000 },
    { source: hub, destination: bulb, protocol: 'tcp' },
    { source: hub, destination: bulb, connectionState: null },
    { source: hub, destination: { external: false } },
    { source: hub },
  ];
  for (const args of bad) assert.throws(() => q(args), /INPUT_INVALID/, JSON.stringify(args));
  assert.throws(
    () => parseQuery({ siteId: 'not-a-uuid', source: hub, destination: bulb }),
    /INPUT_INVALID/,
  );
  assert.throws(() => parseQuery(null), /INPUT_INVALID/);
});

test('collect uses only GET operations, pages at 200 and caps policies at 1000', async () => {
  const s = fixture();
  const calls = [];
  const many = Array.from({ length: 1200 }, (_, i) => policy(1000 + i, Z.iot, Z.iot, 'ALLOW'));
  const pageOf = (items, input) => {
    const { offset, limit } = input.query;
    const data = items.slice(offset, offset + limit);
    return { offset, limit, count: data.length, totalCount: items.length, data };
  };
  const fake = {
    async call(operationId, input) {
      calls.push({ operationId, input });
      switch (operationId) {
        case 'getFirewallZones':
          return pageOf(s.zones, input);
        case 'getNetworksOverviewPage':
          return pageOf(
            s.networks.map(({ id, name, vlanId }) => ({ id, name, vlanId })),
            input,
          );
        case 'getNetworkDetails':
          return s.networks.find((n) => n.id === input.path.networkId);
        case 'getConnectedClientDetails':
          return s.clients[input.path.clientId];
        case 'getFirewallPolicies':
          return pageOf([...s.policies, ...many], input);
        case 'getTrafficMatchingLists':
          return pageOf([], input);
        case 'getFirewallPolicyOrdering':
          return { orderedFirewallPolicyIds: s.ordering };
        default:
          throw new Error(`unexpected ${operationId}`);
      }
    },
  };
  const result = await explainPath(fake, { siteId: site, source: hub, destination: bulb });
  assert.equal(result.verdict, 'ALLOW');
  assert.equal(result.policiesComplete, false);
  assert.ok(result.caveats.some((c) => /first 1000 firewall policies/.test(c)));
  for (const c of calls) assert.equal(byId.get(c.operationId).method, 'GET', c.operationId);
  const policyCalls = calls.filter((c) => c.operationId === 'getFirewallPolicies');
  assert.deepEqual(
    policyCalls.map((c) => [c.input.query.offset, c.input.query.limit]),
    [
      [0, 200],
      [200, 200],
      [400, 200],
      [600, 200],
      [800, 200],
    ],
  );
  const ordering = calls.find((c) => c.operationId === 'getFirewallPolicyOrdering');
  assert.deepEqual(ordering.input.query, {
    sourceFirewallZoneId: Z.internal,
    destinationFirewallZoneId: Z.iot,
  });
  const snapshot = await collect(fake, site, q({ source: hub, destination: bulb }));
  assert.equal(snapshot.policies.length, 1000);
  assert.equal(snapshot.networks[1].ipv4Configuration.prefixLength, 24);
});

test('collect reads Wi-Fi broadcasts and ACL rules only for the same-network case', async () => {
  const s = fixture();
  const calls = [];
  const fake = {
    async call(operationId, input) {
      calls.push(operationId);
      const pageOf = (data) => ({
        offset: 0,
        limit: 200,
        count: data.length,
        totalCount: data.length,
        data,
      });
      if (operationId === 'getFirewallZones') return pageOf(s.zones);
      if (operationId === 'getNetworksOverviewPage') return pageOf(s.networks);
      if (operationId === 'getNetworkDetails')
        return s.networks.find((n) => n.id === input.path.networkId);
      if (operationId === 'getWifiBroadcastPage')
        return pageOf([
          { id: uid(61), name: 'IoT', network: { type: 'SPECIFIC', networkId: N.iot } },
          { id: uid(62), name: 'Main', network: { type: 'NATIVE' } },
        ]);
      if (operationId === 'getWifiBroadcastDetails')
        return {
          id: input.path.wifiBroadcastId,
          name: 'IoT',
          enabled: true,
          clientIsolationEnabled: false,
        };
      if (operationId === 'getAclRulePage') return pageOf([]);
      return pageOf([]);
    },
  };
  const r = await explainPath(fake, {
    siteId: site,
    source: { ipAddress: iotIp(20) },
    destination: { ipAddress: iotIp(21) },
  });
  assert.equal(r.shortCircuit.type, 'SAME_NETWORK');
  assert.deepEqual(
    r.shortCircuit.wifiBroadcasts.map((w) => w.id),
    [uid(61)],
  );
  assert.ok(!calls.includes('getFirewallPolicyOrdering'));
  for (const op of calls) assert.equal(byId.get(op).method, 'GET', op);
});
