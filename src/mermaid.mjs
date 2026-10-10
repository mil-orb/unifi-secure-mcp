export const label = (value) =>
  String(value ?? 'Unnamed')
    .normalize('NFKC')
    .replace(/[^\p{L}\p{N} ._-]/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 64) || 'Unnamed';
export function renderInventory(snapshot) {
  const lines = ['flowchart TB', '  site["UniFi site inventory"]'],
    maps = {};
  let next = 0;
  for (const [key, title] of [
    ['devices', 'Devices'],
    ['networks', 'Networks and VLANs'],
    ['wifi', 'Wi-Fi'],
    ['zones', 'Firewall zones'],
  ]) {
    maps[key] = new Map();
    lines.push(`  subgraph ${key}["${title}"]`);
    for (const item of (snapshot[key]?.data || []).slice(0, 50)) {
      const n = `n${next++}`;
      maps[key].set(item.id, n);
      lines.push(
        `    ${n}["${label(item.name)}${key === 'networks' ? ` VLAN ${label(item.vlanId)}` : ''}"]`,
      );
    }
    lines.push('  end');
  }
  for (const key of Object.keys(maps)) lines.push(`  site -.-> ${key}`);
  const edge = (a, b) => {
    if (a && b) lines.push(`  ${a} --> ${b}`);
  };
  for (const n of snapshot.networks?.data || [])
    edge(maps.zones.get(n.zoneId), maps.networks.get(n.id));
  for (const w of snapshot.wifi?.data || []) {
    const id =
      w.network?.type === 'NATIVE'
        ? (snapshot.networks?.data || []).find((n) => n.default === true)?.id
        : w.network?.networkId;
    edge(maps.wifi.get(w.id), maps.networks.get(id));
  }
  return {
    mermaid: lines.join('\n'),
    counts: Object.fromEntries(Object.entries(maps).map(([k, v]) => [k, v.size])),
    truncated: Object.fromEntries(
      Object.entries(maps).map(([k, v]) => [k, (snapshot[k]?.totalCount ?? 51) > v.size]),
    ),
    notes: [
      'Logical inventory, not a physical cabling map. Dotted links group inventory; solid links use API network references.',
      'At most 50 objects per category. Labels are sanitized and truncated. Render Mermaid in strict mode; all device labels are untrusted.',
    ],
  };
}
export async function inventory(client, siteId) {
  const snapshot = {};
  for (const [key, operation] of [
    ['devices', 'getAdoptedDeviceOverviewPage'],
    ['networks', 'getNetworksOverviewPage'],
    ['wifi', 'getWifiBroadcastPage'],
    ['zones', 'getFirewallZones'],
  ])
    snapshot[key] = await client.call(operation, { path: { siteId }, query: { limit: 50 } });
  return renderInventory(snapshot);
}
