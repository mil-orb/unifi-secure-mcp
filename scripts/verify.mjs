// A real MCP client, not a direct UniFi API shortcut. Live mode is read-only.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
const args = ['serve'];
const index = process.argv.indexOf('--config');
if (index >= 0) {
  if (!process.argv[index + 1]) throw new Error('Missing config path');
  args.push('--config', process.argv[index + 1]);
}
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [fileURLToPath(new URL('../src/cli.mjs', import.meta.url)), ...args],
  stderr: 'pipe',
});
// Never forward raw child stderr, which may contain host-specific diagnostics.
transport.stderr?.on('data', () => {});
const client = new Client({ name: 'unifi-verifier', version: '0.2.0' });
async function call(name, arguments_ = {}) {
  const result = await client.callTool({ name, arguments: arguments_ });
  if (result.isError) throw new Error(result.content?.[0]?.text || 'MCP tool failed');
  return result.structuredContent.result;
}
try {
  await client.connect(transport);
  const listed = await client.listTools();
  const status = await call('unifi_status');
  assert.equal(
    listed.tools.filter((t) => t.name.startsWith('unifi_api_')).length,
    status.enabledOperations,
  );
  assert.ok((await client.listResources()).resources.length >= 2);
  assert.ok((await client.listPrompts()).prompts.length >= 2);
  await client.readResource({ uri: 'unifi://capabilities' });
  await client.getPrompt({
    name: 'unifi_troubleshoot',
    arguments: { symptom: 'Read-only verification' },
  });
  console.log(
    JSON.stringify(
      {
        protocol: 'MCP stdio',
        version: client.getServerVersion().version,
        tools: listed.tools.length,
        status,
      },
      null,
      2,
    ),
  );
  if (process.argv.includes('--live')) {
    const info = await call('unifi_api_get_info');
    const sites = await call('unifi_api_get_site_overview_page', { query: { limit: 1 } });
    const site = sites.data?.[0];
    if (!site) throw new Error('No site available');
    const devices = await call('unifi_api_get_adopted_device_overview_page', {
      path: { siteId: site.id },
      query: { limit: 10 },
    });
    const clients = await call('unifi_api_get_connected_client_overview_page', {
      path: { siteId: site.id },
      query: { limit: 200 },
    });
    const gateway =
      devices.data?.find((d) => d.model === 'UDR7' || d.model?.includes('Dream Router')) ||
      devices.data?.[0];
    let statistics;
    if (gateway)
      statistics = await call('unifi_api_get_adopted_device_latest_statistics', {
        path: { siteId: site.id, deviceId: gateway.id },
      });
    console.log(
      JSON.stringify(
        {
          live: 'read-only API requests through MCP succeeded',
          checkedAt: new Date().toISOString(),
          applicationVersion: info.applicationVersion,
          connectedClients: clients.totalCount,
          returnedClients: clients.data?.length,
          clientTypes: clients.data?.reduce(
            (counts, c) => ({ ...counts, [c.type]: (counts[c.type] || 0) + 1 }),
            {},
          ),
          adoptedDevices: devices.totalCount,
          deviceModel: gateway?.model,
          deviceState: gateway?.state,
          statistics,
          historyConclusion:
            'Historical outage events are not available in this API; current statistics cannot establish a 48-hour outage history.',
        },
        null,
        2,
      ),
    );
  }
} catch (e) {
  console.error(e.message);
  process.exitCode = 1;
} finally {
  await client.close();
}
