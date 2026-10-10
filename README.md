<div align="center">
  <img src="assets/unifi.ico" width="48" height="48" alt="UniFi icon">
  <h1>UniFi Secure MCP</h1>
  <p><strong>Your network. Structured tools. Deliberate changes.</strong></p>
  <p>A local MCP bridge to the official UniFi Network API, built with the UDR7 in mind.</p>
  <p>
    <img alt="MCP stdio" src="https://img.shields.io/badge/MCP-stdio-0ea5e9">
    <img alt="73 API operations" src="https://img.shields.io/badge/API_operations-73-2563eb">
    <img alt="Read-only default" src="https://img.shields.io/badge/default-read--only-16a34a">
    <img alt="Node 24 or newer" src="https://img.shields.io/badge/Node.js-24%2B-43853d">
    <img alt="Unofficial" src="https://img.shields.io/badge/Ubiquiti-unofficial-64748b">
  </p>
  <p><a href="docs/SETUP.md">Setup</a> · <a href="docs/OPERATIONS.md">All operations</a> · <a href="SECURITY.md">Security</a> · <a href="docs/API-VS-UI.md">API vs UI</a> · <a href="docs/AUDIT.md">Audit</a></p>
</div>

## What you get

- **Complete coverage of the bundled Network 10.6.106 specification:** 41 reads and 32 mutation operations, each exposed as a named, validated MCP tool.
- **Read-only execution by default.** Mutation tools prepare five-minute previews. Execution additionally requires write-capable setup, a short-lived operation/site permit, and explicit review.
- **Local credentials and pinned TLS.** Hidden key input; Windows current-user DPAPI; no credential tool arguments, public MCP endpoint, telemetry, or browser automation.
- **MCP tools, resources, and prompts.** Structured JSON results, descriptive schemas, annotations, capability discovery, troubleshooting prompts, and safe Mermaid inventory output.
- **A standard local installation.** Official MCP SDK, locked dependencies, STDIO transport, example configurations, tests, CI, and operator documentation.

This project is an **unofficial integration**, unaffiliated with Ubiquiti or OpenAI. “Secure” describes its design, not a guarantee or independent certification. Read [the limits and threat model](SECURITY.md) before enabling writes.

## Start locally

Requires Node.js 24+, npm, and a supported UniFi Network application with a dedicated API key. Windows uses its built-in PowerShell for DPAPI. Run from this checkout:

```sh
npm ci --ignore-scripts
npm run setup
npm run verify
```

The interactive setup walks through the router address, independent certificate fingerprint verification, hidden API-key entry, and read-only/write-capable selection. It verifies a read before activating new configuration. Keep the default read-only selection initially.

Register the local server with your MCP host using [the setup guide](docs/SETUP.md). Use absolute paths. **Never paste a key into a conversation or put it in host configuration.** This package is not published to npm; do not substitute an unverified similarly named package.

## How requests travel

```mermaid
flowchart LR
    H[Desktop or Codex MCP host] -->|Typed tool call| V[Schema validation]
    V -->|Read| C[Pinned HTTPS client]
    V -->|Mutation| P[Preview with expiry]
    P --> G[Reviewed apply plus local permit]
    G --> A[State check and audit]
    A --> C
    C --> U[Official UniFi Network API]
    U --> R[Secret redaction]
    R --> H
```

There is no arbitrary URL, raw HTTP, shell, or browser tool. Tools are generated from the bundled official schema and inputs are validated again before transmission. A request outside the supported API produces an explicit limitation.

## Coverage

| Area | Capabilities in the pinned API |
| --- | --- |
| Devices and clients | Inventory, details, current statistics, adoption/removal, device and port actions, guest access actions |
| Networks and Wi-Fi | Network/VLAN and Wi-Fi broadcast reads, creation, updates, deletion, network references |
| Security policies | Firewall zones/policies/order, ACL rules/order, DNS policies, traffic matching lists |
| Hotspot | Voucher reads, creation and removal |
| Supporting objects | WAN definitions, VPN information, RADIUS profiles, tags, DPI categories/apps, countries |
| Switching | Stack, MC-LAG and LAG information; hardware support varies |

See [all 73 operations](docs/OPERATIONS.md). Coverage means the documented operations are implemented and registered; it does **not** mean every one has been exercised on production equipment. Not every UI setting has an official API, and a UDR7 cannot supply features that require other hardware.

## Controlled writes

1. Choose `write-capable` during local setup. Execution still starts read-only.
2. Use the relevant `unifi_api_*` mutation tool to prepare a preview.
3. Review its exact request, current state, risk, and recovery requirements.
4. In your own terminal, grant a brief permit for the specific operation and site.
5. Approve `unifi_apply_plan` with the plan ID and exact confirmation phrase.
6. Read back the affected configuration and revoke the permit.

Example with documentation-only placeholders:

```sh
node src/cli.mjs permit --site SITE_UUID --operation updateNetwork --minutes 15
node src/cli.mjs revoke
```

Permit creation is intentionally absent from the MCP toolset. Previews are single-use and expire after five minutes; permits expire within at most one hour. Deletes, restarts, port actions and network/security changes can interrupt access or be irreversible. No automatic rollback or write retry is promised.

## Honest diagnostics

The local API exposes **latest** device statistics, not a historical WAN outage log. Router uptime can show that a device has not restarted; it cannot prove uninterrupted internet or Wi-Fi. This MCP reports that gap instead of falling back to an undocumented endpoint or browser.

Mermaid output is a bounded **logical inventory**, not a guaranteed physical cable map. Render it with Mermaid's strict security mode. The host decides whether to display the diagram or its source.

## Verification and maintenance

```sh
npm test
npm run check
npm run privacy
npm audit
```

Tests use synthetic data and a local HTTPS simulator. The representative write test restores its simulated configuration. An optional authorized `node scripts/verify.mjs --live` performs a small set of reads through a real MCP client; it does not execute mutation operations. See [testing and recovery](docs/TESTING.md).

## Design references

The configuration and documentation were informed by [GitHub's MCP server](https://github.com/github/github-mcp-server/blob/main/docs/server-configuration.md), [Context7](https://github.com/upstash/context7/blob/master/packages/mcp/README.md), and the [official MCP reference servers](https://github.com/modelcontextprotocol/servers). The implementation is specific to this project; these references do not endorse it.

Original code is MIT licensed. The UniFi icon and upstream specification retain their respective rights; see [third-party notices](THIRD-PARTY-NOTICES.md). Static badges describe design facts, not a certification or live test result.
