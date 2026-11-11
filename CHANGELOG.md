# Changelog

## 0.3.0

- Bundled the UniFi Network 10.6.106, 11.0.97 and 11.1.47 API specifications, each pinned by SHA-256 in `spec/manifest.json`. 11.1.47 comes from a public mirror (`"official": false`) because the official URL was unavailable.
- The server reads the router's Network version once at startup and loads the closest bundled specification; optional `specVersion` config pin. `unifi_status`, `unifi://capabilities` and the server instructions report `spec: { loaded, detected, match, bundled }`.
- One version string, read from `package.json`.
- Server instructions and the `unifi_change_review` prompt explain that PUT replaces the whole object (carry `loggingEnabled`, `reportFlowEnabled` and every other field from the preview).
- Schema-keyword guard: a construct the request validator does not understand fails `npm run check` and startup, with its JSON path.
- `scripts/add-spec.mjs` adds a downloaded specification (local file only), updates the manifest, writes a change report to `docs/spec-changes/` (including bold flags for new optional fields that default when omitted), and can prune old specifications after confirmation.
- `npm run check` takes all counts from the manifest; `docs/OPERATIONS.md` gains a "First bundled in" column; generated reports are drift-checked.
- Documentation no longer hard-codes one Network version or operation count. Added version-detection setup notes and a `reportFlowEnabled` / Insights Flows note.
- New read-only helper tool `unifi_explain_path`: resolves an IPv4 source and destination (client, IP, network, zone or external) to firewall zones, walks that zone pair's policies in the effective order shown by the UniFi UI, and reports the deciding policy, any earlier policies whose app/category/domain/region/schedule/IPsec or unrecognised filters can only be decided at runtime, and fixed caveats. GET requests only; a configuration model, not a packet trace.
- New read-only MCP prompt `unifi_iot_audit` (arguments `network`, `trustedHosts`, `dnsServer`, `expectInternet`; each capped at 512 characters, JSON-escaped and labelled as user-provided data): checks spec match, network and Wi-Fi isolation/mDNS/multicast settings, the zone's policies, and a `unifi_explain_path` flow matrix; outputs one pass/fail/undetermined table and proposes fixes only.
- Dependency update: `npm audit fix` (lockfile only, no major or direct-range changes) moved body-parser to 2.4.0, zod to 4.6.7, fast-uri to 3.1.9, ip-address to 10.7.6 and qs to 6.17.1, clearing all `npm audit` advisories.

### Review R1 fixes

- Request bodies containing the redaction marker `[REDACTED]` are refused (`REDACTED_VALUE`), and the server instructions and `unifi_change_review` prompt now say to omit redacted fields or use `@secret:NAME`, and to drop read-only fields such as `id` and `metadata`.
- `@secret:api-key` is refused in any letter case; the `secret` command's reserved-name check is now case-insensitive.
- `allOf` property declarations are intersected instead of the first one winning, restoring validation of ACL source/destination filters, Wi-Fi `radiusConfiguration` and DNS `domain` length on every bundled schema.
- `serve --no-detect` skips the startup version read; `npm run verify` uses it unless `--live` is given.
- `unifi_mermaid` and `unifi_explain_path` are offered only when `toolsets` (if set) expose every operation they read.
- Redaction no longer hides `authorizationMethod`, `grantedAuthorization`, `revokedAuthorization` or `presharedKeyNetworkIds`.
- `npm run privacy` scans unstaged edits and untracked, non-ignored files as well as the index.
- Setup changes permissions only on a new, empty, marked (`.unifi-secure-mcp-private`) or application-created folder, never the home folder or an ancestor of it (any letter case); otherwise `PRIVATE_DIR_NOT_DEDICATED`.
- Windows helper scripts run with `-ExecutionPolicy Bypass` (process scope only); a script PowerShell refuses to run is reported as `POWERSHELL_BLOCKED`, not as unsafe permissions. PowerShell is located under `%SystemRoot%`.
- The decrypted API key is read once per process and re-read after HTTP 401/403 (previously one PowerShell spawn per API call on Windows).
- CA-issued router certificates can be pinned (leaf as the only anchor, exact-bytes pin kept); a changed or expired certificate gets its own message (`TLS_PIN_CHANGED`, `TLS_CERT_EXPIRED`).
- Setup asks for the browser-verified fingerprint before showing the probe's value; a failed enrollment is deleted, and older ones can be deleted after typed confirmation.
- Deeply nested router JSON is refused as `RESPONSE_INVALID` instead of overflowing the stack; a config file that is not a JSON object is `CONFIG_INVALID`.
- The DPAPI helper exchanges UTF-8 bytes with Node instead of using the console code page.
- `unifi_troubleshoot` and `unifi_change_review` arguments are capped at 512 characters, like `unifi_iot_audit`.
- `@modelcontextprotocol/sdk` 1.32.2. CI adds a Prettier check and a Node 26 job.
- Plan-bound permits: with write-capable configuration a preview returns `localPermit` (`permit --plan PLAN_ID`). Run in an interactive terminal, it shows the previewed request and, after `YES`, authorizes only that plan's request hash, once, until the preview expires. Operation/site permits work as before.
- Previews add `sensitiveFields`: each secret field is shown as a `@secret:NAME` reference, a hidden new literal, or omitted.
- A write that fails before any request byte is sent (permit refusal, connection refused, certificate change, credential unavailable) is reported with its own error and audited as `blocked` instead of `WRITE_UNCERTAIN`.
- The `permit` command checks operation IDs against the pinned schema or the one the last server start loaded (recorded as `active-spec.json` in the private directory), and says which.
- Maintainer note: this release changes `src/plans.mjs` and `src/permits.mjs` (plan-bound permits, `blocked` write outcomes, secret-aware previews) on the maintainer's explicit instruction. `test/permits.test.mjs` and `test/plans.test.mjs` are unchanged, so the original assertions still pass.

## 0.2.0

- Implemented all 73 operations from the official Network 10.6.106 specification as individually validated MCP tools.
- Added guided private-key enrollment, configuration, certificate pinning, scoped expiring write permits, previews, audit records, and uncertain-write handling.
- Added bounded Mermaid inventory, MCP resources/prompts, UniFi favicon metadata, and standard local host examples.
- Added representative MCP/HTTPS simulation, schema/security tests, CI configuration, repository privacy scanning and operator documentation.
- Explicitly report historical outage-log limitations and unsupported hardware/API capabilities.
