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

## 0.2.0

- Implemented all 73 operations from the official Network 10.6.106 specification as individually validated MCP tools.
- Added guided private-key enrollment, configuration, certificate pinning, scoped expiring write permits, previews, audit records, and uncertain-write handling.
- Added bounded Mermaid inventory, MCP resources/prompts, UniFi favicon metadata, and standard local host examples.
- Added representative MCP/HTTPS simulation, schema/security tests, CI configuration, repository privacy scanning and operator documentation.
- Explicitly report historical outage-log limitations and unsupported hardware/API capabilities.
