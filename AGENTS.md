# Working on this MCP

Use schema-defined MCP tools for UniFi access. Do not silently fall back to browsers, shell HTTP requests, private controller endpoints, or SSH when an API capability is absent. Report the limitation.

Default execution is read-only. Mutation operation tools create previews. Never grant a write permit on behalf of a user unless that exact operation and site are explicitly authorized. Show the preview and connectivity/security impact before applying. Never retry an uncertain write automatically.

Never read, echo, copy into chat, commit, or upload live credentials, certificates, configuration, logs, inventories, screenshots, SSIDs, client labels, device identifiers, MAC/IP addresses, or telemetry. Runtime data belongs outside this checkout. Use synthetic fixtures and documentation-reserved identifiers in tests/examples. Do not invoke secret.ps1 in Read mode interactively; its output is intended exclusively for a private child-process pipe.

Exception: the user-authorized, visually reviewed redacted documentation image at assets/mcp-demo-redacted.png is allowed at its explicitly pinned digest in the privacy checker. Its unredacted source must never be committed. Adding another screenshot requires a fresh privacy review, not a general image-file exemption.

Do not test every API operation on a real router. Run npm test, npm run check, npm run privacy, and npm audit. Live checks require explicit authorization and must use scripts/verify.mjs --live, which uses a real MCP client and only reads. Production writes are operator-selected; simulation tests must restore synthetic state.

Update docs/OPERATIONS.md with node scripts/check.mjs --write when deliberately upgrading the bundled official schema. Review discriminator normalization and safety gates; operation coverage is not proof of hardware support or successful execution.
