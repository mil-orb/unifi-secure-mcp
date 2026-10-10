# Verification without production churn

`npm test` uses synthetic fixtures. The representative end-to-end test starts a loopback HTTPS simulator with a temporary self-signed certificate, launches the actual STDIO server through the official MCP client, and verifies tool discovery, read redaction, rejected extra input, preview-only behavior, default write denial, exact permit execution, replay denial, and restoration of the synthetic network. It then changes the certificate and verifies that no authenticated request reaches that peer. Temporary files are removed only after checking they remain inside the test directory.

Unit tests cover all-operation registration without execution, input/path restrictions, schema discriminator inheritance, redaction, bounded JSON, Mermaid injection, stale/expired plans, confirmation, revocation, concurrency, audit failure and ambiguous writes. Registration checks do not assert every request shape is proven against firmware.

`npm run check` confirms all 73 operation IDs exist exactly once and generated documentation is current. `npm run verify` performs the MCP handshake and capability/resource/prompt checks against the selected local configuration, without calling the router. `npm run privacy` checks source/staged content for prohibited artifacts and common credential formats; it cannot prove absence of every possible private detail. A separate operator review is still needed before publication.

An explicitly authorized `node scripts/verify.mjs --live` makes only a handful of read calls: version, site discovery, adopted devices, connected clients and latest device statistics. It reports counts and health without printing client labels, addresses or IDs. Never save its output into the repository. No production mutation test is included or run by CI.

To selectively test a real mutation, choose a disposable object with the operator, record its necessary recovery data privately, preview, grant a narrow short-lived permit, apply once, verify, and perform an explicitly reviewed restore if appropriate. Do not exercise restarts, deletes, bulk voucher removal, firewall ordering or connectivity changes merely to increase test coverage. Some operations are not reversible. If a write outcome is uncertain, inspect first and do not automatically retry.

CI is configured for Windows and Linux on Node 24. A successful local Windows run does not imply hosted CI or Linux has already run; inspect the workflow result after pushing. Platform setup prompts also require a real interactive terminal and operator-verified certificate trust.
