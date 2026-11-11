# Security policy and threat model

This is a single-user local STDIO MCP server for a security-critical network controller. It is not independently certified, audited by an external party, or guaranteed defect-free. Version 0.3.x bundles the Network schemas listed in `spec/manifest.json` (each pinned by SHA-256) and loads the one closest to the version the router reports; `unifi_status` shows which. Add schemas only through `scripts/add-spec.mjs` and review its change report deliberately.

## Enforced boundaries

- Named tools come exclusively from the loaded bundled vendor specification. A schema construct the request validator does not understand fails `npm run check` and startup instead of being skipped. No generic request URL/method/header, browser, shell, SSH, or credential-retrieval tool exists.
- Inputs use JSON Schema validation, discriminator-aware request schemas, bounded nesting/body size, exact path parameters, encoded query values, and rejected extra fields. A property declared by several `allOf` members must satisfy all of them, so a placeholder base declaration cannot switch off a field's validation; a test asserts no request-body field of any bundled schema accepts arbitrary JSON. Where a nested field is open in the vendor schema itself, the router remains its only validator.
- Authenticated traffic uses one locally configured HTTPS origin, a trusted pinned certificate, TLS 1.2+, certificate validity checks, no redirect following, and no write retry.
- Credentials are loaded inside the server and never returned intentionally. Responses redact sensitive field names and exact loaded secret values; upstream error bodies are suppressed. A request body containing the redaction marker `[REDACTED]` is refused (`REDACTED_VALUE`), so a redacted snapshot cannot be written back as a real value. `@secret:api-key` (any letter case) is refused, so the UniFi API key cannot be copied into router configuration.
- Hotspot voucher access codes are redacted as credentials. Ordinary country codes remain readable. This limits credential distribution through chat while preserving the underlying API operations.
- All mutation tools preview. Applying requires write-capable configuration, a valid local permit, an unexpired single-use plan, exact confirmation, a cross-process lock, and a durable pre-send audit record. A plan-bound permit (`permit --plan`, granted after the user reads the request in their own terminal) authorizes only that plan's request hash, once; an operation/site permit authorizes any previewed body for its scope until it expires. Previews list each secret field as a `@secret:NAME` reference, a hidden new literal, or omitted, so a preview cannot hide which one is sent. Failures before any request byte is sent are audited as blocked; anything after that is reported as uncertain.
- Where an equivalent GET exists, the target is re-read and compared with the preview. Changed secrets also invalidate the preview. Requests without an equivalent GET explicitly disclose that limitation.
- Requests have a 15-second network deadline, 2 MiB response cap, 128 KiB input cap, four active tool calls, and bounded pagination (1–200 per page). Twenty in-memory plans are retained for at most five minutes each.
- Secrets, certificates, permits, audit records and user configuration live outside source control. Windows private storage ACLs are checked at startup; POSIX private files require owner-only permissions. Setup restricts only new, empty, marked or application-created folders, never the home folder or an ancestor of it. Local runtime source must also be protected.

## Trust and remaining risk

The MCP host, enrolling OS user, operating system, installed code/dependencies and configured controller are trusted. An agent or malware with arbitrary execution as the same user can bypass application gates, decrypt DPAPI credentials, alter permits, or edit the server. Administrator access also defeats local isolation. Separate accounts and host execution/approval policies are necessary where that threat matters.

Tool annotations and confirmation phrases are not human-authentication boundaries. The model can see a confirmation phrase; the host and user must authorize the actual effect. Plan-bound permits move that authorization to the local terminal for one exact request. With an operation/site permit, prompt-injected text could still drive a different body within its scope during the permit window, unless the host asks for each `unifi_apply_plan` call. A UniFi API key may retain broader permissions than the MCP allows. Prefer least privilege and short expiry when available.

Certificate pinning uses an independently enrolled leaf certificate instead of ordinary DNS-name matching. The leaf is the only trust anchor (partial-chain validation, so a CA-issued leaf also works) and its exact bytes are compared; validity dates are enforced. Incorrect initial trust can pin an attacker. Setup asks for the fingerprint from a trusted browser session before showing the probe's value. The initial public-certificate probe sends no credentials. Certificate rotation intentionally breaks access until reviewed enrollment.

Read/compare/write is not an atomic controller transaction; another administrator can change state between checks. Requests already sent cannot be revoked. A lost response or failed post-write audit can leave an uncertain outcome. No automatic rollback is promised, and some actions permanently delete data or interrupt management access.

Responses can contain legitimate private network metadata and untrusted labels. The host may send tool results to its model service according to its policies. Redaction is defense in depth, not a guarantee against every possible secret encoding. Do not publish tool outputs. Mermaid labels are sanitized; render using strict mode. Local audit logs retain operation/site IDs and hashes, but not request bodies or secrets; treat them as private and manage retention locally. Logs are not tamper-proof against the owning account.

This server does not implement HTTP transport, OAuth, multi-user isolation, a monitoring daemon, cloud exposure, automatic upgrades, or historical log collection. Extending it to a remote server requires a separate threat model and authentication design; do not wrap STDIO in an unauthenticated public proxy.

## Reporting and recovery

Do not post a vulnerability with live keys, controller addresses, MACs, SSIDs, screenshots, logs or inventory. Report it privately through this repository's **Security → Report a vulnerability** page, with a minimal synthetic reproduction. This is a community-maintained project with no public security-support SLA.

For suspected credential exposure: revoke the affected key in UniFi, create a replacement through a trusted local workflow, run setup, restart every MCP process, and verify a read. Do not diagnose by printing the key. Revoke permits and inspect controller state after suspected unintended writes.

Review [the local audit](docs/AUDIT.md), [testing](docs/TESTING.md), and the [MCP security guidance](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices). HTTP/OAuth portions of that guidance are outside this STDIO-only implementation's scope.
