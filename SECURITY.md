# Security policy and threat model

This is a single-user local STDIO MCP server for a security-critical network controller. It is not independently certified, audited by an external party, or guaranteed defect-free. Version 0.2.x targets the bundled Network 10.6.106 schema; update and re-review deliberately.

## Enforced boundaries

- Named tools come exclusively from the bundled official specification. No generic request URL/method/header, browser, shell, SSH, or credential-retrieval tool exists.
- Inputs use JSON Schema validation, discriminator-aware request schemas, bounded nesting/body size, exact path parameters, encoded query values, and rejected extra fields.
- Authenticated traffic uses one locally configured HTTPS origin, a trusted pinned certificate, TLS 1.2+, certificate validity checks, no redirect following, and no write retry.
- Credentials are loaded inside the server and never returned intentionally. Responses redact sensitive field names and exact loaded secret values; upstream error bodies are suppressed.
- All mutation tools preview. Applying requires write-capable configuration, a valid exact operation/site permit, an unexpired single-use plan, exact confirmation, a cross-process lock, and a durable pre-send audit record.
- Where an equivalent GET exists, the target is re-read and compared with the preview. Changed secrets also invalidate the preview. Requests without an equivalent GET explicitly disclose that limitation.
- Requests have a 15-second network deadline, 2 MiB response cap, 128 KiB input cap, four active tool calls, and bounded pagination (1–200 per page). Twenty in-memory plans are retained for at most five minutes each.
- Secrets, certificates, permits, audit records and user configuration live outside source control. Windows private storage ACLs are checked at startup; POSIX private files require owner-only permissions. Local runtime source must also be protected.

## Trust and remaining risk

The MCP host, enrolling OS user, operating system, installed code/dependencies and configured controller are trusted. An agent or malware with arbitrary execution as the same user can bypass application gates, decrypt DPAPI credentials, alter permits, or edit the server. Administrator access also defeats local isolation. Separate accounts and host execution/approval policies are necessary where that threat matters.

Tool annotations and confirmation phrases are not human-authentication boundaries. The model can see a confirmation phrase; the host and user must authorize the actual effect. A UniFi API key may retain broader permissions than the MCP allows. Prefer least privilege and short expiry when available.

Certificate pinning uses an independently enrolled leaf certificate instead of ordinary DNS-name matching. Incorrect initial trust can pin an attacker. The initial public-certificate probe sends no credentials. Certificate rotation intentionally breaks access until reviewed enrollment.

Read/compare/write is not an atomic controller transaction; another administrator can change state between checks. Requests already sent cannot be revoked. A lost response or failed post-write audit can leave an uncertain outcome. No automatic rollback is promised, and some actions permanently delete data or interrupt management access.

Responses can contain legitimate private network metadata and untrusted labels. The host may send tool results to its model service according to its policies. Redaction is defense in depth, not a guarantee against every possible secret encoding. Do not publish tool outputs. Mermaid labels are sanitized; render using strict mode. Local audit logs retain operation/site IDs and hashes, but not request bodies or secrets; treat them as private and manage retention locally. Logs are not tamper-proof against the owning account.

This server does not implement HTTP transport, OAuth, multi-user isolation, a monitoring daemon, cloud exposure, automatic upgrades, or historical log collection. Extending it to a remote server requires a separate threat model and authentication design; do not wrap STDIO in an unauthenticated public proxy.

## Reporting and recovery

Do not post a vulnerability with live keys, controller addresses, MACs, SSIDs, screenshots, logs or inventory. Privately contact the repository owner through an already trusted channel with a minimal synthetic reproduction. This private project has no public security-support SLA.

For suspected credential exposure: revoke the affected key in UniFi, create a replacement through a trusted local workflow, run setup, restart every MCP process, and verify a read. Do not diagnose by printing the key. Revoke permits and inspect controller state after suspected unintended writes.

Review [the local audit](docs/AUDIT.md), [testing](docs/TESTING.md), and the [MCP security guidance](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices). HTTP/OAuth portions of that guidance are outside this STDIO-only implementation's scope.
