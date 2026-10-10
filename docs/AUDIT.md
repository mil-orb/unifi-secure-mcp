# Implementation security review

Date: 2026-10-10. Scope: version 0.2.0 source, local configuration/storage workflow, MCP transport, official API mapping, mutation controls, representative simulator tests, dependencies and repository hygiene. This is a developer review, not an independent penetration test or certification.

| Area | Review and mitigation | Residual limitation |
| --- | --- | --- |
| API surface | Exact official operation registry; schemas validate before transmission; no arbitrary request tool | New firmware/specification changes require deliberate review |
| Request construction | Fixed origin and prefix, validated/encoded path/query, no redirects | Config-owning OS user is trusted |
| Transport trust | Pinned leaf identity, CA validation, expiry, TLS minimum; mismatched-certificate test | Initial fingerprint must be independently verified |
| Credential handling | Hidden input; private child-process DPAPI pipe; known-secret and field redaction; generic errors | Same-user code can decrypt; encoded or unknown secret values may evade redaction |
| Storage and source ACLs | Owner-protected private storage; startup ACL validation; install hardening helper | Host tooling may change ACLs; recheck after upgrades |
| Setup replacement | Verify a new enrollment generation before switching config atomically | Old/failed encrypted generations require local cleanup |
| Writes | Local exact-site/operation permit, expiry, single-use plan, confirmation, audit and lock | Human approval is host policy; no atomic controller compare-and-swap |
| Failure handling | Durable pre-send audit; uncertain outcomes consumed; no retries | Request may have succeeded despite a lost response |
| Resource limits | Input/response/depth/pagination/concurrency/plan limits | Transport parses MCP messages before application limits; local host is trusted |
| Prompt/diagram injection | Output treated as data; strict label sanitizer; no UI or shell fallback | Host must respect boundaries and render Mermaid strictly |
| MCP interoperability | Official SDK, typed tools, structured results, prompts/resources, annotations and icon | Different hosts may render diagrams/icons differently |
| Production validation | Limited reads through a real MCP client; representative writes only in a simulator | No claim that all operations work on UDR7 hardware |
| Publication hygiene | Source allowlist, ignore rules, staged-content scanning and separate private-data exclusion | Automated scanning cannot establish a universal no-secrets guarantee |

During development, checks caught and corrected a CLI startup syntax error and a Windows PowerShell module-resolution issue in the ACL helper. The end-to-end test now exercises both actual process startup and secure storage instead of relying solely on unit tests. Setup activation was made transactional, private writes atomic, and audit-file symlinks rejected.

Credential-response procedure: treat any secret emitted by a diagnostic helper as exposed, revoke it, enroll a replacement, and restart all processes. Never invoke the private secret-read helper interactively. This report contains implementation findings only; deployment-specific incident records belong in private operator storage.

Review evidence is recorded in test results and dependency audit output at release time; do not interpret a clean dependency audit as absence of vulnerabilities. Remaining risks above are documented rather than hidden behind a “perfect” claim. Review [SECURITY.md](../SECURITY.md) before deployment.

## Local verification evidence

- 12 automated tests passed on Windows with Node 24, including the actual MCP/HTTPS simulator path and restoration of synthetic state.
- All 73 documented operations were registered and their schemas compiled; coverage checking invoked zero router operations.
- A fresh MCP process successfully performed limited live reads on a UDR7 running Network 10.6.106. No production writes were tested.
- `npm audit` reported zero known vulnerabilities in the installed dependency graph at review time.
- Private-storage ACL validation passed after inherited sandbox access was removed from migrated files.
- Staged-source checks found no deployment secrets or identifiers; the bundled schema was independently compared with the public vendor source to distinguish vendor examples from private data.
- Hosted CI is configured separately; consult the actual workflow result rather than inferring its outcome from these local checks.
