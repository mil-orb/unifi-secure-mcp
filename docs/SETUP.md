# Setup and configuration

## Guided enrollment

Install Node.js 24 or newer, obtain this trusted checkout, then run `npm ci --ignore-scripts` and `npm run setup` from an interactive local terminal.

The wizard asks for a local HTTPS origin and a dedicated private directory outside the checkout. It probes only the public certificate first, sending no API key. Compare its SHA-256 fingerprint against an independently trusted router certificate, then enter the verified fingerprint. Merely copying the presented fingerprint does not independently authenticate the router. The initial certificate-only probe deliberately allows an untrusted certificate; every authenticated API request requires valid pinned TLS.

Create a dedicated, expiring key using UniFi's documented API-key workflow. Enter the key into the hidden terminal prompt. Never put it in chat, shell arguments, environment variables, issue reports, screenshots, or git. The wizard does not automate dashboard configuration.

Select `readonly` (default) or `write-capable`. New credentials are stored as a private enrollment generation, tested with a read, and activated by atomically replacing the configuration file. Previous or failed generations remain private on disk for recovery; remove obsolete generations locally after confirming the active path. Re-enrollment does not migrate named secret slots; recreate needed slots locally. Restart MCP processes after changing configuration.

## Where settings live

The default config is `~/.unifi-secure-mcp/config.json`. Select another using `--config ABSOLUTE_PATH` or `UNIFI_MCP_CONFIG`. The config contains the router origin and private directory, **never the API key**. Treat it as private network metadata anyway.

| Field | Meaning |
| --- | --- |
| `version` | Must be `1` |
| `baseUrl` | HTTPS origin only; no path, query, fragment, or credentials |
| `dataDir` | Absolute dedicated private directory outside the checkout |
| `credentialStore` | `dpapi` on Windows; `file` on other platforms |
| `writeEnabled` | `false` by default; `true` makes the apply tool available but does not grant a permit |
| `toolsets` | Optional exact API tag names to expose; omission exposes every operation of the loaded schema |
| `specVersion` | Optional pin to one bundled schema version (for example `"11.0.97"`); must be listed in `spec/manifest.json` or startup fails with `CONFIG_INVALID` |

`node src/cli.mjs operations` lists each operation's ID, tool name, tag and path. Use those exact tag strings for toolsets. Unknown tags fail startup. Toolset filtering is a presentation restriction; write enforcement also checks the local permit. Helper tools that read through several tags (`unifi_mermaid`, `unifi_explain_path`) are offered only when the toolsets expose every operation they read; otherwise they are not listed and calls to them fail.

Windows secrets are encrypted for the enrolling Windows user using DPAPI. Setup restricts private-directory ACLs; startup rejects unexpected allow entries in private storage. POSIX storage is an owner-only file, **not encrypted by this application**. Use OS encryption and appropriate account isolation. These controls do not defend against malware, elevated code, or an agent with unrestricted execution as the credential owner.

## Network version detection

The server bundles several UniFi Network API schemas, listed in `spec/manifest.json`. When the configuration is complete, it makes one read at startup (`getInfo`, `GET /v1/info`) to learn the router's Network version, then loads one bundled schema for the life of the process. It prefers the newest bundled schema that is **not newer** than the router: an older schema is a subset the router accepts, while a newer one could allow request fields the router rejects. Detection failure never stops startup; an unreachable router can delay it by up to the 15-second request deadline. `serve --no-detect` skips this read (match `not-detected`); `npm run verify` uses it unless `--live` is given, so non-live verification never contacts the router.

| `match` | Meaning |
| --- | --- |
| `exact` | A bundled schema has the router's exact version |
| `nearest-older` | The router is between two bundled versions of its major; the nearest older one is used |
| `newer-than-bundled` | The router is newer than every bundled schema of its major; the newest of that major is used, and newer request fields are unavailable until a newer schema is added |
| `older-than-bundled` | The router is older than every bundled schema of its major; the oldest of that major is used, and some accepted request fields may be rejected with HTTP 400 |
| `major-mismatch` | No bundled schema shares the router's major version; the newest is used with a warning. Review every change with extra care |
| `pinned` | `specVersion` is set and differs from the detected version |
| `not-detected` | The version could not be read; the pin, or else the newest bundled schema, is used |

`unifi_status` and the `unifi://capabilities` resource report `spec: { loaded, detected, match, bundled }`, and the server instructions name the loaded and detected versions. Restart MCP processes after a firmware upgrade so detection runs again.

Set `specVersion` only to override detection, for example to stay on a schema you have already reviewed. A pin always wins over detection. To add a newer schema, download its `openapi.json` yourself, then run `node scripts/add-spec.mjs PATH --source URL` from the checkout (it never uses the network) and review the generated `docs/spec-changes/` report; see [CONTRIBUTING](../CONTRIBUTING.md).

## ChatGPT desktop/Work and Codex

The [official OpenAI MCP documentation](https://learn.chatgpt.com/docs/extend/mcp) describes shared local `~/.codex/config.toml` configuration for the desktop app, Codex CLI and IDE extension. Add the following with your own absolute paths:

```toml
[mcp_servers.unifi]
command = 'C:\Program Files\nodejs\node.exe'
args = ['C:\Tools\unifi-secure-mcp\src\cli.mjs', 'serve', '--config', 'C:\Private\unifi\config.json']
startup_timeout_sec = 45
tool_timeout_sec = 120

[mcp_servers.unifi.tools.unifi_apply_plan]
approval_mode = 'prompt'
```

These are example paths, not an existing user's configuration. On macOS/Linux, substitute absolute POSIX paths. `examples/codex.toml` and `examples/mcp.json` contain generic templates. Configure STDIO, not a URL. Do not add API keys to either example.

Restart the MCP server from the host's MCP settings after registration or changes. Already-running conversations can retain old tools or processes. Check `unifi_status`, then a small read. `npm run verify` independently checks the MCP handshake, tool/resource/prompt discovery and local status; it is not proof that every host conversation has reloaded.

Hosted ChatGPT Work/web does not automatically receive local STDIO access. Availability of local executors is host-dependent. This project does not expose a tunnel, remote listener, or router port to make cloud access work.

## Safe write workflow

Mutation operation tools create previews even while execution is read-only. Their `readOnlyHint` describes their actual behavior: previewing performs reads and stores only transient local state. `unifi_apply_plan` is explicitly annotated as potentially destructive. Annotations inform hosts; the server enforces authorization separately.

After reviewing an operation-specific preview, grant a narrow permit locally:

```sh
node src/cli.mjs permit --site SITE_UUID --operation updateWifiBroadcast --minutes 15
```

Use actual IDs from your own MCP reads. Repeat `--site` or `--operation` only when needed. Permits replace previous permits, last 1–60 minutes, and authorize only exact operation/site combinations. They are shared by local processes using the same private directory. Plans belong to one process and are lost on restart. Approval text is an explicit confirmation mechanism, not cryptographic evidence of human approval; keep host confirmation enabled.

Apply once, read back state, then `node src/cli.mjs revoke`. Revocation blocks the next authorization check; it cannot cancel a request already sent. Keep independent management access for changes that can disconnect the MCP host.

For a Wi-Fi password or other string secret, use `node src/cli.mjs secret --name wifi_password`. The hidden prompt stores it locally; use `@secret:wifi_password` in the relevant request body. Secret references cannot appear in URLs, paths, or queries. Never use a redacted response as a replacement request: provide all required documented fields, and supply unchanged secret fields through local slots where needed. A body containing `[REDACTED]` is refused with `REDACTED_VALUE`. `api-key` is reserved: it cannot be stored as a slot or referenced as `@secret:api-key`, in any letter case.

## Filesystem hardening

Protect installed source and dependencies from less-trusted users as well as protecting credentials. On Windows PowerShell 7, run `scripts/harden-install.ps1` from outside the installation directory after installation; it restricts the checkout to the current user, SYSTEM and administrators. It validates paths and rejects reparse points. This is unsuitable for a shared development checkout unless those permissions are intended. Recheck permissions after host/sandbox tooling or upgrades changes them. On POSIX, protect the installation with OS ownership/permissions appropriate to the dedicated runtime user.

## Troubleshooting

- **401/403:** expired/revoked key or insufficient UniFi permissions. Re-enroll locally; restart old processes. Do not print a key to diagnose it.
- **TLS failure:** verify the configured origin, certificate and expiry. Re-enroll a changed certificate through an independently trusted channel. There is no insecure TLS flag.
- **404/unsupported operation:** compare the installed Network version and hardware with the loaded schema (`unifi_status` → `spec`). Complete registration does not guarantee firmware support.
- **Unsafe storage:** repair ownership/ACLs, then restart. Do not weaken protection just to make startup pass.
- **Stale plan:** re-read and review a fresh preview. The server cannot make its read/compare/write sequence atomic with the controller.
- **Write uncertainty:** inspect the affected resource before deciding on manual recovery. Never retry automatically.
- **Stale write lock:** first verify no writer is running. Only an operator should remove `write.lock` from the private directory after investigating the previous operation.

No browser, SSH, or undocumented API fallback is provided.
