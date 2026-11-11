# Setup and configuration

## Guided enrollment

Install Node.js 24 or newer, obtain this trusted checkout, then run `npm ci --ignore-scripts` and `npm run setup` from an interactive local terminal.

The wizard asks for a local HTTPS origin and a dedicated private directory outside the checkout. The directory must be new, empty, or one this application created before: setup replaces the permissions of the folder and everything inside it, so it refuses a folder that already holds other files (`PRIVATE_DIR_NOT_DEDICATED`), your home folder, and any folder that contains it. The same rule applies to the folder holding the config file (the default `~/.unifi-secure-mcp` qualifies). Setup marks each folder it restricts with a `.unifi-secure-mcp-private` file.

Setup then probes only the public certificate, sending no API key, and asks you for the SHA-256 fingerprint shown by the router's certificate in a browser session you already trust. It does not display the probe's fingerprint first, so your entry is an independent check; the probe's value is shown only after a mismatch, and setup stops (`TLS_FINGERPRINT_MISMATCH`). The initial certificate-only probe deliberately allows an untrusted certificate; every authenticated API request requires valid pinned TLS. A certificate issued by a CA (custom or ACME) is pinned the same way: the enrolled leaf is the only trust anchor, and only its exact bytes pass.

Create a dedicated, expiring key using UniFi's documented API-key workflow. Enter the key into the hidden terminal prompt. Never put it in chat, shell arguments, environment variables, issue reports, screenshots, or git. The wizard does not automate dashboard configuration.

Select `readonly` (default) or `write-capable`. New credentials are stored as a private enrollment generation, tested with a read, and activated by atomically replacing the configuration file. A failed generation is deleted at once, so its API key does not stay on disk. After a successful switch, setup lists older generations in the same data directory and deletes them only if you type `DELETE`; keep them if another MCP process still uses them, and revoke their keys in UniFi either way. Re-enrollment does not migrate named secret slots; recreate needed slots locally. Restart MCP processes after changing configuration.

## Where settings live

The default config is `~/.unifi-secure-mcp/config.json`. Select another using `--config ABSOLUTE_PATH` or `UNIFI_MCP_CONFIG`. The config contains the router origin and private directory, **never the API key**. Treat it as private network metadata anyway.

| Field             | Meaning                                                                                                                                             |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `version`         | Must be `1`                                                                                                                                         |
| `baseUrl`         | HTTPS origin only; no path, query, fragment, or credentials                                                                                         |
| `dataDir`         | Absolute dedicated private directory outside the checkout                                                                                           |
| `credentialStore` | `dpapi` on Windows; `file` on other platforms                                                                                                       |
| `writeEnabled`    | `false` by default; `true` makes the apply tool available but does not grant a permit                                                               |
| `toolsets`        | Optional exact API tag names to expose; omission exposes every operation of the loaded schema                                                       |
| `specVersion`     | Optional pin to one bundled schema version (for example `"11.0.97"`); must be listed in `spec/manifest.json` or startup fails with `CONFIG_INVALID` |

`node src/cli.mjs operations` lists each operation's ID, tool name, tag and path. Use those exact tag strings for toolsets. Unknown tags fail startup. Toolset filtering is a presentation restriction; write enforcement also checks the local permit. Helper tools that read through several tags (`unifi_mermaid`, `unifi_explain_path`) are offered only when the toolsets expose every operation they read; otherwise they are not listed and calls to them fail.

Windows secrets are encrypted for the enrolling Windows user using DPAPI. Setup restricts private-directory ACLs; startup rejects unexpected allow entries in private storage. POSIX storage is an owner-only file, **not encrypted by this application**. Use OS encryption and appropriate account isolation. These controls do not defend against malware, elevated code, or an agent with unrestricted execution as the credential owner.

## Network version detection

The server bundles several UniFi Network API schemas, listed in `spec/manifest.json`. When the configuration is complete, it makes one read at startup (`getInfo`, `GET /v1/info`) to learn the router's Network version, then loads one bundled schema for the life of the process. It prefers the newest bundled schema that is **not newer** than the router: an older schema is a subset the router accepts, while a newer one could allow request fields the router rejects. Detection failure never stops startup; an unreachable router can delay it by up to the 15-second request deadline. `serve --no-detect` skips this read (match `not-detected`); `npm run verify` uses it unless `--live` is given, so non-live verification never contacts the router.

| `match`              | Meaning                                                                                                                                                              |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `exact`              | A bundled schema has the router's exact version                                                                                                                      |
| `nearest-older`      | The router is between two bundled versions of its major; the nearest older one is used                                                                               |
| `newer-than-bundled` | The router is newer than every bundled schema of its major; the newest of that major is used, and newer request fields are unavailable until a newer schema is added |
| `older-than-bundled` | The router is older than every bundled schema of its major; the oldest of that major is used, and some accepted request fields may be rejected with HTTP 400         |
| `major-mismatch`     | No bundled schema shares the router's major version; the newest is used with a warning. Review every change with extra care                                          |
| `pinned`             | `specVersion` is set and differs from the detected version                                                                                                           |
| `not-detected`       | The version could not be read; the pin, or else the newest bundled schema, is used                                                                                   |

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

After reviewing a preview, authorize exactly that request locally. With write-capable configuration, each preview returns `localPermit`, a command such as:

```sh
node src/cli.mjs permit --plan PLAN_ID
```

Run it in your own interactive terminal. It prints the request as the server previewed it (secret values hidden; `sensitiveFields` says whether each secret field is a `@secret:NAME` reference, a new literal or omitted) and its request hash, then asks you to type `YES`. The resulting permit names that plan and request hash only: the model cannot apply a different body, another plan, or the same plan twice under it, and it expires with the preview (five minutes). The server stores each preview for this purpose as `preview-PLAN_ID.json` in the private data directory (redacted request, operation, site and hash) and deletes it when the plan is applied, discarded or expired.

The broader operation/site permit remains available when you need it, for example for several changes in a row:

```sh
node src/cli.mjs permit --site SITE_UUID --operation updateWifiBroadcast --minutes 15
```

It authorizes any previewed body for those operations and sites until it expires, so the host's per-call approval is then the only human gate: never set `unifi_apply_plan` to "always allow" in a host. Use actual IDs from your own MCP reads. Repeat `--site` or `--operation` only when needed. Permits replace previous permits; operation/site permits last 1–60 minutes and authorize only exact operation/site combinations. The `permit` command checks operation IDs against the schema the server loaded at its last start (or the `specVersion` pin), so a permit is not silently read-only on an older router. They are shared by local processes using the same private directory. Plans belong to one process and are lost on restart. Approval text is an explicit confirmation mechanism, not cryptographic evidence of human approval; keep host confirmation enabled.

Apply once, read back state, then `node src/cli.mjs revoke`. Revocation blocks the next authorization check; it cannot cancel a request already sent. Keep independent management access for changes that can disconnect the MCP host.

For a Wi-Fi password or other string secret, use `node src/cli.mjs secret --name wifi_password`. The hidden prompt stores it locally; use `@secret:wifi_password` in the relevant request body. Secret references cannot appear in URLs, paths, or queries. Never use a redacted response as a replacement request: provide all required documented fields, and supply unchanged secret fields through local slots where needed. A body containing `[REDACTED]` is refused with `REDACTED_VALUE`. `api-key` is reserved: it cannot be stored as a slot or referenced as `@secret:api-key`, in any letter case.

## Filesystem hardening

Protect installed source and dependencies from less-trusted users as well as protecting credentials. On Windows PowerShell 7, run `scripts/harden-install.ps1` from outside the installation directory after installation; it restricts the checkout to the current user, SYSTEM and administrators. It validates paths and rejects reparse points. This is unsuitable for a shared development checkout unless those permissions are intended. Recheck permissions after host/sandbox tooling or upgrades changes them. On POSIX, protect the installation with OS ownership/permissions appropriate to the dedicated runtime user.

## Troubleshooting

- **401/403:** expired/revoked key or insufficient UniFi permissions. Re-enroll locally; restart old processes. Do not print a key to diagnose it.
- **TLS failure:** verify the configured origin, certificate and expiry. `TLS_PIN_CHANGED` means the router presented a certificate other than the enrolled one; `TLS_CERT_EXPIRED` means the enrolled certificate is outside its validity dates. Re-enroll a changed or renewed certificate through an independently trusted channel. There is no insecure TLS flag.
- **PowerShell could not run a helper script (`POWERSHELL_BLOCKED`, Windows):** the server runs its bundled `scripts/*.ps1` with `-ExecutionPolicy Bypass` for that child process only. An execution policy set by Group Policy (`Get-ExecutionPolicy -List`, scopes MachinePolicy/UserPolicy) still wins; ask the machine's administrator. A checkout downloaded as a ZIP may carry Windows' download mark: after verifying the download, run `Get-ChildItem -Recurse CHECKOUT | Unblock-File` in PowerShell. This is distinct from `INSECURE_FILE`, which means the private files' permissions are wrong.
- **`PRIVATE_DIR_NOT_DEDICATED`:** choose a new or empty folder for the private data (or the config file).
- **404/unsupported operation:** compare the installed Network version and hardware with the loaded schema (`unifi_status` → `spec`). Complete registration does not guarantee firmware support.
- **Unsafe storage:** repair ownership/ACLs, then restart. Do not weaken protection just to make startup pass.
- **Stale plan:** re-read and review a fresh preview. The server cannot make its read/compare/write sequence atomic with the controller.
- **Write uncertainty:** inspect the affected resource before deciding on manual recovery. Never retry automatically. A failure before any request byte left (local permit refusal, connection refused, certificate change, credential unavailable) is reported with its own error and audited as `blocked`, not as uncertain.
- **Stale write lock:** first verify no writer is running. Only an operator should remove `write.lock` from the private directory after investigating the previous operation.

No browser, SSH, or undocumented API fallback is provided.
