# UniFi API versus the dashboard

Neither interface universally provides more data or control. The dashboard is broader for interactive administration and historical diagnosis. The official API provides explicit, documented operations that are useful for automation and reproducible inspection. The MCP intentionally covers that API boundary.

| Task | Official local API / this MCP | UniFi dashboard | Practical implication |
| --- | --- | --- | --- |
| Current connected devices | Structured paginated client/device records | Searchable lists and visual detail | MCP can count/filter records and cite current state |
| Gateway health | Latest heartbeat, uptime, utilization and interface statistics | Current health plus richer diagnostic views | A current snapshot is not historical evidence |
| Past internet interruptions | No outage-event history operation in the bundled local schema | System logs include event history | MCP must report insufficient evidence for a past 48-hour outage claim |
| Networks and Wi-Fi | Typed create/read/update/delete operations and documented body fields | Guided configuration and explanatory forms | API is suited to repeatable reviewed changes; UI may expose additional settings |
| Firewall and ACL policy | Zones, policies/rules and ordering operations | Visual policy management and additional context | MCP needs explicit review of scope and connectivity impact |
| DNS and matching lists | Documented policy/list operations | Interactive policy management | Structured tooling supports comparison and controlled updates |
| Hardware actions | Documented adoption/removal, restart and port actions | Contextual device controls | Both can be disruptive; API availability still depends on hardware |
| RF/Wi-Fi diagnosis | Limited latest statistics in documented endpoints | Richer RF, interference, historical and optimization views | Do not invent equivalent API controls |
| Traffic/security activity | The bundled local schema does not expose a general historical traffic-log feed | Logging and security views depend on model, version and enabled features | Distinguish limited blocked/threat views from full flow-session logging |
| WAN/VPN/RADIUS | Supporting information is exposed for specified operations | Wider configuration workflows | Read access to a supporting object does not imply API write support |
| Automation and bulk analysis | Machine-readable results; explicit operation schemas; repeatable workflows | Primarily interactive | API advantage is automation, not automatically broader privileges |
| Historical retention | Could collect future samples with separately designed storage | Existing supported histories/log exports | Starting polling now cannot recreate missing past observations |
| Topology | Relationships available in returned objects; bounded Mermaid inventory | A richer vendor topology presentation | This MCP does not claim a complete physical cable map |
| Cloud/multiple sites | Separate Site Manager APIs exist; not configured by this local server | Site Manager and console UI | A local Network key and schema are not the same integration as cloud APIs |

“All operations” means all 73 operations in **Network 10.6.106's official local specification**, including operations a UDR7 may not support. It does not mean every private endpoint used internally by the UI, every UniFi OS setting, or every other UniFi product API. New firmware may add operations; updating requires schema review and a deliberate release.

The server will not switch to browser automation, SSH, or undocumented endpoints when a capability is absent. It reports the gap. Any future logs/SIEM integration should be a separately scoped, authenticated input with explicit retention and privacy controls.

Sources: [official local specification](https://developer.ui.com/network/v10.6.106/openapi.json), [UniFi API overview](https://help.ui.com/hc/en-us/articles/30076656117655-Getting-Started-with-the-Official-UniFi-API), [system logs and SIEM](https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs-SIEM-Integration), [traffic logging and model limitations](https://help.ui.com/hc/en-us/articles/32201256219799-Traffic-Flows-and-Traffic-Logging-in-UniFi-Network).
