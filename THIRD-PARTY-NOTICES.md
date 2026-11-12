# Third-party notices

UniFi, Ubiquiti and associated marks belong to their owners. This project is unofficial and is not endorsed by Ubiquiti or OpenAI.

`assets/unifi.ico` is the original UniFi dashboard favicon (the dashboard's `/favicon.ico?v3` asset), included at the operator's request for identification. It contains no deployment configuration. It is excluded from this project's MIT license; no ownership or general redistribution permission is claimed. Review the rights before redistributing publicly or replace it with an original asset. Hosts may choose not to render ICO MCP icons.

The `spec/unifi-network-<version>.json` files are Ubiquiti's public UniFi Network OpenAPI specifications. `spec/manifest.json` is authoritative for which files are bundled, their SHA-256 and their source:

| File                               | Source                                                                                                                                                                                                                            |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `spec/unifi-network-10.6.106.json` | [Official Network 10.6.106 specification](https://developer.ui.com/network/v10.6.106/openapi.json)                                                                                                                                |
| `spec/unifi-network-11.0.97.json`  | [Official Network 11.0.97 specification](https://developer.ui.com/network/v11.0.97/openapi.json)                                                                                                                                  |
| `spec/unifi-network-11.1.47.json`  | Community mirror [beezly/unifi-apis](https://github.com/beezly/unifi-apis/blob/main/unifi-network/11.1.47.json) (`"official": false` in the manifest); the developer.ui.com URL for 11.1.47 was not available when it was bundled |

They are vendor-authored references, not captures from a personal controller. Vendor sample values are documentation examples. They retain upstream rights and are excluded from the original-code license. `docs/spec-changes/` contains generated comparisons of these files.

Runtime dependencies retain their own licenses. Refer to their package metadata and license files. `package-lock.json` pins resolved versions and integrity hashes. Documentation links to GitHub MCP, Context7 and MCP reference servers acknowledge design references, not affiliation or copied branding.
