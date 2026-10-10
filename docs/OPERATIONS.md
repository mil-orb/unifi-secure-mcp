# API operation coverage

Generated from Ubiquiti's Network 10.6.106 OpenAPI specification. All 73 operation IDs are registered: 41 reads and 32 mutations. Coverage means implementation/registration, not that every endpoint was executed against a router. Hardware and firmware can limit individual operations.

| Official operation ID | Method | API path | MCP behavior |
| --- | --- | --- | --- |
| `getCountries` | GET | `/v1/countries` | Read |
| `getDpiApplications` | GET | `/v1/dpi/applications` | Read |
| `getDpiApplicationCategories` | GET | `/v1/dpi/categories` | Read |
| `getInfo` | GET | `/v1/info` | Read |
| `getPendingDevicePage` | GET | `/v1/pending-devices` | Read |
| `getSiteOverviewPage` | GET | `/v1/sites` | Read |
| `getAclRulePage` | GET | `/v1/sites/{siteId}/acl-rules` | Read |
| `createAclRule` | POST | `/v1/sites/{siteId}/acl-rules` | Preview → permitted apply |
| `getAclRuleOrdering` | GET | `/v1/sites/{siteId}/acl-rules/ordering` | Read |
| `updateAclRuleOrdering` | PUT | `/v1/sites/{siteId}/acl-rules/ordering` | Preview → permitted apply |
| `deleteAclRule` | DELETE | `/v1/sites/{siteId}/acl-rules/{aclRuleId}` | Preview → permitted apply |
| `getAclRule` | GET | `/v1/sites/{siteId}/acl-rules/{aclRuleId}` | Read |
| `updateAclRule` | PUT | `/v1/sites/{siteId}/acl-rules/{aclRuleId}` | Preview → permitted apply |
| `getConnectedClientOverviewPage` | GET | `/v1/sites/{siteId}/clients` | Read |
| `getConnectedClientDetails` | GET | `/v1/sites/{siteId}/clients/{clientId}` | Read |
| `executeConnectedClientAction` | POST | `/v1/sites/{siteId}/clients/{clientId}/actions` | Preview → permitted apply |
| `getDeviceTagPage` | GET | `/v1/sites/{siteId}/device-tags` | Read |
| `getAdoptedDeviceOverviewPage` | GET | `/v1/sites/{siteId}/devices` | Read |
| `adoptDevice` | POST | `/v1/sites/{siteId}/devices` | Preview → permitted apply |
| `removeDevice` | DELETE | `/v1/sites/{siteId}/devices/{deviceId}` | Preview → permitted apply |
| `getAdoptedDeviceDetails` | GET | `/v1/sites/{siteId}/devices/{deviceId}` | Read |
| `executeAdoptedDeviceAction` | POST | `/v1/sites/{siteId}/devices/{deviceId}/actions` | Preview → permitted apply |
| `executePortAction` | POST | `/v1/sites/{siteId}/devices/{deviceId}/interfaces/ports/{portIdx}/actions` | Preview → permitted apply |
| `getAdoptedDeviceLatestStatistics` | GET | `/v1/sites/{siteId}/devices/{deviceId}/statistics/latest` | Read |
| `getDnsPolicyPage` | GET | `/v1/sites/{siteId}/dns/policies` | Read |
| `createDnsPolicy` | POST | `/v1/sites/{siteId}/dns/policies` | Preview → permitted apply |
| `deleteDnsPolicy` | DELETE | `/v1/sites/{siteId}/dns/policies/{dnsPolicyId}` | Preview → permitted apply |
| `getDnsPolicy` | GET | `/v1/sites/{siteId}/dns/policies/{dnsPolicyId}` | Read |
| `updateDnsPolicy` | PUT | `/v1/sites/{siteId}/dns/policies/{dnsPolicyId}` | Preview → permitted apply |
| `getFirewallPolicies` | GET | `/v1/sites/{siteId}/firewall/policies` | Read |
| `createFirewallPolicy` | POST | `/v1/sites/{siteId}/firewall/policies` | Preview → permitted apply |
| `getFirewallPolicyOrdering` | GET | `/v1/sites/{siteId}/firewall/policies/ordering` | Read |
| `updateFirewallPolicyOrdering` | PUT | `/v1/sites/{siteId}/firewall/policies/ordering` | Preview → permitted apply |
| `deleteFirewallPolicy` | DELETE | `/v1/sites/{siteId}/firewall/policies/{firewallPolicyId}` | Preview → permitted apply |
| `getFirewallPolicy` | GET | `/v1/sites/{siteId}/firewall/policies/{firewallPolicyId}` | Read |
| `patchFirewallPolicy` | PATCH | `/v1/sites/{siteId}/firewall/policies/{firewallPolicyId}` | Preview → permitted apply |
| `updateFirewallPolicy` | PUT | `/v1/sites/{siteId}/firewall/policies/{firewallPolicyId}` | Preview → permitted apply |
| `getFirewallZones` | GET | `/v1/sites/{siteId}/firewall/zones` | Read |
| `createFirewallZone` | POST | `/v1/sites/{siteId}/firewall/zones` | Preview → permitted apply |
| `deleteFirewallZone` | DELETE | `/v1/sites/{siteId}/firewall/zones/{firewallZoneId}` | Preview → permitted apply |
| `getFirewallZone` | GET | `/v1/sites/{siteId}/firewall/zones/{firewallZoneId}` | Read |
| `updateFirewallZone` | PUT | `/v1/sites/{siteId}/firewall/zones/{firewallZoneId}` | Preview → permitted apply |
| `deleteVouchers` | DELETE | `/v1/sites/{siteId}/hotspot/vouchers` | Preview → permitted apply |
| `getVouchers` | GET | `/v1/sites/{siteId}/hotspot/vouchers` | Read |
| `createVouchers` | POST | `/v1/sites/{siteId}/hotspot/vouchers` | Preview → permitted apply |
| `deleteVoucher` | DELETE | `/v1/sites/{siteId}/hotspot/vouchers/{voucherId}` | Preview → permitted apply |
| `getVoucher` | GET | `/v1/sites/{siteId}/hotspot/vouchers/{voucherId}` | Read |
| `getNetworksOverviewPage` | GET | `/v1/sites/{siteId}/networks` | Read |
| `createNetwork` | POST | `/v1/sites/{siteId}/networks` | Preview → permitted apply |
| `deleteNetwork` | DELETE | `/v1/sites/{siteId}/networks/{networkId}` | Preview → permitted apply |
| `getNetworkDetails` | GET | `/v1/sites/{siteId}/networks/{networkId}` | Read |
| `updateNetwork` | PUT | `/v1/sites/{siteId}/networks/{networkId}` | Preview → permitted apply |
| `getNetworkReferences` | GET | `/v1/sites/{siteId}/networks/{networkId}/references` | Read |
| `getRadiusProfileOverviewPage` | GET | `/v1/sites/{siteId}/radius/profiles` | Read |
| `getLagPage` | GET | `/v1/sites/{siteId}/switching/lags` | Read |
| `getLag` | GET | `/v1/sites/{siteId}/switching/lags/{lagId}` | Read |
| `getMcLagDomainPage` | GET | `/v1/sites/{siteId}/switching/mc-lag-domains` | Read |
| `getMcLagDomain` | GET | `/v1/sites/{siteId}/switching/mc-lag-domains/{mcLagDomainId}` | Read |
| `getSwitchStackPage` | GET | `/v1/sites/{siteId}/switching/switch-stacks` | Read |
| `getSwitchStack` | GET | `/v1/sites/{siteId}/switching/switch-stacks/{switchStackId}` | Read |
| `getTrafficMatchingLists` | GET | `/v1/sites/{siteId}/traffic-matching-lists` | Read |
| `createTrafficMatchingList` | POST | `/v1/sites/{siteId}/traffic-matching-lists` | Preview → permitted apply |
| `deleteTrafficMatchingList` | DELETE | `/v1/sites/{siteId}/traffic-matching-lists/{trafficMatchingListId}` | Preview → permitted apply |
| `getTrafficMatchingList` | GET | `/v1/sites/{siteId}/traffic-matching-lists/{trafficMatchingListId}` | Read |
| `updateTrafficMatchingList` | PUT | `/v1/sites/{siteId}/traffic-matching-lists/{trafficMatchingListId}` | Preview → permitted apply |
| `getVpnServerPage` | GET | `/v1/sites/{siteId}/vpn/servers` | Read |
| `getSiteToSiteVpnTunnelPage` | GET | `/v1/sites/{siteId}/vpn/site-to-site-tunnels` | Read |
| `getWansOverviewPage` | GET | `/v1/sites/{siteId}/wans` | Read |
| `getWifiBroadcastPage` | GET | `/v1/sites/{siteId}/wifi/broadcasts` | Read |
| `createWifiBroadcast` | POST | `/v1/sites/{siteId}/wifi/broadcasts` | Preview → permitted apply |
| `deleteWifiBroadcast` | DELETE | `/v1/sites/{siteId}/wifi/broadcasts/{wifiBroadcastId}` | Preview → permitted apply |
| `getWifiBroadcastDetails` | GET | `/v1/sites/{siteId}/wifi/broadcasts/{wifiBroadcastId}` | Read |
| `updateWifiBroadcast` | PUT | `/v1/sites/{siteId}/wifi/broadcasts/{wifiBroadcastId}` | Preview → permitted apply |
