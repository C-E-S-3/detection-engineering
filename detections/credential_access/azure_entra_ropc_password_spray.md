# Azure Entra ROPC Legacy OAuth Password Spray

## Description

Detects password spray attacks leveraging the deprecated OAuth 2.0 Resource Owner Password Credentials (ROPC) flow against Azure CLI and other Microsoft Entra applications. In ROPC, credentials are submitted directly to the OAuth token endpoint (`grant_type=password`) without triggering interactive Conditional Access Policy (CAP) evaluation for MFA — meaning organizations that enforce MFA via CAP for browser flows remain vulnerable to ROPC-based credential attacks.

This technique was exploited by LSHIY LLC (AS32167) in a June 2026 campaign that made 81M+ login attempts and compromised 78 accounts across 64 organizations. Any authentication using `AppId=04b07795-8ddb-461a-bbee-02f9e1bf7b46` (Azure CLI) with ROPC protocol is highly suspicious in enterprise environments.

**False positive sources:** Automated pipelines or legacy scripts that authenticate to Azure via ROPC for service account access (uncommon in well-configured environments; any legitimate ROPC use should be reviewed).

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Brute Force: Password Spraying |
| Technique ID | T1110.003 |
| Secondary Technique | Use Alternate Authentication Material: Application Access Token |
| Secondary Technique ID | T1550.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
`azure_ad`
| where category="SignInLogs"
| search (AppId="04b07795-8ddb-461a-bbee-02f9e1bf7b46"
          OR authenticationProtocol="ropc"
          OR authenticationProtocol="resourceOwnerPasswordCredential"
          OR clientAppUsed="Azure CLI")
| stats count dc(UserPrincipalName) as unique_accounts
    min(_time) as firstTime max(_time) as lastTime
    values(UserPrincipalName) as accounts
    values(IPAddress) as src_ips
    values(ResultType) as result_codes
    by AppId AppDisplayName
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    unique_accounts >= 10 AND count >= 100, 90,
    unique_accounts >= 3 AND count >= 20, 75,
    count >= 10, 50,
    1=1, 25)
| where risk_score >= 50
| table firstTime lastTime AppDisplayName AppId unique_accounts count src_ips result_codes accounts risk_score
```

```spl
`azure_ad`
| where category="SignInLogs" AND ResultType="0"
| search (AppId="04b07795-8ddb-461a-bbee-02f9e1bf7b46"
          OR authenticationProtocol="ropc"
          OR clientAppUsed="Azure CLI")
| `security_content_ctime(_time)`
| eval risk_score=90
| table _time UserPrincipalName IPAddress AppDisplayName AppId authenticationProtocol ConditionalAccessStatus risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| 10+ unique accounts targeted, 100+ attempts | 90 | High-confidence spray campaign; volume indicates automated tooling |
| 3+ unique accounts targeted, 20+ attempts | 75 | Moderate-confidence spray; may be automated script or initial tooling |
| 10+ attempts (single account) | 50 | Possible credential stuffing or targeted brute force; investigate |
| Successful ROPC login (any volume) | 90 | Successful auth via ROPC to Azure CLI is anomalous in properly configured tenants; CAP bypass likely |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| LSHIY LLC (AS32167/AS955) | [Huntress — LSHIY ROPC Password Spray (2026-07-01)](https://www.huntress.com/blog/lshiy-password-spray-attack) |
| Generic credential spray operators | [MITRE ATT&CK — T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/) |
| Kali365 PhaaS | [FBI IC3 PSA260521 — device code + ROPC hybrid attacks](https://www.ic3.gov/PSA/2026/PSA260521) |

## References

- [Huntress — No (Bad) CAP: Inside an Ongoing LSHIY Password Spray Attack (2026-07-01)](https://www.huntress.com/blog/lshiy-password-spray-attack)
- [The Hacker News — Azure CLI Password Spray Hits at Least 78 Microsoft Accounts in 81M+ Attempts (2026-07-01)](https://thehackernews.com/2026/07/azure-cli-password-spray-hits-at-least.html)
- [Microsoft — Legacy authentication protocols and CAP](https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication)
- [Red Canary — BAV2ROPC: Legacy Authentication in Azure AD](https://redcanary.com/blog/threat-detection/bav2ropc/)
- [MITRE ATT&CK — T1110.003 Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- [MITRE ATT&CK — T1550.001 Use Alternate Authentication Material: Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
