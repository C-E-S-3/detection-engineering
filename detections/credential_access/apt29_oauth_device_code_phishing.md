# APT29 — OAuth Device Code and App-Specific Password Phishing

## Description

Detects successful OAuth device code flow authentications and App-Specific Password (ASP) generation events that may indicate phishing-based authentication bypass. APT29 sub-clusters (UNC6293, UNC7005/STORM-2945, UNC5976) are documented users of both techniques to bypass multi-factor authentication against Microsoft 365 and Google accounts.

**OAuth device code phishing:** Adversaries send victims a device code URL (e.g., `microsoft.com/devicelogin`) via email or messaging apps. The victim enters the code, granting the attacker a persistent access token without ever seeing a password prompt. The device code flow is a legitimate OAuth 2.0 feature but is rarely used in enterprise environments.

**App-Specific Password (ASP) phishing:** Adversaries trick Google Workspace users into generating an App-Specific Password, which bypasses TOTP/hardware-key MFA entirely, granting attacker access via IMAP/legacy protocols.

False positive sources: legitimate device-code applications (Apple TV, Xbox, printer setup), IT-provisioned service accounts using ASPs. Tune by excluding known device types, service account UPNs, and IT provisioning subnets.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Steal Application Access Token |
| Technique ID | T1528 |
| Sub-technique (secondary) | Use Alternate Authentication Material: Application Access Token (T1550.001) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |
| Actions on Objectives |

## Splunk Detection Query

```spl
index=o365 OR index=azure_ad sourcetype IN ("azure:aad:signin","o365:management:activity")
(AuthenticationProtocol="deviceCode" OR GrantType="urn:ietf:params:oauth:grant-type:device_code")
ResultType=0
| eval risk_score=case(
    match(IPAddress,"^(?:77\.88\.|37\.9\.|5\.45\.|185\.117\.)"), 90,
    ClientAppUsed="Other clients" OR ClientAppUsed="IMAP4", 85,
    match(UserAgent,"python|curl|wget|requests|go-http"), 85,
    1=1, 75)
| where risk_score >= 75
| stats count min(_time) as firstTime max(_time) as lastTime
    values(UserPrincipalName) as users
    values(IPAddress) as src_ips
    values(AppDisplayName) as apps
    values(ClientAppUsed) as client_app
    values(DeviceDetail.operatingSystem) as os
    values(UserAgent) as user_agents
    by ConditionalAccessStatus ResourceDisplayName risk_score
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime users src_ips apps client_app os user_agents
        ConditionalAccessStatus ResourceDisplayName risk_score count
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Device code auth from known residential proxy or Tor exit ranges | 90 | APT29 documented use of commercial residential proxies; device code from proxy = near-certain attacker-side auth |
| Device code auth via IMAP4 / legacy protocol client | 85 | Legacy protocol access after device code suggests attacker using token for mailbox access |
| Device code auth via scripted client (python/curl/requests) | 85 | Automated token capture — human users don't use CLI tools for device code auth |
| Device code auth from any source (baseline) | 75 | Device code flow is rarely used legitimately in enterprise; any successful auth warrants review |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| APT29 (Cozy Bear) sub-clusters UNC6293, UNC7005/STORM-2945, UNC5976 | [Google GTIG 2026-08-20](https://cloud.google.com/blog/topics/threat-intelligence/distinct-clusters-target-individuals-of-interest-to-russia) |
| MIDNIGHT BLIZZARD (APT29) | [MITRE ATT&CK G0016](https://attack.mitre.org/groups/G0016/) |

## References

- [Google GTIG: Going with the Flow(s) — Distinct Clusters Target Individuals of Interest to Russia (2026-08-20)](https://cloud.google.com/blog/topics/threat-intelligence/distinct-clusters-target-individuals-of-interest-to-russia)
- [MITRE ATT&CK T1528 — Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [MITRE ATT&CK T1550.001 — Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
- [Microsoft: Protect against OAuth device code phishing](https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication)
- [MITRE ATT&CK G0016 — APT29](https://attack.mitre.org/groups/G0016/)
