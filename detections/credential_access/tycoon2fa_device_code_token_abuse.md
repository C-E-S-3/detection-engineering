# Tycoon 2FA Post-Compromise Automated Token Abuse — Node.js Agent in Entra Sign-in Logs

## Description

Detects the post-compromise behavioral signature of the Tycoon 2FA Phishing-as-a-Service (PhaaS) kit after OAuth device code phishing succeeds. Operators use Node.js automation tools (user-agent strings `node` or `undici`) to replay stolen OAuth access and refresh tokens against Microsoft Entra ID / Azure AD and Microsoft 365 services. This user-agent pattern is observable in Entra sign-in logs and is highly anomalous for enterprise environments where M365 access normally originates from browsers or managed apps. False positives are possible where internal Node.js applications legitimately authenticate to M365 using `undici` — baseline expected device-code sign-ins per user and treat first-seen occurrences as highest priority. This detection complements `eviltokens_oauth_device_code_phishing.md`, which focuses on the device code grant phase; this rule focuses on the subsequent token-replay phase.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Use Alternate Authentication Material: Application Access Token |
| Technique ID | T1550.001 |

**Secondary mapping:**

| Tactic | Technique ID | Technique |
|--------|-------------|-----------|
| Initial Access | TA0001 | T1566.002 — Phishing: Spearphishing Link (Trustifi click-tracking URL delivery) |
| Credential Access | TA0006 | T1528 — Steal Application Access Token (device code grant phase) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
`azure_monitor_aad`
| search operationName="Sign-in activity"
| eval user_agent=coalesce(userAgent, 'deviceDetail.browser')
| where match(user_agent, "(?i)(^|\\s)node[/\\s0-9]|undici")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(ipAddress) as src_ips
    values(user_agent) as user_agents
    dc(ipAddress) as unique_ips
    by userPrincipalName, appDisplayName, authenticationProtocol
| eval risk_score=case(
    match(user_agents, "(?i)undici") AND authenticationProtocol="deviceCode", 92,
    match(user_agents, "(?i)undici"), 85,
    match(user_agents, "(?i)node") AND authenticationProtocol="deviceCode", 90,
    match(user_agents, "(?i)node"), 75,
    1=1, 65)
| where risk_score >= 65
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime userPrincipalName appDisplayName authenticationProtocol src_ips user_agents unique_ips risk_score
```

**Supplemental: Known Tycoon 2FA operator IPs in Entra sign-ins**

```spl
`azure_monitor_aad`
| search operationName="Sign-in activity"
| where match(ipAddress, "47\\.90\\.180\\.205|47\\.252\\.11\\.99")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(ipAddress) as src_ips
    by userPrincipalName, appDisplayName, authenticationProtocol, conditionalAccessStatus
| eval risk_score=95
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime userPrincipalName appDisplayName authenticationProtocol conditionalAccessStatus src_ips risk_score
```

**Supplemental: Trustifi click-tracking redirect chain in proxy logs**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where (Web.url="*trustifi*click*" OR Web.url="*trustifi*/api/o/v1/click*")
  by Web.src Web.dest Web.url Web.http_referrer Web.http_user_agent
| `drop_dm_object_name(Web)`
| eval risk_score=case(
    match(url, "trustifi") AND match(http_referrer, "(?i)invoice|payment|document"), 75,
    match(url, "trustifi") AND isnotnull(http_referrer), 60,
    1=1, 50)
| where risk_score >= 50
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src dest url http_referrer http_user_agent risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `undici` user-agent with device code protocol | 92 | Near-certain Tycoon2FA post-compromise token replay; `undici` is a Node.js HTTP/2 client not used by standard M365 clients |
| `node` user-agent with device code protocol | 90 | Automation tooling replaying device code-obtained tokens; very high confidence |
| `undici` user-agent (any protocol) | 85 | Attacker automation; legitimate enterprise M365 apps do not use `undici` |
| `node` user-agent (any protocol) | 75 | Node.js automation accessing M365; validate vs. approved internal apps |
| Known Tycoon2FA IP (47.90.180.205 or 47.252.11.99) | 95 | Direct attribution to Alibaba Cloud AS45102 Tycoon2FA infrastructure |
| Trustifi click URL → Cloudflare Workers chain | 50–75 | Delivery chain indicator; low confidence alone, correlate with device code sign-in within 30 minutes |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Tycoon 2FA PhaaS Operators | [BleepingComputer — Tycoon2FA Device Code Phishing (2026-05-17)](https://www.bleepingcomputer.com/news/security/tycoon2fa-hijacks-microsoft-365-accounts-via-device-code-phishing/) |
| eSentire TRU (researcher) | [eSentire — Tycoon 2FA OAuth Device Code Phishing](https://www.esentire.com/blog/tycoon-2fa-operators-adopt-oauth-device-code-phishing) |

## References

- [BleepingComputer — Tycoon2FA Hijacks Microsoft 365 Accounts via Device Code Phishing (2026-05-17)](https://www.bleepingcomputer.com/news/security/tycoon2fa-hijacks-microsoft-365-accounts-via-device-code-phishing/)
- [eSentire — Tycoon 2FA Operators Adopt OAuth Device Code Phishing](https://www.esentire.com/blog/tycoon-2fa-operators-adopt-oauth-device-code-phishing)
- [eSentire IOC Repository — Tycoon 2FA](https://github.com/eSentire/iocs/tree/main/Tycoon2FA)
- [MITRE ATT&CK — T1550.001 Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
- [MITRE ATT&CK — T1528 Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [Microsoft — OAuth 2.0 Device Authorization Grant Flow](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code)
