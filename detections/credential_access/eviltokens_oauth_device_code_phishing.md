# EvilTokens OAuth 2.0 Device Code Phishing — Application Access Token Abuse

## Description

Detects abuse of the OAuth 2.0 device authorization flow (device code phishing) as used by the EvilTokens phishing-as-a-service (PhaaS) platform. Attackers distribute phishing emails containing QR codes or links that redirect victims to fake Microsoft/DocuSign/SharePoint login pages. Upon victim authorization, the attacker receives OAuth access and refresh tokens, granting persistent access to Microsoft 365 accounts without needing credentials. Threat actors linked to this service include Storm-237, UTA0355, ShinyHunters, and TA2723. Common false positives: legitimate device code logins from kiosks, printers, or smart TVs; baseline device code activity per environment and alert on anomalous volume or new devices.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Application Access Token |
| Technique ID | T1550.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.uri_path="*/oauth2/deviceauth*" OR Web.uri_path="*/oauth2/v2.0/devicecode*"
  by Web.src Web.dest Web.uri_path Web.http_user_agent Web.http_method
| `drop_dm_object_name(Web)`
| eval risk_score=case(
    match(http_user_agent, "(?i)python|curl|wget|powershell|go-http"), 85,
    match(uri_path, "deviceauth|devicecode"), 70,
    1=1, 55)
| where risk_score >= 55
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src dest uri_path http_user_agent http_method risk_score
```

**Supplemental: Azure AD — suspicious device code grant tokens**

```spl
`azure_monitor_aad`
| search operationName="Sign-in activity" authenticationProtocol="deviceCode"
| stats count min(_time) as firstTime max(_time) as lastTime values(ipAddress) as src_ips
  by userPrincipalName, appDisplayName, conditionalAccessStatus, authenticationRequirement
| eval risk_score=case(
    conditionalAccessStatus="failure", 80,
    authenticationRequirement="singleFactorAuthentication", 75,
    count > 5, 70,
    1=1, 60)
| where risk_score >= 60
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime userPrincipalName appDisplayName src_ips conditionalAccessStatus risk_score
```

**Supplemental: OAuth refresh token reuse from new location**

```spl
`azure_monitor_aad`
| search operationName="Sign-in activity" tokenProtectionStatus="unbound"
| stats count min(_time) as firstTime max(_time) as lastTime dc(ipAddress) as unique_ips
  by userPrincipalName, appDisplayName
| where unique_ips > 2
| eval risk_score=case(
    unique_ips > 5, 85,
    unique_ips > 2, 70,
    1=1, 55)
| where risk_score >= 55
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime userPrincipalName appDisplayName unique_ips risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Device code flow from scripting/automation user agent | 85 | Automated harvesting; real device flows come from browsers/apps |
| Device code endpoint access (any user agent) | 70 | Baseline detection; needs correlation with volume or new device |
| Azure AD sign-in via device code with failed CA policy | 80 | Attacker-controlled device likely missing expected compliant device policy |
| Single-factor auth via device code | 75 | MFA bypass; device code grant skips interactive MFA challenge |
| OAuth refresh token used from 3+ unique IPs | 70-85 | Token theft and redistribution pattern |

## Associated Threat Actors

| Actor | Relationship to Detection |
|-------|--------------------------|
| EvilTokens (PhaaS) | Platform sold on Telegram enabling device code phishing; supports Microsoft 365, planned expansion to Gmail and Okta |
| Storm-237 | Confirmed EvilTokens customer; targets finance, HR, logistics sectors |
| UTA0355 / UTA032 | EvilTokens-linked operators targeting US, Canada, France, Australia |
| ShinyHunters | Associated with EvilTokens campaigns; known for large-scale data theft |
| TA2723 / UNK_AcademicFlare | EvilTokens-linked threat actors |

## References

- [BleepingComputer - EvilTokens Service Fuels Microsoft Device Code Phishing](https://www.bleepingcomputer.com/news/security/new-eviltokens-service-fuels-microsoft-device-code-phishing-attacks/)
- [MITRE ATT&CK - T1550.001 Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
- [Microsoft - OAuth Device Authorization Grant Flow](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code)
- [CISA - Protecting Against OAuth Device Code Phishing](https://www.cisa.gov/news-events/cybersecurity-advisories)
