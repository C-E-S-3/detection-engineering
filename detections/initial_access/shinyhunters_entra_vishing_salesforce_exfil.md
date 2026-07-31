# ShinyHunters Entra Vishing — MFA Device Registration and Salesforce Exfiltration

## Description

Detects ShinyHunters (UNC6661) voice phishing (vishing) attacks targeting Microsoft Entra (Azure AD) to bypass MFA and gain access to enterprise SaaS applications including Salesforce. The attack pattern involves an attacker impersonating IT support, convincing an employee to complete a Microsoft Entra device registration or MFA authentication step, resulting in persistent account access. This was used in the July 2026 Brinks Home breach (1.1M+ Salesforce records) and is part of a broader 2026 campaign against enterprises using Salesforce, Okta, Microsoft 365, and Google Workspace.

False positives: Legitimate IT-managed device enrollment generates similar Azure AD audit events. Tune by creating exceptions for enrollments originating from corporate MDM systems and known IT admin accounts. Focus alert investigation on enrollments immediately followed by unusual Salesforce API activity or data access from new geographic locations.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Phishing: Vishing |
| Technique ID | T1566.004 |

Secondary techniques (post-access):

| Tactic | Technique ID | Technique |
|--------|-------------|-----------|
| Initial Access | T1078 | Valid Accounts |
| Credential Access | T1621 | Multi-Factor Authentication Request Generation |
| Persistence | T1098.005 | Account Manipulation: Device Registration |
| Collection | T1213.004 | Data from Information Repositories: CRM Software |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |

## Splunk Detection Query

```spl
`o365`
(Operation="Add device" OR Operation="Register user device" OR
 Operation="Add registered users to device" OR Operation="Update StsRefreshTokensValidFrom"
 OR ClientIP IN ("138.226.246.94", "212.86.125.24", "213.111.148.90", "94.154.32.160"))
| stats count min(_time) as firstTime max(_time) as lastTime
  values(Operation) as operations values(ClientIP) as client_ips
  values(UserAgent) as user_agents
  by UserId
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval ioc_ip_match=if(
    match(mvjoin(client_ips, " "), "138\.226\.246\.94|212\.86\.125\.24|213\.111\.148\.90|94\.154\.32\.160"),
    "yes", "no")
| eval risk_score=case(
    ioc_ip_match="yes", 90,
    match(mvjoin(operations, " "), "(?i)Update StsRefreshTokensValidFrom"), 85,
    count > 5, 80,
    match(mvjoin(operations, " "), "(?i)(Add device|Register user device)"), 65,
    1=1, 50)
| where risk_score >= 65
| table firstTime lastTime UserId operations client_ips user_agents ioc_ip_match count risk_score
| sort -risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Authentication from known ShinyHunters IOC IP | 90 | Direct IOC match; IPs confirmed in Microsoft campaign analysis (July 13, 2026) |
| `Update StsRefreshTokensValidFrom` operation | 85 | Invalidates existing sessions to consolidate attacker's new session; strongly suspicious |
| Device registration/addition > 5 events | 80 | Bulk device registration unusual for single user; indicates automated enrollment |
| New Entra device registration or user device addition | 65 | Starting point for vishing follow-through; requires corroboration |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| ShinyHunters (UNC6661, UNC6240) | [MITRE ATT&CK Campaign C0059](https://attack.mitre.org/campaigns/C0059/), [Microsoft Security Blog (July 13, 2026)](https://www.microsoft.com/en-us/security/blog/2026/07/13/defending-saas-based-applications-against-shinyhunters-oauth-abuse/) |

## References

- [Microsoft Security Blog — Defending SaaS apps against ShinyHunters OAuth abuse (July 13, 2026)](https://www.microsoft.com/en-us/security/blog/2026/07/13/defending-saas-based-applications-against-shinyhunters-oauth-abuse/)
- [BleepingComputer — ShinyHunters claims Brinks Home breach](https://www.bleepingcomputer.com/news/security/shinyhunters-claims-brinks-home-breach-threatens-to-leak-stolen-data/)
- [Obsidian Security — Behind the breach: ShinyHunters 2026 voice phishing campaign](https://www.obsidiansecurity.com/blog/behind-the-breach-shinyhunters-2026-voice-phishing-campaign/)
- [ReliaQuest — ShinyHunters targets Salesforce (2026)](https://reliaquest.com/blog/threat-spotlight-shinyhunters-data-breach-targets-salesforce-amid-scattered-spider-collaboration/)
- [MITRE ATT&CK — T1566.004 Phishing: Vishing](https://attack.mitre.org/techniques/T1566/004/)
- [MITRE ATT&CK — T1621 Multi-Factor Authentication Request Generation](https://attack.mitre.org/techniques/T1621/)
