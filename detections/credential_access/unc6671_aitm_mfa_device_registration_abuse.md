# UNC6671 / BlackFile — AiTM MFA Device Registration Abuse

## Description

Detects attacker-controlled MFA device registration events that follow a vishing-facilitated Adversary-in-the-Middle (AiTM) credential capture. After intercepting a victim's credentials and MFA code over a vishing call, UNC6671 (BlackFile) immediately registers a new attacker-controlled authenticator on the compromised account — establishing persistence that survives password resets unless the new MFA device is also removed.

The primary signal is a successful MFA factor setup event on Okta or Azure AD/Entra originating from a non-corporate IP, especially a commercial VPN or hosting provider address. The second SPL search correlates authentication challenges immediately preceding a new device registration, which is the most reliable indicator of AiTM MFA interception.

**False positive sources:** Legitimate employee self-service MFA enrollment, IT help desk–initiated MFA setup on behalf of users, onboarding workflows. Correlate src_ip against known corporate ranges and IT NAT egress addresses before escalating.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Multi-Factor Authentication Interception |
| Technique ID | T1111 |
| Secondary Technique | Modify Authentication Process |
| Secondary Technique ID | T1556 |
| Tertiary Technique | Adversary-in-the-Middle |
| Tertiary Technique ID | T1557.002 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

### Query 1 — Okta: Successful MFA Factor Setup Events

```spl
`okta` eventType="system.multifactor.factor.setup" outcome.result="SUCCESS"
| rename actor.login as user, client.ipAddress as src_ip,
         target{0}.displayName as enrolled_factor,
         client.geographicalContext.country as country,
         client.geographicalContext.city as city
| stats count as setup_count
    min(_time) as firstTime
    max(_time) as lastTime
    values(src_ip) as src_ips
    values(country) as countries
    values(city) as cities
    values(enrolled_factor) as enrolled_factors
    by user
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    setup_count >= 3, 90,
    setup_count >= 1, 75)
| where risk_score >= 75
| table firstTime lastTime user src_ips countries cities setup_count enrolled_factors risk_score
```

### Query 2 — M365: New Authenticator Registration via Azure AD Audit Log

```spl
`o365` Operation="Update user." OR Operation="Add method for MFA" OR Operation="Register security info"
| rename UserId as user, ClientIP as src_ip, ModifiedProperties{0}.NewValue as new_value
| stats count as change_count
    min(_time) as firstTime
    max(_time) as lastTime
    values(src_ip) as src_ips
    values(Operation) as operations
    values(new_value) as new_values
    by user
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    change_count >= 1, 75)
| where risk_score >= 75
| table firstTime lastTime user src_ips operations change_count new_values risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Any MFA factor setup (Okta) | 75 | Any new authenticator registration warrants investigation; legitimate enrollment should be expected and pre-approved |
| 3+ MFA factor setup events same user | 90 | Repeated registration attempts suggest attacker-controlled enrollment during active compromise |
| Any Azure AD authenticator registration | 75 | Baseline alert; correlate with prior failed/challenged auth from same session |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| UNC6671 / BlackFile | [Google TI — BlackFile Vishing Operation (2026-05-15)](https://cloud.google.com/blog/topics/threat-intelligence/blackfile-vishing-extortion-operation) |
| ShinyHunters / UNC6240 | [MITRE ATT&CK — ShinyHunters (G1010)](https://attack.mitre.org/groups/G1010/) |
| Scattered Spider (UNC3944) | [CISA — Scattered Spider Advisory AA23-320A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a) |

## References

- [Google TI — Welcome to BlackFile: Inside a Vishing Extortion Operation](https://cloud.google.com/blog/topics/threat-intelligence/blackfile-vishing-extortion-operation)
- [MITRE ATT&CK — T1111: Multi-Factor Authentication Interception](https://attack.mitre.org/techniques/T1111/)
- [MITRE ATT&CK — T1556: Modify Authentication Process](https://attack.mitre.org/techniques/T1556/)
- [MITRE ATT&CK — T1557.002: Adversary-in-the-Middle: AiTM](https://attack.mitre.org/techniques/T1557/002/)
- [CISA — Phishing-Resistant MFA Fact Sheet](https://www.cisa.gov/resources-tools/resources/phishing-resistant-mfa-fact-sheet)
