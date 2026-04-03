# Cloud Privileged Role Assignment (Azure AD / Entra ID Global Admin Escalation)

## Description

Detects unauthorized assignment of highly privileged cloud roles — particularly Global Administrator, Privileged Role Administrator, Application Administrator, and Exchange Administrator in Azure AD/Microsoft Entra ID. This is a critical persistence technique: once an attacker achieves domain admin or initial cloud access, creating or promoting a cloud administrator account provides a persistent re-entry path that survives on-premises remediation, password resets, and even OS rebuilds. The Handala hacktivist group (Iranian MOIS-linked) used this technique in the 2026 Stryker attack: after compromising a Windows domain admin account they immediately created a Global Administrator account, enabling control of ~80,000 devices for data wiping. Nation-state actors and ransomware operators use this to ensure persistence even if the initial compromise vector is closed. Common false positives: authorized IT admin onboarding, provisioning automation (Global Admin must be a known service account), break-glass account configuration; baseline normal admin assignment operators and alert on deviations.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Persistence |
| Tactic ID | TA0003 |
| Technique | Account Manipulation: Additional Cloud Roles |
| Technique ID | T1098.003 |

Secondary techniques: T1136.003 (Create Account: Cloud Account — attacker creates new admin), T1078.004 (Valid Accounts: Cloud Accounts — attacker uses created admin account), T1485 (Data Destruction — ultimate impact in Handala/wiper campaigns)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Change
  where Change.action="modified"
    AND Change.object_category IN ("azure_ad_role","entra_id_role","directory_role")
    AND (Change.result IN ("success","Success"))
  by Change.dest Change.user Change.src Change.object Change.result
     Change.command Change.object_attrs
| `drop_dm_object_name(Change)`
| eval high_priv_role=case(
    match(object_attrs, "(?i)global administrator|company administrator"), 1,
    match(object_attrs, "(?i)privileged role administrator|privileged authentication administrator"), 1,
    match(object_attrs, "(?i)application administrator|cloud application administrator"), 1,
    match(object_attrs, "(?i)exchange administrator|user administrator|groups administrator"), 1,
    1=1, 0)
| where high_priv_role=1
| eval risk_score=case(
    match(object_attrs, "(?i)global administrator|company administrator"), 95,
    match(object_attrs, "(?i)privileged role administrator|privileged authentication administrator"), 92,
    match(object_attrs, "(?i)application administrator|cloud application administrator"), 85,
    match(object_attrs, "(?i)exchange administrator"), 80,
    1=1, 75)
| where risk_score >= 80
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user src object object_attrs result risk_score
```

**Supplemental: Azure AD audit log — role assignment to new or recently created account**

```spl
`o365`
  EventName IN ("Add member to role.","Add eligible member to role.","Add scoped member to role.")
  Operation IN ("Add member to role.","Add eligible member to role.")
| eval target_role=mvindex('ModifiedProperties{}.NewValue', 0)
| eval target_user=mvindex('ObjectId', 0)
| search target_role IN ("Global Administrator","Company Administrator",
    "Privileged Role Administrator","Privileged Authentication Administrator",
    "Application Administrator","Exchange Administrator")
| eval risk_score=case(
    match(target_role, "(?i)Global Administrator|Company Administrator"), 95,
    match(target_role, "(?i)Privileged Role|Privileged Authentication"), 92,
    match(target_role, "(?i)Application Administrator|Exchange Administrator"), 82,
    1=1, 75)
| where risk_score >= 80
| table _time, UserId, target_user, target_role, ClientIP, risk_score
```

**Supplemental: New Azure AD global admin account created and used from unexpected location**

```spl
`o365`
  EventName="Add user." OR Operation="Add user."
| eval new_user=coalesce('ObjectId','UserId')
| join new_user
    [search `o365`
      EventName="UserLoggedIn" OR Operation="UserLoggedIn"
    | eval new_user=UserId
    | stats first(_time) as login_time, first(ClientIP) as login_ip,
            first(UserAgent) as login_ua by new_user
    | where login_time > relative_time(now(),"-24h")]
| eval account_age_hours=round((login_time - _time)/3600,1)
| where account_age_hours <= 2
| eval risk_score=case(
    account_age_hours <= 0.5, 97,
    account_age_hours <= 1, 92,
    account_age_hours <= 2, 87,
    1=1, 80)
| where risk_score >= 87
| table _time, new_user, login_ip, login_ua, account_age_hours, login_time risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Global Administrator role assigned (any) | 95 | Highest privilege in tenant; legitimate assignment is rare and controlled; unauthorized = game over for tenant |
| Privileged Role Administrator assigned | 92 | Can assign all other roles including Global Admin; functionally equivalent in blast radius |
| New account assigned Global Admin within 30 minutes of creation | 97 | Classic attacker move: create admin → immediately promote → use for persistence or mass action |
| Application/Exchange Administrator assigned | 80-85 | High privilege but narrower scope; still warrants immediate review outside provisioning windows |
| Admin assignment from unrecognized IP/country | +5 bonus | Geographic anomaly compounds privilege risk; combine with UEBA enrichment |

## Associated Threat Actors

| Actor | Relationship to Detection |
|-------|--------------------------|
| Handala (Hatef / Hamsa) | Iranian MOIS-linked hacktivist group. Used Global Administrator account creation in the 2026 Stryker data wiper attack to deploy wiper across ~80,000 devices |
| Scattered Spider (UNC3944) | Routinely abuses helpdesk social engineering to gain initial cloud access, then immediately elevates to Global Admin for persistence before deploying ransomware |
| Lapsus$ (DEV-0537) | Pioneered cloud admin privilege escalation as primary attack surface; assigned GA roles to attacker-controlled accounts within minutes of initial access |
| North Korea IT Workers | Create fraudulent cloud admin accounts as part of insider threat campaigns; use GA access for cryptocurrency theft and data exfiltration |

## References

- [BleepingComputer - Handala Stryker Wiper Attack](https://www.bleepingcomputer.com/news/security/medtech-giant-stryker-fully-operational-after-data-wiping-attack/)
- [MITRE ATT&CK - T1098.003 Account Manipulation: Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/)
- [MITRE ATT&CK - T1136.003 Create Account: Cloud Account](https://attack.mitre.org/techniques/T1136/003/)
- [Microsoft - Detect and Respond to Privileged Identity Management](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-security-wizard)
- [CISA - Microsoft Cloud Security Best Practices](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a)
