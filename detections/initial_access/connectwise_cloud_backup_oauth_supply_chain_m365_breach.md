# ConnectWise Cloud Backup OAuth Supply Chain — Microsoft 365 Tenant Compromise

## Description

Detects unauthorized Microsoft 365 tenant access via compromised OAuth application credentials, as exploited in the October 2026 ConnectWise Cloud Backup supply chain attack. Attackers stole the ConnectWise Cloud Backup (SkyKick) OAuth app client credentials and used them to authenticate as the app's service principal against 162–173 MSP customer tenants. Because authentication used OAuth app-to-app client credentials rather than user accounts, no per-tenant MFA was triggered.

This detection covers both the specific ConnectWise IOC (App ID `506e08f9-6e9a-4da4-942b-a099a03644ae`) and the generic behavioral pattern: an OAuth app authenticating successfully from a commercial hosting IP range outside the vendor's known infrastructure.

**False positives:** Legitimate ConnectWise Cloud Backup operations (disabled after Oct 17, 2026); other MSP backup tools authenticating from cloud infrastructure during backup windows; programmatic OAuth app health-checks from monitoring services.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Steal Application Access Token |
| Technique ID | T1528 |
| Secondary Tactic | Defense Evasion |
| Secondary Tactic ID | TA0005 |
| Secondary Technique | Use Alternate Authentication Material: Application Access Token |
| Secondary Technique ID | T1550.001 |
| Tertiary Tactic | Persistence |
| Tertiary Tactic ID | TA0003 |
| Tertiary Technique | Account Manipulation: Additional Cloud Credentials |
| Tertiary Technique ID | T1098.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Actions on Objectives |

## Splunk Detection Query

### Query 1 — Specific IOC: ConnectWise Cloud Backup App Sign-in

```spl
`o365` EventType="AzureActiveDirectory"
    (Operation="UserLoggedIn" OR Operation="Sign-in activity" OR Operation="Authenticate application")
| eval app_id=coalesce(AppId, ApplicationId, ClientAppId)
| where app_id="506e08f9-6e9a-4da4-942b-a099a03644ae"
| stats count min(_time) as firstTime max(_time) as lastTime
    values(src_ip) as src_ips
    values(user) as users
    values(dest) as tenants
    by app_id Operation
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime app_id Operation tenants users src_ips count risk_score
```

### Query 2 — Generic: OAuth App Authentication from Hosting Provider IP

```spl
`o365` EventType="AzureActiveDirectory"
    (Operation="UserLoggedIn" OR Operation="Authenticate application")
    NOT (src_ip=10.0.0.0/8 OR src_ip=172.16.0.0/12 OR src_ip=192.168.0.0/16)
| iplocation src_ip
| where isnotnull(app_id)
| stats count min(_time) as firstTime max(_time) as lastTime
    values(src_ip) as src_ips dc(src_ip) as unique_src_ips
    values(user) as users
    by app_id Operation City Country
| where unique_src_ips > 3 OR (count > 50 AND Country!="United States")
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=70
| where risk_score >= 70
| table firstTime lastTime app_id Operation unique_src_ips src_ips users City Country count risk_score
```

### Query 3 — Service Principal Credential Addition (Persistence Indicator)

```spl
`o365` EventType="AzureActiveDirectory"
    (Operation="Add service principal credentials"
     OR Operation="Update application – Certificates and secrets management"
     OR Operation="Add member to role")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(src_ip) as src_ips
    values(ModifiedProperties) as changes
    by user Operation ObjectId
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(user, "(?i)service|svc|app|automation|backup"), 65,
    1=1, 80)
| where risk_score >= 65
| table firstTime lastTime user Operation ObjectId src_ips risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Sign-in from compromised ConnectWise app ID `506e08f9-6e9a-4da4-942b-a099a03644ae` | 90 | Direct IOC match; app identity confirmed compromised Oct 13–17, 2026 |
| OAuth app auth from hosting provider, >3 source IPs | 70 | Anomalous distribution of auth sources; legitimate backup apps auth from stable cloud infrastructure |
| Service principal credential addition by service account | 65 | Persistence mechanism; lower score acknowledges legitimate automation |
| Service principal credential addition by user account | 80 | Uncommon; warrants immediate investigation |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (ConnectWise Cloud Backup supply chain, Oct 2026) | [BleepingComputer — ConnectWise M365 supply chain attack (2026-10-17)](https://www.bleepingcomputer.com/news/security/hackers-breach-microsoft-365-tenants-via-connectwise-supply-chain-attack/) |

## References

- [BleepingComputer — Hackers breach Microsoft 365 tenants via ConnectWise supply chain attack (2026-10-17)](https://www.bleepingcomputer.com/news/security/hackers-breach-microsoft-365-tenants-via-connectwise-supply-chain-attack/)
- [MITRE ATT&CK — T1528: Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [MITRE ATT&CK — T1550.001: Use Alternate Authentication Material: Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
- [MITRE ATT&CK — T1098.001: Account Manipulation: Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)
- [Microsoft — Understanding OAuth app-only authentication in Microsoft 365](https://learn.microsoft.com/en-us/azure/active-directory/develop/app-only-access-primer)
