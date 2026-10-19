---
scraped_at: "2026-10-19"
source_url: "https://www.bleepingcomputer.com/news/security/hackers-breach-microsoft-365-tenants-via-connectwise-supply-chain-attack/"
report_type: threat-intel
severity: high
title: "ConnectWise Cloud Backup OAuth Supply Chain Attack — 173 Microsoft 365 MSP Tenants Compromised"
---

# ConnectWise Cloud Backup OAuth Supply Chain Attack — 173 Microsoft 365 MSP Tenants Compromised

## Executive Summary

On October 17, 2026, ConnectWise disclosed that attackers compromised the OAuth application credentials backing their **Cloud Backup (SkyKick)** product — an MSP-facing Microsoft 365 backup service. The stolen credentials were used to authenticate as the ConnectWise Cloud Backup first-party OAuth application (`506e08f9-6e9a-4da4-942b-a099a03644ae`) against Microsoft's identity platform, bypassing tenant-level MFA entirely because the access occurred through an already-trusted OAuth app identity, not a user credential.

Between **October 13, 2026 (03:12 UTC)** and **October 15, 2026 (08:34 UTC)**, attackers accessed Microsoft 365 service principals across **162–173 MSP customer tenants** with read/write access to mail, OneDrive, SharePoint, and Teams data. ConnectWise suspended the Cloud Backup service and disabled the compromised app identities on October 17, 2026.

This attack demonstrates a class of OAuth supply chain compromise where a compromised *software vendor's* OAuth app credential grants attacker access to *all downstream customer tenants* that have granted that app consent — with no per-tenant MFA required.

---

## Attack Timeline

| Time (UTC) | Event |
|------------|-------|
| 2026-10-13 03:12 | First unauthorized sign-in attempts detected |
| 2026-10-15 06:13 | Main exploitation window begins |
| 2026-10-15 08:34 | Main exploitation window ends |
| 2026-10-17 | ConnectWise suspends Cloud Backup service; app identities disabled |
| 2026-10-17 | Public disclosure via BleepingComputer |

---

## Indicators of Compromise

### OAuth Application Identifiers

| Indicator | Type | Confidence | Notes |
|-----------|------|-----------|-------|
| `506e08f9-6e9a-4da4-942b-a099a03644ae` | OAuth App ID (Application ID / Client ID) | High | ConnectWise Cloud Backup / SkyKick app identity used in exploitation |

### IP Addresses

| Indicator | Type | Confidence | Notes |
|-----------|------|-----------|-------|
| `144.172.64.128` | IPv4 | Medium (single source) | Attacker IP observed in unauthorized M365 sign-in events; commercial hosting; `curl`/`python-requests` user-agent strings |

---

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

---

## Lockheed Martin Kill Chain

- **Delivery** — OAuth credential compromise at vendor enables access to customer tenants
- **Actions on Objectives** — Mail, OneDrive, SharePoint, Teams data access and attempted credential persistence

---

## Technical Details

### How OAuth App Supply Chain Compromise Bypasses MFA

ConnectWise Cloud Backup operates as a **first-party application** in each MSP customer's Microsoft Entra ID (Azure AD) tenant. When an MSP installs the product, they grant the ConnectWise Cloud Backup app (`506e08f9-6e9a-4da4-942b-a099a03644ae`) consent with delegated permissions including:
- `Mail.Read` / `Mail.ReadWrite`
- `Files.ReadWrite.All`
- `Sites.ReadWrite.All`
- `Directory.ReadWrite.All`

Authentication to Microsoft's identity platform is done using **OAuth client credentials** (client secret or certificate) held by ConnectWise's infrastructure — not by individual user accounts. Because this is app-to-app authentication, **no per-tenant user MFA applies**. An attacker who obtains the vendor's OAuth client credentials can access all consenting tenants without ever triggering an MFA challenge.

### Observed Attacker Behavior

- Authenticated as the ConnectWise Cloud Backup service principal in ~173 MSP customer tenants
- Microsoft Graph API calls observed:
  - `Directory.ReadWrite.All` — directory enumeration and attempted service principal manipulation
  - Credential addition attempts on existing service principals (T1098.001)
- User-agent strings: `curl/7.x`, `python-requests/2.x` (consistent with automated tooling)
- Source IP: `144.172.64.128` (commercial hosting provider, not associated with ConnectWise infrastructure)

---

## Splunk Detection Queries

### 1. Sign-ins from Compromised ConnectWise OAuth App ID

```spl
`o365` EventType="AzureActiveDirectory" Operation="UserLoggedIn" OR Operation="Sign-in activity"
| eval app_id=coalesce(AppId, ApplicationId, ClientAppId)
| where app_id="506e08f9-6e9a-4da4-942b-a099a03644ae"
| stats count min(_time) as firstTime max(_time) as lastTime
    values(src_ip) as src_ips
    values(dest) as tenants
    values(user) as users
    by app_id Operation
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime app_id Operation tenants users src_ips count risk_score
```

### 2. Suspicious OAuth App Sign-ins from Commercial Hosting (Generic)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication
    where Authentication.action=success Authentication.app=*
    by Authentication.src Authentication.app Authentication.user Authentication.dest
| `drop_dm_object_name(Authentication)`
| lookup cloud_hosting_ranges src as src OUTPUT is_hosting_provider
| where is_hosting_provider=true
| lookup known_oauth_service_principals app as app OUTPUT is_expected_src
| where is_expected_src=false
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=70
| where risk_score >= 70
| table firstTime lastTime src app user dest count risk_score
```

### 3. Service Principal Credential Addition (T1098.001)

```spl
`o365` EventType="AzureActiveDirectory"
    (Operation="Add service principal credentials" OR Operation="Update application – Certificates and secrets management")
| rex field=ModifiedProperties "(?i)KeyIdentifier\": \[\"(?P<key_id>[0-9a-f\-]{36})"
| stats count min(_time) as firstTime max(_time) as lastTime
    values(key_id) as added_keys
    values(src_ip) as src_ips
    by user Operation ObjectId
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(user, "(?i)service|app|automation"), 65,
    1=1, 80)
| where risk_score >= 65
| table firstTime lastTime user Operation ObjectId added_keys src_ips risk_score
```

---

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Sign-in from known-compromised app ID `506e08f9-6e9a-4da4-942b-a099a03644ae` | 90 | Direct IOC match; app identity confirmed malicious during Oct 13–17 window |
| OAuth app sign-in from hosting provider IP (generic) | 70 | Strong indicator; legitimate MSP tools auth from cloud but rarely from residential or hosting provider ranges inconsistent with vendor |
| Service principal credential addition | 65–80 | Common persistence technique; score higher if performed by non-human/service account caller |

---

## Affected Products

| Product | Version / Context |
|---------|-------------------|
| ConnectWise Cloud Backup (SkyKick) | All tenants using app `506e08f9-6e9a-4da4-942b-a099a03644ae` |
| Microsoft 365 / Entra ID | All tenants that granted consent to the ConnectWise Cloud Backup app |

**Affected data:** Mail, OneDrive, SharePoint, Microsoft Teams

---

## Associated Threat Actors

Attribution not established as of October 19, 2026. Attacker infrastructure (`144.172.64.128`) is a commercial hosting address with no public actor attribution. Automation tooling (curl/python user-agents) suggests scripted access rather than interactive intrusion.

---

## Recommended Actions

1. **Search Entra ID sign-in logs** for app ID `506e08f9-6e9a-4da4-942b-a099a03644ae` with timestamps outside normal ConnectWise backup windows
2. **Review service principal audit logs** for credential additions to any service principal Oct 13–17, 2026
3. **Block / revoke** any remaining ConnectWise Cloud Backup service principal grant until ConnectWise confirms remediation
4. **Implement Conditional Access policies** restricting OAuth app sign-ins to known, registered cloud infrastructure IP ranges where feasible
5. **Audit OAuth app consent grants** across the tenant — revoke apps with Directory.ReadWrite.All that are not actively needed

---

## References

- [BleepingComputer — Hackers breach Microsoft 365 tenants via ConnectWise supply chain attack (2026-10-17)](https://www.bleepingcomputer.com/news/security/hackers-breach-microsoft-365-tenants-via-connectwise-supply-chain-attack/)
- [Huntress — ConnectWise Cloud Backup investigation notes](https://www.huntress.com/)
- [Microsoft — T1528: Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [MITRE ATT&CK — T1550.001: Use Alternate Authentication Material: Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
- [MITRE ATT&CK — T1098.001: Account Manipulation: Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)
