---
scraped_at: 2026-11-19T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/cold-relic-a-case-study-in-impersonation-and-compromise
report_type: threat-intel
severity: high
title: "COLD RELIC (COLDRIVER / Star Blizzard): Google Workspace Intrusion via MFA Fatigue, Rogue Device Registration, and Cloud-Scale Data Collection"
---

# COLD RELIC (COLDRIVER / Star Blizzard): Google Workspace Intrusion via MFA Fatigue, Rogue Device Registration, and Cloud-Scale Data Collection

**Source:** Google Threat Intelligence Group (GTIG)  
**Published:** 2026-11-17  
**Severity:** High — Russia FSB actor; persistent cloud access surviving password resets; tenant-wide data collection; cross-cloud pivoting from Entra ID to Google Workspace  
**Note:** This report covers COLD RELIC's cloud identity attack chain, which is distinct from the VHD/CPL phishing chain documented in `2026-09-29_microsoft-security-blog-star-blizzard-redflick-cosmicpulse.md`.

---

## 1. IOCs

No concrete network or file IOCs are publicly disclosed in this report. The full indicator set is gated behind Google Threat Intelligence Collection access.

**Authentication behavioral indicators (not network IOCs):**

| Indicator | Type | Context |
|-----------|------|---------|
| `?file=<victim_name>` URI parameter | Phishing URL pattern | First-hop compromised redirect carries prior victim's name as `file=` param — reveals relationship targeting |
| `?ref=<lure_name>` URI parameter | Phishing URL pattern | Lure-themed parameter in redirect to phishing domain |
| `AS5650` | Residential proxy ASN | ASN cited as example of residential proxies used to avoid impossible-travel detection |
| `AS20115` | Residential proxy ASN | ASN cited as example of residential proxies geolocated near victim |

---

## 2. TTPs

| Tactic | Tactic ID | Technique ID | Technique | Usage |
|--------|-----------|-------------|-----------|-------|
| Initial Access | TA0001 | T1566.004 | Spearphishing via Service | Builds pretext via encrypted messaging apps (Signal, WhatsApp); shares phishing link targeting Google Workspace or Entra ID SSO |
| Initial Access | TA0001 | T1078.004 | Valid Accounts: Cloud Accounts | Uses stolen super-admin credentials or SSO-federated Entra ID session to access Google Workspace |
| Credential Access | TA0006 | T1621 | MFA Request Generation | Sends repeated MFA push notifications until victim approves one (MFA fatigue); follows with immediate device registration |
| Persistence | TA0003 | T1098.005 | Account Manipulation: Device Registration | Registers rogue MFA device, passkeys, and backup codes immediately after fatigue success; survives subsequent password resets |
| Defense Evasion | TA0005 | T1562.008 | Impair Defenses: Disable or Modify Cloud Logs | Queries Admin security investigation and email audit logs; deletes Alert Center notifications including government-backed attack alerts |
| Credential Access | TA0006 | T1552.001 | Credentials in Files | Performs Drive keyword searches for `password`, `cred`, `.bak`, `.pst` to discover stored credentials and secrets |
| Discovery | TA0007 | T1087.004 | Account Discovery: Cloud Account | Downloads full employee list / directory; exports user rosters to support future impersonation |
| Discovery | TA0007 | T1082 | System Information Discovery | Queries audit and security investigation logs to gauge detection visibility |
| Discovery | TA0007 | T1083 | File and Directory Discovery | Drive keyword searches for sensitive files, credentials, and personnel data |
| Collection | TA0009 | T1119 | Automated Collection | Customer Takeout: initiates tenant-wide Google Workspace data export |
| Collection | TA0009 | T1114.002 | Email Collection: Remote Email Collection | Grants OAuth `https://mail.google.com/` scope to external clients (Thunderbird, Proton Mail) for persistent inbox sync |
| Collection | TA0009 | T1530 | Data from Cloud Storage | Bulk downloads from victim's Google Drive; mass external sharing to attacker-controlled Gmail accounts |
| Lateral Movement | TA0008 | T1550.001 | Use Alternate Authentication Material: Application Access Token | OAuth session persists after password reset; unrevoked passkeys reauthenticate attacker months later |
| Exfiltration | TA0010 | T1567.002 | Exfiltration to Cloud Storage | Mass external sharing of files to attacker-controlled Google accounts; Customer Takeout to attacker email |
| Credential Access | TA0006 | T1528 | Steal Application Access Token | Phishes Entra ID OAuth tokens in Case Study 2; uses federated SSO token to pivot into Google Workspace |

---

## 3. Malware & Tools

No custom malware deployed. COLD RELIC relies entirely on native cloud features:

| Tool/Feature | Usage |
|---|---|
| Google Customer Takeout | Admin-initiated tenant-wide data export |
| Google Drive mass sharing | Bulk external file sharing to attacker-controlled accounts |
| Google Alert Center API | Queried and deleted defensive alert notifications |
| Google Admin SDK (audit API) | Queried audit logs to assess detection coverage |
| OAuth mail scope | Grants `https://mail.google.com/` to unapproved email clients for persistent sync |
| Google Passkeys / Backup codes | Used as persistence mechanism surviving password and session resets |
| Residential proxy networks | Used near victim's geography to evade impossible-travel alerts |

---

## 4. Threat Actor / Campaign Attribution

| Field | Value |
|---|---|
| Actor | COLD RELIC |
| Also known as | COLDRIVER, UNC4057, Star Blizzard, Callisto, Gossamer Bear |
| Attribution | Russia FSB (assessed by US DOJ) |
| Targeting | Government officials, defense contractors, NGOs — Europe and North America |
| Active since | 2015 (GTIG tracking); Google Workspace campaigns observed late 2025 through November 2026 |
| Relationship to prior reports | Same actor as `2026-09-29_microsoft-security-blog-star-blizzard-redflick-cosmicpulse.md` (RedFlick CPL chain) but distinct attack chain focused on cloud identity theft |

---

## 5. Splunk Detection Searches

### 5a. MFA Fatigue Followed by Successful Login and Device Registration

```spl
`google_workspace` log_type=login OR log_type=device
| eval event_name=coalesce(events{}.name, name)
| eval user=coalesce(actor.email, user)
| eval ip=coalesce(ipAddress, ip_address)
| bin _time span=30m
| stats
    count(eval(event_name="login_failure" AND login_challenge_method IN ("push", "phone", "totp"))) as mfa_failures,
    count(eval(event_name="login_success")) as login_successes,
    values(event_name) as event_names,
    min(_time) as firstTime, max(_time) as lastTime
  by user ip _time
| where mfa_failures >= 5 AND login_successes >= 1
| join type=inner user [
    search `google_workspace` log_type=device
    | eval event_name=coalesce(events{}.name, name)
    | search event_name IN ("DEVICE_REGISTER_COMPLETE", "2sv_enroll")
    | stats count as device_enroll_count min(_time) as enroll_time by user
    | where device_enroll_count >= 1
]
| where enroll_time <= lastTime + 3600
| eval risk_score=case(mfa_failures >= 10, 90, mfa_failures >= 5, 75, 1=1, 60)
| where risk_score >= 75
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime user ip mfa_failures login_successes enroll_time risk_score
```

*Detects: MFA fatigue (5+ failures in 30 min window) followed by successful login, correlated with device/passkey enrollment within 1 hour — the core COLD RELIC persistence chain.*

### 5b. Google Customer Takeout Initiated (Any Admin)

```spl
`google_workspace` log_type=admin
| eval event_name=coalesce(events{}.name, name)
| search event_name="CUSTOMER_TAKEOUT_INITIATED" OR event_name="CUSTOMER_TAKEOUT_CREATED"
| eval user=coalesce(actor.email, user)
| eval ip=coalesce(ipAddress, ip_address)
| stats count min(_time) as firstTime max(_time) as lastTime by user ip event_name
| eval risk_score=90
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime user ip event_name risk_score
```

*Detects: Tenant-wide Customer Takeout export — a rare, high-impact admin action used by COLD RELIC for mass data collection.*

### 5c. Bulk Drive External Sharing to Freemail

```spl
`google_workspace` log_type=drive
| eval event_name=coalesce(events{}.name, name)
| search event_name IN ("change_user_access", "change_document_visibility", "shared_drive_membership_change")
| eval shared_to=coalesce(parameters{}.value, target_user)
| search shared_to="*@gmail.com" OR shared_to="*@proton.me" OR shared_to="*@outlook.com" OR shared_to="*@yahoo.com"
| eval user=coalesce(actor.email, user)
| bin _time span=1h
| stats count as share_count values(shared_to) as recipients min(_time) as firstTime max(_time) as lastTime by user _time
| where share_count >= 20
| eval risk_score=case(share_count >= 100, 90, share_count >= 50, 80, share_count >= 20, 70)
| where risk_score >= 70
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime user share_count recipients risk_score
```

*Detects: Bulk sharing of Drive files to freemail providers within a 1-hour window — consistent with COLD RELIC exfiltration methodology.*

### 5d. OAuth Broad Mail Scope Granted to Unapproved Client

```spl
`google_workspace` log_type=token
| eval event_name=coalesce(events{}.name, name)
| search event_name="AUTHORIZE"
| eval scope=coalesce(scope, parameters{}.value)
| search scope="*mail.google.com*"
| eval client_id=coalesce(client_id, parameters{}.value)
| eval user=coalesce(actor.email, user)
| stats count min(_time) as firstTime max(_time) as lastTime by user client_id scope
| eval risk_score=90
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime user client_id scope risk_score
```

*Detects: OAuth authorization of `mail.google.com` scope — indicates an external email client being granted persistent inbox access, used by COLD RELIC for long-term email collection.*

### 5e. Alert Center Batch Deletion (Anti-Forensic)

```spl
`google_workspace` log_type=alert
| eval event_name=coalesce(events{}.name, name)
| search event_name IN ("ALERT_DELETION", "BATCH_DELETE_ALERTS", "DELETE_ALERT")
| eval user=coalesce(actor.email, user)
| eval ip=coalesce(ipAddress, ip_address)
| stats count as deletion_count min(_time) as firstTime max(_time) as lastTime by user ip
| where deletion_count >= 1
| eval risk_score=case(deletion_count >= 10, 90, deletion_count >= 3, 80, 1=1, 75)
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime user ip deletion_count risk_score
```

*Detects: Deletion of Alert Center notifications — COLD RELIC deletes government-backed attack alerts to suppress defender visibility.*

---

## 6. Executive Summary

Google Threat Intelligence Group (GTIG) published a November 2026 case study documenting COLD RELIC's (Russia FSB, also tracked as COLDRIVER / Star Blizzard) evolving methodology for compromising Google Workspace tenants belonging to government, defense, and NGO targets.

The attack chain differs substantially from COLD RELIC's earlier endpoint-focused phishing (VHD/CPL delivery) and is entirely living-off-the-land within cloud services. In Case Study 1, the actor obtained super-admin credentials and used residential proxy infrastructure geolocated near the victim to evade impossible-travel detection. MFA push fatigue was used to obtain approval, after which the actor immediately enrolled rogue MFA devices, passkeys, and backup codes — creating persistence that survived password resets. The actor then performed tenant-wide Customer Takeout, bulk Drive downloads, mass external sharing to freemail accounts, OAuth inbox sync to external clients, and queried and deleted Alert Center notifications.

Case Study 2 demonstrates cross-cloud lateral movement: the actor impersonated a compromised contact over encrypted messaging to social-engineer a second victim, harvested their Microsoft Entra ID credentials/tokens via AiTM phishing through a compromised redirect site, and pivoted through the federated SSO relationship into the victim's Google Workspace to bulk-download files.

The GTIG report contains no public network IOCs (full indicator set is in GTI Collection). Detection relies on behavioral analytics against Google Workspace audit logs: MFA fatigue followed by device enrollment, Customer Takeout creation, bulk external sharing spikes, broad OAuth mail scope grants, and Alert Center deletion events.

**Key defensive actions:** Deploy phishing-resistant MFA (FIDO2 hardware keys); require approval workflows for new MFA device/passkey enrollment; revoke all sessions, tokens, passkeys, and backup codes during IR (not just passwords); alert on Customer Takeout creation and bulk freemail sharing; audit OAuth grants for `mail.google.com` scope regularly.

---

## References

- [GTIG Report: COLD RELIC — A Case Study in Impersonation and Compromise (Nov 17, 2026)](https://cloud.google.com/blog/topics/threat-intelligence/cold-relic-a-case-study-in-impersonation-and-compromise)
- [MITRE ATT&CK — COLDRIVER (G1091)](https://attack.mitre.org/groups/G1091/)
- [MITRE ATT&CK — T1621: MFA Request Generation](https://attack.mitre.org/techniques/T1621/)
- [MITRE ATT&CK — T1098.005: Account Manipulation: Device Registration](https://attack.mitre.org/techniques/T1098/005/)
- [Prior COLD RELIC / RedFlick report (Sep 29, 2026)](2026-09-29_microsoft-security-blog-star-blizzard-redflick-cosmicpulse.md)
