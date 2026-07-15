# Microsoft ADFS CVE-2026-56155: Insufficient Access Control Privilege Escalation

## Description

Detects exploitation of CVE-2026-56155, a CWE-1220 (Insufficient Granularity of Access Control) vulnerability in Microsoft Active Directory Federation Services (ADFS). An authorized attacker with existing network access to the ADFS environment can elevate privileges locally by abusing gaps in ADFS access control enforcement around Relying Party Trust evaluation and token issuance scope.

The vulnerability differs from the DPAPI key extraction technique tracked in `adfs_machine_dpapi_signing_key_extraction` — that detection covers Golden SAML via DPAPI masterkey recovery. CVE-2026-56155 targets the access control evaluation logic directly, allowing an attacker to obtain tokens for relying parties they are not entitled to access, or to modify ADFS configuration to broaden their own access scope.

**Observable attack phases:**

1. ADFS enumeration — attacker uses PowerShell ADFS cmdlets (Get-AdfsRelyingPartyTrust, Get-AdfsCertificate) to map current configuration and identify weak access control targets.
2. Access control modification — attacker modifies a Relying Party Trust (issuance authorisation rules, claim transformation) or adds a rogue RPT to receive tokens they are not authorized for.
3. Token acquisition — ADFS issues tokens to the attacker's controlled application or their modified RPT, granting access to downstream resources with elevated privileges.
4. Lateral movement — attacker uses ADFS service account credentials or the acquired tokens to authenticate to additional systems using explicit credentials (Windows Event 4648) or network logons (Event 4624 Type 3).

**False positive sources:** Legitimate ADFS administrators running federation onboarding scripts; scheduled PKI tasks rotating token-signing certificates; ADFS WAP/proxy health check logons (Event 4624 Type 3); bulk ADFS migration tooling. Correlate with approved change management records for all detections in this ruleset.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Privilege Escalation |
| Tactic ID | TA0004 |
| Technique | Exploitation for Privilege Escalation |
| Technique ID | T1068 |

Secondary techniques:

| Technique | ID | Description |
|-----------|-----|-------------|
| Domain Policy Modification: Domain Trust Modification | T1484.002 | Modifying ADFS Relying Party Trusts or Claims Provider Trusts to expand access control scope |
| Valid Accounts: Domain Accounts | T1078.002 | Lateral movement using ADFS service account credentials acquired post-exploit |
| Use Alternate Authentication Material: Application Access Token | T1550.001 | Using ADFS-issued tokens for downstream application access after access control bypass |
| Command and Scripting Interpreter: PowerShell | T1059.001 | ADFS PowerShell module cmdlets used for enumeration and configuration modification |
| Subvert Trust Controls: Code Signing Policy Modification | T1553.004 | Modification of ADFS token-signing certificates |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Actions on Objectives |

## Wazuh Rules

| Rule ID | Level | Description |
|---------|-------|-------------|
| 103945 | 7 | Anchor: PowerShell process with ADFS module or cmdlet reference (Sysmon Event 1) |
| 103946 | 14 | ADFS Relying Party Trust add/modify/remove via PowerShell |
| 103947 | 14 | ADFS certificate or token-signing key modification via PowerShell |
| 103948 | 12 | ADFS claims provider trust or transform policy modification via PowerShell |
| 103949 | 13 | ADFS global authentication policy or endpoint configuration modified via PowerShell |
| 103950 | 13 | Explicit credential logon (Event 4648) targeting ADFS-related service |
| 103951 | 10 | Network logon (Event 4624 Type 3) to ADFS service account |
| 103952 | 13 | ADFS service host (Microsoft.IdentityServer.ServiceHost.exe) spawned admin process (Event 4688) |
| 103953 | 12 | ADFS admin event log records Relying Party Trust lifecycle change |
| 103954 | 14 | Rapid ADFS PowerShell cmdlet burst by same user (5+ in 120 seconds) |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (
    (Processes.process_name IN ("powershell.exe","pwsh.exe")
     AND (Processes.process="*AdfsRelyingParty*"
       OR Processes.process="*AdfsClaimsProvider*"
       OR Processes.process="*AdfsCertificate*"
       OR Processes.process="*AdfsProperties*"
       OR Processes.process="*AdfsGlobalAuth*"
       OR Processes.process="*Set-Adfs*"
       OR Processes.process="*Add-Adfs*"
       OR Processes.process="*Remove-Adfs*"))
    OR (Processes.parent_process_name="Microsoft.IdentityServer.ServiceHost.exe"
        AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","net.exe","whoami.exe","nltest.exe"))
  )
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)(?:Set|Add|Remove)-AdfsRelyingPartyTrust")                     , 90,
    match(process,"(?i)(?:Set|Add|Remove|Update)-AdfsCertificate")                    , 90,
    match(process,"(?i)(?:Set|Add|Remove)-AdfsClaimsProviderTrust")                   , 80,
    match(process,"(?i)(?:Set|Add|Remove)-AdfsClaimsTransformPolicy")                 , 80,
    match(process,"(?i)Set-AdfsProperties")                                            , 85,
    match(process,"(?i)Set-AdfsGlobalAuthenticationPolicy")                            , 85,
    match(parent_process_name,"(?i)Microsoft\.IdentityServer\.ServiceHost")            , 90,
    1=1                                                                                , 60)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| comment "Secondary detection: ADFS service account explicit-credential and network logon events"
index=wineventlog (EventCode=4648 OR EventCode=4624)
| eval adfs_match=case(
    EventCode=4648 AND match(Target_Server_Name,"(?i)adfs|federation|sts|wsfed|stsservice"), "explicit_cred_to_adfs_service",
    EventCode=4624 AND Logon_Type="3"
      AND match(Account_Name,"(?i)adfs|adfssvc|adfs_svc|federation|sts_svc|fedsvc|svc_adfs"), "network_logon_adfs_account",
    true(), null())
| where isnotnull(adfs_match)
| stats count min(_time) as firstTime max(_time) as lastTime
    values(EventCode) as event_codes
    values(Target_Server_Name) as target_servers
    values(adfs_match) as detection_types
    by Computer Account_Name Logon_Process_Name Source_Network_Address
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime Computer Account_Name Source_Network_Address target_servers detection_types count
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Set/Add/Remove-AdfsRelyingPartyTrust in command line | 90 | Direct modification of ADFS token issuance access controls; highest-risk ADFS admin operation for CVE-2026-56155 |
| Set/Add/Update-AdfsCertificate in command line | 90 | Token-signing key change outside scheduled PKI rotation indicates attacker preparing forged token issuance |
| Set-AdfsGlobalAuthenticationPolicy in command line | 85 | Global auth policy changes can disable access controls across all relying parties |
| Set-AdfsProperties in command line | 85 | Global ADFS property changes affect token lifetime, endpoint availability, and protocol bindings |
| Set/Add/Remove-AdfsClaimsProviderTrust or transform policy | 80 | Claims manipulation enables injection of elevated group memberships into issued tokens |
| Microsoft.IdentityServer.ServiceHost.exe parent process | 90 | ADFS service host spawning admin tools has no benign explanation; confirmed post-exploit execution |
| Explicit credential logon to ADFS service name (4648) | 75 | Unusual use of explicit credentials targeting ADFS service in network context |
| Rapid cmdlet burst (5+ in 120s, same user) | 85 | Scripted ADFS enumeration prior to targeted access control modification |

## Associated Threat Actors

| Actor | Techniques | References |
|-------|-----------|-----------|
| COZY BEAR / APT29 | T1550.001, T1484.002 (Golden SAML operator) | [MITRE ATT&CK G0016](https://attack.mitre.org/groups/G0016/) — known ADFS targeting for federated identity attacks (SolarWinds) |
| SCATTERED SPIDER / Octo Tempest | T1484.002, T1078.002 | [MITRE ATT&CK G1015](https://attack.mitre.org/groups/G1015/) — active targeting of federated identity infrastructure |
| Unattributed (CISA KEV) | T1068, T1484.002 | CVE-2026-56155 added to CISA KEV 2026-07-14 indicating confirmed in-the-wild exploitation |

## References

- [CISA Known Exploited Vulnerabilities Catalog — CVE-2026-56155](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [MITRE ATT&CK T1068 — Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [MITRE ATT&CK T1484.002 — Domain Policy Modification: Domain Trust Modification](https://attack.mitre.org/techniques/T1484/002/)
- [MITRE ATT&CK T1550.001 — Use Alternate Authentication Material: Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
- [MITRE ATT&CK T1078.002 — Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)
- [CWE-1220: Insufficient Granularity of Access Control](https://cwe.mitre.org/data/definitions/1220.html)
- [Microsoft ADFS Security Best Practices — Audit Policy and Monitoring](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/deployment/best-practices-securing-ad-fs)
- [CyberArk: Golden SAML Attack — forging ADFS tokens](https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-services)
