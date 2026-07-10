# ADFS Token-Signing Key Extraction via Machine DPAPI

## Description

Detects attempts to recover Active Directory Federation Services (ADFS) token-signing private keys through Windows Machine DPAPI — a post-exploitation technique enabling Golden SAML attacks. When `AutoCertificateRollover` is disabled and certificates are manually rotated without updating the ADFS WID configuration, the active signing key resides in `C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\` under machine-scoped DPAPI protection. An attacker with SYSTEM-level access can extract the `DPAPI_SYSTEM` LSA secret, decrypt machine masterkeys from `C:\Windows\System32\Microsoft\Protect\S-1-5-18\`, and recover the private key — enabling forged SAML assertions that impersonate any user including Global Administrators across all relying party trusts (Microsoft 365, Entra ID, etc.).

This technique bypasses standard ADFS credential theft detections that target LSASS, the live ADFS process, or WID/DKM extraction paths. The "ghost certificate" condition (Windows Event ID 385) is a prerequisite indicator.

**False positives:** Legitimate DPAPI operations by ADFS service accounts; security tooling (Volatility, AD forensics suites) running authorized assessments; administrative access to MachineKeys by PKI/CA admins.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | OS Credential Dumping |
| Technique ID | T1003 |
| Secondary Technique | Unsecured Credentials: Private Keys |
| Secondary Technique ID | T1552.004 |
| Resulting Technique | Use Alternate Authentication Material: SAML Tokens |
| Resulting Technique ID | T1550.003 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="SharpDPAPI.exe"
      OR (Processes.process="*sharpdpapi*" AND Processes.process="*/machine*")
      OR (Processes.process_name IN ("powershell.exe","cmd.exe","wmic.exe","rundll32.exe")
          AND (Processes.process="*MachineKeys*"
            OR Processes.process="*Protect\\S-1-5-18*"
            OR Processes.process="*dpapi_system*"
            OR Processes.process="*DPAPI_SYSTEM*")))
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name,"(?i)^sharpdpapi")                              , 90,
    match(process,"(?i)sharpdpapi.*(/machine|--machine)")              , 90,
    match(process,"(?i)Protect\\\\S-1-5-18")                          , 85,
    match(process,"(?i)MachineKeys")                                   , 80,
    match(process,"(?i)dpapi_system")                                  , 85,
    1=1                                                                , 60)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| comment "Secondary detection: file object access on ADFS Machine DPAPI directories (requires SACL on MachineKeys\ and Protect\S-1-5-18\)"
index=wineventlog EventCode=4663
    (Object_Name="*\\Microsoft\\Crypto\\RSA\\MachineKeys\\*"
  OR Object_Name="*\\Microsoft\\Protect\\S-1-5-18\\*")
    NOT Process_Name IN ("*\\lsass.exe","*\\services.exe","*\\svchost.exe",
                         "*\\cryptsvc.dll","*\\dphost.exe","*\\wlms.exe")
| eval risk_score=case(
    like(Object_Name,"%Protect\\S-1-5-18%"), 85,
    like(Object_Name,"%MachineKeys%")       , 80,
    1=1                                     , 70)
| where risk_score >= 75
| stats count min(_time) as firstTime max(_time) as lastTime
    values(Object_Name) as accessed_paths
    by Computer Subject_Account_Name Process_Name Accesses risk_score
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime Computer Subject_Account_Name Process_Name accessed_paths Accesses risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| SharpDPAPI.exe process name | 90 | Offensive tool with no legitimate administrative use; named binary indicates attacker tooling |
| SharpDPAPI with /machine flag in cmdline | 90 | Explicit targeting of machine-scoped DPAPI; no legitimate admin workflow requires this flag against ADFS paths |
| Access to `Protect\S-1-5-18\` by non-system process | 85 | Machine DPAPI masterkey store; should only be accessed by SYSTEM during normal operation |
| Reference to `DPAPI_SYSTEM` string in command | 85 | LSA secret name used to decrypt machine masterkeys; no benign PowerShell workflow references this string |
| Access to `MachineKeys\` by non-PKI process | 80 | Broad but high-value path; legitimate access limited to Crypto API, IIS, and CA services |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Mandiant Red Team (technique discovery) | [Google TI Blog](https://cloud.google.com/blog/topics/threat-intelligence/recovering-active-adfs-signing-keys-machine-dpapi) |
| COZY BEAR / APT29 | [MITRE ATT&CK G0016](https://attack.mitre.org/groups/G0016/) — known Golden SAML user (SolarWinds) |
| SCATTERED SPIDER / Octo Tempest | [MITRE ATT&CK G1015](https://attack.mitre.org/groups/G1015/) — known to target federated identity infrastructure |

## References

- [Mandiant: The 'Ghost' in the Database: Recovering Active ADFS Signing Keys via Machine DPAPI (July 7, 2026)](https://cloud.google.com/blog/topics/threat-intelligence/recovering-active-adfs-signing-keys-machine-dpapi)
- [MITRE ATT&CK T1003 — OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [MITRE ATT&CK T1552.004 — Unsecured Credentials: Private Keys](https://attack.mitre.org/techniques/T1552/004/)
- [MITRE ATT&CK T1550.003 — Use Alternate Authentication Material: SAML Tokens](https://attack.mitre.org/techniques/T1550/003/)
- [CyberArk: Golden SAML Attack (2017)](https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-services)
- [GhostPack/SharpDPAPI on GitHub](https://github.com/GhostPack/SharpDPAPI)
