---
scraped_at: "2026-07-10T08:30:00Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/recovering-active-adfs-signing-keys-machine-dpapi"
report_type: threat-intel
severity: high
title: "The Ghost in the Database: Recovering Active ADFS Signing Keys via Machine DPAPI"
---

## 1. IOCs

### File System Paths (Attack Artifacts)

| Type | Indicator | Context |
|------|-----------|---------|
| Directory | `C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\` | ADFS active token-signing RSA private key blobs stored here when AutoCertificateRollover is disabled |
| Directory | `C:\Windows\System32\Microsoft\Protect\S-1-5-18\` | Machine-scoped DPAPI masterkeys; decryptable via DPAPI_SYSTEM LSA secret |
| Tool | `SharpDPAPI /machine` | Offensive tool used to decrypt machine-scoped DPAPI key material and extract ADFS signing keys |

### Windows Event IDs (Detection Indicators)

| Event ID | Source | Context |
|----------|--------|---------|
| 385 | ADFS / AD FS Admin | ADFS configuration-to-runtime certificate mismatch ("ghost" condition indicator) — fires when WID config cert differs from the active machine-scoped signing cert |
| 4663 | Security | Object access on `MachineKeys\` or `S-1-5-18\` directories (requires SACL configuration) |
| 299 | ADFS / AD FS Admin | Token issuance event — correlate with Entra ID sign-in to detect token forgery |

### No Network-Based IOCs

This is a technique disclosure from a Mandiant red team engagement. No threat-actor-attributed IPs, domains, or file hashes were published.

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|--------------|----------------|-------|
| Credential Access | TA0006 / T1003 | OS Credential Dumping | Attacker with SYSTEM on ADFS host extracts the DPAPI_SYSTEM LSA secret and decrypts machine masterkeys to recover the active ADFS token-signing private key |
| Credential Access | TA0006 / T1552.004 | Unsecured Credentials: Private Keys | Active ADFS token-signing private key stored as an RSA key blob in MachineKeys\ under machine DPAPI protection, accessible to SYSTEM without touching LSASS |
| Defense Evasion | TA0005 / T1070 | Indicator Removal | Technique avoids LSASS access and live ADFS process injection — bypasses most ADFS credential theft detections designed around WID/DKM extraction |
| Lateral Movement / Impact | TA0008 / T1550.003 | Use Alternate Authentication Material: SAML Tokens | Recovered signing key enables forging SAML assertions for any user, bypassing MFA and Conditional Access across all relying party trusts including Microsoft 365 / Entra ID |

---

## 3. Malware & Tools

| Tool | Type | Notes |
|------|------|-------|
| SharpDPAPI | Offensive / Pentesting | .NET DPAPI offline decryption tool; `/machine` flag targets machine-scoped masterkeys using `DPAPI_SYSTEM` LSA secret; published by Will Schroeder (harmj0y) |

---

## 4. Threat Actor / Campaign Attribution

- **Discovery context:** Mandiant red team engagement (unrestricted scope)
- **No attributed threat actor:** This is technique research, not an incident report
- **Technique lineage:** Extends "Golden SAML" (CyberArk 2017) and Mandiant's 2021 ADFS network replication secret theft research
- **Relevance:** Any post-exploitation adversary with SYSTEM access on an ADFS host can leverage this; particularly relevant to China-nexus actors (e.g., COZY BEAR, UNC3886) known to target AD infrastructure and federated identity systems

---

## 5. Splunk Detection Searches

```spl
| comment "Detect SharpDPAPI execution or access to machine DPAPI paths used in ADFS signing key theft"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="SharpDPAPI.exe" OR Processes.process="*sharpdpapi*" OR Processes.process="*/machine*" OR
         (Processes.process_name IN ("powershell.exe","cmd.exe","wmic.exe") AND
          Processes.process IN ("*MachineKeys*","*Protect\\S-1-5-18*","*dpapi_system*","*DPAPI_SYSTEM*")))
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
     Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name,"(?i)sharpdpapi")                         , 90,
    match(process,"(?i)(MachineKeys|Protect\\\\S-1-5-18)")       , 80,
    1=1                                                          , 60)
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| comment "Detect file system access to ADFS Machine DPAPI paths via Windows Security Event 4663 (requires SACL on directories)"
| index=wineventlog EventCode=4663
  (Object_Name="*\\Microsoft\\Crypto\\RSA\\MachineKeys\\*" OR Object_Name="*\\Protect\\S-1-5-18\\*")
  NOT (Process_Name="*lsass.exe" OR Process_Name="*services.exe" OR Process_Name="*svchost.exe")
| eval risk_score=case(
    like(Object_Name,"%Protect\\S-1-5-18%") AND like(Object_Name,"%.key%"), 90,
    like(Object_Name,"%MachineKeys%"), 85,
    1=1, 70)
| where risk_score >= 70
| stats count min(_time) as firstTime max(_time) as lastTime
    values(Object_Name) as accessed_paths
    by Computer Subject_Account_Name Process_Name Accesses risk_score
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime Computer Subject_Account_Name Process_Name accessed_paths Accesses risk_score
```

```spl
| comment "Detect ADFS ghost certificate condition via Event ID 385 — indicates AutoCertificateRollover drift enabling this attack path"
| index=wineventlog EventCode=385 source="AD FS"
| stats count min(_time) as firstTime max(_time) as lastTime by host Message
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime host Message count
```

```spl
| comment "Detect potential SAML token forgery — Entra ID sign-in without correlated ADFS issuance event (Event IDs 299/411)"
`o365`
| search Workload=AzureActiveDirectory Operation="UserLoggedIn"
    AuthenticationDetails{}.authenticationMethod="SAML"
    ResultType=0
| eval signin_time=_time, signin_user=UserId, signin_ip=ClientIP
| join type=left signin_user [
    index=wineventlog EventCode IN (299,411) source="AD FS"
    | rex field=Message "(?i)caller identity:\s*(?<adfs_user>[^\r\n]+)"
    | stats max(_time) as adfs_issuance_time by adfs_user
    | rename adfs_user as signin_user]
| where isnull(adfs_issuance_time) OR (signin_time - adfs_issuance_time) > 300
| eval risk_score=90
| table _time signin_user signin_ip adfs_issuance_time risk_score
```

---

## 6. Executive Summary

Mandiant researchers disclosed a post-exploitation technique for recovering active ADFS token-signing private keys via Windows Machine DPAPI — specifically targeting environments where `AutoCertificateRollover` is disabled and certificates were manually rotated without updating the ADFS WID configuration database. In this "ghost certificate" condition, the active signing key resides in the machine cryptographic store (`C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\`) rather than the WID/DKM-backed location that standard ADFS extraction tools target.

An attacker with SYSTEM-level code execution on the ADFS host can:
1. Extract the `DPAPI_SYSTEM` LSA secret
2. Decrypt machine masterkeys from `C:\Windows\System32\Microsoft\Protect\S-1-5-18\`
3. Recover the active RSA token-signing private key
4. Forge SAML assertions impersonating any user — including Global Administrators — that are accepted as valid by Microsoft Entra ID

The technique bypasses LSASS, live ADFS process injection, and WID/DKM-based extraction methods — making it invisible to most existing ADFS credential theft detections. The tool demonstrated was SharpDPAPI with the `/machine` parameter.

**Severity: High.** Requires prior SYSTEM-level access on the ADFS host (Tier 0 infrastructure), but the payoff is persistent, undetectable identity impersonation across all federated services. Organizations should audit ADFS certificate state (`Get-AdfsCertificate`), monitor for Event ID 385, configure SACLs on the affected directories, and consider migrating ADFS signing certificates to HSMs.

---

## References

- [Mandiant: The 'Ghost' in the Database: Recovering Active ADFS Signing Keys via Machine DPAPI](https://cloud.google.com/blog/topics/threat-intelligence/recovering-active-adfs-signing-keys-machine-dpapi)
- [MITRE ATT&CK T1550.003 — Use Alternate Authentication Material: SAML Tokens](https://attack.mitre.org/techniques/T1550/003/)
- [MITRE ATT&CK T1003 — OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [MITRE ATT&CK T1552.004 — Unsecured Credentials: Private Keys](https://attack.mitre.org/techniques/T1552/004/)
- [CyberArk: Golden SAML (2017)](https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-services)
- [Microsoft: ADFS Certificate Rotation](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/manage-ssl-certificates-ad-fs-wap)
- [harmj0y/SharpDPAPI on GitHub](https://github.com/GhostPack/SharpDPAPI)
