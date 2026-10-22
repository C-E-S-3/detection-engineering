---
scraped_at: "2026-10-22T00:00:00Z"
source_url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a"
report_type: threat-intel
severity: critical
title: "#StopRansomware: SafePay Ransomware — 600+ Victims, Multi-Agency Advisory AA26-293A"
---

## 1. IOCs

### Domains

No network infrastructure domains publicly confirmed in secondary coverage. Authoritative IOCs (Tables 2–5 in the advisory) are available as STIX XML/JSON from the CISA advisory page; retrieve from https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a.

### IPs

No specific IP addresses confirmed in secondary coverage. The advisory reportedly lists nine IP addresses in machine-readable STIX format; retrieve from the CISA advisory page.

> **Note:** SafePay threat actors are reported to route through **Mullvad VPN** exit nodes for initial access, making source IP blocking insufficient. Defenders should alert on Mullvad ASN ranges (AS39351 — Lunaticmedia) in VPN authentication logs rather than specific IPs.

### Hashes

No file hashes confirmed in secondary coverage. Machine-readable STIX from CISA is the authoritative source.

### Exploited Vulnerabilities

| CVE | Product | CVSS | Description |
|-----|---------|------|-------------|
| CVE-2020-3259 | Cisco ASA / FTD | 7.5 | Information disclosure leaking VPN session credentials |
| CVE-2023-20269 | Cisco ASA / FTD VPN | 5.0 | Remote access VPN brute-force enabling unauthorized access |
| CVE-2023-27532 | Veeam Backup & Replication | 7.5 | Unauthenticated credential extraction from configuration database |
| CVE-2024-40711 | Veeam Backup & Replication | 9.8 | Unauthenticated RCE via .NET deserialization; chained with CVE-2023-27532 |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1133 | External Remote Services | VPN access gained via credential exposure, brute force, or exploiting Cisco ASA/Veeam vulnerabilities |
| Initial Access | T1110 | Brute Force | Password spray / brute force against VPN and RDP authentication portals |
| Initial Access | T1190 | Exploit Public-Facing Application | Active exploitation of CVE-2020-3259, CVE-2023-20269, CVE-2023-27532, CVE-2024-40711 |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | PowerShell used throughout intrusion for discovery and lateral movement |
| Execution | T1072 | Software Deployment Tools | PsExec used for remote command execution across compromised hosts |
| Discovery | T1135 | Network Share Discovery | ShareFinder.ps1 (from PowerSploit/PowerView) used to enumerate Active Directory file shares for ransomware target identification |
| Discovery | T1069.002 | Permission Groups Discovery: Domain Groups | Active Directory enumeration to identify administrative accounts and groups |
| Privilege Escalation | T1136.001 | Create Account: Local Account | New administrative accounts created using built-in Windows administrative tools to maintain persistence and escalate privileges |
| Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | PsExec and equivalent tools used to execute ransomware payload across discovered network shares |
| Lateral Movement | T1570 | Lateral Tool Transfer | Ransomware payload and tools copied to discovered shares prior to detonation |
| Impact | T1490 | Inhibit System Recovery | Shadow copies deleted; NAS devices factory-reset; backup agent processes (Veeam, Windows Server Backup) terminated prior to encryption |
| Impact | T1486 | Data Encrypted for Impact | File encryption with SafePay ransomware payload |

**Pre-Encryption Attack Chain:**
1. Initial access via compromised VPN credentials (brute force, phishing, Cisco/Veeam CVE exploitation)
2. Anonymize via Mullvad VPN exit nodes
3. Elevate privileges; create new local admin accounts if needed
4. Run ShareFinder.ps1 via PowerShell to enumerate AD file shares
5. Lateral movement via PsExec to spread across discovered shares
6. Terminate backup agents; delete shadow copies; factory-reset NAS devices
7. Deploy ransomware payload via SMB admin shares to maximize encryption scope

---

## 3. Malware & Tools

| Tool / Malware | Type | Notes |
|----------------|------|-------|
| SafePay Ransomware | Ransomware | Active since August 2024; 600+ confirmed victims as of August 2026; operates a data-leak extortion site |
| ShareFinder.ps1 | PowerShell Recon Script | From PowerSploit/PowerView; enumerates accessible SMB shares across AD-joined hosts |
| PsExec | Legitimate Admin Tool | Microsoft Sysinternals; abused for remote command execution and ransomware staging |
| PowerShell | Built-in Interpreter | Used throughout intrusion lifecycle |

---

## 4. Threat Actor / Campaign Attribution

**Actor:** SafePay (ransomware group / RaaS operation)

- **Active since:** August 2024
- **Victim count:** 600+ organizations worldwide as of August 2026
- **Impacted sectors:** Multiple critical infrastructure sectors; not limited to specific verticals
- **Governments involved in advisory:** FBI, CISA, U.S. Secret Service (USSS), Landeskriminalamt Rheinland-Pfalz (Germany), and UK partners
- **Leak site:** Operates a data-leak extortion site; confirms victims before/after encryption
- **No ransomware-as-a-service (RaaS) affiliation:** SafePay appears to operate independently rather than as an affiliate program

**Note:** No formal MITRE ATT&CK group designation (Gxxxx) is currently assigned to SafePay.

---

## 5. Splunk Detection Searches

```spl
| comment "SafePay Detection 1: ShareFinder.ps1 AD share enumeration — pre-ransomware recon (T1135, T1059.001)"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name IN ("powershell.exe","pwsh.exe"))
    AND (Processes.process IN ("*ShareFinder*","*Invoke-ShareFinder*","*Get-NetFileServer*","*Find-DomainShare*"))
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)invoke-sharefinder"), 90,
    match(process,"(?i)sharefinder|find-domainshare"), 85,
    match(process,"(?i)get-netfileserver"), 80,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| comment "SafePay Detection 2: Shadow copy deletion — pre-ransomware backup destruction (T1490)"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name IN ("vssadmin.exe","wmic.exe","wbadmin.exe","bcdedit.exe"))
    AND (Processes.process IN ("*delete*shadow*","*shadowcopy*delete*","*delete*catalog*","*recoveryenabled*no*","*ignorefailures*yes*"))
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)delete.*shadow|shadowcopy.*delete"), 95,
    match(process,"(?i)delete.*catalog|recoveryenabled.*no"), 85,
    1=1, 80)
| where risk_score >= 80
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| comment "SafePay Detection 3: Backup agent process termination — Veeam and Windows Backup killed pre-encryption (T1490)"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name IN ("net.exe","net1.exe","taskkill.exe","sc.exe"))
    AND (Processes.process IN ("*stop*veeam*","*stop*backup*","*stop*vss*","*VeeamBackup*","*/IM*VeeamAgent*","*wbengine*"))
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)veeam"), 85,
    match(process,"(?i)wbengine|windows.*backup"), 80,
    match(process,"(?i)vss|volume.*shadow"), 80,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| comment "SafePay Detection 4: PsExec lateral movement for ransomware staging — remote execution via SMB (T1021.002, T1570)"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name IN ("psexec.exe","psexec64.exe","PsExec.exe"))
    OR (Processes.parent_process_name IN ("psexec.exe","psexec64.exe")
        AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","mshta.exe","wscript.exe","cscript.exe"))
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    parent_process_name IN ("psexec.exe","psexec64.exe"), 80,
    match(process,"(?i)-s|-accepteula|-d"), 75,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

---

## 6. Executive Summary

On October 20, 2026, the FBI, CISA, U.S. Secret Service, and partner agencies in Germany and the United Kingdom issued joint advisory AA26-293A warning that SafePay ransomware has compromised at least 600 organizations worldwide since August 2024. The group gains initial access by exploiting exposed VPN services — primarily via brute-force attacks and exploitation of Cisco ASA (CVE-2020-3259, CVE-2023-20269) and Veeam Backup & Replication (CVE-2023-27532, CVE-2024-40711) vulnerabilities — while routing through Mullvad VPN to anonymize traffic.

Once inside, operators use PowerShell and ShareFinder.ps1 to enumerate Active Directory file shares and identify high-value targets, then move laterally via PsExec. Critically, before deploying ransomware, SafePay actors destroy backup infrastructure: shadow copies are deleted, backup agents terminated, and NAS devices factory-reset to eliminate recovery options.

**Recommended immediate actions:**
- Patch Cisco ASA/FTD (CVE-2020-3259, CVE-2023-20269) and Veeam Backup & Replication (CVE-2023-27532, CVE-2024-40711)
- Enforce MFA on all VPN authentication portals
- Alert on Mullvad VPN ASN (AS39351) in authentication logs
- Enable detection for ShareFinder.ps1 / PowerView usage
- Deploy offline or air-gapped backup copies inaccessible from the production network
- Monitor for shadow copy deletion and backup agent termination outside of maintenance windows

---

## References

- [CISA Advisory AA26-293A — #StopRansomware: SafePay Ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a)
- [IC3 CSA 261020 — StopRansomware: SafePay Ransomware (PDF)](https://www.ic3.gov/CSA/2026/261020.pdf)
- [CISA/FBI Advisory Press Release](https://www.cisa.gov/news-events/news/cisa-fbi-and-partners-warn-organizations-safepay-ransomware-actors-targeting-multiple-critical)
- [CVE-2024-40711 — Veeam Backup & Replication Unauthenticated RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-40711)
- [CVE-2023-27532 — Veeam Backup & Replication Credential Disclosure](https://nvd.nist.gov/vuln/detail/CVE-2023-27532)
- [MITRE ATT&CK T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [MITRE ATT&CK T1135 — Network Share Discovery](https://attack.mitre.org/techniques/T1135/)
