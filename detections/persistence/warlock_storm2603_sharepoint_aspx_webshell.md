# Warlock / Storm-2603: SharePoint ASPX Web Shell Deployment

## Description

Detects ASPX web shells deployed to SharePoint or IIS directories, specifically the file names used by the Storm-2603 (Warlock) threat actor: `spinstall0.aspx` and `layout2sp.aspx`. The detection also covers the broader pattern of any ASPX file written to IIS/SharePoint web roots by non-administrative processes, which is a common persistence mechanism for China-nexus actors exploiting SharePoint CVEs (CVE-2025-53770, CVE-2026-45659, CVE-2026-50522, CVE-2026-56164).

False positives: Developers legitimately deploying ASPX pages to IIS; SharePoint farm administrators publishing custom pages. Tune by excluding known software deployment accounts and CI/CD service accounts. The specific file names `spinstall0.aspx` and `layout2sp.aspx` have no legitimate use and should always alert.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Persistence |
| Tactic ID | TA0003 |
| Technique | Server Software Component: Web Shell |
| Technique ID | T1505.003 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where (Filesystem.file_name IN ("spinstall0.aspx","layout2sp.aspx")
      OR (Filesystem.file_name="*.aspx"
          AND Filesystem.file_path IN ("*\\inetpub\\wwwroot\\*",
                                       "*\\SharePoint\\*",
                                       "*/inetpub/wwwroot/*",
                                       "*/sharepoint/*")))
  by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_name,"(?i)(spinstall0|layout2sp)\.aspx"), 98,
    match(file_path,"(?i)(wwwroot|sharepoint)") AND match(file_name,"\.aspx$")
      AND NOT match(user,"(?i)(deploy|ci|svc|sharepoint_farm|iis_iusrs)"), 75,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime dest user process_name file_name file_path risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("w3wp.exe","svchost.exe")
    AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe",
        "certutil.exe","bitsadmin.exe","mshta.exe","regsvr32.exe","rundll32.exe","net.exe","net1.exe",
        "whoami.exe","ipconfig.exe","nltest.exe","systeminfo.exe","tasklist.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)(-enc|-encodedcommand|IEX|FromBase64String|DownloadString|DownloadFile)"), 95,
    match(process_name,"(?i)(certutil|bitsadmin|mshta|regsvr32|rundll32)"), 90,
    match(process_name,"(?i)(whoami|ipconfig|nltest|systeminfo|tasklist)"), 75,
    match(process_name,"(?i)(cmd|powershell|pwsh)"), 80,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| File named spinstall0.aspx or layout2sp.aspx created anywhere | 98 | Known-bad Storm-2603 web shell names; no legitimate use |
| ASPX written to IIS/SharePoint web root by non-service account | 75 | Strong indicator of web shell deployment; legitimate deployments use service accounts |
| IIS worker (w3wp.exe) spawning encoded PowerShell or download cradle | 95 | Post-exploitation via web shell; near-certain malicious activity |
| IIS worker spawning certutil, bitsadmin, mshta, regsvr32, or rundll32 | 90 | Living-off-the-land via web shell; no legitimate IIS use for these binaries |
| IIS worker spawning reconnaissance commands (whoami, ipconfig, nltest) | 75 | Operator reconnaissance via web shell |
| IIS worker spawning cmd.exe or PowerShell (no additional context) | 80 | Suspicious; some legitimate SharePoint customizations may trigger; review required |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Storm-2603 / Gold Salem / Longlegs (Warlock) | [MITRE ATT&CK — G1xxx (Storm-2603)](https://attack.mitre.org/groups/), [Symantec/Broadcom Bulletin](https://www.broadcom.com/support/security-center/protection-bulletin/warlock-ransomware-targets-water-and-telecom-operators), [IMDA Advisory](https://www.imda.gov.sg/-/media/imda/files/regulations-and-licensing/regulations/advisories/infocomm-media-cyber-security/storm-2603-exploits-sharepoint-vulnerabilities-to-deliver-backdoor-and-warlock-ransomware.pdf) |
| Multiple China-nexus actors | CVE-2025-53770 (ToolShell) was exploited by multiple state-sponsored groups targeting SharePoint |

## References

- [Rewterz — SharePoint 0-Day Exploited to Deploy Warlock Ransomware](https://rewterz.com/threat-advisory/sharepoint-0-day-exploited-to-deploy-warlock-ransomware-active-iocs)
- [Symantec/Broadcom — Warlock Ransomware Targets Water and Telecom Operators](https://www.broadcom.com/support/security-center/protection-bulletin/warlock-ransomware-targets-water-and-telecom-operators)
- [CyberPress — Warlock Attackers Abuse Vulnerable Driver to Disable Security Tools](https://cyberpress.org/warlock-ransomware-sharepoint/)
- [Microsoft — Disrupting Active Exploitation of On-Premises SharePoint Vulnerabilities](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/)
- [MITRE ATT&CK — T1505.003 Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
