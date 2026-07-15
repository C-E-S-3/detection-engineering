# AD FS Local Privilege Escalation (CVE-2026-56155)

## Description

Detects post-exploitation privilege escalation on Active Directory Federation Services (AD FS) servers via CVE-2026-56155 (CVSS 7.8, CWE: Insufficient Granularity of Access Control). An authenticated local user on an ADFS server exploits an access control weakness to elevate to administrative privileges. Added to CISA KEV on July 14, 2026 with confirmed in-the-wild exploitation.

This detection targets process activity on ADFS hosts that is consistent with privilege escalation post-exploit: command interpreters or discovery tools spawning under ADFS service processes, and local group membership modification commands executed in the ADFS server context. Because the attack vector is local, adversary presence on the ADFS host already represents a significant breach.

False positive sources: legitimate ADFS administrators running diagnostic PowerShell sessions, Microsoft-automated maintenance tasks on ADFS servers.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Privilege Escalation |
| Tactic ID | TA0004 |
| Technique | Exploitation for Privilege Escalation |
| Technique ID | T1068 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where (Processes.parent_process_name IN ("adfssrv.exe", "Microsoft.IdentityServer.ServiceHost.exe")
    AND Processes.process_name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "net.exe", "net1.exe",
        "whoami.exe", "wmic.exe", "nltest.exe", "dsquery.exe", "reg.exe"))
  OR (Processes.process IN ("*localgroup*administrators*", "*net user*", "*Add-LocalGroupMember*")
    AND Processes.dest_category="ad_fs_server")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)localgroup.{0,30}administrators") OR match(process, "(?i)Add-LocalGroupMember"), 95,
    parent_process_name IN ("adfssrv.exe", "Microsoft.IdentityServer.ServiceHost.exe")
        AND process_name IN ("cmd.exe", "powershell.exe", "pwsh.exe"), 85,
    parent_process_name IN ("adfssrv.exe", "Microsoft.IdentityServer.ServiceHost.exe"), 70,
    1=1, 55)
| where risk_score >= 55
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Local admin group modification on ADFS host | 95 | Direct indicator of privilege escalation completion; adversary adding account to local Administrators |
| ADFS service process spawning a command interpreter | 85 | ADFS service processes should never directly spawn cmd/PowerShell; strongly anomalous |
| ADFS service process spawning any unexpected child | 70 | Broad catch for post-exploit reconnaissance from ADFS process context |
| Local discovery commands matching ADFS server context | 55 | Lower confidence; correlate with other events on ADFS host |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (actively exploited, CISA KEV July 14, 2026) | [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |

## References

- [Tenable — Microsoft July 2026 Patch Tuesday (2026-07-14)](https://www.tenable.com/blog/microsofts-july-2026-patch-tuesday-addresses-569-cves-cve-2026-56155-cve-2026-56164)
- [CISA KEV — CVE-2026-56155](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Microsoft Security Update Guide — July 2026](https://msrc.microsoft.com/update-guide/)
- [MITRE ATT&CK T1068](https://attack.mitre.org/techniques/T1068/)
