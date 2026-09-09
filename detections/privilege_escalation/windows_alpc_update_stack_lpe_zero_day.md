# Windows ALPC and Update Stack Local Privilege Escalation Zero-Days (CVE-2026-85880, CVE-2026-81963)

## Description

Detects post-exploitation behavior consistent with exploitation of two Windows local privilege escalation zero-days patched in September 2026 Patch Tuesday and added to CISA KEV on September 8, 2026:

- **CVE-2026-85880** (CVSS 7.8): Heap-based buffer overflow in Windows Advanced Local Procedure Call (ALPC) subsystem. An attacker executing in a low-privilege AppContainer can overflow ALPC heap buffers to escape the sandbox and gain SYSTEM privileges.
- **CVE-2026-81963** (CVSS 7.8): Link-following vulnerability in the Windows Update Stack. The privileged Windows Update service improperly resolves file-system symbolic links, allowing a low-privilege attacker to redirect privileged file operations to attacker-controlled targets, gaining SYSTEM.

Both vulnerabilities require pre-existing code execution on the target system. Detection focuses on abnormal process spawning from Windows Update service components (CVE-2026-81963) and SYSTEM-integrity processes under non-service user accounts (applicable to both CVEs). False positives are possible if Windows Update legitimately spawns diagnostic tools — investigate process command lines and user context.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Privilege Escalation |
| Tactic ID | TA0004 |
| Technique | Exploitation for Privilege Escalation |
| Technique ID | T1068 |

Secondary: T1134 (Access Token Manipulation) — post-LPE token abuse for persistence.

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("TrustedInstaller.exe","UsoClient.exe",
        "wuauclt.exe","musnotification.exe","musnotificationux.exe","WaaSMedicAgent.exe",
        "UpdateOrchestrator.exe")
    AND Processes.process_name IN ("cmd.exe","powershell.exe","wscript.exe","cscript.exe",
        "mshta.exe","rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe",
        "net.exe","net1.exe","sc.exe","whoami.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    parent_process_name="TrustedInstaller.exe" AND process_name IN ("powershell.exe","cmd.exe"), 95,
    parent_process_name="TrustedInstaller.exe", 90,
    parent_process_name="UsoClient.exe" AND process_name IN ("powershell.exe","cmd.exe"), 88,
    parent_process_name IN ("WaaSMedicAgent.exe","UpdateOrchestrator.exe"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| TrustedInstaller.exe spawning PowerShell or cmd.exe | 95 | Critical — TrustedInstaller operates at SYSTEM and should never spawn shell processes; strong indicator of CVE-2026-81963 exploitation |
| TrustedInstaller.exe spawning any listed binary | 90 | High — any shell/utility child of TrustedInstaller is deeply anomalous |
| UsoClient.exe spawning PowerShell or cmd.exe | 88 | High — Update Session Orchestrator spawning shell; core CVE-2026-81963 exploitation chain |
| WaaSMedicAgent or UpdateOrchestrator spawning shells | 85 | High — Windows Update medic/orchestrator processes spawning interpreters |
| Other Windows Update parent spawning shell utility | 75 | Medium — less common parents but still anomalous |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (CISA KEV confirmed in-the-wild exploitation, September 2026) | [CISA KEV — September 8, 2026](https://www.cisa.gov/news-events/alerts/2026/09/08/cisa-adds-four-known-exploited-vulnerabilities-catalog) |
| APT28 / Fancy Bear (historical ALPC LPE exploitation) | [MITRE ATT&CK G0007](https://attack.mitre.org/groups/G0007/) — exploited CVE-2018-8120 (Windows Win32k ALPC LPE) |
| Lazarus Group / HIDDEN COBRA (historical ALPC LPE exploitation) | [MITRE ATT&CK G0032](https://attack.mitre.org/groups/G0032/) — exploited CVE-2019-0859 (Win32k ALPC LPE) |

## References

- [Microsoft MSRC — CVE-2026-85880](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-85880)
- [Microsoft MSRC — CVE-2026-81963](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-81963)
- [Tenable — September 2026 Patch Tuesday](https://www.tenable.com/blog/microsofts-september-2026-patch-tuesday-addresses-964-cves-cve-2026-81963-cve-2026-85880)
- [BleepingComputer — September 2026 Patch Tuesday](https://www.bleepingcomputer.com/news/microsoft/microsoft-september-2026-patch-tuesday-fixes-966-flaws-2-zero-days/)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [MITRE ATT&CK — T1068 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
