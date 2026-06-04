# Windows Netlogon CVE-2026-41089 Domain Controller 0-Click RCE

## Description

Detects post-exploitation indicators of CVE-2026-41089, a CVSS 9.8 stack-based buffer overflow in the Windows Netlogon service enabling unauthenticated 0-click remote code execution on any Windows Server domain controller (Windows Server 2012 R2 through 2025). No credentials, user interaction, or prior access are required — a single specially crafted RPC packet over LSRPC/TCP triggers the overflow.

**Primary detection:** `msimg32.dll` appearing outside its legitimate `C:\Windows\System32\` or `C:\Windows\SysWOW64\` path is a confirmed active IOC in CVE-2026-41089 exploitation campaigns. Attackers plant a malicious copy in an application working directory to achieve DLL sideloading persistence post-exploitation.

**Supplemental detection:** Repeated Netlogon service crashes (Windows System Event IDs 7031/7034) on a domain controller may indicate active exploitation probing or failed exploit attempts.

False positives: `msimg32.dll` can legitimately appear in application directories for certain legacy software (older Adobe products, some Office add-ins). Investigate the creating process before escalating; any creation from `lsass.exe`, `svchost.exe`, network service processes, or immediately following anomalous Netlogon traffic is high-fidelity.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access, Privilege Escalation, Defense Evasion |
| Tactic ID | TA0001, TA0004, TA0005 |
| Technique | Exploit Public-Facing Application; Hijack Execution Flow: DLL Side-Loading |
| Technique ID | T1190, T1574.002 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_name="msimg32.dll"
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_guid
| `drop_dm_object_name(Filesystem)`
| where NOT (file_path LIKE "%\\Windows\\System32\\%" OR file_path LIKE "%\\Windows\\SysWOW64\\%")
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    1=1, 90)
| where risk_score >= 90
| table firstTime lastTime dest user file_path file_name process_guid risk_score
```

Supplemental — Netlogon service crash detection (Windows System Event Log):

```spl
`wineventlog_system` (EventCode=7031 OR EventCode=7034) service_name="Netlogon"
| stats count min(_time) as firstTime max(_time) as lastTime values(EventCode) as event_codes by dest service_name
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    count >= 3, 80,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest service_name event_codes count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `msimg32.dll` written outside System32/SysWOW64 | 90 | High-confidence post-exploitation IOC confirmed in active CVE-2026-41089 campaigns; legitimate applications rarely write this DLL to arbitrary paths |
| Netlogon service crash (1–2 occurrences) | 60 | May indicate exploitation probe, failed exploit attempt, or unrelated service instability |
| Netlogon service crash (3+ occurrences) | 80 | Pattern of repeated crashes strongly suggests active exploitation campaign against this domain controller |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (multiple post-disclosure opportunistic actors) | [Microsoft MSRC — CVE-2026-41089](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-41089) |
| Ransomware Affiliates (historical Netlogon / ZeroLogon precedent) | [CISA — ZeroLogon Alert AA20-283A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-283a) |
| Iran-linked APTs (historical Netlogon exploitation: IRGC, MuddyWater) | [NSA/CISA — CVE-2020-1472 Advisory](https://media.defense.gov/2020/Sep/18/2002497236/-1/-1/0/CSA_ZEROLOGON_UOO224904-20.PDF) |

## References

- [BleepingComputer — CVE-2026-41089 Actively Exploited (2026-06-01)](https://www.bleepingcomputer.com/news/microsoft/critical-windows-netlogon-remote-code-execution-flaw-now-exploited-in-attacks/)
- [Help Net Security — Netlogon RCE Exploited CVE-2026-41089 (2026-06-01)](https://www.helpnetsecurity.com/2026/06/01/windows-netlogon-rce-exploited-cve-2026-41089/)
- [Microsoft MSRC — CVE-2026-41089](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-41089)
- [MITRE ATT&CK — T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1574.002: Hijack Execution Flow: DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
