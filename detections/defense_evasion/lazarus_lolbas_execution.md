# Lazarus LOLBAS Execution

## Description

Detects Lazarus Group's extensive use of living-off-the-land binaries and scripts (LOLBAS) for defense evasion. Covers certutil for file decoding/downloading, bitsadmin for file transfer, mshta for script execution, regsvr32 for COM scriptlet execution, rundll32 for proxy execution, wmic for remote process creation, and PowerShell download cradles.

False positive sources: Legitimate administrative usage of these binaries. Tuning: focus on specific command-line argument combinations rather than binary execution alone.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | System Binary Proxy Execution |
| Technique ID | T1218 |
| Secondary Techniques | BITS Jobs (T1197), Ingress Tool Transfer (T1105) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation / Installation |

## Splunk Detection Query

```spl
`crowdstrike`
(Image="*\\certutil.exe" OR Image="*\\bitsadmin.exe" OR Image="*\\mshta.exe"
OR Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe" OR Image="*\\wmic.exe"
OR Image="*\\powershell.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe")
| search
    (ProcessCommandLine="*certutil* -urlcache*" OR ProcessCommandLine="*certutil* -decode*")
    OR (ProcessCommandLine="*bitsadmin* /transfer*")
    OR (ProcessCommandLine="*mshta* http*" OR ProcessCommandLine="*mshta* vbscript:*")
    OR (ProcessCommandLine="*regsvr32* /s /u /i:http*")
    OR (ProcessCommandLine="*rundll32* javascript:*" OR ProcessCommandLine="*rundll32*,a /p:*")
    OR (ProcessCommandLine="*wmic* process call create*" AND ProcessCommandLine="*http*")
    OR (ProcessCommandLine="*powershell*" AND ProcessCommandLine="*downloadstring*" OR ProcessCommandLine="*iex*")
| stats count by ComputerName, Image, ProcessCommandLine, ParentImage, UserName, _time
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Certutil URL cache / decode | High | File download and decoding bypass |
| Bitsadmin transfer | High | Stealthy file download via BITS |
| Mshta remote/script execution | High | Application whitelisting bypass |
| Regsvr32 remote scriptlet | High | Squiblydoo technique |
| Rundll32 JavaScript execution | Critical | Proxy execution for payloads |
| WMIC remote process creation | High | Lateral movement via WMI |
| PowerShell download cradle | High | Remote payload retrieval and execution |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Lazarus Group (HIDDEN COBRA) | [MITRE - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/) |

## References

- [MITRE ATT&CK - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/)
- [LOLBAS Project](https://lolbas-project.github.io/)
- [CISA - HIDDEN COBRA](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-106a)
