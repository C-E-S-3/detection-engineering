# Lazarus Multi-Technique EDR Detection

## Description

Broad detection for Lazarus Group TTPs via CrowdStrike EDR covering multiple execution techniques: DLL sideloading from non-standard paths, certutil abuse for decoding/downloading, rundll32 JavaScript/proxy execution, mshta script execution, regsvr32 squiblydoo, and suspicious screensaver (.scr) execution. This rule covers a wide surface of known Lazarus tooling.

False positive sources: Legitimate use of certutil for certificate management, rundll32 for Control Panel items, regsvr32 for COM registration. Tuning: whitelist specific known-good command patterns.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | Command and Scripting Interpreter |
| Technique ID | T1059 |
| Secondary Techniques | System Binary Proxy Execution (T1218), Signed Binary Proxy Execution: Rundll32 (T1218.011), Signed Binary Proxy Execution: Mshta (T1218.005), Signed Binary Proxy Execution: Regsvr32 (T1218.010) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
`crowdstrike`
(FileName IN ("*.dll", "*.exe", "*.scr", "*.vbs", "*.ps1") OR ProcessCommandLine="*")
| search
    (FileName IN ("mscoree.dll", "iertutil.dll", "oleaut32.dll") AND NOT (Image="C:\\Windows\\System32\\*" OR Image="C:\\Windows\\SysWOW64\\*"))
    OR (ProcessCommandLine="*certutil* -decode*" OR ProcessCommandLine="*certutil* -urlcache*")
    OR (ProcessCommandLine="*rundll32* javascript:*" OR ProcessCommandLine="*rundll32.exe*,a /p:*")
    OR (ProcessCommandLine="*mshta* http*" OR ProcessCommandLine="*mshta* javascript:*")
    OR (ProcessCommandLine="*regsvr32* /s /u /i:http*" OR ProcessCommandLine="*regsvr32* scrobj.dll*")
    OR (FileName="*.scr" AND ParentImage!="*explorer.exe")
| stats count by ComputerName, FileName, ProcessCommandLine, ParentImage, Image, UserName
| where count > 0
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| DLL sideload from non-system path | High | Known Lazarus DLL sideloading technique |
| Certutil decode/download | High | Ingress tool transfer / decode for staging |
| Rundll32 JavaScript execution | Critical | Proxy execution for script-based payloads |
| Mshta remote/script execution | High | Application whitelisting bypass |
| Regsvr32 squiblydoo | High | COM scriptlet-based execution |
| .scr from non-explorer parent | Medium | Masquerading as screensaver file |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Lazarus Group (HIDDEN COBRA) | [MITRE - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/) |

## References

- [MITRE ATT&CK - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/)
- [CISA - HIDDEN COBRA North Korean Malicious Cyber Activity](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-106a)
