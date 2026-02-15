# Lazarus Encoded Command Execution

## Description

Detects encoded or obfuscated command execution via PowerShell, cmd.exe, wscript, or cscript, a technique commonly used by the Lazarus Group. This detection looks for encoded command flags (-enc, -encodedcommand), base64 decoding functions (FromBase64String), and convert-based decoding patterns.

False positive sources: Enterprise management tools (SCCM, Intune, DSC) that deploy encoded PowerShell. Tuning: exclude known management tool parent processes and signed scripts.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | Command and Scripting Interpreter: PowerShell |
| Technique ID | T1059.001 |
| Secondary Technique | Obfuscated Files or Information (T1027) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
`crowdstrike`
process_name IN ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe")
(process="*-enc*" OR process="*-encodedcommand*" OR process="*frombase64string*"
 OR process="*::frombase64string*" OR process="*convert*::*base64*")
| stats count by src, user, process_name, process, parent_process_name
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Any encoded command execution match | Varies by context | Base64 encoding in command lines is a common evasion technique used across multiple threat actors |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Lazarus Group (HIDDEN COBRA) | [MITRE - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/) |

## References

- [MITRE ATT&CK - PowerShell (T1059.001)](https://attack.mitre.org/techniques/T1059/001/)
- [CISA - HIDDEN COBRA](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-106a)
