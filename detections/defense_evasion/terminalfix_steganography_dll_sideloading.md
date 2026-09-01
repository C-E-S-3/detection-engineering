# TerminalFix: PNG Steganography Payload Delivery with DLL Sideloading from ProgramData Hex Path

## Description

Detects the TerminalFix campaign's two-stage defense evasion chain: (1) downloading a steganographic PNG image from a CDN-hosted domain to extract shellcode, followed by (2) DLL sideloading from a 16-character lowercase hex-named subdirectory of `C:\ProgramData\`. Legitimate software does not place DLLs in directories named with random hex strings under ProgramData, and legitimate processes do not follow the pattern of fetching PNG files immediately before DLL execution from such paths.

This detection also covers the registry persistence artifact: a Run key value named `LockScreenContentServer_[alphanumeric]`, which mimics a legitimate-sounding Windows component but is not created by any known Windows or common application.

False positive sources: custom enterprise software that uses UUID/hex-based directories under ProgramData could trigger the path-based rule; validate by confirming the parent process and correlating with the registry persistence indicator.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| **Tactic** | Defense Evasion |
| **Tactic ID** | TA0005 |
| **Technique** | DLL Sideloading |
| **Technique ID** | T1574.002 |
| **Sub-technique** | — |
| **Secondary Techniques** | T1027.003 (Steganography), T1547.001 (Registry Run Keys) |

## Lockheed Martin Kill Chain Phase

Exploitation / Installation

## Splunk SPL Query

### Rule 1: DLL Created in 16-char Hex ProgramData Subdirectory

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_name="*.dll"
    AND Filesystem.file_path="*\\ProgramData\\*"
    AND Filesystem.action=created
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| rex field=file_path "ProgramData\\\\(?P<subdir>[^\\\\]+)\\\\"
| where match(subdir, "^[a-f0-9]{16}$")
| eval risk_score=85
| table firstTime lastTime dest user file_path file_name subdir risk_score
```

### Rule 2: Registry Run Key Named LockScreenContentServer (TerminalFix Persistence)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Registry
  where Registry.registry_path="*\\CurrentVersion\\Run*"
    AND Registry.registry_value_name="LockScreenContentServer_*"
  by Registry.dest Registry.user Registry.registry_path
     Registry.registry_value_name Registry.registry_value_data
| `drop_dm_object_name(Registry)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user registry_path registry_value_name registry_value_data risk_score
```

### Rule 3: Process Executing from 16-char Hex ProgramData Directory

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_path="*\\ProgramData\\*"
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_path Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| rex field=process_path "ProgramData\\\\(?P<subdir>[^\\\\]+)\\\\"
| where match(subdir, "^[a-f0-9]{16}$")
| eval risk_score=85
| table firstTime lastTime dest user parent_process_name process_name process_path process risk_score
```

### Rule 4: Composite — DLL Sideload Path Correlated with Run Key Persistence (High Confidence)

```spl
index=* sourcetype=* (
  ("LockScreenContentServer_" AND ("HKCU" OR "CurrentVersion\\Run"))
  OR ("ProgramData" AND (
    "f47f2a8c21c9df4e" OR
    match(_raw, "ProgramData\\[a-f0-9]{16}")
  ))
)
| stats count min(_time) as firstTime max(_time) as lastTime by host user
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime host user count risk_score
```

## Risk Score Logic

| Score | Condition |
|-------|-----------|
| 95 | Registry Run key `LockScreenContentServer_*` observed (near-certain TerminalFix) |
| 90 | Registry Run key `LockScreenContentServer_*` with DLL in hex ProgramData path |
| 85 | DLL creation or process execution from `C:\ProgramData\[a-f0-9]{16}\` |
| 60 | Process execution from any non-standard ProgramData subdirectory |

## Associated Threat Actors

| Actor | Type | Description |
|-------|------|-------------|
| TerminalFix (unattributed) | ClickFix Campaign | August 2026 campaign; fake Cloudflare CAPTCHA → Python stager → PNG steganography → DLL sideloading → reverse WebSocket tunnel to `gitnow[.]dev:443` |

## References

- [Microsoft Security Blog — TerminalFix Campaign (2026-08-28)](https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/)
- [MITRE ATT&CK — T1574.002 DLL Sideloading](https://attack.mitre.org/techniques/T1574/002/)
- [MITRE ATT&CK — T1027.003 Steganography](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK — T1547.001 Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)
- [Threat Intel Report — TerminalFix (this repo)](../../threat-intel/2026-09-01_microsoft-com-security-blog-terminalfix-reverse-tunnel-clickfix.md)
