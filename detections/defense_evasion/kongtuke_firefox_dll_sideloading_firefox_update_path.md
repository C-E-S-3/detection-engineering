# KongTuke Firefox DLL Side-Loading via Firefox Updates Path

## Description

Detects KongTuke implant staging malicious DLLs (`firefoxupdate.dll`, `mozglue.dll`, `xul.dll`) into `%LOCALAPPDATA%\Mozilla\Firefox\Updates\` combined with a `.local` redirect file that forces the legitimate, signed `plugin-container.exe` to side-load the malicious libraries instead of those from the real Firefox installation. Delivery is via ClickFix social engineering; a fake CAPTCHA dialog prompts the user to paste a PowerShell command that downloads and stages the payload.

False positive sources are minimal — the `%LOCALAPPDATA%\Mozilla\Firefox\Updates\` path is not used by legitimate Firefox installations for DLL storage; legitimate update artifacts from Mozilla are placed in `%PROGRAMFILES%\Mozilla Firefox\` or a profile-specific update staging directory, not in `LOCALAPPDATA`. Any DLL or `.exe.local` file written here is highly anomalous.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Hijack Execution Flow: DLL Side-Loading |
| Technique ID | T1574.002 |
| Secondary Tactic | Persistence (TA0003) |
| Secondary Technique | T1546.015 — Event Triggered Execution: COM Hijacking (firefoxupdate.dll COM proxy stub) |

## Lockheed Martin Kill Chain Phase

| Phase | Applies |
|-------|---------|
| Exploitation | Yes — ClickFix PowerShell execution |
| Installation | Yes — DLL staging + COM proxy stub registration |
| Command & Control | Yes — xul.dll WASM C2 engine activates post-installation |

## Splunk Detection Query

### Primary: DLL or Redirect Written to Firefox Updates Path

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path="*\\Mozilla\\Firefox\\Updates\\*"
    AND (Filesystem.file_name="*.dll" OR Filesystem.file_name="*.exe.local")
    AND Filesystem.action=created
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_name,"firefoxupdate\.dll|mozglue\.dll|xul\.dll"), 95,
    match(file_name,"\.exe\.local$"), 85,
    true(), 75
  )
| where risk_score >= 75
| table firstTime lastTime dest user file_path file_name process_name risk_score
```

### Secondary: plugin-container.exe Running from Non-Standard Path

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="plugin-container.exe"
    AND NOT Processes.process_path="*\\Mozilla Firefox\\*"
    AND NOT Processes.process_path="*\\Program Files*\\Mozilla Firefox\\*"
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_path Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name process_name process_path process risk_score
```

### Tertiary: ClickFix Delivery — Scripting Engine Writing DLL to Firefox Updates

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path="*\\AppData\\Local\\Mozilla\\Firefox\\Updates\\*"
    AND Filesystem.action=created
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| where process_name IN ("powershell.exe","pwsh.exe","mshta.exe","wscript.exe","cscript.exe","cmd.exe")
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user process_name file_path file_name risk_score
```

## Risk Score Logic

| Score | Condition |
|-------|-----------|
| 95 | Known malicious filename (`firefoxupdate.dll`, `mozglue.dll`, `xul.dll`) written to Firefox Updates path, OR scripting engine (PowerShell/mshta/wscript) writing any file to Firefox Updates path |
| 90 | `plugin-container.exe` executing from a non-standard directory (not `%PROGRAMFILES%\Mozilla Firefox\`) |
| 85 | `.exe.local` redirect file written to Firefox Updates path |
| 75 | Any `.dll` written to Firefox Updates path by an unrecognized parent process |

## Associated Threat Actors

| Actor | Technique | Reference |
|-------|-----------|-----------|
| KongTuke | T1574.002, T1546.015, T1568.002 (DGA), ETW patching | [Unit42 KongTuke ClickFix Firefox Report](https://unit42.paloaltonetworks.com/kongtuke-clickfix-campaign-abuses-mozilla-firefox/) |
| KongTuke / Mistic | T1574.002 (MpExtMs.exe Teams vector) | `detections/defense_evasion/mistic_backdoor_kongtuke_dll_sideload.md` |

## References

- [Unit42 — KongTuke ClickFix Campaign Abuses Mozilla Firefox Binary (2026-08-12)](https://unit42.paloaltonetworks.com/kongtuke-clickfix-campaign-abuses-mozilla-firefox/)
- [Threat Intel Report — 2026-08-12 KongTuke Firefox DLL Sideloading](../../threat-intel/2026-08-12_unit42-paloaltonetworks-com-kongtuke-clickfix-firefox-dll-sideloading.md)
- [MITRE ATT&CK T1574.002 — DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- [MITRE ATT&CK T1546.015 — COM Hijacking](https://attack.mitre.org/techniques/T1546/015/)
- [MITRE ATT&CK T1568.002 — Domain Generation Algorithms](https://attack.mitre.org/techniques/T1568/002/)
- [Microsoft — .local Files and DLL Redirection](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-redirection)
