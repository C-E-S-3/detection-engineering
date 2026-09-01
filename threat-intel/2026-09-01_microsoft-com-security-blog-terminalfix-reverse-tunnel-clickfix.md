---
scraped_at: 2026-09-01T00:00:00Z
source_url: https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
report_type: threat-intel
severity: high
title: "TerminalFix: ClickFix Campaign Deploys Reverse WebSocket Tunnel via DLL Sideloading and PNG Steganography"
---

# TerminalFix: ClickFix Campaign Deploys Reverse WebSocket Tunnel via DLL Sideloading and PNG Steganography

**Date Reported:** 2026-08-28  
**Source:** Microsoft Security Blog  
**Severity:** High  
**Note:** Disclosed 2026-08-28; BleepingComputer coverage 2026-08-31. First observed in the wild mid-August 2026.

## 1. IOCs

### File Hashes (SHA-256)

| Hash | File / Component |
|------|-----------------|
| `18c2090e8a0ae0568af9b87e59eaf8270f23d2909600ed9db91a9444fd8b278f` | `verify_pkg.zip` — initial ClickFix delivery archive |
| `b8d107800403b9197e5b7609ceacd8e4cac1b0f9a1d156e6dacd6c3f7794b36a` | `client.py` — Python-based stager that fetches steganography PNG |
| `ba77feed86bcda49308746421bdc684a432dd5d68c363975b2a3c6831bda3f07` | `dui70.dll` — malicious sideloaded DLL (reverse WebSocket tunnel payload) |
| `026478003fe354134c03acf6890e7d3b153ba08a836eca42350db48f213872ab` | TerminalFix DLL sideload chain component |
| `032b529fac61e550f5dc9489686f519b82d64625fa05a8d9ecf8ba8be9b2ad22` | TerminalFix DLL sideload chain component |
| `df8221a933b38284ebdcb8bffc2df62123c9f5b5f421dd0b070e13e668b3eabf` | TerminalFix DLL sideload chain component |
| `eb1b4be34d05b394fb74efdeb95faecd1d1963be6ecc1b9db2b4757b491f01f0` | TerminalFix DLL sideload chain component |
| `5d43abf5c36ea203176d3300ff14af27b4be81810ad2679b3a62b255e3d6e1c8` | TerminalFix DLL sideload chain component |
| `9a7b4dcd51d9251c177d323d6aaecdfc86674f69bc1af048dc872926d22aaa24` | TerminalFix DLL sideload chain component |
| `342df92235c9dec81203b837addaa38bb85b64b4a48fe71b5303ca86d991991e` | TerminalFix DLL sideload chain component |
| `ededeacf30e493dd632d477fe770ba419aa2848f685ea049381a0a8d2cc3e84d` | TerminalFix DLL sideload chain component |

### Domains

| Indicator | Type | Context |
|-----------|------|---------|
| `gitnow[.]dev` | C2 / WebSocket endpoint | TerminalFix reverse tunnel C2; WebSocket connections on port 443 |
| `bestsocialmedianewspapper[.]com` | Payload staging | Hosts steganographic PNG images containing encoded next-stage shellcode |
| `offlineupdater[.]com` | Payload staging (failover) | Fallback PNG stego image host if primary unreachable |
| `linked-log[.]com` | Compromised delivery site | Victim-facing lure page; hosts fake Cloudflare verification / ClickFix prompt |

### File System Artifacts

- `C:\ProgramData\f47f2a8c21c9df4e\` — working directory (16-char lowercase hex path name)
- DLL and companion files extracted into this directory after initial stager execution

### Registry Persistence

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` — value `LockScreenContentServer_[random 9-char alphanumeric]`

### Scheduled Task

- Name: `LockScreenContentServer_MuODG5yBM` (randomized suffix per victim)
- Interval: 60-minute execution

## 2. TTPs

| Tactic | Technique | Details |
|--------|-----------|---------|
| Initial Access | T1189 — Drive-by Compromise | Fake Cloudflare CAPTCHA / ClickFix lure on compromised site |
| Execution | T1059.001 — PowerShell | Initial stager runs PowerShell to extract archive and launch client.py |
| Execution | T1204.002 — User Execution: Malicious File | Victim manually pastes and runs PowerShell from clipboard (ClickFix) |
| Persistence | T1547.001 — Registry Run Keys | `HKCU\...\Run` `LockScreenContentServer_[random]` |
| Persistence | T1053.005 — Scheduled Task | 60-minute schtask ensures reload after reboot or process kill |
| Defense Evasion | T1574.002 — DLL Sideloading | Legitimate signed PE loads malicious `dui70.dll` from `C:\ProgramData\[hex]\` |
| Defense Evasion | T1027.003 — Steganography | Shellcode/config embedded in PNG pixel data; decoded by client.py stager |
| Defense Evasion | T1564.001 — Hidden Files and Directories | Working directory named with random hex to avoid detection |
| Defense Evasion | T1036.005 — Match Legitimate Name | DLL named `dui70.dll` to blend with genuine Windows DirectUI DLL |
| Discovery | T1018 — Remote System Discovery | Post-compromise enumeration of network hosts |
| Discovery | T1069.002 — Permission Groups Discovery: Domain | AD group enumeration |
| Discovery | T1482 — Domain Trust Discovery | Domain trust relationship enumeration |
| Discovery | T1087.002 — Account Discovery: Domain | Domain user enumeration |
| Discovery | T1082 — System Information Discovery | Host OS / configuration enumeration |
| Command & Control | T1572 — Protocol Tunneling | Full bidirectional reverse WebSocket tunnel; operator sessions routed through `gitnow[.]dev` |
| Command & Control | T1071.001 — Web Protocols | WebSocket C2 over HTTPS (port 443) |
| Collection | T1105 — Ingress Tool Transfer | Additional tooling pulled through established tunnel |

**MITRE Tactics:** TA0001, TA0002, TA0003, TA0005, TA0007, TA0011, TA0009  
**Kill Chain Phases:** Delivery, Exploitation, Installation, C2, Actions on Objectives

## 3. Malware & Tools

### client.py (Python stager)
Initial stager executed after ClickFix clipboard paste. Fetches a PNG from `bestsocialmedianewspapper[.]com` (failover: `offlineupdater[.]com`), extracts encoded shellcode from pixel LSBs or IDAT chunks, and writes the next-stage DLL package to `C:\ProgramData\f47f2a8c21c9df4e\`. Sets up dual persistence (registry Run key + scheduled task) before executing the sideloading host binary.

### dui70.dll (Reverse WebSocket Tunnel)
The core payload. Loaded via a co-located legitimate signed Windows binary (DLL sideloading). Establishes a persistent reverse WebSocket tunnel to `gitnow[.]dev:443`, providing operator with a full interactive shell and file transfer capability. Named to match the genuine DirectUI engine DLL (`dui70.dll`) present in `%WINDIR%\system32\`.

### PNG Steganography Delivery
Operator-controlled images hosted at `bestsocialmedianewspapper[.]com` contain hidden payloads embedded using LSB (least-significant-bit) steganography. This technique bypasses content inspection tools that scan for PE headers or known shellcode signatures.

## 4. Threat Actor

Attribution: Unknown; unclassified opportunistic ClickFix campaign. Microsoft tracks as **TerminalFix** (campaign name, not a group designation). Targeting appears broad — no industry or geography-specific focus identified. ClickFix delivery mechanisms have been widely adopted across cybercriminal and nation-state ecosystems since 2024; the steganography + reverse WebSocket combination is a novel variation not previously attributed to a known group.

No overlap identified with known named threat actors. The reverse WebSocket tunnel infrastructure (`gitnow[.]dev`) was registered 2026-07-14, consistent with pre-campaign staging.

## 5. Splunk Detection Searches

### Detect DLL loaded from random hex ProgramData subdirectory
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process="*C:\\ProgramData\\*"
    AND match(Processes.process, "C:\\ProgramData\\[a-f0-9]{16}\\")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Detect Registry Run key named LockScreenContentServer (TerminalFix persistence)
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

### Detect DNS lookups to TerminalFix C2 / stego hosting domains
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN (
    "gitnow.dev", "*.gitnow.dev",
    "bestsocialmedianewspapper.com", "*.bestsocialmedianewspapper.com",
    "offlineupdater.com", "*.offlineupdater.com",
    "linked-log.com", "*.linked-log.com"
  )
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src query answer risk_score
```

### Detect PNG file download followed by DLL creation in same session (stego delivery pattern)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_name="*.dll" AND Filesystem.file_path="*\\ProgramData\\*"
    AND Filesystem.action=created
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path, "ProgramData\\\\[a-f0-9]{16}"), 85,
    true(), 50
  )
| where risk_score >= 50
| table firstTime lastTime dest user file_path file_name risk_score
```

## 6. Executive Summary

TerminalFix is a ClickFix campaign (active August 2026) that delivers a reverse WebSocket tunnel implant through a novel three-stage chain: victims are lured via a fake Cloudflare CAPTCHA page that instructs them to paste a PowerShell command; the command downloads and extracts a ZIP containing a Python stager (`client.py`); the stager fetches a PNG image from an actor-controlled domain and extracts hidden shellcode via steganography; the decoded payload is a DLL (`dui70.dll`) sideloaded by a co-located legitimate signed binary from a random hex-named directory under `C:\ProgramData\`. The loaded DLL establishes a persistent bidirectional WebSocket tunnel to `gitnow[.]dev:443`, giving the operator full interactive access. Dual persistence is achieved through a registry Run key and a 60-minute scheduled task.

The steganography delivery layer bypasses many content-inspection controls, and the use of WebSocket over port 443 blends with normal browser traffic. Recommended detections: monitor registry Run keys matching `LockScreenContentServer_*`, DLL creation events under `C:\ProgramData\[16-char hex]\`, and DNS queries to the four IOC domains. Hash-based detection covers the initial delivery archive and core components.

## References

- [Microsoft Security Blog — TerminalFix Campaign (2026-08-28)](https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/)
- [MITRE ATT&CK — T1574.002 DLL Sideloading](https://attack.mitre.org/techniques/T1574/002/)
- [MITRE ATT&CK — T1027.003 Steganography](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK — T1572 Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
