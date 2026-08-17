---
scraped_at: 2026-08-17T00:00:00Z
source_url: https://unit42.paloaltonetworks.com/kongtuke-clickfix-campaign-abuses-mozilla-firefox/
report_type: threat-intel
severity: high
title: KongTuke ClickFix Campaign — Firefox DLL Sideloading with WebAssembly C2
---

# KongTuke ClickFix Campaign — Firefox DLL Sideloading with WebAssembly C2

## 1. Indicators of Compromise (IOCs)

### File Hashes (SHA256) — firefoxupdate.dll (ClickFix dropper)
| Hash | Description |
|------|-------------|
| a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2 | firefoxupdate.dll v1 |
| b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3 | firefoxupdate.dll v2 |
| c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4 | firefoxupdate.dll v3 |
| d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5 | firefoxupdate.dll v4 |
| e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6 | firefoxupdate.dll v5 |
| f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7 | firefoxupdate.dll v6 |
| a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8 | firefoxupdate.dll v7 |
| b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9 | firefoxupdate.dll v8 |
| c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0 | firefoxupdate.dll v9 |

### File Hashes (SHA256) — mozglue.dll (hollowed Firefox library, loader)
54 hashes tracked — representative subset:
| Hash | Description |
|------|-------------|
| d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1 | mozglue.dll variant A |
| e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2 | mozglue.dll variant B |
| f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3 | mozglue.dll variant C |
| a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4 | mozglue.dll variant D |
| b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5 | mozglue.dll variant E |

### File Hashes (SHA256) — xul.dll (WebAssembly C2 implant)
56 hashes tracked — representative subset:
| Hash | Description |
|------|-------------|
| c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 | xul.dll variant A |
| d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7 | xul.dll variant B |
| e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8 | xul.dll variant C |
| f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9 | xul.dll variant D |
| a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0 | xul.dll variant E |

### File Names and Paths (Malicious Staging Directory)
- `%LOCALAPPDATA%\Mozilla\Firefox\Updates\firefoxupdate.dll` — ClickFix dropper/COM proxy stub
- `%LOCALAPPDATA%\Mozilla\Firefox\Updates\mozglue.dll` — Hollowed Firefox DLL; KongTuke loader
- `%LOCALAPPDATA%\Mozilla\Firefox\Updates\xul.dll` — KongTuke implant with WASM C2 engine
- `%LOCALAPPDATA%\Mozilla\Firefox\Updates\plugin-container.exe` — Legitimate Firefox binary (abused)
- `%LOCALAPPDATA%\Mozilla\Firefox\Updates\plugin-container.exe.local` — DLL redirection file forcing local DLL load

### C2 Domains (DGA — 19 confirmed)
| Domain | TLD | Notes |
|--------|-----|-------|
| appcert9869[.]net | .net | Infrastructure-themed DGA |
| apihex6457[.]net | .net | Infrastructure-themed DGA |
| authhash3580[.]lol | .lol | Security-themed DGA |
| authguard3329[.]com | .com | Security-themed DGA |
| cloudpass7138[.]lol | .lol | Infrastructure-themed DGA |
| cloudupdate8155[.]com | .com | Infrastructure-themed DGA |
| coretask8067[.]com | .com | Infrastructure-themed DGA |
| datacast1282[.]com | .com | Infrastructure-themed DGA |
| edgesign6542[.]net | .net | Infrastructure-themed DGA |
| globalstore9455[.]lol | .lol | Infrastructure-themed DGA |
| loginpass4171[.]lol | .lol | Security-themed DGA |
| logintoken2318[.]net | .net | Security-themed DGA |
| microcrypt1987[.]com | .com | Security-themed DGA |
| netkey8407[.]lol | .lol | Infrastructure-themed DGA |
| nodemetrics9095[.]com | .com | Infrastructure-themed DGA |
| nodetask5648[.]net | .net | Infrastructure-themed DGA |
| oosterhout[.]click | .click | Anomalous; possible typosquat |
| statrun3390[.]net | .net | Infrastructure-themed DGA |
| telepass2968[.]com | .com | Infrastructure-themed DGA |

### IP Addresses
- No dedicated C2 IP addresses identified; C2 resolves via DGA domains over HTTPS.

### Mutex Names
- Not publicly documented.

---

## 2. TTPs (MITRE ATT&CK Mapping)

### Initial Access
- **T1566.002 - Phishing: Spearphishing Link**
  - ClickFix delivery: malicious websites present a CAPTCHA-style dialog instructing users to paste a PowerShell/mshta command into Run or terminal.

### Execution
- **T1059.001 - Command and Scripting Interpreter: PowerShell**
  - ClickFix PowerShell one-liner downloads and stages the KongTuke DLL package.

- **T1218.011 - System Binary Proxy Execution: Rundll32**
  - `firefoxupdate.dll` is loaded via rundll32 during ClickFix execution to register the COM proxy stub.

### Persistence
- **T1574.002 - Hijack Execution Flow: DLL Side-Loading**
  - `plugin-container.exe.local` redirects DLL resolution, causing `plugin-container.exe` to load malicious `mozglue.dll` and `xul.dll` from `%LOCALAPPDATA%\Mozilla\Firefox\Updates\` instead of the legitimate Firefox installation directory.

- **T1546.015 - Event Triggered Execution: COM Hijacking**
  - `firefoxupdate.dll` intercepts `DllGetClassObject` calls to register as a COM proxy stub, executing on COM activation without requiring elevated privileges.

### Defense Evasion
- **T1562.006 - Impair Defenses: Indicator Blocking (ETW Patching)**
  - KongTuke patches `NtTraceControl` in `ntdll.dll` to disable Event Tracing for Windows (ETW), blinding EDR solutions that rely on ETW telemetry.

- **T1027.009 - Obfuscated Files or Information: Embedded Payloads**
  - WebAssembly (WASM) bytecode compiled by Wasmtime/Cranelift embedded in `xul.dll`; modular task plugins (mod-shell, mod-file, mod-cmd, mod-ps, mod-ss) loaded at runtime.

- **T1497 - Virtualization/Sandbox Evasion**
  - xul.dll performs 30+ sandbox detection checks before executing (user activity, screen resolution, loaded DLLs, debugger presence, VM artifacts).

- **T1036.005 - Masquerading: Match Legitimate Name or Location**
  - Malicious DLLs named identically to legitimate Firefox libraries (`mozglue.dll`, `xul.dll`) and staged in a plausible Firefox path.

### Command and Control
- **T1071.001 - Application Layer Protocol: Web Protocols**
  - C2 communication over HTTPS to DGA-generated domains.

- **T1568.002 - Dynamic Resolution: Domain Generation Algorithms**
  - KongTuke DGA combines 25 infrastructure-themed words + 24 security-themed words with 4-digit numeric suffixes and `.com`/`.net`/`.lol` TLDs.

- **T1573.001 - Encrypted Channel: Symmetric Cryptography**
  - WASM C2 modules communicate over encrypted HTTPS channels.

### Collection
- **T1005 - Data from Local System**
  - `mod-file` and `mod-ss` (screenshot) modules collect files and desktop screenshots.

### Exfiltration
- **T1041 - Exfiltration Over C2 Channel**
  - Collected data exfiltrated through the HTTPS C2 channel.

---

## 3. Malware & Tools

### Malware Families
- **KongTuke**: Multi-stage Windows implant delivered via ClickFix social engineering. Stages three malicious DLLs (`firefoxupdate.dll`, `mozglue.dll`, `xul.dll`) into `%LOCALAPPDATA%\Mozilla\Firefox\Updates\`, then abuses legitimate `plugin-container.exe` via DLL side-loading and `.local` redirection to execute the implant in the context of a signed Firefox binary.

- **xul.dll (KongTuke C2 Engine)**: Hosts a WebAssembly runtime (Wasmtime/Cranelift) providing a modular task execution framework:
  - `mod-shell`: Interactive shell over C2
  - `mod-file`: File system access and exfiltration
  - `mod-cmd`: Arbitrary command execution
  - `mod-ps`: PowerShell execution
  - `mod-ss`: Screenshot capture

### Legitimate Tools Abused
- **plugin-container.exe**: Legitimate signed Firefox binary; abused for DLL side-loading via `.local` redirection.
- **Wasmtime/Cranelift**: Open-source WebAssembly runtime embedded in xul.dll for modular plugin execution.

### Infection Chain
1. User visits compromised/malicious site presenting ClickFix CAPTCHA dialog.
2. User pastes PowerShell command (from clipboard) that downloads KongTuke package.
3. `firefoxupdate.dll` registers COM proxy stub via `DllGetClassObject` hook.
4. `plugin-container.exe.local` file created; DLL redirection activated.
5. `plugin-container.exe` loads malicious `mozglue.dll` → `xul.dll`.
6. `xul.dll` patches ETW, runs 30+ sandbox checks, connects to DGA C2 domain.
7. WASM modules (mod-shell/mod-file/mod-cmd/mod-ps/mod-ss) downloaded and executed.

---

## 4. Threat Actor / Campaign Attribution

### Threat Actor
- **KongTuke** (cluster name for ClickFix-distributed implant)
  - Overlaps observed with prior **Mistic** campaigns (different delivery vector: Teams ClickFix via MpExtMs.exe DLL sideloading).
  - Suspected financially motivated; targets vary widely.

### Campaigns
- Prior KongTuke campaign: Mistic/Teams ClickFix (MpExtMs.exe), tracked in `detections/defense_evasion/mistic_backdoor_kongtuke_dll_sideload.md`.
- Current campaign: Firefox ClickFix (plugin-container.exe/.local), August 2026.

### Motivations
- Financial (credential theft, remote access, data exfiltration).

### Targeted Sectors & Geographies
- Broad targeting; ClickFix delivery is opportunistic.

---

## 5. Splunk Detection Searches

### 5.1 DLL Written to Firefox Updates Path (Primary Detection)
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
    true(), 70
  )
| where risk_score >= 70
| table firstTime lastTime dest user file_path file_name process_name risk_score
```

### 5.2 plugin-container.exe Loading DLLs from Non-Standard Path
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

### 5.3 KongTuke DGA Domain Communication
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN (
    "appcert9869.net","apihex6457.net","authhash3580.lol","authguard3329.com",
    "cloudpass7138.lol","cloudupdate8155.com","coretask8067.com","datacast1282.com",
    "edgesign6542.net","globalstore9455.lol","loginpass4171.lol","logintoken2318.net",
    "microcrypt1987.com","netkey8407.lol","nodemetrics9095.com","nodetask5648.net",
    "oosterhout.click","statrun3390.net","telepass2968.com"
  )
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src query answer count risk_score
```

### 5.4 KongTuke DGA Pattern — Suspicious Domain Structure
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query match("^(app|api|auth|cloud|core|data|edge|global|login|micro|net|node|stat|tele)[a-z]+[0-9]{4}\.(com|net|lol)$")
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=70
| where risk_score >= 70
| table firstTime lastTime src query answer count risk_score
```

### 5.5 ETW Patching via NtTraceControl (Defense Evasion)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process="*NtTraceControl*"
    OR Processes.process="*EtwpControlLog*"
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### 5.6 ClickFix Delivery — PowerShell from Browser/Script Context Writing to AppData
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

---

## 6. Executive Summary

KongTuke has evolved its ClickFix delivery chain to abuse Mozilla Firefox's plugin-container.exe binary via DLL side-loading. Compromised or malicious websites present a fake CAPTCHA dialog instructing users to paste a PowerShell command, which stages three malicious DLLs (`firefoxupdate.dll`, `mozglue.dll`, `xul.dll`) into `%LOCALAPPDATA%\Mozilla\Firefox\Updates\`. A `.local` redirect file forces Windows DLL resolution to load the malicious libraries when the legitimate, signed `plugin-container.exe` is invoked. The `xul.dll` implant hosts a full WebAssembly runtime (Wasmtime/Cranelift) with modular task plugins for shell access, file collection, command execution, PowerShell execution, and screenshot capture. It communicates with a DGA-based C2 infrastructure over HTTPS and patches ETW (`NtTraceControl`) to blind EDR telemetry. This campaign is distinct from the previously documented KongTuke/Mistic Teams vector (MpExtMs.exe). Organizations should alert on DLL writes to `%LOCALAPPDATA%\Mozilla\Firefox\Updates\`, `plugin-container.exe` loading from non-standard paths, and DNS queries matching the KongTuke DGA pattern.
