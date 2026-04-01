---
scraped_at: "2026-04-02T00:00:00Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package/"
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### IP Addresses
- None found.

### Domains/URLs
- `http://sfrclak[.]com:8000` - C2 server for WAVESHAPER.V2
- `http://sfrclak[.]com:8000/6202033` - C2 server for WAVESHAPER.V2

### File Hashes
- None found.

### Email Addresses
- `ifstap@proton.me` - Attacker-controlled email address used to compromise the axios NPM package maintainer account.

### File Names/Paths
- `%TEMP%\6202033.ps1` - PowerShell script downloaded and executed by the Windows payload.
- `/Library/Caches/com.apple.act.mond` - Location of the macOS Mach-O binary payload.
- `/tmp/ld.py` - Location of the Linux Python backdoor payload.

### Registry Keys
- `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdate` - Persistence mechanism for WAVESHAPER.V2 on Windows.

### Mutex Names
- None found.

### C2 Infrastructure
- `http://sfrclak[.]com:8000` - C2 server for WAVESHAPER.V2
- `http://sfrclak[.]com:8000/6202033` - C2 server for WAVESHAPER.V2

## 2. TTPs (MITRE ATT&CK Mapping)

- **Tactic: Initial Access**
  - **Technique: Supply Chain Compromise (T1195.002)**
    - The attacker compromised the axios NPM package by introducing a malicious dependency (`plain-crypto-js`) into legitimate package releases.

- **Tactic: Execution**
  - **Technique: Command and Scripting Interpreter: JavaScript (T1059.007)**
    - The malicious dependency used an obfuscated JavaScript dropper (`setup.js`) to execute OS-specific payloads.
  - **Technique: Command and Scripting Interpreter: PowerShell (T1059.001)**
    - The Windows payload used PowerShell scripts to execute commands and establish persistence.
  - **Technique: Command and Scripting Interpreter: Bash (T1059.004)**
    - The macOS payload used bash scripts to download and execute a Mach-O binary.

- **Tactic: Persistence**
  - **Technique: Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (T1547.001)**
    - The Windows payload created a registry key to ensure persistence across reboots.

- **Tactic: Defense Evasion**
  - **Technique: Obfuscated Files or Information (T1027)**
    - The dropper used custom XOR and Base64-based obfuscation to conceal C2 URLs and commands.

- **Tactic: Command and Control**
  - **Technique: Application Layer Protocol: Web Protocols (T1071.001)**
    - The backdoor communicated with the C2 server over HTTP using Base64-encoded JSON data.

- **Tactic: Discovery**
  - **Technique: System Information Discovery (T1082)**
    - The backdoor collected system telemetry, including hostname, username, OS version, and running processes.
  - **Technique: File and Directory Discovery (T1083)**
    - The backdoor enumerated directories and retrieved detailed file metadata.

- **Tactic: Execution**
  - **Technique: Command and Scripting Interpreter: Python (T1059.006)**
    - The Linux payload used a Python backdoor for execution.

## 3. Malware & Tools

### Malware Families
- **WAVESHAPER.V2**: A cross-platform backdoor with variants for Windows, macOS, and Linux. Capabilities include reconnaissance, command execution, file system enumeration, and persistence.
- **SILKBELL**: A JavaScript dropper used to deliver OS-specific payloads.

### Tools
- **PowerShell**: Used by the Windows payload for execution and persistence.
- **Bash**: Used by the macOS payload for downloading and executing the Mach-O binary.
- **Python**: Used by the Linux payload for backdoor functionality.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: UNC1069
  - **Motivation**: Financially motivated.
  - **Origin**: North Korea nexus.
  - **Active Since**: At least 2018.
  - **Known Malware**: WAVESHAPER and WAVESHAPER.V2.
  - **Infrastructure Overlaps**: sfrclak[.]com and 142.11.206.73 linked to previous UNC1069 campaigns.

## 5. Splunk Detection Searches

### Network IOCs
#### Detect HTTP Traffic to C2 Domains
```spl
index=network sourcetype=bro_http OR sourcetype=pan:traffic
| search dest_ip IN ("142.11.206.73", "23.254.167.216") OR url IN ("http://sfrclak.com:8000", "http://sfrclak.com:8000/6202033")
| stats count by src_ip, dest_ip, url
```

### Endpoint IOCs
#### Detect Execution of Obfuscated JavaScript Dropper
```spl
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
| search EventID=1 Image="*\node.exe" CommandLine="*setup.js*"
| stats count by Computer, User, CommandLine
```

#### Detect PowerShell Script Execution
```spl
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
| search EventID=4104 ScriptBlockText="*curl -s -X POST -d packages.npm.org/product1*"
| stats count by Computer, User, ScriptBlockText
```

#### Detect Registry Key Persistence
```spl
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
| search EventID=13 TargetObject="HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MicrosoftUpdate"
| stats count by Computer, User, TargetObject
```

### Hash Lookups
#### Detect Known Malicious Hashes
```spl
index=main sourcetype=endpoint
| search file_hash IN ("e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09", "fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf", "92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a", "617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101", "ed8560c1ac7ceb6983ba995124d5917dc1a00288912387a6389296637d5f815c", "f7d335205b8d7b20208fb3ef93ee6dc817905dc3ae0c10a0b164f4e7d07121cd", "58401c195fe0a6204b42f5f90995ece5fab74ce7c69c67a24c61a057325af668")
| stats count by file_name, file_path, file_hash
```

### Behavioral TTPs
#### Detect Obfuscated JavaScript Execution
```spl
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
| search EventID=1 CommandLine="*Base64*" OR CommandLine="*XOR*"
| stats count by Computer, User, CommandLine
```

## 6. Executive Summary

On March 31, 2026, Google Threat Intelligence Group (GTIG) identified a supply chain attack targeting the popular NPM package `axios`. The attack involved the introduction of a malicious dependency, `plain-crypto-js`, which deployed the WAVESHAPER.V2 backdoor across Windows, macOS, and Linux systems. This activity has been attributed to UNC1069, a North Korea-nexus threat actor active since 2018. Organizations using the affected versions of `axios` are urged to take immediate remediation steps, including auditing dependencies, blocking C2 infrastructure, and rotating potentially exposed credentials. The attack highlights the critical need for robust supply chain security measures to mitigate risks associated with third-party software dependencies.