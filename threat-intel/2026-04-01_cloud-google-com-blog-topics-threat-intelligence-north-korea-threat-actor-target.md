---
scraped_at: 2026-03-31T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package/
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### IP Addresses
- **142.11.206.73**: C2 server for WAVESHAPER.V2
- **23.254.167.216**: Suspected UNC1069 infrastructure

### Domains/URLs
- **sfrclak[.]com**: C2 domain for WAVESHAPER.V2
- **http://sfrclak[.]com:8000**: C2 URL for WAVESHAPER.V2
- **http://sfrclak[.]com:8000/6202033**: C2 URL for WAVESHAPER.V2

### File Hashes
- **e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09**: SHA256, Obfuscated JavaScript dropper (setup.js)
- **fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf**: SHA256, WAVESHAPER.V2 Linux Python RAT
- **92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a**: SHA256, WAVESHAPER.V2 macOS native binary
- **617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101**: SHA256, WAVESHAPER.V2 Windows Stage 1 payload
- **ed8560c1ac7ceb6983ba995124d5917dc1a00288912387a6389296637d5f815c**: SHA256, WAVESHAPER.V2 unknown
- **f7d335205b8d7b20208fb3ef93ee6dc817905dc3ae0c10a0b164f4e7d07121cd**: SHA256, system.bat
- **58401c195fe0a6204b42f5f90995ece5fab74ce7c69c67a24c61a057325af668**: SHA256, plain-crypto-js-4.2.1.tgz

### Email Addresses
- **ifstap@proton.me**: Attacker-controlled email address used to compromise axios maintainer account

### File Names/Paths
- **setup.js**: Obfuscated JavaScript dropper
- **%PROGRAMDATA%\wt.exe**: Copied PowerShell executable for evasion
- **%TEMP%\6202033.ps1**: PowerShell script payload
- **/Library/Caches/com.apple.act.mond**: macOS payload location
- **/tmp/ld.py**: Linux Python backdoor
- **%PROGRAMDATA%\system.bat**: Hidden batch file for persistence

### Registry Keys
- **HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdate**: Persistence mechanism for WAVESHAPER.V2 on Windows

## 2. TTPs (MITRE ATT&CK Mapping)

- **T1195.002 (Supply Chain Compromise: Compromise Software Dependencies and Development Tools)**: Compromised axios NPM package with malicious dependency.
- **T1059.007 (Command and Scripting Interpreter: JavaScript)**: Use of obfuscated JavaScript dropper (setup.js).
- **T1059.001 (Command and Scripting Interpreter: PowerShell)**: Execution of PowerShell scripts for payload delivery.
- **T1070.004 (Indicator Removal on Host: File Deletion)**: Dropper deletes itself and reverts modified files to hide traces.
- **T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder)**: Persistence via registry key on Windows.
- **T1105 (Ingress Tool Transfer)**: Download of payloads from C2 servers.
- **T1574.013 (Hijack Execution Flow: DLL Search Order Hijacking)**: Copies PowerShell executable to evade detection.
- **T1027 (Obfuscated Files or Information)**: XOR and Base64 obfuscation of C2 commands.
- **T1071.001 (Application Layer Protocol: Web Protocols)**: C2 communication over HTTP.

## 3. Malware & Tools

- **WAVESHAPER.V2**: Multi-platform backdoor with reconnaissance, command execution, and persistence capabilities.
- **SILKBELL**: Obfuscated JavaScript dropper used to deploy WAVESHAPER.V2.
- **plain-crypto-js**: Malicious NPM package used as a payload delivery vehicle.

## 4. Threat Actor / Campaign Attribution

- **UNC1069**: Financially motivated North Korea-nexus threat actor active since 2018. Known for supply chain attacks and use of WAVESHAPER malware family.

## 5. Splunk Detection Searches

### Network IOCs

#### Detect communication with C2 domain (sfrclak[.]com)
```spl
index=network sourcetype=proxy OR sourcetype=dns
| search dest_domain="sfrclak.com" OR dest_ip="142.11.206.73" OR dest_ip="23.254.167.216"
| stats count by src_ip, dest_ip, dest_domain
```

#### Detect HTTP POST requests to C2 URLs
```spl
index=network sourcetype=proxy
| search uri_path="/6202033" OR uri="http://sfrclak.com:8000"
| stats count by src_ip, dest_ip, uri
```

### Endpoint IOCs

#### Detect execution of obfuscated JavaScript dropper (setup.js)
```spl
index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
EventCode=1 Image="*\node.exe" CommandLine="*setup.js*"
| stats count by ComputerName, User, CommandLine
```

#### Detect PowerShell script execution
```spl
index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
EventCode=4104 ScriptBlockText="*curl*packages.npm.org/product1*"
| stats count by ComputerName, User, ScriptBlockText
```

#### Detect persistence via registry key
```spl
index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
EventCode=13 TargetObject="HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdate"
| stats count by ComputerName, User, TargetObject
```

### Hash Lookups

#### Detect known malicious hashes
```spl
index=endpoint sourcetype=files
| search file_hash IN ("e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09", "fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf", "92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a", "617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101", "ed8560c1ac7ceb6983ba995124d5917dc1a00288912387a6389296637d5f815c", "f7d335205b8d7b20208fb3ef93ee6dc817905dc3ae0c10a0b164f4e7d07121cd", "58401c195fe0a6204b42f5f90995ece5fab74ce7c69c67a24c61a057325af668")
| stats count by ComputerName, file_name, file_hash
```

## 6. Executive Summary

On March 31, 2026, Google Threat Intelligence Group (GTIG) identified a supply chain attack targeting the popular NPM package `axios`. The attack introduced a malicious dependency, `plain-crypto-js`, which deployed the WAVESHAPER.V2 backdoor across Windows, macOS, and Linux systems. This activity is attributed to UNC1069, a North Korea-nexus threat actor. Key IOCs include the domain `sfrclak[.]com`, IP `142.11.206.73`, and several malicious file hashes. Organizations using `axios` should immediately audit their dependency trees, block identified IOCs, and implement strict version control to mitigate risks. Deploying endpoint detection and response (EDR) solutions and monitoring for suspicious activity is strongly recommended.
