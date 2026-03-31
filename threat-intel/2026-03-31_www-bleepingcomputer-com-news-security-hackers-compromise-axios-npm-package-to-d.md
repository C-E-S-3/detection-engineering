---
scraped_at: "2026-03-31T09:53:43-04:00"
source_url: "https://www.bleepingcomputer.com/news/security/hackers-compromise-axios-npm-package-to-drop-cross-platform-malware/"
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### IP Addresses
- No new IP addresses identified.

### Domains/URLs
- `https://fs-loader.com/script/` (already tracked, not new)

### File Hashes
- No file hashes provided in the source.

### File Names/Paths
- `%PROGRAMDATA%\wt.exe` (Windows persistence mechanism)
- `/Library/Caches/com.apple.act.mond` (macOS malware binary location)
- `/tmp/ld.py` (Linux Python-based payload location)

### Registry Keys
- No registry keys identified.

### Mutex Names
- No mutex names identified.

### C2 Infrastructure
- No specific C2 IPs or domains provided.

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactics and Techniques
- **T1190 - Exploit Public-Facing Application**: Compromise of the npm account to inject malicious dependencies.
- **T1059.005 - Command and Scripting Interpreter: Visual Basic**: Use of VBScript on Windows to execute malicious scripts.
- **T1059.001 - Command and Scripting Interpreter: PowerShell**: Use of PowerShell for persistence and execution of malicious scripts on Windows.
- **T1059.002 - Command and Scripting Interpreter: AppleScript**: Use of AppleScript on macOS to download and execute malicious binaries.
- **T1059.006 - Command and Scripting Interpreter: Python**: Use of Python-based payloads on Linux systems.
- **T1070.004 - Indicator Removal on Host: File Deletion**: Deletion of the dropper and modified package.json file to evade detection.
- **T1105 - Ingress Tool Transfer**: Downloading next-stage payloads from a C2 server.
- **T1219 - Remote Access Tools**: Deployment of a Remote Access Trojan (RAT) for command execution and persistence.

## 3. Malware & Tools

### Malware Families
- Remote Access Trojan (RAT): Used to execute commands, maintain persistence, and exfiltrate data.

### Tools
- **plain-crypto-js@^4.2.1**: Malicious dependency injected into the Axios npm package.
- **setup.js**: Obfuscated dropper script executed during package installation.

### Living Off the Land Binaries (LOLBins)
- **PowerShell**: Copied to `%PROGRAMDATA%\wt.exe` for persistence and execution.
- **nohup**: Used on Linux systems to execute Python-based payloads in the background.

## 4. Threat Actor / Campaign Attribution

- No specific attribution to a known threat actor.
- Researchers suggest the attack was a carefully planned supply chain compromise.
- The attack does not align with the tactics of the known group "TeamPCP," which has conducted similar attacks in the past.

## 5. Splunk Detection Searches

### File Path Indicators

#### Windows: Detecting `wt.exe` in `%PROGRAMDATA%`
```spl
index=wineventlog EventCode=4688 "New Process Creation" 
| search New_Process_Name="*\\wt.exe"
| table _time, ComputerName, User, New_Process_Name, CommandLine
```

#### macOS: Detecting binary in `/Library/Caches/com.apple.act.mond`
```spl
index=osquery result_name="file" file_path="/Library/Caches/com.apple.act.mond"
| table _time, host, file_path, action
```

#### Linux: Detecting `/tmp/ld.py`
```spl
index=linux_logs source="/var/log/*" "*/tmp/ld.py*"
| table _time, host, file_path, action
```

### Behavioral TTPs

#### Detecting PowerShell Execution for Persistence
```spl
index=wineventlog EventCode=4104 ScriptBlockText="*wt.exe*"
| table _time, ComputerName, User, ScriptBlockText
```

#### Detecting AppleScript Execution
```spl
index=osquery result_name="processes" name="osascript"
| table _time, host, name, path, arguments
```

#### Detecting Python Payload Execution on Linux
```spl
index=linux_logs source="/var/log/*" "python*ld.py*"
| table _time, host, user, process_name, command
```

## 6. Executive Summary

On March 31, 2026, a supply chain attack compromised the popular Axios npm package, which has over 100 million weekly downloads. The attackers injected a malicious dependency into the package, enabling the delivery of a cross-platform Remote Access Trojan (RAT) to Windows, macOS, and Linux systems. The malware utilized platform-specific techniques, including VBScript, PowerShell, AppleScript, and Python, to establish persistence and execute commands. Organizations using the Axios npm package are advised to immediately lock to the last known clean versions (axios@1.14.0 and axios@0.30.3), rotate credentials, and rebuild affected environments from a known good state.

