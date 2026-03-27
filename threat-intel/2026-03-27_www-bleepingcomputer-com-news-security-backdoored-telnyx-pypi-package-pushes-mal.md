---
scraped_at: "2026-03-27T21:13:26Z"
source_url: "https://www.bleepingcomputer.com/news/security/backdoored-telnyx-pypi-package-pushes-malware-hidden-in-wav-audio/"
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### IP Addresses
- None identified in the source.

### Domains/URLs
- `https://fs-loader.com/script/` - Remote C2 server hosting malicious WAV files.

### File Hashes
- None identified in the source.

### File Names/Paths
- `telnyx/_client.py` - Malicious Python file in compromised Telnyx PyPI package.
- `ringtone.wav` - Malicious WAV file used for second-stage payload on Linux/macOS.
- `hangup.wav` - Malicious WAV file used for second-stage payload on Windows.
- `msbuild.exe` - Executable dropped on Windows for persistence.

### Registry Keys
- None identified in the source.

### Mutex Names
- None identified in the source.

### C2 Infrastructure
- None explicitly identified beyond the domain listed above.

## 2. TTPs (MITRE ATT&CK Mapping)

- **T1195.002 - Supply Chain Compromise: Compromise Software Supply Chain**  
  - TeamPCP compromised the Telnyx PyPI package to distribute malicious versions (4.87.1 and 4.87.2).

- **T1027 - Obfuscated Files or Information**  
  - Malicious code was embedded in WAV audio files using steganography.

- **T1070.004 - Indicator Removal on Host: File Deletion**  
  - The malware uses a lock file to limit repeated execution within 12-hour windows, potentially to evade detection.

- **T1074.001 - Data Staged: Local Data Staging**  
  - The malware collects SSH keys, credentials, cloud tokens, cryptocurrency wallets, and environment variables for exfiltration.

- **T1078 - Valid Accounts**  
  - Threat actors used stolen credentials to compromise the PyPI publishing account.

- **T1078.004 - Valid Accounts: Cloud Accounts**  
  - The malware targets cloud tokens and Kubernetes secrets.

- **T1059.001 - Command and Scripting Interpreter: PowerShell**  
  - The malware executes scripts to perform malicious actions on the victim's machine.

- **T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder**  
  - On Windows, the malware achieves persistence by placing an executable in the Startup folder.

## 3. Malware & Tools

- **Malware Families**: Credential-stealing malware leveraging steganography.
- **Tools**: `msbuild.exe` (used for persistence on Windows).
- **Techniques**: Steganography to hide malicious payloads in WAV files.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: TeamPCP  
  - Known for supply-chain attacks and wiper malware targeting Iranian systems.  
  - Previously linked to attacks on Aqua Security's Trivy vulnerability scanner and the LiteLLM Python library.

## 5. Splunk Detection Searches

### Detecting Access to Malicious Domain
```spl
index=proxy OR index=network 
| search url="https://fs-loader.com/script/*" 
| stats count by src_ip, dest_ip, url, user
```

### Detecting Execution of `msbuild.exe` from Startup Folder
```spl
index=wineventlog EventCode=4688 New_Process_Name="*\\Startup\\msbuild.exe"
| stats count by ComputerName, User, New_Process_Name
```

### Detecting Execution of Malicious Python File
```spl
index=oswin:sysmon EventCode=1 Image="*\\python.exe" CommandLine="*telnyx/_client.py*"
| stats count by ComputerName, User, CommandLine
```

### Detecting Kubernetes Privileged Pod Deployment
```spl
index=kube:apiserver verb=create kind=Pod
| search requestObject.spec.containers.securityContext.privileged=true
| stats count by user.username, requestObject.metadata.name, requestObject.metadata.namespace
```

## 6. Executive Summary

A supply-chain attack attributed to the TeamPCP threat actor has compromised the Telnyx PyPI package, a popular Python SDK with over 740,000 monthly downloads. Malicious versions (4.87.1 and 4.87.2) were uploaded, delivering credential-stealing malware hidden in WAV audio files using steganography. The malware targets SSH keys, cloud tokens, and other sensitive data, and achieves persistence on Windows systems via the Startup folder. Organizations using the affected package versions should treat systems as compromised, immediately roll back to version 4.87.0, and rotate all secrets. Detection mechanisms should be implemented to identify malicious activity and prevent further compromise.
