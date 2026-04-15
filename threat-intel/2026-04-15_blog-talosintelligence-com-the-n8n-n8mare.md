---
scraped_at: "2026-04-15T12:02:23Z"
source_url: "https://blog.talosintelligence.com/the-n8n-n8mare/"
report_type: threat-intel
severity: "high"
title: "Threat actors abuse n8n automation platform for phishing and malware delivery"
---

## 1. Indicators of Compromise (IOCs)
### IP Addresses
None identified.

### Domains/URLs
- hxxps[://]onedrivedownload[.]zoholandingpage[.]com/my-workspace/DownloadedOneDrive (Malicious phishing URL delivering malware)
- hxxps[://]majormetalcsorp[.]com/Openfolder (Malicious phishing URL delivering malware)
- hxxps[://]pagepoinnc[.]app[.]n8n[.]cloud/webhook/downloading-1a92cb4f-cff3-449d-8bdd-ec439b4b3496 (Malicious n8n webhook URL delivering malware)
- hxxps[://]monicasue[.]app[.]n8n[.]cloud/webhook/download-file-92684bb4-ee1d-4806-a264-50bfeb750dab (Malicious n8n webhook URL delivering malware)

### File Hashes
- 93a09e54e607930dfc068fcbc7ea2c2ea776c504aa20a8ca12100a28cfdcc75a (SHA256, "DownloadedOneDriveDocument.exe" malware payload)
- 7f30259d72eb7432b2454c07be83365ecfa835188185b35b30d11654aadf86a0 (SHA256, "OneDrive_Document_Reader_pHFNwtka_installer.msi" malware payload)

### Other IOCs
None identified.

## 2. TTPs (MITRE ATT&CK Mapping)
- **T1566.002 - Phishing: Spearphishing Link**
  - Threat actors use phishing emails containing malicious n8n webhook URLs to deliver malware payloads.
- **T1203 - Exploitation for Client Execution**
  - Malicious payloads exploit user interaction (e.g., completing CAPTCHA) to execute malware.
- **T1059.001 - Command and Scripting Interpreter: PowerShell**
  - Malware uses PowerShell commands to configure and execute remote monitoring tools as backdoors.
- **T1071.001 - Application Layer Protocol: Web Protocols**
  - Abuse of n8n webhook URLs for C2 communication and payload delivery.
- **T1083 - File and Directory Discovery**
  - Backdoor tools exfiltrate system information using Python modules.

## 3. Malware & Tools
### Malware Families
- Modified Datto Remote Monitoring and Management (RMM) tool
- Modified ITarian Endpoint Management RMM tool

### Tools
- Armadillo anti-analysis packer
- PowerShell
- Python modules for data exfiltration

## 4. Threat Actor / Campaign Attribution
No specific threat actor attribution provided. Campaigns observed include:
- Phishing campaign using n8n webhook URLs to deliver malware payloads disguised as OneDrive documents.
- Device fingerprinting campaigns leveraging invisible tracking pixels embedded in emails.

## 5. Splunk Detection Searches
### Detecting Malicious Domains
```spl
index=proxy OR index=dns
| search "onedrivedownload.zoholandingpage.com" OR "majormetalcsorp.com" OR "pagepoinnc.app.n8n.cloud" OR "monicasue.app.n8n.cloud"
| stats count by src_ip, dest_ip, dest_domain
| table src_ip, dest_ip, dest_domain, count
```
*Detects access to known malicious domains and n8n webhook URLs.*

### Detecting Malicious File Hashes
```spl
index=endpoint
| search file_hash="93a09e54e607930dfc068fcbc7ea2c2ea776c504aa20a8ca12100a28cfdcc75a" OR file_hash="7f30259d72eb7432b2454c07be83365ecfa835188185b35b30d11654aadf86a0"
| stats count by file_name, file_path, file_hash
| table file_name, file_path, file_hash, count
```
*Detects execution or presence of malicious files based on their hashes.*

### Detecting PowerShell Abuse
```spl
index=xmlwineventlog
EventCode=4104
| search "Datto RMM" OR "ITarian Endpoint"
| stats count by User, CommandLine
| table User, CommandLine, count
```
*Detects suspicious PowerShell commands related to RMM tool abuse.*

### Detecting n8n Webhook Abuse
```spl
index=email
| search "webhook" AND "n8n.cloud"
| stats count by sender, recipient, subject
| table sender, recipient, subject, count
```
*Detects emails containing n8n webhook URLs.*

## 6. Executive Summary
Cisco Talos has identified significant abuse of the n8n AI workflow automation platform by threat actors to deliver malware and fingerprint devices. Malicious n8n webhook URLs embedded in phishing emails facilitate payload delivery, bypassing traditional security filters. Observed payloads include modified remote monitoring tools used as backdoors. Organizations should monitor for suspicious n8n webhook activity, block identified malicious domains, and implement behavioral detection for unusual traffic patterns. Immediate actions include updating email security filters and sharing IOCs with threat intelligence platforms.