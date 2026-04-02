---
scraped_at: "2026-04-02T11:32:18Z"
source_url: "https://blog.talosintelligence.com/an-overview-of-ransomware-threats-in-japan-in-2025-and-early-detection-insights-from-qilin-cases/"
report_type: threat-intel
severity: "high"
title: "Qilin ransomware affiliates leverage EDR killer malware and geo-fencing tactics"
---

## 1. Indicators of Compromise (IOCs)
### IP Addresses
- None identified.

### Domains/URLs
- None identified.

### File Hashes
- `Win.Tool.EdrKiller-10059833-0`: SHA256 hash for EDR killer malware targeting over 300 EDR drivers.
- `Win.Malware.Bumblebee-10056548-0`: SHA256 hash for Bumblebee malware variant.
- `Win.Tool.ThrottleStop-10059849-0`: SHA256 hash for ThrottleStop malware variant.

### Other IOCs
- Geo-fencing excluded localization list targeting systems configured for languages commonly used in post-Soviet countries.

## 2. TTPs (MITRE ATT&CK Mapping)
### Tactics and Techniques
- **Initial Access (TA0001)**
  - **T1078: Valid Accounts**: Qilin affiliates use stolen credentials obtained from platforms like Telegram and Breach Forums.
- **Defense Evasion (TA0005)**
  - **T1562.001: Impair Defenses - Disable or Modify Tools**: EDR killer malware disables over 300 EDR drivers.
  - **T1027: Obfuscated Files or Information**: Malware employs obfuscation techniques to evade detection.
- **Impact (TA0040)**
  - **T1486: Data Encrypted for Impact**: Qilin ransomware encrypts victim data to demand ransom.

## 3. Malware & Tools
### Malware Families
- Qilin ransomware.
- EDR killer malware targeting endpoint detection and response solutions.

### Tools
- Credential harvesting platforms like Telegram and Breach Forums.
- Geo-fencing malware to exclude systems in post-Soviet regions.

## 4. Threat Actor / Campaign Attribution
### Threat Actor
- **Qilin ransomware group**: Active in Japan, responsible for 16.4% of ransomware incidents in 2025.
- Affiliates potentially linked to post-Soviet regions.

### Campaigns
- Qilin ransomware operations targeting manufacturing, healthcare, and other critical sectors in Japan.

## 5. Splunk Detection Searches
### Detection for EDR Killer Malware
```spl
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon
| search EventID=1 Image="*\EDRKiller.exe"
| stats count by Computer, User, Image
| where count > 0
```
*Detects execution of EDR Killer malware based on process creation logs.*

### Detection for Credential Harvesting
```spl
index=main sourcetype=XmlWinEventLog:Security
| search EventCode=4624 LogonType=3 AccountName="*"
| stats count by AccountName, ComputerName
| where count > 5
```
*Detects suspicious logon activity using stolen credentials.*

### Detection for Geo-fencing Malware
```spl
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon
| search EventID=1 CommandLine="*locale*"
| stats count by Computer, User, CommandLine
| where count > 0
```
*Detects malware performing geo-fencing checks based on locale settings.*

### Detection for Ransomware Execution
```spl
index=main sourcetype=XmlWinEventLog:Security
| search EventCode=4663 ObjectType="File" AccessMask="WRITE_DAC"
| stats count by ObjectName, AccountName
| where count > 10
```
*Detects ransomware encrypting files by monitoring file access control changes.*

## 6. Executive Summary
Qilin ransomware affiliates have been observed leveraging advanced techniques, including EDR killer malware and geo-fencing, to evade detection and target critical sectors in Japan. The group primarily relies on stolen credentials for initial access and demonstrates operational maturity with refined attack manuals. Manufacturing and healthcare sectors are heavily targeted, with ransomware execution typically occurring six days post-compromise. Immediate actions include deploying detection rules for credential misuse, monitoring endpoint activity for EDR tampering, and implementing robust defenses against ransomware execution.