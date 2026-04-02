---
scraped_at: "2026-04-02T13:32:19Z"
source_url: "https://www.bleepingcomputer.com/news/security/medtech-giant-stryker-fully-operational-after-data-wiping-attack/"
report_type: threat-intel
severity: "high"
title: "Handala hacktivist group targets Stryker with data-wiping attack"
---

## 1. Indicators of Compromise (IOCs)
### IP Addresses
- None identified

### Domains
- None identified

### File Hashes
- None identified

### Other
- Global Administrator account created by attackers after compromising a Windows domain admin account

## 2. TTPs (MITRE ATT&CK Mapping)
### Tactics and Techniques
- **T1070.004 - Indicator Removal on Host: File Deletion**
  - Attackers used a malicious file to hide their activity while inside the network.
- **T1485 - Data Destruction**
  - Attackers deployed data-wiping malware to erase nearly 80,000 devices.
- **T1078.002 - Valid Accounts: Domain Accounts**
  - Attackers compromised a Windows domain admin account and created a Global Administrator account.

## 3. Malware & Tools
- **Data-Wiping Malware**
  - Used by the Handala group to erase systems during the attack.
- **Malicious File**
  - Discovered by investigators, used to hide malicious activity.

## 4. Threat Actor / Campaign Attribution
- **Threat Actor**: Handala (also known as Handala Hack Team, Hatef, Hamsa)
  - **Motivation**: Pro-Palestinian hacktivism, linked to Iran's Ministry of Intelligence and Security (MOIS).
  - **Targeted Sectors**: Healthcare and Israeli organizations.
  - **Known Activities**: Data-wiping malware attacks, sensitive data leaks.

## 5. Splunk Detection Searches
### Detecting Domain Account Compromise
```spl
index=wineventlog EventCode=4624 LogonType=2 OR LogonType=10
| stats count by Account_Name, Logon_Type, ComputerName
| where Logon_Type IN (2, 10) AND Account_Name="Domain Admin"
| table Account_Name, Logon_Type, ComputerName, count
```
*Detects interactive or remote logins using domain admin accounts.*

### Detecting Data-Wiping Malware Execution
```spl
index=sysmon EventID=1
| search Image="*\wiper.exe" OR CommandLine="*delete*"
| stats count by Image, CommandLine, ComputerName
```
*Detects execution of known data-wiping malware or suspicious file deletion commands.*

### Detecting Malicious File Activity
```spl
index=sysmon EventID=11
| search TargetFilename="*malicious_file_name*"
| stats count by TargetFilename, ComputerName
```
*Detects creation or modification of files identified as malicious.*

## 6. Executive Summary
The Iranian-linked Handala hacktivist group targeted Stryker Corporation, a leading medical technology company, in a significant data-wiping attack. The attackers compromised a Windows domain admin account, created a Global Administrator account, and deployed data-wiping malware to erase nearly 80,000 devices. Investigators also discovered a malicious file used to hide attacker activity within the network. This attack highlights the importance of securing domain accounts and implementing robust defenses against data-wiping malware. Immediate actions include reviewing domain account activity, enhancing endpoint monitoring, and applying guidance from CISA and Microsoft on securing Intune and hardening Windows domains.