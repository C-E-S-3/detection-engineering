---
scraped_at: "2026-04-02T19:02:19Z"
source_url: "https://blog.talosintelligence.com/the-democratisation-of-business-email-compromise-fraud/"
report_type: threat-intel
severity: "high"
title: "React2Shell Exploitation Campaign Targets Next.js Applications"
---

## 1. Indicators of Compromise (IOCs)
### IP Addresses
None identified.

### Domains/URLs
None identified.

### File Hashes
- **SHA256:** `96fa6a7714670823c83099ea01d24d6d3ae8fef027f01a4ddac14f123b1c9974`
  - **Context:** Associated with W32.Injector:Gen.21ie.1201 malware.
- **SHA256:** `9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507`
  - **Context:** Associated with Win.Worm.Coinminer::1201 malware.
- **SHA256:** `90b1456cdbe6bc2779ea0b4736ed9a998a71ae37390331b6ba87e389a49d3d59`
  - **Context:** Associated with Auto.90B145.282358.in02 malware.
- **SHA256:** `38d053135ddceaef0abb8296f3b0bf6114b25e10e6fa1bb8050aeecec4ba8f55`
  - **Context:** Associated with W32.38D053135D-95.SBX.TG malware.
- **SHA256:** `5e6060df7e8114cb7b412260870efd1dc05979454bd907d8750c669ae6fcbcfe`
  - **Context:** Associated with W32.5E6060DF7E-100.SBX.TG malware.
- **SHA256:** `e303ac1a9b378382830fc6a0b5a9574eca415d14d9282e2b4aced725db9cfbc5`
  - **Context:** Associated with W32.E303AC1A9B-95.SBX.TG malware.

### Other IOCs
None identified.

## 2. TTPs (MITRE ATT&CK Mapping)
### Tactic: Initial Access
- **Technique ID:** T1190
- **Technique Name:** Exploit Public-Facing Application
- **Description:** Attackers exploit the React2Shell vulnerability (CVE-2025-55182) in Next.js applications to gain unauthorized access.

### Tactic: Credential Access
- **Technique ID:** T1552
- **Technique Name:** Unsecured Credentials
- **Description:** Automated credential harvesting campaign extracts sensitive data such as cloud tokens, database credentials, and SSH keys from compromised hosts.

### Tactic: Persistence
- **Technique ID:** T1078
- **Technique Name:** Valid Accounts
- **Description:** Attackers use harvested credentials to establish persistent, unauthenticated access.

### Tactic: Defense Evasion
- **Technique ID:** T1070
- **Technique Name:** Indicator Removal on Host
- **Description:** Attackers shuffle stolen credentials through multiple transfers to obscure the trail.

### Tactic: Lateral Movement
- **Technique ID:** T1210
- **Technique Name:** Exploitation of Remote Services
- **Description:** Attackers use harvested credentials to move laterally within compromised environments.

## 3. Malware & Tools
### Malware Families
- W32.Injector:Gen.21ie.1201
- Win.Worm.Coinminer::1201
- Auto.90B145.282358.in02
- W32.38D053135D-95.SBX.TG
- W32.5E6060DF7E-100.SBX.TG
- W32.E303AC1A9B-95.SBX.TG

### Tools
- **NEXUS Listener:** A custom framework used to automatically extract and aggregate sensitive data from compromised hosts.

## 4. Threat Actor / Campaign Attribution
### Threat Actor
- **Name:** Unknown
- **Motivation:** Credential harvesting and lateral movement.
- **Targeted Sectors:** Organizations using Next.js applications, potentially spanning multiple industries.

### Campaign
- **Name:** React2Shell Exploitation Campaign
- **Description:** Large-scale automated credential harvesting campaign exploiting the React2Shell vulnerability in Next.js applications.

## 5. Splunk Detection Searches
### Network IOCs
```spl
index=network
sourcetype=pan:traffic OR sourcetype=proxy
| search dest_ip IN ("142.11.206.73", "23.254.167.216")
| stats count by dest_ip, src_ip, dest_port
| table dest_ip, src_ip, dest_port, count
```
*Detects network traffic to known C2 servers.*

### Endpoint IOCs
```spl
index=endpoint
sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon
| search Image="*\d4aa3e7010220ad1b458fac17039c274_63_Exe.exe" OR Image="*\9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507.exe" OR Image="*\APQ9305.dll" OR Image="*\content.js" OR Image="*\a2cf85d22a54e26794cbc7be16840bb1.exe" OR Image="*\48a4f5fb6dc4633a41e6fe0aa65b4fa6.exe"
| stats count by Image, Computer
| table Image, Computer, count
```
*Detects execution of malicious files associated with the campaign.*

### Behavioral TTPs
```spl
index=web
sourcetype=web:access
| search "POST /api/*" "React2Shell" "CVE-2025-55182"
| stats count by uri, src_ip
| table uri, src_ip, count
```
*Detects exploitation attempts targeting Next.js applications.*

## 6. Executive Summary
Cisco Talos has identified a large-scale automated credential harvesting campaign exploiting the React2Shell vulnerability (CVE-2025-55182) in Next.js applications. Using a custom framework called NEXUS Listener, attackers rapidly extract sensitive data such as cloud tokens, database credentials, and SSH keys from compromised hosts. This campaign poses significant risks for lateral movement and supply chain integrity. Organizations should audit Next.js applications, rotate compromised credentials, and implement robust security measures such as RASP and WAF rules to mitigate the threat.