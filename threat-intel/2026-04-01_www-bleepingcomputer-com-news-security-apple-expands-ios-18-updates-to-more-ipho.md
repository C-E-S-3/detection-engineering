---
scraped_at: "2026-04-01T17:50:49-04:00"
source_url: "https://www.bleepingcomputer.com/news/security/apple-expands-ios-18-updates-to-more-iphones-to-block-darksword-attacks/"
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### CVEs
- CVE-2025-31277
- CVE-2025-43529
- CVE-2026-20700
- CVE-2025-14174
- CVE-2025-43510
- CVE-2025-43520

## 2. TTPs (MITRE ATT&CK Mapping)

- **Tactic:** Initial Access  
  **Technique:** Exploit Public-Facing Application (T1190)  
  **Description:** The DarkSword exploit kit targets vulnerabilities in iOS versions 18.4 through 18.7 to gain unauthorized access to devices.

- **Tactic:** Collection  
  **Technique:** Input Capture (T1056)  
  **Description:** The GhostBlade JavaScript infostealer is used to steal sensitive information from compromised devices.

- **Tactic:** Command and Control  
  **Technique:** Remote Access Tools (T1219)  
  **Description:** The GhostKnife backdoor provides remote access capabilities to attackers.

- **Tactic:** Execution  
  **Technique:** Command and Scripting Interpreter: JavaScript (T1059.007)  
  **Description:** The GhostSaber JavaScript malware is used to execute arbitrary code on compromised devices.

## 3. Malware & Tools

- **GhostBlade:** A highly aggressive JavaScript-based information stealer.
- **GhostKnife:** A backdoor malware used for remote access.
- **GhostSaber:** JavaScript malware capable of executing code and stealing data.

## 4. Threat Actor / Campaign Attribution

- **PARS Defense:** A Turkish commercial surveillance vendor reportedly using the DarkSword exploit kit.
- **UNC6748:** A threat actor group observed utilizing the DarkSword exploit kit.
- **UNC6353:** A suspected Russian espionage group leveraging the DarkSword exploit kit.

## 5. Splunk Detection Searches

### CVE Exploitation Detection

```spl
index=web proxy
| search "CVE-2025-31277" OR "CVE-2025-43529" OR "CVE-2026-20700" OR "CVE-2025-14174" OR "CVE-2025-43510" OR "CVE-2025-43520"
| stats count by src_ip, dest_ip, uri_path, http_user_agent
```
*Comment: This search identifies potential exploitation attempts of the listed CVEs by analyzing web proxy logs for related indicators.*

### GhostBlade JavaScript Infostealer Detection

```spl
index=web OR index=endpoint
sourcetype=web_proxy OR sourcetype=XmlWinEventLog
| search "GhostBlade"
| stats count by src_ip, dest_ip, file_name, process_name
```
*Comment: This search detects activity related to the GhostBlade JavaScript infostealer by looking for its name in logs.*

### GhostKnife Backdoor Detection

```spl
index=endpoint
sourcetype=crowdstrike:events:sensor OR sourcetype=XmlWinEventLog
| search "GhostKnife"
| stats count by src_ip, dest_ip, process_name, parent_process_name
```
*Comment: This search identifies the presence of the GhostKnife backdoor on endpoints by detecting its process name.*

### GhostSaber JavaScript Malware Detection

```spl
index=web OR index=endpoint
sourcetype=web_proxy OR sourcetype=XmlWinEventLog
| search "GhostSaber"
| stats count by src_ip, dest_ip, file_name, process_name
```
*Comment: This search identifies activity related to the GhostSaber JavaScript malware by looking for its name in logs.*

## 6. Executive Summary

A new threat intelligence report highlights the active exploitation of the DarkSword exploit kit targeting iPhones running iOS versions 18.4 through 18.7. The kit exploits six CVEs, some of which have been patched in recent iOS updates. Threat actors, including Turkish surveillance vendor PARS Defense, UNC6748, and UNC6353, have been observed deploying three malware families—GhostBlade, GhostKnife, and GhostSaber—via this exploit kit. Organizations should prioritize patching affected iOS devices to version 18.7.7 or later and implement detection mechanisms for the associated IOCs and TTPs to mitigate potential risks.
