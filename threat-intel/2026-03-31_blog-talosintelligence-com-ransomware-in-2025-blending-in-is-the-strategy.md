---
scraped_at: "2026-03-31T10:00:02.000Z"
source_url: "https://blog.talosintelligence.com/ransomware-in-2025-blending-in-is-the-strategy/"
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

No new IOCs were identified in the source.

## 2. TTPs (MITRE ATT&CK Mapping)

- **Tactic: Initial Access**
  - **Technique ID**: T1566.001 (Spearphishing Attachment)
  - **Description**: 40% of ransomware initial access is achieved through phishing attacks.

- **Tactic: Lateral Movement**
  - **Technique ID**: T1021.001 (Remote Desktop Protocol)
  - **Description**: Ransomware actors use RDP to move laterally within networks.

  - **Technique ID**: T1059.001 (PowerShell)
  - **Description**: PowerShell is used by ransomware actors for lateral movement and system exploration.

  - **Technique ID**: T1569.002 (System Services: Service Execution)
  - **Description**: PsExec is leveraged by ransomware actors to execute commands and expand access.

- **Tactic: Credential Access**
  - **Technique ID**: T1078 (Valid Accounts)
  - **Description**: Ransomware actors use valid accounts for initial access, lateral movement, and execution.

## 3. Malware & Tools

- **Malware Families**:
  - **Qilin**: A ransomware group employing double-extortion tactics, combining data encryption with threats to release stolen information publicly.
  - **Akira**: A ransomware group known for evolving tactics and absorbing affiliates from defunct groups.
  - **Play**: Another prominent ransomware group with adaptable tactics.

- **Tools Abused**:
  - **RDP**: Used for lateral movement.
  - **PowerShell**: Used for system exploration and lateral movement.
  - **PsExec**: Used for command execution and access expansion.

## 4. Threat Actor / Campaign Attribution

- **Threat Actors**:
  - **Qilin**: Ranked as the most active ransomware group in 2025, targeting over 40 victims per month (except January).
  - **Akira**: Ranked second in activity, leveraging evolving tactics and absorbing affiliates.
  - **Play**: Ranked third, maintaining prominence through adaptable strategies.

- **Targeted Sectors**:
  - **Manufacturing**: The most targeted sector due to its complex environments and limited tolerance for disruption.
  - **Professional, Scientific, and Technical Services**: The second most targeted sector, facing exposure due to access spanning multiple systems or organizations.

## 5. Splunk Detection Searches

### Detecting RDP Usage for Lateral Movement
```spl
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Security-Auditing EventCode=4624 LogonType=10
| stats count by Account_Name, ComputerName, IpAddress
| where count > 10
| table Account_Name, ComputerName, IpAddress
# This search identifies multiple RDP logins from the same account, which could indicate lateral movement.
```

### Detecting Suspicious PowerShell Commands
```spl
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-PowerShell
| search EventCode=4104
| search "Invoke-Expression" OR "IEX" OR "DownloadString"
| stats count by User, CommandLine
| where count > 5
| table User, CommandLine
# This search identifies potentially malicious PowerShell commands being executed.
```

### Detecting PsExec Usage
```spl
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1
| search Image="*\\PsExec.exe"
| stats count by User, ComputerName, CommandLine
| where count > 5
| table User, ComputerName, CommandLine
# This search identifies the use of PsExec for lateral movement or command execution.
```

### Detecting Valid Account Usage for Lateral Movement
```spl
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Security-Auditing EventCode=4624
| stats count by Account_Name, Logon_Type, IpAddress
| where Logon_Type=3 OR Logon_Type=10
| table Account_Name, Logon_Type, IpAddress
# This search identifies the use of valid accounts for lateral movement.
```

## 6. Executive Summary

The Cisco Talos report highlights a significant shift in ransomware tactics, with attackers increasingly blending into legitimate user activity to evade detection. Ransomware groups like Qilin, Akira, and Play are leveraging tools such as RDP, PowerShell, and PsExec for lateral movement and system compromise. Manufacturing and professional services sectors remain top targets due to their complex environments and high exposure. Organizations are advised to strengthen identity protections, monitor administrative tool usage, and enhance their ransomware response readiness to mitigate these evolving threats.