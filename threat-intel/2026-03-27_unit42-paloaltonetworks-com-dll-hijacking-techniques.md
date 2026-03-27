---
scraped_at: 2024-06-10T15:30:00Z
source_url: https://unit42.paloaltonetworks.com/dll-hijacking-techniques/
report_type: threat-intel
---

# Threat Intelligence Report: DLL Hijacking Techniques

**Note:** The provided content is a partial scrape containing mostly site metadata, JavaScript, and CSS. However, some threat intelligence keywords and context are available from metadata and keywords.

## 1. Indicators of Compromise (IOCs)

No explicit IOCs (IP addresses, domains, file hashes, email addresses, file names/paths, registry keys, mutexes, or C2 infrastructure) are present in the provided text.

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactic: Execution
- **Technique:** T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking
  - **Description:** Adversaries abuse DLL hijacking by placing a malicious DLL in a location where a legitimate application will load it instead of the intended DLL, enabling execution of attacker code.

### Tactic: Defense Evasion
- **Technique:** T1036.005 - Masquerading: Match Legitimate Name or Location
  - **Description:** Malicious DLLs are named and placed to mimic legitimate files, evading detection.

### Tactic: Persistence
- **Technique:** T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
  - **Description:** DLL hijacking may be used in conjunction with persistence mechanisms, though not explicitly detailed in the metadata.

## 3. Malware & Tools

### Malware Families Mentioned (from metadata/keywords)
- **AsyncRAT:** Remote Access Trojan known for using DLL hijacking and sideloading.
- **Cloaked Ursa:** Threat actor/campaign known for DLL hijacking.
- **Dridex:** Banking Trojan frequently using DLL hijacking for execution and persistence.
- **PlugX:** RAT commonly deployed via DLL sideloading/hijacking.

### Legitimate Tools Abused
- **DLL Sideloading/Hijacking:** Abuse of legitimate Windows applications to load malicious DLLs.

### Custom Tooling
- No explicit custom tools described in the metadata.

## 4. Threat Actor / Campaign Attribution

### Named Threat Groups / Campaigns
- **Cloaked Ursa:** Known threat actor/campaign leveraging DLL hijacking.
- **Dridex Operators:** Financially motivated group using Dridex malware.
- **PlugX Operators:** Often associated with Chinese APTs.

### Known Affiliations or Motivations
- **Cybercrime:** Financially motivated (Dridex, PlugX).
- **Espionage:** Possible (PlugX, Cloaked Ursa).
- **Targeted Sectors:** Not specified in metadata, but historically includes finance, government, and enterprise.

### Targeted Geographies
- Not specified in metadata.

## 5. Splunk Detection Searches

### DLL Hijacking Detection (Sysmon)
```spl
# Detect suspicious DLL loading by legitimate processes (DLL hijacking)
index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=7
| eval dll_path=Lower(ImageLoaded)
| search dll_path IN ("*asyncRAT*", "*dridex*", "*plugx*")
| stats count by Image, dll_path, Hostname, User
```
*Detects suspicious DLLs loaded by legitimate processes, focusing on known malware families.*

### DLL Sideloading (Windows Security Logs)
```spl
# Look for DLLs loaded from unusual locations by trusted binaries
index=endpoint sourcetype=WinEventLog:Security EventCode=4688
| where like(CommandLine, "%.dll%") AND (like(CommandLine, "%AppData%") OR like(CommandLine, "%Temp%"))
| stats count by ParentProcessName, CommandLine, User, Computer
```
*Detects DLLs loaded from user-writable directories by trusted processes.*

### Malware Family Hash Lookup (CrowdStrike)
```spl
# Search for known Dridex, PlugX, AsyncRAT hashes (if available)
index=crowdstrike:events:sensor
| lookup malware_hashes hash as FileHash OUTPUT malware_family
| where malware_family IN ("Dridex", "PlugX", "AsyncRAT")
| stats count by FileName, FileHash, malware_family, ComputerName
```
*Correlates endpoint events with known malware hashes (requires hash list).*

### Suspicious Process Creation (DLL Hijacking Context)
```spl
# Correlate DLL loading with process creation for known LOLBins abused in DLL hijacking
index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1 OR EventCode=7
| transaction ProcessId startswith=EventCode=1 endswith=EventCode=7
| search Image IN ("*regsvr32.exe*", "*rundll32.exe*", "*svchost.exe*")
| stats count by Image, ImageLoaded, Hostname, User
```
*Detects DLL hijacking via common LOLBins.*

## 6. Executive Summary

DLL hijacking remains a prevalent technique for both cybercriminal and espionage-focused threat actors, enabling stealthy execution and persistence of malware such as AsyncRAT, Dridex, PlugX, and campaigns like Cloaked Ursa. Attackers abuse legitimate Windows applications to load malicious DLLs, often evading detection by masquerading as trusted files. Organizations should prioritize monitoring for suspicious DLL loading, especially from user-writable directories and by trusted binaries, and correlate endpoint events with known malware families. Immediate actions include tightening application whitelisting, monitoring for DLL hijacking behaviors, and updating endpoint detection rules to cover these techniques.

---

**No explicit IOCs were found in the provided content. This report is based on metadata, keywords, and known threat context. For actionable IOCs, refer to the full Unit 42 article or threat intelligence feeds.**
