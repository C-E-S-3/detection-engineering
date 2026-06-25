---
scraped_at: 2026-06-23T00:00:00Z
source_url: https://securelist.com/whatsapp-vbs-rmm-campaign/120290/
report_type: threat-intel
severity: high
title: "Unknown Chinese-Linked Actor Distributes VBScript via WhatsApp to Deploy ManageEngine Endpoint Central RMM"
---

## 1. IOCs

### IP Addresses

| Indicator | Type | Context |
|-----------|------|---------|
| 202.61.160[.]201 | IPv4 | Stage-2 VBScript download server; infrastructure overlap with ValleyRAT and Gh0st RAT prior campaigns; Asia-Pacific address space |

### Domains / URLs

No distinct C2 domains confirmed in public reporting; full IOC list in Kaspersky Securelist report.

### File Hashes

Full SHA256/MD5 hashes available in Securelist report (direct access blocked at time of collection). No hashes confirmed via secondary sources.

### Other Indicators

| Indicator | Type | Context |
|-----------|------|---------|
| Simplified Chinese code comments (Windows Update module references, system integrity checks) | Script artifact | Consistent across multiple VBScript variants; Chinese-language operator (low confidence) |
| ManageEngine Endpoint Central (preconfigured) | Tool | Legitimate RMM software abused as persistent remote access backdoor; delivered as ZIP archive |

---

## 2. TTPs (MITRE ATT\&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1566.004 | Phishing: Spearphishing via Messaging Service | VBScript attachments distributed via compromised WhatsApp accounts using plausible business document file names (invoices, bank statements, payment records) in multiple languages |
| Execution | T1204.002 | User Execution: Malicious File | Victim opens and runs VBScript attachment believing it is a legitimate financial document |
| Execution | T1059.005 | Command and Scripting Interpreter: Visual Basic | Obfuscated VBScript serves as first-stage dropper; downloads and executes two secondary VBScript payloads |
| Defense Evasion | T1548.002 | Abuse Elevation Control Mechanism: Bypass User Account Control | Secondary VBScript modifies HKCU registry keys to suppress UAC prompts; facilitates silent RMM installation |
| Defense Evasion | T1036 | Masquerading | VBScript files named as routine business documents (invoices, bank statements); legitimate ManageEngine binary used as backdoor |
| Command & Control | T1219 | Remote Access Software | ManageEngine Endpoint Central deployed as fully functional RMM backdoor providing persistent remote access |
| Command & Control | T1105 | Ingress Tool Transfer | ZIP archive containing preconfigured ManageEngine Endpoint Central downloaded from attacker-controlled server |

---

## 3. Malware & Tools

| Name | Type | Notes |
|------|------|-------|
| VBScript dropper (Stage 1) | Dropper | Obfuscated; embedded simplified Chinese comments; file name mimics business document |
| VBScript Stage 2a (UAC bypass) | Defense evasion | Modifies HKCU registry to disable UAC prompts; enables silent elevation |
| VBScript Stage 2b (RMM installer) | Loader | Downloads and extracts ZIP containing ManageEngine Endpoint Central from 202.61.160[.]201 |
| ManageEngine Endpoint Central | RMM (abused) | Legitimate remote monitoring and management software; preconfigured for attacker C2; not itself malicious but used as backdoor |

---

## 4. Threat Actor / Campaign Attribution

| Attribute | Detail |
|-----------|--------|
| Actor | Unknown; Kaspersky tracks as unnamed cluster |
| Nexus | Possibly China-nexus (low confidence) |
| Evidence | Simplified Chinese comments throughout VBScript variants; one C2 IP (202.61.160[.]201) overlaps with prior ValleyRAT and Gh0st RAT infrastructure |
| Campaign scale | Mass campaign; ~80% of victims in Malaysia; also Brazil, India, Mexico, Singapore, UK, Spain, Taiwan, Australia, Russia, Vietnam |
| Initial access vector | Compromised WhatsApp user accounts — exact compromise method unknown; attacker uses contact list for distribution |
| Objective | Persistent remote access via RMM for espionage, data theft, or follow-on compromise |

**Overlap with known actors:**
- ValleyRAT (Silk Typhoon-adjacent, primarily targeting Chinese-speaking diaspora and corporate networks)
- Gh0st RAT (historically associated with PRC-linked operations; widely reused by multiple actors)
- Low confidence — infrastructure overlap alone is insufficient for high-confidence attribution

---

## 5. Splunk Detection Searches

### 5a. VBScript Execution from User-Writable Paths

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where (Processes.process_name="wscript.exe" OR Processes.process_name="cscript.exe")
  AND (Processes.process="*.vbs*" OR Processes.process="*.vbe*")
  AND (Processes.process="*\\Downloads\\*" OR Processes.process="*\\AppData\\Roaming\\*"
    OR Processes.process="*\\AppData\\Local\\Temp\\*" OR Processes.process="*\\Desktop\\*")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(parent_process_name, "(?i)(whatsapp|telegram|signal|viber)"), 90,
    match(process, "(?i)(invoice|payment|statement|factura|rechnung|facture)"), 80,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### 5b. UAC Registry Bypass from VBScript Child Process

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Registry
where Registry.registry_path="*\\Software\\Classes\\ms-settings\\*"
  OR Registry.registry_path="*\\Software\\Classes\\mscfile\\shell\\open\\command*"
by Registry.dest Registry.user Registry.registry_path Registry.registry_value_name
   Registry.registry_value_data
| `drop_dm_object_name(Registry)`
| join dest [
  | tstats `security_content_summariesonly` count
    from datamodel=Endpoint.Processes
    where Processes.process_name="wscript.exe" OR Processes.process_name="cscript.exe"
    by Processes.dest
  ]
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime dest user registry_path registry_value_name registry_value_data risk_score
```

### 5c. ManageEngine Endpoint Central Installation from Unusual Parent

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where (Processes.process_name="ManageEngine_Endpoint_Central*.exe"
    OR Processes.process="*ManageEngine*EndpointCentral*"
    OR Processes.process="*DesktopCentral_Agent*.msi*")
  AND NOT (Processes.parent_process_name IN ("msiexec.exe", "setup.exe", "install.exe", "sccm*"))
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(parent_process_name, "(?i)(wscript|cscript|cmd|powershell)"), 90,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

---

## 6. Executive Summary

Kaspersky published research on June 22, 2026 documenting an ongoing mass campaign in which an unidentified threat actor — assessed with low confidence to be Chinese-speaking — distributes obfuscated VBScript files through compromised WhatsApp accounts. The lures are disguised as routine business documents (invoices, bank statements, debt notices) in multiple languages, maximizing cross-regional reach.

Once executed, the VBScript downloads two secondary scripts from an attacker-controlled server (202.61.160[.]201, overlapping with ValleyRAT and Gh0st RAT infrastructure). The first script bypasses Windows UAC by modifying HKCU registry keys; the second downloads and installs a preconfigured ManageEngine Endpoint Central package, giving the attacker full remote access to the compromised system.

Malaysia accounts for approximately 80% of observed infections, with additional victims across Brazil, India, Mexico, Singapore, UK, Spain, Taiwan, Australia, Russia, and Vietnam. The abuse of legitimate RMM software makes this campaign stealthy against endpoint detection tools that allowlist known administration tools.

**Recommended actions:**
- Block 202.61.160[.]201 at the network perimeter
- Alert on wscript.exe/cscript.exe spawning from Downloads or AppData paths
- Alert on UAC bypass registry modifications (HKCU\Software\Classes\ms-settings)
- Alert on ManageEngine Endpoint Central installation with scripting engine parent
- Review and restrict RMM software deployment to IT-managed processes only
