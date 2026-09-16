---
scraped_at: "2026-09-16T06:00:00Z"
source_url: "https://www.ncsc.gov.uk/news/uk-allies-expose-spyware-iranian-state-actors-target-dissidents-activists-journalists"
report_type: threat-intel
severity: high
title: "Iran MOIS HEAVYGRAM/CHOSEN BRICK Telegram-Controlled Spyware — NCSC/FBI/AIVD Joint Advisory"
---

# Iran MOIS HEAVYGRAM/CHOSEN BRICK Telegram-Controlled Spyware

**Published:** September 15, 2026  
**Authors:** UK NCSC, FBI, Netherlands AIVD  
**Advisory References:** FLASH-20260915-001 (FBI update to FLASH-20260320-001)

---

## 1. IOCs

### Domains (Legitimate Services Abused for C2)

| Indicator | Type | Notes |
|-----------|------|-------|
| api.telegram.org | Domain | Telegram Bot API endpoint used for bidirectional C2; each victim device communicates with a unique bot ID |

*Note: No attacker-controlled infrastructure IOCs were publicly released in this advisory. Specific SHA256 hashes and C2 Telegram bot tokens are available in the restricted FBI FLASH report (FLASH-20260915-001). The lack of public IOCs is intentional — releasing bot tokens would burn them.*

### Behavioral IOCs

| Indicator | Type | Notes |
|-----------|------|-------|
| HKCU\Software\Microsoft\Windows\CurrentVersion\Run | Registry | Persistence key where HEAVYGRAM/CHOSEN BRICK registers its executable for autostart on user logon |
| HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes | Registry | Malware adds its own process name to Defender exclusion list post-installation |
| HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths | Registry | Malware may also add its install directory to Defender path exclusions |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access (TA0001) | T1566.004 | Phishing: Spearphishing via Service | Attacker contacts victim via WhatsApp or Telegram, impersonating a known contact or the platform's technical support team; directs victim to install a fake app update |
| Initial Access (TA0001) | T1204.001 | User Execution: Malicious Link | Victim instructed to click link and install fake messaging platform update that bundles CHOSEN BRICK |
| Execution (TA0002) | T1059.001 | Command and Scripting Interpreter: PowerShell | Potential install-time setup; specific execution method not publicly confirmed |
| Persistence (TA0003) | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys/Startup Folder | Malware buries itself in a Windows registry Run key activated on every user logon |
| Defense Evasion (TA0005) | T1562.001 | Impair Defenses: Disable or Modify Tools | Adds itself to Microsoft Defender exclusion list (by process name and/or file path) to prevent real-time scanning |
| Collection (TA0009) | T1114 | Email Collection | Copies victim's emails for exfiltration |
| Collection (TA0009) | T1139 | Bash History | Reads message history from chat applications |
| Collection (TA0009) | T1113 | Screen Capture | Takes screenshots of the victim's screen |
| Collection (TA0009) | T1123 | Audio Capture | Activates device microphone to record audio |
| Collection (TA0009) | T1125 | Video Capture | Potential webcam access based on capability description |
| Collection (TA0009) | T1115 | Clipboard Data | May monitor clipboard content |
| Command and Control (TA0011) | T1102.002 | Web Service: Bidirectional Communication | Uses Telegram Bot API (api.telegram.org) for C2; each infected device communicates with a unique bot, preventing discovery of other victims from any single compromised device |
| Exfiltration (TA0010) | T1041 | Exfiltration Over C2 Channel | Collected data exfiltrated through the Telegram C2 channel |

---

## 3. Malware & Tools

### HEAVYGRAM (FBI designation) / CHOSEN BRICK (NCSC designation)

- **Platform:** Windows
- **Language:** Not publicly specified
- **First observed:** Autumn 2023 (wider campaign); active against UK/US/Netherlands targets from at least 2025
- **C2 mechanism:** Telegram Bot API — each infected device is assigned a unique Telegram bot, isolating victims from each other
- **Capabilities:**
  - Read emails and chat messages
  - Capture screenshots
  - Activate microphone for audio recording
  - Access contact lists
  - Monitor social media accounts
  - Exfiltrate collected data
- **Persistence:** Windows registry Run key (autostart on logon)
- **Defense evasion:** Self-adds to Microsoft Defender exclusion list (process name and/or path)
- **Installation lure:** Fake app updates for WhatsApp, Telegram, or tech support tools; a decoy "legitimate-looking screen" is displayed while CHOSEN BRICK installs silently in the background

---

## 4. Threat Actor / Campaign Attribution

### UNC6085 / Iran Ministry of Intelligence and Security (MOIS)

- **Attribution confidence:** High — joint assessment by NCSC, FBI, and AIVD
- **Sponsor:** Iranian Ministry of Intelligence and Security (MOIS), the country's primary civilian intelligence agency
- **Objectives:** Intelligence collection, surveillance, reputation damage, and operational pressure against individuals the Iranian regime views as opponents
- **Targets:** Iranian diaspora, dissidents, activists, journalists, human rights defenders, and academics in the UK, US, Netherlands, and globally
- **Campaign timeline:** Autumn 2023 – present (ongoing as of September 2026)
- **Related groups:** MOIS-linked clusters include MuddyWater (G0069), APT34/OilRig; however HEAVYGRAM/CHOSEN BRICK represents a distinct espionage-focused toolset targeting individuals rather than enterprise networks

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_host="api.telegram.org"
    AND NOT All_Traffic.app IN ("Chrome","Firefox","Safari","msedge","opera","brave","telegram","Telegram")
by All_Traffic.src All_Traffic.dest_host All_Traffic.app All_Traffic.process All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(app,"(?i)(powershell|wscript|cscript|cmd|mshta|regsvr32|rundll32)"), 95,
    match(app,"(?i)(python|node|java|javaw|werfault|svchost)"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime src user app process dest_host risk_score
```
*Detects non-browser, non-messaging processes connecting to api.telegram.org — a strong indicator of Telegram-based C2 malware such as HEAVYGRAM/CHOSEN BRICK.*

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Registry
where Registry.registry_key_name="*\\CurrentVersion\\Run*"
    AND NOT Registry.registry_value_data IN ("*Microsoft*","*Adobe*","*Google*","*Zoom*","*Teams*")
by Registry.dest Registry.user Registry.registry_key_name Registry.registry_value_name
   Registry.registry_value_data Registry.process_name
| `drop_dm_object_name(Registry)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(registry_value_data,"(?i)(\\\\AppData\\\\|\\\\Temp\\\\|\\\\ProgramData\\\\)"), 85,
    match(registry_value_data,"(?i)\\\\Users\\\\"), 75,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user registry_key_name registry_value_name registry_value_data process_name risk_score
```
*Detects new autostart Run key entries from non-standard paths, consistent with HEAVYGRAM persistence mechanism. Tune by adding known-good application names to the exclusion list.*

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Registry
where (Registry.registry_key_name="*\\Windows Defender\\Exclusions\\Processes*"
    OR Registry.registry_key_name="*\\Windows Defender\\Exclusions\\Paths*")
    AND NOT Registry.process_name IN ("MsMpEng.exe","SecurityHealthService.exe","MpCmdRun.exe","ConfigSecurityPolicy.exe","powershell.exe","pwsh.exe")
by Registry.dest Registry.user Registry.registry_key_name Registry.registry_value_name
   Registry.registry_value_data Registry.process_name
| `drop_dm_object_name(Registry)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(registry_value_data,"(?i)(\\\\AppData\\\\|\\\\Temp\\\\|\\\\ProgramData\\\\)"), 95,
    match(process_name,"(?i)(powershell|wscript|cscript|cmd|mshta)\.exe"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user registry_key_name registry_value_name registry_value_data process_name risk_score
```
*Detects Defender exclusion entries added directly to the registry by non-Defender processes — a specific HEAVYGRAM/CHOSEN BRICK evasion behavior. Note: the godloader_defender_exclusion_manipulation detection covers PowerShell-based Add-MpPreference; this rule catches direct registry writes.*

---

## 6. Executive Summary

On September 15, 2026, the UK's National Cyber Security Centre (NCSC), the FBI, and the Netherlands' General Intelligence and Security Service (AIVD) jointly published a technical advisory exposing a sustained Iranian state espionage campaign targeting dissidents, activists, and journalists worldwide.

The malware — designated HEAVYGRAM by the FBI and CHOSEN BRICK by the NCSC — is a Windows spyware family controlled via the Telegram messaging platform. Each infected device communicates with a unique Telegram bot, preventing discovery of other victims. Once installed, it can steal emails, read chat messages, take screenshots, record audio, and access contact lists.

The campaign is attributed with high confidence to Iran's Ministry of Intelligence and Security (MOIS). Targets are lured via WhatsApp or Telegram messages from accounts impersonating known contacts or platform technical support, directing them to install fake app updates that silently install the malware. The malware persists via Windows registry Run keys and evades detection by adding itself to Microsoft Defender's exclusion list.

The advisory updates a March 2026 FBI FLASH report with expanded malware analysis and new IOCs. Organizations supporting Iranian diaspora communities, journalists, human rights organizations, or academic researchers should treat any non-standard process communicating with the Telegram API as high-priority for investigation.

---

## References

- [NCSC — UK, US, Netherlands expose Iranian state spyware (2026-09-15)](https://www.ncsc.gov.uk/news/uk-allies-expose-spyware-iranian-state-actors-target-dissidents-activists-journalists)
- [FBI IC3 Technical Report FLASH-20260915-001 (PDF)](https://www.ic3.gov/CSA/2026/260915.pdf)
- [FBI FLASH-20260320-001 — Initial MOIS Telegram C2 Campaign Alert (2026-03-20)](https://www.ic3.gov/CSA/2026/260320.pdf)
- [Computer Weekly — UK, US, Netherlands warn over Iranian state spyware (2026-09-15)](https://www.computerweekly.com/news/366650300/UK-US-and-Netherlands-warn-over-Iranian-state-spyware-campaign)
- [NuclearCoffee — Iranian Hackers Use Telegram-Controlled Malware](https://nuclearcoffee.org/iranian-hackers-use-telegram-controlled-malware-to-spy-on-dissidents-and-journalists/)
- [MITRE ATT&CK — T1102.002 Web Service: Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002/)
- [MITRE ATT&CK — T1547.001 Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE ATT&CK — T1562.001 Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
