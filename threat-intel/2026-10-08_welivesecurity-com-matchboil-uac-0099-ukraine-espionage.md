---
scraped_at: "2026-10-13T00:00:00Z"
source_url: "https://www.welivesecurity.com/en/eset-research/matchboil-new-tricks-same-old-evil-intentions/"
report_type: threat-intel
severity: high
title: "MATCHBOIL: New Tricks, Same Old Evil Intentions — UAC-0099 Upgrades Dropper, Deploys MATCHWOK Backdoor Against Ukrainian Critical Infrastructure"
---

## 1. IOCs

### Domains

> **Note:** The complete ESET IOC appendix is hosted on welivesecurity.com (DNS unavailable in this environment). The indicators below are from CERT-UA's earlier MATCHBOIL V2 advisory and may not reflect all infrastructure from the October 2026 ESET publication. Cross-reference with ESET's GitHub IoC repository for the full list.

| Indicator | Role |
|-----------|------|
| kaufen-qpon[.]icu | MATCHBOIL V2 C2 domain (CERT-UA advisory, earlier campaign) |

### IPs

| Indicator | Role |
|-----------|------|
| 64[.]94[.]84[.]204 | MATCHBOIL V2 C2 server IP (CERT-UA advisory, earlier campaign) |

### Hashes

No hashes published in accessible secondary reporting. See ESET GitHub for full sample SHA-256 list.

### Artifacts

| Artifact | Description |
|----------|-------------|
| `DocumentTask` | Windows scheduled task name created by MATCHBOIL for persistence |
| `*.dll` (custom C# loader) | MATCHBOIL V2/V3 delivered as a DLL loaded by a custom C# bootstrapper |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment | Spearphishing emails to Ukrainian organizations in transportation, manufacturing, and energy; archive contains VBScript/HTA dropper |
| Initial Access | T1566.002 | Phishing: Spearphishing Link | Links to archives hosting VBScript files in some delivery variants |
| Execution | T1204.002 | User Execution: Malicious File | Victim opens archive; VBScript or HTA auto-executes or requires user double-click |
| Execution | T1059.005 | Command and Scripting Interpreter: Visual Basic | VBScript stage downloads and executes MATCHBOIL dropper |
| Execution | T1218.005 | System Binary Proxy Execution: Mshta | HTA file variant uses mshta.exe for LOLBin execution |
| Defense Evasion | T1027 | Obfuscated Files or Information | .NET Reactor obfuscation applied to MATCHBOIL dropper; code mutation to hinder static analysis |
| Defense Evasion | T1497 | Virtualization/Sandbox Evasion | MATCHBOIL V3 checks for sandbox artifacts before executing payload |
| Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task | MATCHBOIL creates `DocumentTask` scheduled task pointing to MATCHWOK backdoor path |
| Persistence | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Alternative persistence via HKCU\Software\Microsoft\Windows\CurrentVersion\Run |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | MATCHWOK backdoor communicates over HTTPS; polls C2 every 2 minutes |
| Command and Control | T1041 | Exfiltration Over C2 Channel | System metadata (hostname, username, OS version) embedded in HTTPS request headers during initial C2 registration |
| Discovery | T1082 | System Information Discovery | MATCHBOIL gathers host information prior to C2 registration |

---

## 3. Malware & Tools

| Name | Type | Notes |
|------|------|-------|
| MATCHBOIL | C# Downloader / Dropper | Fetches MATCHWOK payload via three-stage HTTPS exchange; V2 (April 2026) is first DLL variant loaded by custom C# bootstrapper; V3 adds enhanced sandbox evasion; C2 server address stored in local config file |
| MATCHWOK | C# Backdoor | Full-featured backdoor attributed exclusively to UAC-0099; polls C2 every 2 minutes; provides remote shell, file operations, and keylogging capabilities |

---

## 4. Threat Actors

| Actor | Description |
|-------|-------------|
| UAC-0099 | Russia-aligned threat actor (medium confidence attribution); assessed by ESET as a possible initial access broker supplying access to Sandworm; active since at least 2024; exclusively targets Ukrainian organizations; CERT-UA first documented MATCHBOIL in August 2025 |

---

## 5. Victims / Targeting

| Sector | Country |
|--------|---------|
| Transportation | Ukraine |
| Manufacturing / Industrial | Ukraine |
| Energy | Ukraine |

---

## 6. Recommended SPL Searches

### Hunt: MATCHBOIL DocumentTask Scheduled Task Creation

```spl
index=wineventlog EventCode=4698
| rex field=Message "Task Name:\s*(?<task_name>[^\n]+)"
| rex field=Message "Action:.*?(?:Command|Arguments):\s*(?<task_action>[^\n]+)"
| where like(lower(task_name), "%documenttask%")
| eval risk_score=90
| table _time dest user task_name task_action risk_score
```

### Hunt: VBScript / HTA Spawning MATCHBOIL

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.parent_process_name="wscript.exe" OR Processes.parent_process_name="mshta.exe"
         OR Processes.parent_process_name="cscript.exe")
    AND (Processes.process_name="schtasks.exe")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| search process="*DocumentTask*"
| eval risk_score=85
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Hunt: MATCHBOIL C2 Domain (CERT-UA V2 IOC)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query="kaufen-qpon.icu"
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src query answer risk_score
```

---

## 7. Executive Summary

ESET Research published October 8, 2026 detailed analysis of MATCHBOIL, a custom C# downloader attributed to UAC-0099, a Russia-aligned threat actor exclusively targeting Ukrainian critical infrastructure. The malware has evolved through at least three versions since April 2024, with the most recent variant (V2/V3) delivered as a DLL loaded by a custom C# bootstrapper — a significant operational security improvement over earlier standalone executables.

The campaign begins with spearphishing emails delivering archives containing VBScript or HTA files. Upon user execution, the dropper downloads MATCHBOIL via HTTPS, which in turn fetches the MATCHWOK C# backdoor and establishes persistence via a scheduled task named "DocumentTask." MATCHWOK polls its C2 server every two minutes and embeds system metadata in HTTP headers during initial registration.

ESET assesses UAC-0099 as a possible initial access broker supplying footholds to other Russia-aligned actors, including Sandworm. All confirmed victims are Ukrainian organizations in transportation, manufacturing, and energy — sectors aligned with Russian targeting priorities.

---

## 8. References

- [ESET WeLiveSecurity — MATCHBOIL: New tricks, same old evil intentions (2026-10-08)](https://www.welivesecurity.com/en/eset-research/matchboil-new-tricks-same-old-evil-intentions/)
- [Infosecurity Magazine — Russia-Aligned UAC-0099 Evolves MATCHBOIL Malware](https://www.infosecurity-magazine.com/news/russia-aligned-uac-0099-evolves/)
- [The Record — Russian-aligned spies upgrade malware used in attacks on Ukrainian transport, energy firms](https://therecord.media/russia-ukraine-malware-transportation)
- [Dark Reading — Russian Spies Give 'MatchBoil' Malware a Stealthy Facelift](https://www.darkreading.com/cyberattacks-data-breaches/russian-spies-matchboil-malware-facelift)
- [Help Net Security — What is MATCHBOIL? (2026-10-08)](https://www.helpnetsecurity.com/2026/10/08/matchboil-malware-uac-0099/)
- [MITRE ATT&CK — T1053.005 Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- [CERT-UA Advisory (earlier MATCHBOIL V2 campaign)](https://cert.gov.ua/)
