---
scraped_at: "2026-10-07T00:00:00Z"
source_url: "https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/"
report_type: threat-intel
severity: high
title: "Blinder Tunnel: CL-STA-1178 Iran-Nexus Campaign Targets Iraqi Critical Infrastructure via GitHub C2 and ShelbyLoader V2"
---

## 1. Indicators of Compromise (IOCs)

### File Hashes

| Hash | Type | File | Description |
|------|------|------|-------------|
| `6e7d9b33f1e72ea1ede71373a604ecdb060dab7d42055179c1eede9ecd1fd239` | SHA256 | `DubaiAirport_Carrers_IT_Test.zip` | Initial malicious archive delivered via spear-phishing; poses as Dubai Airports IT recruitment coding challenge |
| `f5b12772db6817f7a765a6fe7565fd3d4f87edc28e42fe3ec0244a372a410fc9` | SHA256 | `FlightManager.csproj` | Weaponized Visual Studio project file; triggers AppDomainManager hijacking and DLL sideloading on build |
| `53f35e49eb9b271fd8cbcd3daacb525328dbf159a03dbd1c7adebe0363daa402` | SHA256 | `RuntimeBroker.dll` | ShelbyLoader V2 — primary malicious RAT loader; masquerades as Windows RuntimeBroker component |

### Phishing / Credential-Harvesting Domains

| Domain (defanged) | Role |
|-------------------|------|
| `cloud.g-drive[.]cam` | Fake Google Drive lure used in parallel credential-harvesting operation against Israeli entity |
| `googeldrive[.]cam` | Typosquat Google Drive lure |
| `drivegoogel[.]cam` | Typosquat Google Drive lure |
| `googelmeet[.]online` | Fake Google Meet lure |
| `meetonline[.]cam` | Fake Google Meet lure |

### C2 Infrastructure

GitHub repositories and issue pages used as dead-drop resolvers; specific repository URLs not disclosed by Unit 42. C2 commands encrypted with AES and hidden in GitHub issue comment bodies.

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Usage |
|--------|-----------|----|-------|
| Initial Access | Spearphishing Attachment | T1566.001 | Malicious ZIP delivered as a fake Dubai Airports IT coding challenge via recruitment-themed spear-phishing |
| Execution | User Execution: Malicious File | T1204.002 | Victim opens the .zip and triggers MSBuild on the FlightManager.csproj |
| Defense Evasion | Hijack Execution Flow: AppDomain Manager Injection | T1574.014 | `.csproj` file specifies a malicious AppDomainManager DLL (`RuntimeBroker.dll`); .NET runtime auto-loads the attacker's DLL before the application's own code |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 | Malicious DLL named `RuntimeBroker.dll` to blend with the legitimate Windows process |
| Defense Evasion | Obfuscated Files or Information | T1027 | C2 commands AES-encrypted inside GitHub issue comments |
| Command and Control | Web Service: Dead Drop Resolver | T1102.001 | ShelbyC2 V2 RAT polls GitHub issue comments to retrieve encrypted C2 commands and decryption keys |
| Command and Control | Protocol Tunneling | T1572 | Blackwood component runs the open-source Chisel utility in memory to create an encrypted TCP tunnel |
| Credential Access | Phishing | T1566 | Parallel campaign spoofing Google Drive to harvest credentials from Israeli targets |
| Collection | Data from Local System | T1005 | ShelbyC2 V2 RAT performs post-compromise data collection before tunneling |

---

## 3. Malware & Tools

| Name | Type | Description |
|------|------|-------------|
| **ShelbyLoader V2** | Loader/RAT stager | Malicious DLL masquerading as Windows RuntimeBroker; loads ShelbyC2 V2 payload in memory |
| **ShelbyC2 V2** | RAT | Full-featured remote access trojan; uses GitHub issues as dead-drop C2 channel with AES-encrypted commands; falls back to encrypted instructions in issue comments if access token is revoked |
| **Blackwood** | Tunneler | Custom memory-only tunneling component built on the open-source Chisel reverse proxy/tunnel utility; creates an encrypted TCP tunnel for persistent access |

---

## 4. Threat Actor / Campaign Attribution

| Field | Value |
|-------|-------|
| Cluster | CL-STA-1178 (Unit 42 designation) |
| State Nexus | Iran |
| Activity Period | Infrastructure staging: November 2025; Campaign activation: March 2026; GitHub C2 simulation: April 2026; Report published: October 6, 2026 |
| Primary Targets | Iraqi critical infrastructure; parallel credential-harvesting against Israeli entities |
| Attribution Indicators | Persian-language metadata in an MP3 embedded in the public repository; one C2 server hosted on an Iranian ISP; victimology and tradecraft overlap with known IRGC-linked campaigns |
| Linked Activity | Infrastructure ownership and tradecraft overlaps link CL-STA-1178 to Nimbus Manticore (Palo Alto) / APT34 subgroup (tentative) |

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="msbuild.exe"
    (Processes.process="*.csproj*" OR Processes.process="*.proj*")
    (Processes.process="*downloads*" OR Processes.process="*temp*" OR
     Processes.process="*appdata*" OR Processes.process="*desktop*" OR
     Processes.process="*documents*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)(downloads|desktop)"), 90,
    match(process,"(?i)(temp|appdata)"), 85,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```
*Detects MSBuild executing .csproj files from user-controlled directories — Blinder Tunnel delivery vector.*

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_name="RuntimeBroker.dll"
    NOT (Filesystem.file_path="*\\Windows\\System32\\*" OR
         Filesystem.file_path="*\\Windows\\SysWOW64\\*")
  by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path
     Filesystem.process_name Filesystem.process_id
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user file_name file_path process_name risk_score
```
*Detects creation of RuntimeBroker.dll outside of Windows system directories — ShelbyLoader V2 IOC.*

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_category="internet"
    All_Traffic.process_name IN ("msbuild.exe","dotnet.exe","csc.exe")
  by All_Traffic.src All_Traffic.dest_host All_Traffic.dest_port
     All_Traffic.process_name All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| where risk_score >= 85
| table firstTime lastTime src dest_host dest_port process_name user risk_score
```
*Detects .NET build tools making outbound internet connections — anomalous in most environments; may indicate ShelbyC2 GitHub C2 beacon.*

---

## 6. Executive Summary

Unit 42 published on October 6, 2026 a campaign report tracking CL-STA-1178, an Iran-state-aligned threat actor that targeted Iraqi critical infrastructure in a campaign called **Blinder Tunnel**. The actor impersonated the Dubai Airports IT department to deliver trojanized coding challenges to software engineers. Targets who downloaded and built the malicious Visual Studio project (`FlightManager.csproj`) triggered AppDomainManager injection, loading `ShelbyLoader V2` (`RuntimeBroker.dll`) into memory. The loader deployed `ShelbyC2 V2`, a RAT that uses GitHub issue comments as an encrypted dead-drop C2 channel — a technique that blends into legitimate developer traffic. A custom tunneling component called **Blackwood**, built on the open-source Chisel utility, provided persistent encrypted access. Attribution rests on Persian-language metadata embedded in the campaign's own decoy assets and Iranian ISP hosting.

The campaign demonstrates the increasing use of development environment abuse (weaponized .csproj files) and legitimate platform abuse (GitHub as C2) by Iranian APT actors. Security teams should monitor MSBuild processes executing projects from user-writable directories, outbound GitHub API calls from non-standard processes, and DLLs named after Windows components in non-system paths.
