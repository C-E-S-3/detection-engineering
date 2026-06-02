---
scraped_at: 2026-06-02T00:00:00Z
source_url: https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/
report_type: threat-intel
severity: high
title: "Screening Serpens (UNC1549 / Smoke Sandstorm): MiniUpdate RAT and MiniJunk V2 Target US, Israel, and UAE in Conflict-Aligned Espionage"
---

## 1. IOCs

No specific network indicators (C2 domain names, IP addresses, or file hashes) were publicly released in the Unit 42 report at time of this writing. Unit 42 notes that the group uses **three to five Azure-hosted C2 domains per target**, with domain names chosen to resemble legitimate Windows service process names (e.g., patterns resembling `svchost`, `winupdate`, `msdefender`). These domains rotate per campaign wave.

**Behavioral IOCs:**
- Signed Windows binaries (Microsoft-signed or third-party-signed .NET applications) spawning unexpected child processes or loading DLLs from non-standard paths
- Presence of `.config` files in program directories with `appDomainManagerAssembly` or `appDomainManagerType` XML elements not matching the application's legitimate assembly
- Outbound HTTPS connections from .NET host processes to Azure-hosted domains (*.azurewebsites.net, *.blob.core.windows.net, *.azurestaticapps.net) not matching known SaaS applications
- Executable files padded to ~12 MB via embedded junk code strings (MiniJunk V2 file inflation anti-analysis technique)
- DLL files loaded from non-standard paths alongside otherwise-legitimate executables (two-stage sideloading chain)
- Spear-phishing emails impersonating aerospace/defense recruitment portals with job description attachments

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment | Highly personalized spear-phishing lures disguised as aerospace/defense/telecom job recruitment; tailored to each target's professional profile |
| Initial Access | T1566.002 | Phishing: Spearphishing Link | Fake hiring portals and spoofed employment websites used to deliver malicious .NET applications or DLLs |
| Execution | T1574.014 | Hijack Execution Flow: AppDomainManager | MiniUpdate: trojanized `.config` file alongside a legitimate .NET binary forces the CLR to load an attacker-controlled `AppDomainManager` DLL at runtime, intercepting the initialization phase before security controls engage |
| Execution | T1574.002 | Hijack Execution Flow: DLL Side-Loading | Two-stage DLL sideloading chain: Stage 1 legitimate signed binary loads attacker DLL; Stage 2 payload DLL loads the final MiniUpdate or MiniJunk V2 RAT into memory |
| Defense Evasion | T1027.009 | Obfuscated Files or Information: Embedded Payloads | MiniJunk V2 inflates binary size to ~12 MB by embedding thousands of meaningless Java/Python code strings, pushing past automated scanner file-size limits and flooding analysis tools with noise |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location | Azure C2 domains named to resemble Windows service processes; signed host executables mimic legitimate management tools |
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | MiniUpdate supports UAC privilege escalation opcode to disable endpoint defenses |
| Persistence | T1574.014 | Hijack Execution Flow: AppDomainManager | `.config` file persistence in program directory ensures RAT loads on every execution of the legitimate host application |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | All MiniUpdate and MiniJunk V2 C2 traffic uses HTTPS to Azure-hosted endpoints |
| Command and Control | T1102 | Web Service | Azure cloud services abused as C2 hosting, blending in with legitimate enterprise traffic |
| Collection | T1005 | Data from Local System | MiniUpdate supports file exfiltration opcodes; chunked upload capability added in April 2026 variants for stealthier large-file exfil |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | Arbitrary shell command execution opcode supported; observed deploying PowerShell post-compromise |
| Discovery | T1057 | Process Discovery | MiniUpdate process enumeration and termination opcodes |
| Defense Evasion | T1620 | Reflective Code Loading | MiniUpdate supports dynamic DLL loading into memory via opcode, enabling memory-resident payloads without disk writes |

**Infection Chain (MiniUpdate):**
1. Target receives a personalized spear-phishing email with a job description lure for an aerospace/defense/telecom role.
2. Malicious attachment or link delivers a legitimate-looking .NET application alongside a trojanized `.config` file and a sideloaded DLL.
3. When the host .NET binary executes, the CLR reads the `.config` file and loads the attacker's AppDomainManager before the application starts (Stage 1 sideload).
4. The AppDomainManager DLL performs a second sideload, loading the MiniUpdate RAT payload into process memory.
5. MiniUpdate establishes HTTPS C2 to one of three to five Azure-hosted domains dedicated to this target.
6. The RAT operator issues commands via a 16–18 opcode dispatcher: shell execution, process list/kill, file exfil, DLL injection, UAC bypass, chunked upload.

**MiniJunk V2 distinguishing characteristics:**
- Evolved from original MiniJunk tracked by Check Point Research / Nimbus Manticore (same underlying malware family, distinct attribution cluster)
- File size inflated from typical <2 MB to ~12 MB via junk code strings from multiple programming languages
- Same infection chain as MiniUpdate (spear-phish → sideloading → Azure C2) but with separate dedicated infrastructure per target

## 3. Malware & Tools

| Malware | Platform | Description |
|---------|----------|-------------|
| MiniUpdate | Windows (.NET) | New RAT family first identified by Unit 42; deployed via AppDomainManager hijacking; 16–18 opcode command dispatcher supporting shell execution, process enumeration/kill, file exfil, in-memory DLL loading, UAC bypass, chunked file upload; samples uploaded March 26, April 15, April 17, 2026 |
| MiniJunk V2 | Windows (.NET) | Evolution of MiniJunk (first seen in Nimbus Manticore campaign); file-size inflation to ~12 MB using embedded junk strings defeats scanner thresholds; same sideloading chain as MiniUpdate; samples uploaded February 17 and March 27, 2026 |

## 4. Threat Actor / Campaign Attribution

| Attribute | Detail |
|-----------|--------|
| Threat Actor | Screening Serpens |
| Aliases | UNC1549 (Mandiant/Google), Smoke Sandstorm (Microsoft), Iranian Dream Job (ClearSky) |
| Nexus | Iran — suspected Islamic Revolutionary Guard Corps (IRGC) or Ministry of Intelligence |
| Active since | At least 2022; expanded into Western Europe in late 2025 |
| Campaign timeline | February–April 2026 (samples aligned with regional conflict starting February 28, 2026) |
| Target sectors | Aerospace, defense manufacturing, telecommunications, technology |
| Target countries | United States, Israel, United Arab Emirates; likely two additional Middle Eastern entities |
| Motivation | Espionage; intelligence collection aligned with Iranian geopolitical priorities during regional conflict |
| Relationship to Nimbus Manticore | Both groups deploy MiniJunk variants and use AppDomainManager hijacking; Unit 42 and Check Point track as separate clusters — possible task-sharing within IRGC apparatus |

## 5. Splunk Detection Searches

```spl
| comment "Search 1: AppDomainManager hijacking — .config file written to program directory with appDomainManager XML element"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_name="*.config"
    AND (Filesystem.file_path="*\\Program Files\\*"
         OR Filesystem.file_path="*\\Program Files (x86)\\*"
         OR Filesystem.file_path="*\\ProgramData\\*"
         OR Filesystem.file_path="*\\AppData\\Local\\*")
    AND Filesystem.action=created
    AND NOT Filesystem.process_name IN ("msiexec.exe","setup.exe","install.exe","devenv.exe","nuget.exe","dotnet.exe","vsdbg.exe")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| where risk_score >= 75
| table firstTime lastTime dest user file_path file_name process_name risk_score
```

```spl
| comment "Search 2: MiniUpdate / MiniJunk sideloading — legitimate .NET host spawning unexpected child process from non-standard path"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("dotnet.exe","csc.exe","msbuild.exe","regasm.exe","regsvcs.exe","installutil.exe")
    AND NOT Processes.process_name IN ("conhost.exe","WerFault.exe","csc.exe","vbc.exe","csi.exe","dotnet.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| where risk_score >= 80
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

```spl
| comment "Search 3: MiniJunk V2 file inflation — large .NET assemblies (>8 MB) loaded from unexpected paths"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_name="*.dll"
    AND Filesystem.file_size > 8388608
    AND NOT (Filesystem.file_path="*\\Windows\\*"
             OR Filesystem.file_path="*\\Program Files\\*"
             OR Filesystem.file_path="*\\Program Files (x86)\\*")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.file_size Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=70
| table firstTime lastTime dest user file_path file_name file_size process_name risk_score
```

```spl
| comment "Search 4: Azure-hosted C2 beacon pattern — .NET processes making unusual outbound HTTPS to Azure domains"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port=443
    AND (All_Traffic.dest="*.azurewebsites.net"
         OR All_Traffic.dest="*.blob.core.windows.net"
         OR All_Traffic.dest="*.azurestaticapps.net")
  by All_Traffic.src All_Traffic.dest All_Traffic.app All_Traffic.src_user All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| where bytes_out < 5000
| eval risk_score=50
| table firstTime lastTime src src_user dest app bytes_out risk_score
```

**Tuning notes:**
- Search 1: `.config` file creation by non-installer processes in program directories is highly suspicious; exclude your software management tooling (SCCM, Ansible, Puppet) from the NOT list.
- Search 2: .NET host processes spawning shells is rare in most environments; this will catch legitimate MSBuild tasks — correlate with known build schedules.
- Search 3: File size threshold of 8 MB is conservative to catch MiniJunk V2's ~12 MB inflation; tune up if your environment has legitimate large DLLs in user-writable paths.
- Search 4: Low bytes_out filter targets the periodic check-in beacons; larger data transfers from the same source to Azure subdomains may indicate exfiltration. This search requires a list of known-legitimate Azure tenant endpoints to whitelist.

## 6. Executive Summary

Palo Alto Networks Unit 42 published research in late May 2026 documenting a new Screening Serpens (UNC1549 / Smoke Sandstorm / Iranian Dream Job) campaign coinciding with the regional conflict that began on February 28, 2026. Unit 42 identified six new RAT variants deployed against entities in the United States, Israel, and UAE in the aerospace, defense manufacturing, and telecommunications sectors.

The six variants split into two new malware families. **MiniUpdate** is a newly discovered .NET RAT deployed via AppDomainManager hijacking — a technique where a trojanized `.config` file forces the CLR runtime to load an attacker-controlled DLL before the legitimate application initializes, defeating endpoint security controls that monitor executable launches. MiniUpdate supports 16–18 opcodes covering shell execution, process enumeration, file exfiltration, in-memory DLL injection, UAC bypass, and chunked large-file upload. Each target receives a dedicated set of three to five Azure-hosted C2 domains named to resemble Windows system processes.

**MiniJunk V2** is an evolved iteration of the MiniJunk backdoor previously documented by Check Point Research in the context of the related Nimbus Manticore cluster. The V2 variant inflates its binary to approximately 12 MB by embedding thousands of meaningless Java and Python code strings, defeating automated scanners with file-size limits and flooding manual analysis tools with irrelevant data.

Both families share an identical infection chain: highly personalized aerospace/defense job-recruitment spear-phishing → DLL sideloading (two-stage) → Azure HTTPS C2. Unit 42 urges defenders to implement behavioral detection for AppDomainManager hijacking and signed-binary-loads-untrusted-DLL patterns rather than relying on signature-based detection, as both families have near-zero VirusTotal detection rates at time of submission.

**Immediate actions:**
1. Deploy Search 1 to detect `.config` file creation in program directories by non-installer processes.
2. Review all third-party .NET applications for unexpected `.config` files containing `appDomainManager` XML elements.
3. Configure EDR rules to flag DLL loads from user-writable paths by signed host applications.
4. Deploy Search 2 to catch .NET hosting processes spawning interactive shells.
5. Train security teams and HR/recruiting staff on aerospace/defense job-recruitment spear-phishing lures; Screening Serpens targets professionals directly.

## References

- [Unit 42 — Tracking Iranian APT Screening Serpens' 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [The Hacker News — Iranian Hackers Deploy MiniFast and MiniJunk V2 via Phishing and SEO Poisoning](https://thehackernews.com/2026/05/iranian-hackers-deploy-minifast-and.html)
- [Cybersecurity News — MiniUpdate RAT Uses Azure-Hosted C2 Domains for Targeted Espionage Campaigns](https://cybersecuritynews.com/miniupdate-rat-uses-azure-hosted-c2-domains/)
- [Check Point Research — Fast and Furious: Nimbus Manticore Operations (2026-05-22)](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Cybersecurity Dive — Iran-linked hackers target key US, allied sectors](https://www.cybersecuritydive.com/news/iran-cyberattacks-espionage-us-israel-uae/820990/)
- [MITRE ATT&CK — T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [MITRE ATT&CK — T1574.002 DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- [MITRE ATT&CK — T1027.009 Embedded Payloads](https://attack.mitre.org/techniques/T1027/009/)
- [MITRE ATT&CK — G1030 Screening Serpens](https://attack.mitre.org/groups/G1030/)
