---
scraped_at: 2026-06-06T00:00:00Z
source_url: https://www.microsoft.com/en-us/security/blog/2026/05/26/poisoned-search-results-gpu-mining-cryptojacking-campaign-abusing-screenconnect-microsoft-net-utilities/
report_type: threat-intel
severity: medium
title: "GPU Cryptojacking Campaign Abuses ScreenConnect and Microsoft .NET Utilities via SEO Poisoning and AI Chatbot Manipulation"
---

# GPU Cryptojacking Campaign Abuses ScreenConnect and Microsoft .NET Utilities via SEO Poisoning and AI Chatbot Manipulation

Microsoft Security published research on May 26, 2026 documenting a large-scale GPU cryptojacking campaign active since at least March 2026. Attackers use coordinated SEO poisoning — and in some cases AI chatbot result manipulation — to funnel users seeking legitimate GPU utilities to malicious download sites. Once a victim executes the trojanized installer, the campaign deploys ScreenConnect for persistent remote management, uses DLL sideloading and process hollowing to evade detection, excludes itself from Microsoft Defender, and installs one of three GPU miners (gminer, lolMiner, or SRBMiner-MULTI) via six separate persistence mechanisms. Over 150 malicious download domains have been identified.

## 1. IOCs

### Domains

| Domain | Role |
|--------|------|
| direct-download[.]gleeze[.]com | Malicious utility download portal |
| start-download[.]gleeze[.]com | Malicious utility download portal |
| direct-downloads[.]giize.com | Malicious utility download portal |
| free-download[.]giize.com | Malicious utility download portal |
| directdownload[.]icu | Malicious utility download portal |
| minemine.gleeze[.]com | C2 WebSocket endpoint (wss://minemine.gleeze[.]com:8443/ws) |

### IP Addresses

| IP | Role |
|----|------|
| 193.42.11[.]108 | Campaign infrastructure / payload staging |
| 93.115[.]10.35 | Campaign infrastructure / payload staging |
| 198.23[.]185.238 | Campaign infrastructure / payload staging |
| 2.59.132[.]106 | Campaign infrastructure / payload staging |

### File Hashes (SHA256)

| Hash | Description |
|------|-------------|
| 16562974deec80e41ef57a71a6de8c03ceb393005fb1432f8d9d82c61294ef8c | Malicious installer dropper |
| 1b2555b09ac62164638f47c8272beb6b0f97186e37d3a54cb84c723ff7a2eee5 | Malicious installer dropper |
| 062bb28765fbaa11f8cc341fa16e2c7f942a122d929cb41f4a0f755b4429f246 | Malicious installer dropper |
| c7425fbe6c3a4937934215c54027d4b67202d12ab490682fae03498870d66d06 | Malicious installer dropper |
| a460d00ef93c8ce70d32e48e55781af66a53328fc2dde45519be196c265de074 | Malicious installer / DLL payload |
| db2d33c4e6e4a5c2263b56e8303c343305a94dde1fc2968304ba260acbbd9f9f | Malicious installer / DLL payload |
| cf3f8160eb5a5580e0c35054847e3ac4d01e9fe74fab8bc12bf6e8a40bf696b2 | Malicious installer / DLL payload |
| 69077fcf940fc5852fb32beed15636756ebc04ac971b7ed71d36251e7ea70a20 | Malicious installer / DLL payload |
| 2ee93ccbcd49ed94c65dcf52e7dcb8f0fa0a443ca24c0e0c7f79152efba657b7 | Malicious installer / DLL payload |
| 9ff07c9fafa9c03fdf69e4abf6806aa7c938b5480e7e258f227db0719ecd6386 | Malicious installer / DLL payload |
| 7035c2abeb617e828dfda1b119b8544fa9ae15a1d263d18bc5506acaf381f496 | Persistence component (RuntimeHost.exe) |
| e021662a652ba95c8778b991056696ab3c9b0f60d5e23b1e6cf73c3847db6610 | Persistence component (RuntimeHost.exe) |

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Description |
|--------|-----------|----|-------------|
| Initial Access | Drive-by Compromise | T1189 | SEO-poisoned search results and AI chatbot recommendations direct users to attacker-controlled utility download sites |
| Initial Access | Malicious Link | T1204.002 | User executes trojanized installer believing it to be a legitimate system utility (CrystalDiskInfo, HWMonitor, FurMark, etc.) |
| Defense Evasion | DLL Side-Loading | T1574.002 | `autorun.dll` sideloaded alongside the ScreenConnect installer package; malicious code in autorun.dll executes when ScreenConnect loads |
| Defense Evasion | Process Injection: Process Hollowing | T1055.012 | `SimpleRunPE.exe` hollows signed Windows system processes and injects the cryptomining payload |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | Malware adds exclusion rules to Microsoft Defender to prevent detection of mining binaries and persistence artifacts |
| Defense Evasion | Virtualization/Sandbox Evasion | T1497 | Campaign terminates if analysis tools or virtual machine indicators are detected |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | T1547.001 | Two registry Run key entries and one Startup folder shortcut ensure miner restarts after reboot |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 | Three scheduled tasks created for mining process persistence and watchdog behavior |
| Command and Control | Remote Access Software | T1219 | ScreenConnect (ConnectWise) deployed as persistent RMM tool allowing attacker to control infected hosts and install additional payloads |
| Impact | Resource Hijacking | T1496 | gminer, lolMiner, or SRBMiner-MULTI deployed to exploit GPU resources for cryptocurrency mining |

## 3. Malware & Tools

| Tool | Type | Notes |
|------|------|-------|
| autorun.dll | Malicious DLL | Sideloaded via ScreenConnect installer (`vcredist_x64.dll`); entry point for dropper execution |
| SimpleRunPE.exe | Process Hollowing Dropper | Hollows signed Windows utilities to inject the mining payload without creating new suspicious processes |
| RuntimeHost.exe | Persistence Component | Watchdog / miner restart component installed via scheduled task and registry Run keys |
| ScreenConnect (ConnectWise) | Remote Management Tool (abused) | Legitimate RMM software used as persistent backdoor access; attacker uses it to push updates and additional payloads |
| gminer | GPU Miner | Legitimate GPU miner abused for unauthorized Ethereum/Ergo/Ravencoin mining |
| lolMiner | GPU Miner | Legitimate GPU miner abused for unauthorized cryptocurrency mining |
| SRBMiner-MULTI | GPU Miner | Legitimate GPU miner supporting CPU+GPU mining for multiple algorithms |

### Impersonated Utilities (SEO Poisoning Lures)

- CrystalDiskInfo
- HWMonitor (CPUID)
- Display Driver Uninstaller (DDU)
- FurMark (GPU stress test)
- K-Lite Codec Pack
- PDFgear

## 4. Threat Actor / Campaign Attribution

No specific threat actor group has been publicly attributed to this campaign. The targeting of owners of high-performance systems (gamers, content creators, crypto miners) indicates a financially motivated cryptojacking operation. The sophistication of the SEO poisoning operation (150+ domains, AI chatbot manipulation, anti-analysis features) suggests an organized criminal group with sustained infrastructure investment.

Campaign active since at least March 2026, with a significant surge in infections observed April–June 2026.

## 5. Splunk Detection Searches

```spl
`-- Detect execution of GPU mining binaries (gminer, lolMiner, SRBMiner-MULTI)`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("gminer.exe","lolminer.exe","lolMiner.exe",
                                    "SRBMiner-MULTI.exe","srbminer.exe","srbminer-multi.exe",
                                    "miniZ.exe","PhoenixMiner.exe","TRex.exe","NBMiner.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
`-- Detect ScreenConnect installed from unexpected paths or spawning suspicious children`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name IN ("ScreenConnect.ClientService.exe","ScreenConnect.WindowsClient.exe")
         AND Processes.process_path NOT IN ("C:\\Program Files (x86)\\ScreenConnect Client*",
                                             "C:\\Program Files\\ScreenConnect Client*"))
     OR (Processes.parent_process_name IN ("ScreenConnect.ClientService.exe","ScreenConnect.WindowsClient.exe")
         AND Processes.process_name IN ("cmd.exe","powershell.exe","wscript.exe","mshta.exe",
                                         "regsvr32.exe","rundll32.exe","certutil.exe"))
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_path Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    isnotnull(process_path) AND NOT match(process_path,"Program Files"), 85,
    process_name IN ("powershell.exe","cmd.exe"), 80,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process process_path risk_score
```

```spl
`-- Detect DLL sideloading: autorun.dll or vcredist_x64.dll loaded from non-standard paths`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process IN ("*autorun.dll*","*vcredist_x64.dll*","*SimpleRunPE.exe*",
                               "*RuntimeHost.exe*")
    AND NOT (Processes.process_path IN ("C:\\Windows\\*","C:\\Program Files\\*",
                                         "C:\\Program Files (x86)\\*"))
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user parent_process_name process_name process process_path risk_score
```

```spl
`-- Network: connections to known campaign WebSocket C2 and staging IPs`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest IN ("193.42.11.108","93.115.10.35","198.23.185.238","2.59.132.106")
     OR All_Traffic.dest_port=8443
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    dest IN ("193.42.11.108","93.115.10.35","198.23.185.238","2.59.132.106"), 90,
    dest_port=8443, 50)
| where risk_score >= 50
| table firstTime lastTime src dest dest_port app count risk_score
```

## 6. Executive Summary

A large-scale GPU cryptojacking campaign documented by Microsoft on May 26, 2026 has operated since at least March 2026, infecting high-performance Windows systems via SEO-poisoned download portals impersonating popular system utilities (CrystalDiskInfo, HWMonitor, FurMark, Display Driver Uninstaller, K-Lite Codec Pack, PDFgear). In a notable development, some victims discovered the malicious sites after AI chatbot assistants (LLMs) included attacker-controlled domains in generated responses, representing a new AI-enabled distribution channel.

After execution, the installer deploys ScreenConnect (ConnectWise RMM) as a persistent backdoor, uses DLL sideloading (`autorun.dll` via `vcredist_x64.dll`) and process hollowing (`SimpleRunPE.exe`) to evade endpoint protection, adds Defender exclusions, and detects analysis environments before deploying one of three GPU miners (gminer, lolMiner, SRBMiner-MULTI). Six persistence mechanisms (3 scheduled tasks, 2 registry Run keys, 1 Startup folder shortcut) ensure survival across reboots. The ScreenConnect backdoor allows the operator to install additional malware as needed.

Detection priority: GPU miner process execution is high-confidence malicious (score 90); ScreenConnect from non-standard paths is strong suspicious (score 80–85); blocking the known IP indicators will prevent C2 beacon establishment.

## References

- [Microsoft Security Blog — GPU Mining via SEO Poisoning and ScreenConnect (2026-05-26)](https://www.microsoft.com/en-us/security/blog/2026/05/26/poisoned-search-results-gpu-mining-cryptojacking-campaign-abusing-screenconnect-microsoft-net-utilities/)
- [BleepingComputer — GPU Mining Malware Spreads via SEO Poisoning, AI Chatbots (2026-06-01)](https://www.bleepingcomputer.com/news/security/gpu-mining-malware-spreads-via-seo-poisoning-ai-chatbots/)
- [MITRE ATT&CK — T1496 Resource Hijacking](https://attack.mitre.org/techniques/T1496/)
- [MITRE ATT&CK — T1574.002 DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- [MITRE ATT&CK — T1219 Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [MITRE ATT&CK — T1562.001 Impair Defenses](https://attack.mitre.org/techniques/T1562/001/)
