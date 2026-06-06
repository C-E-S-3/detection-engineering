# Unauthorized GPU Cryptominer Execution (gminer / lolMiner / SRBMiner-MULTI)

## Description

Detects unauthorized execution of GPU mining software — specifically gminer, lolMiner, and SRBMiner-MULTI — as used in the May–June 2026 cryptojacking campaign documented by Microsoft (CVE-agnostic). In that campaign, attackers used SEO-poisoned download sites impersonating popular GPU utilities (CrystalDiskInfo, HWMonitor, FurMark, Display Driver Uninstaller) to deliver trojanized installers that deployed ScreenConnect for persistent access and then launched GPU miners to hijack victim computing resources.

This detection applies broadly to any unauthorized GPU mining activity regardless of delivery vector; cryptomining software executed on corporate endpoints is nearly always malicious. False positives: legitimate mining operations where employees are explicitly authorized to run miners (highly unusual in enterprise environments). A suppression list of approved mining hosts should be maintained if applicable.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Impact |
| Tactic ID | TA0040 |
| Technique | Resource Hijacking |
| Technique ID | T1496 |

Secondary: T1574.002 (DLL Side-Loading — delivery via `autorun.dll` sideloaded with ScreenConnect), T1219 (Remote Access Software — ScreenConnect deployed as persistent C2), T1053.005 (Scheduled Task — persistence for miner watchdog), T1547.001 (Registry Run Keys — additional persistence)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
`-- Primary: detect known GPU miner process execution`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN (
    "gminer.exe","lolminer.exe","lolMiner.exe",
    "SRBMiner-MULTI.exe","srbminer.exe","srbminer-multi.exe",
    "miniZ.exe","PhoenixMiner.exe","TRex.exe","NBMiner.exe",
    "XMRig.exe","xmrig.exe","cpuminer.exe","cgminer.exe","bfgminer.exe"
  )
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name IN ("gminer.exe","lolminer.exe","lolMiner.exe",
                     "SRBMiner-MULTI.exe","srbminer.exe","srbminer-multi.exe"), 95,
    process_name IN ("XMRig.exe","xmrig.exe"), 90,
    1=1, 85)
| where risk_score >= 85
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
`-- Supplemental: detect miner CLI argument patterns indicating pool connections`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process IN ("*--pool*","*stratum+tcp*","*stratum+ssl*",
                               "*-o pool.*","*-u wallet*","*--wallet*",
                               "*--server*mining*","*pooladdress*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
`-- Supplemental: detect network connections to known GPU mining campaign C2 and infrastructure IPs`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest IN ("193.42.11.108","93.115.10.35","198.23.185.238","2.59.132.106")
     OR (All_Traffic.dest_port=8443 AND All_Traffic.app IN ("websocket","wss","ssl"))
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    dest IN ("193.42.11.108","93.115.10.35","198.23.185.238","2.59.132.106"), 90,
    1=1, 55)
| where risk_score >= 55
| table firstTime lastTime src dest dest_port app count risk_score
```

```spl
`-- Supplemental: detect ScreenConnect installed outside standard program directories`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("ScreenConnect.ClientService.exe","ScreenConnect.WindowsClient.exe",
                                    "ConnectWise.ClientService.exe")
    AND NOT Processes.process_path IN (
      "C:\\Program Files (x86)\\ScreenConnect Client*",
      "C:\\Program Files\\ScreenConnect Client*",
      "C:\\Program Files (x86)\\ConnectWise*",
      "C:\\Program Files\\ConnectWise*"
    )
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process_path Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime dest user parent_process_name process_name process_path risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| gminer.exe, lolMiner.exe, or SRBMiner-MULTI.exe execution | 95 | These are commercial GPU mining tools with no legitimate enterprise use case; near-certain true positive in corporate environments |
| XMRig or other CPU/GPU miner execution | 90 | XMRig is the most widely deployed mining software in crimeware; execution on corporate endpoint is near-certain malicious |
| Process command line contains stratum+tcp/ssl or pool connection string | 85 | Mining pool connection strings in command line indicate active mining activity |
| ScreenConnect running from non-standard path | 85 | Legitimate ConnectWise ScreenConnect installs to well-known paths; non-standard path installation indicates attacker-deployed RMM persistence |
| Connection to known campaign infrastructure IPs | 90 | Direct connection to documented GPU mining campaign staging and C2 servers |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (GPU cryptojacking campaign, March–June 2026) | [Microsoft Security Blog — GPU Mining via ScreenConnect (2026-05-26)](https://www.microsoft.com/en-us/security/blog/2026/05/26/poisoned-search-results-gpu-mining-cryptojacking-campaign-abusing-screenconnect-microsoft-net-utilities/) |
| WeedHack MaaS (Minecraft-targeted GPU mining, 2026) | [McAfee Labs — WeedHack (2026-06-03)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/weedhack-minecraft-malware-as-a-service-campaign-research/) |
| UNC6603 / React2Shell cryptomining cluster (2026) | [Google TI — React2Shell Cryptomining](https://cloud.google.com/blog/topics/threat-intelligence/threat-actors-exploit-react2shell-cve-2025-55182) |

## References

- [Microsoft Security Blog — GPU Mining Cryptojacking Campaign (2026-05-26)](https://www.microsoft.com/en-us/security/blog/2026/05/26/poisoned-search-results-gpu-mining-cryptojacking-campaign-abusing-screenconnect-microsoft-net-utilities/)
- [BleepingComputer — GPU Mining Malware via SEO Poisoning and AI Chatbots (2026-06-01)](https://www.bleepingcomputer.com/news/security/gpu-mining-malware-spreads-via-seo-poisoning-ai-chatbots/)
- [MITRE ATT&CK — T1496 Resource Hijacking](https://attack.mitre.org/techniques/T1496/)
- [MITRE ATT&CK — T1574.002 DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- [MITRE ATT&CK — T1219 Remote Access Software](https://attack.mitre.org/techniques/T1219/)
