---
scraped_at: 2026-06-06T00:00:00Z
source_url: https://www.sophos.com/en-us/blog/pointing-a-cursor-at-evading-detection
report_type: threat-intel
severity: high
title: "AI-Orchestrated EDR Evasion Lab: Threat Actor Uses Cursor IDE and Claude Opus 4.5 to Build Iterative Malware Testing Framework Against Sophos, CrowdStrike, and Defender"
---

# AI-Orchestrated EDR Evasion Lab: Threat Actor Uses Cursor IDE and Claude Opus 4.5 to Build Iterative Malware Testing Framework Against Sophos, CrowdStrike, and Defender

Sophos X-Ops published "Pointing a Cursor at evading detection" on June 2, 2026, documenting a threat actor who built a fully AI-orchestrated malware development and EDR evasion testing laboratory. The actor used Cursor (an AI-native coding IDE) and Claude Opus 4.5 as a coordinating AI agent via Model Context Protocol (MCP) to develop, test, and iteratively refine nearly 80 evasion modules across 70+ techniques — specifically targeting Sophos, CrowdStrike Falcon, and Microsoft Defender. The framework's Cobalt Strike profiles, Sliver C2 server, and Telegram bot C2 infrastructure were linked to ransomware deployment and data theft operations. No specific threat actor group was named in the public disclosure.

## 1. IOCs

No specific file hashes, domains, or IP addresses were disclosed in the public Sophos report for this campaign. Detection relies on behavioral TTPs described in Section 5.

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Description |
|--------|-----------|----|-------------|
| Resource Development | Develop Capabilities: Malware | T1587.001 | AI agents (Claude Opus 4.5 + Cursor IDE) used to iteratively write Rust and Go payloads with EDR evasion properties; ~80 modules developed |
| Defense Evasion | Obfuscated Files or Information: Polymorphic Code | T1027.014 | Payload generator wraps raw shellcode in layers of encryption, alternative execution techniques, and junk code insertion to change binary signatures between iterations |
| Defense Evasion | Virtualization/Sandbox Evasion | T1497 | Test harness runs payloads against live EDR agents on Windows Server 2022 VMs; iterations continue until all EDR detections are bypassed |
| Defense Evasion | Indicator Removal: File Deletion | T1070.004 | OPSEC hardening agent within the AI framework removes forensic artifacts post-test |
| Execution | Command and Scripting Interpreter: Python | T1059.006 | Python-based shellcode injector injects payloads into signed Windows executables while preserving original functionality |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | Cobalt Strike profiles designed to disguise beacon traffic as legitimate HTTP/HTTPS web requests |
| Command and Control | Application Layer Protocol: File Transfer Protocols | T1071.002 | Sliver C2 framework (Ubuntu VM) used as primary post-exploitation command and control server |
| Command and Control | Web Service: Bidirectional Communication | T1102.002 | Telegram Bot API used as external C2 channel, routing operator commands through Telegram's infrastructure |
| Command and Control | Proxy: Multi-hop Proxy | T1090.003 | Cloudflare Worker configured to conceal the backend C2 infrastructure |
| Lateral Movement | N/A — Active Directory Discovery | T1018 | Automated Active Directory discovery panel developed and tested as part of the ransomware toolkit |

### AI Orchestration Architecture (Novel TTP)

The framework uses MCP (Model Context Protocol) to connect multiple AI agents to Git repositories and tool integrations:

| Agent Role | AI Model | Function |
|-----------|----------|----------|
| Orchestrator | Claude Opus 4.5 | Core operations, sets rules for all other agents, coordinates overall framework |
| EDR Tester | Claude agent | Tests payload variants against live EDR agents (Sophos, CrowdStrike, Defender) |
| OPSEC Hardener | Claude agent | Removes forensic artifacts, hardens operational security |
| Documenter | Claude agent | Produces technical documentation of successful evasion modules |
| Proxy Stress Tester | Claude agent | Tests proxy and C2 infrastructure resilience |
| VM Deployer | Claude agent | Manages virtual machine deployment for isolated testing environments |

## 3. Malware & Tools

| Tool / Component | Type | Notes |
|-----------------|------|-------|
| Python shellcode injector | Custom malware | Injects shellcode into signed Windows binaries while preserving their original functionality; enables signed process execution as cover |
| Rust/Go payload generator | Custom malware | Modular loader that wraps raw shellcode in encryption, evasion, and alternative execution layers; 80 modules, 70+ techniques |
| Cobalt Strike (custom profiles) | Post-exploitation framework | Profiles configured to blend beacon traffic with legitimate web request patterns |
| Sliver C2 framework | Open-source C2 | Ubuntu VM hosting Sliver as primary post-exploitation C2; open-source alternative to Cobalt Strike |
| Telegram Bot API C2 | C2 mechanism | External operator communication channel over Telegram's infrastructure |
| Cloudflare Worker | Infrastructure | Proxies C2 traffic to conceal backend infrastructure IP addresses |
| Cursor IDE | AI development tool (abused) | AI-native coding IDE used to generate and refine evasion payload code |
| Claude Opus 4.5 (via MCP) | AI model (abused) | Coordinating agent directing all other specialized agents via MCP |

## 4. Threat Actor / Campaign Attribution

| Attribution | Detail | Confidence |
|-------------|--------|-----------|
| Unknown ransomware operator | Sophos linked the framework to ransomware deployment and data theft operations; Cobalt Strike operator logs contained ransom note references and multiple organizations listed on a data leak site | Medium |
| No public actor name | Sophos did not publicly identify the group; activity detected via anomalous endpoint registration within a customer tenant | Low |

This campaign represents a significant maturation in adversarial use of AI for malware development. The use of MCP to coordinate multiple specialized AI agents in a production-like CI/CD pipeline for evasion testing is a novel and concerning TTP that will likely be replicated by other threat actors.

## 5. Splunk Detection Searches

```spl
`-- Detect Sliver C2 framework process execution`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("sliver-server","sliver-client","sliver")
     OR (Processes.process IN ("*sliver*","*implant*beacon*")
         AND Processes.process_name IN ("bash","sh"))
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
`-- Detect Cobalt Strike beacon traffic patterns: HTTP GET/POST to unexpected hosts with sleep jitter`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port IN (80, 443, 8080, 8443)
    AND All_Traffic.bytes_out BETWEEN 200 AND 800
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| stats count avg(bytes_out) as avg_bytes stdev(bytes_out) as stddev_bytes
        min(_time) as firstTime max(_time) as lastTime
  by src dest dest_port
| where count > 30 AND stddev_bytes < 100
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    count > 100 AND stddev_bytes < 50, 75,
    count > 50 AND stddev_bytes < 100, 65,
    1=1, 55)
| where risk_score >= 55
| table firstTime lastTime src dest dest_port count avg_bytes stddev_bytes risk_score
```

```spl
`-- Detect shellcode injection: signed Windows binaries spawned from non-standard parent paths`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("svchost.exe","dllhost.exe","notepad.exe","calc.exe",
                                    "mspaint.exe","explorer.exe","werfault.exe")
    AND NOT (Processes.process_path IN ("C:\\Windows\\System32\\*",
                                          "C:\\Windows\\SysWOW64\\*",
                                          "C:\\Windows\\explorer.exe"))
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process_path Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name process_name process_path risk_score
```

```spl
`-- Detect Telegram Bot API C2 communication from endpoints`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("api.telegram.org","t.me")
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| lookup processes_by_host src as src OUTPUT process_name
| where isnotnull(process_name) AND NOT process_name IN ("chrome.exe","firefox.exe","msedge.exe",
                                                          "Teams.exe","slack.exe","discord.exe",
                                                          "thunderbird.exe","outlook.exe")
| eval risk_score=75
| table firstTime lastTime src query answer process_name risk_score
```

## 6. Executive Summary

Sophos X-Ops documented the first known case of a fully AI-orchestrated malware development pipeline being used operationally in a ransomware campaign. The threat actor built a multi-VM testing laboratory where a Claude Opus 4.5 agent coordinated five specialized sub-agents via MCP to develop, test, and refine EDR-evasion payloads against live Sophos, CrowdStrike, and Microsoft Defender installations.

The modular Python payload generator produced Rust and Go binaries across nearly 80 different evasion modules covering 70+ techniques. Cobalt Strike with custom masquerading profiles, a Sliver C2 server, a Telegram Bot API C2, and a Cloudflare Worker proxy formed the post-exploitation infrastructure. The same repository contained AD discovery tooling and references to multiple ransomware leak site victims, confirming operational use.

Key implications for defenders:
- AI-assisted iterative development dramatically reduces the time required to achieve EDR bypass; behavioral/heuristic detection must be paired with signature-based controls
- The Sliver C2 and Telegram Bot C2 combination is increasingly common among ransomware operators as an alternative to/supplement of Cobalt Strike
- Process injection into signed Windows binaries (via hollow or overwrite) is the preferred payload execution mechanism; monitoring process execution paths is critical

## References

- [Sophos X-Ops — Pointing a Cursor at Evading Detection (2026-06-02)](https://www.sophos.com/en-us/blog/pointing-a-cursor-at-evading-detection)
- [BleepingComputer — AI-Built Ransomware Toolkit Automates EDR Evasion (2026-06-04)](https://www.bleepingcomputer.com/news/security/ai-built-ransomware-toolkit-automates-edr-evasion-ad-discovery/)
- [Help Net Security — AI Agents EDR Evasion Techniques (2026-06-02)](https://www.helpnetsecurity.com/2026/06/02/ai-agents-edr-evasion-techniques/)
- [MITRE ATT&CK — T1587.001 Develop Capabilities: Malware](https://attack.mitre.org/techniques/T1587/001/)
- [MITRE ATT&CK — T1027.014 Polymorphic Code](https://attack.mitre.org/techniques/T1027/014/)
- [MITRE ATT&CK — T1102.002 Web Service: Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002/)
- [Model Context Protocol — Anthropic](https://docs.anthropic.com/en/docs/agents-and-tools/mcp)
