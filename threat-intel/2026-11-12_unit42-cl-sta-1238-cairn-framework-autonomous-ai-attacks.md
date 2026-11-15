---
scraped_at: "2026-11-15T00:00:00Z"
source_url: "https://unit42.paloaltonetworks.com/cl-sta-1238-cairn-framework-autonomous-ai-attacks/"
report_type: threat-intel
severity: high
title: "CL-STA-1238: China-Nexus Autonomous AI Cyber Operations Using Cairn Framework"
---

# CL-STA-1238: China-Nexus Autonomous AI Cyber Operations Using Cairn Framework

## 1. IOCs

No extractable IOCs from search summaries. Source article should be consulted for full indicator list.

| Type | Indicator | Confidence | Notes |
|------|-----------|------------|-------|
| — | No IOCs available without direct article access | — | Consult Unit 42 report for infrastructure IOCs; Cairn framework uses dynamic C2 making static indicators low-value |

## 2. TTPs

| Tactic | Technique | ID | Description |
|--------|-----------|-----|-------------|
| Reconnaissance | Active Scanning | T1595 | Cairn AI agents conduct fully automated reconnaissance and vulnerability scanning against target networks without human operator involvement |
| Initial Access | Exploit Public-Facing Application | T1190 | Autonomous exploitation of identified vulnerabilities; AI planner selects and chains exploits based on reconnaissance output |
| Execution | Command and Scripting Interpreter | T1059 | AI-generated payloads executed via scripting interpreters; command selection and sequencing handled autonomously by Cairn framework |
| Persistence | (varies by target system) | — | Persistence mechanisms selected and deployed autonomously by Cairn agent based on target OS and privilege level |
| Defense Evasion | Indicator Removal | T1070 | Cairn framework instructs agents to clean logs and remove indicators as part of operation playbooks |
| Defense Evasion | Obfuscated Files or Information | T1027 | AI-generated payloads obfuscated dynamically; evades static signature detection by generating novel variants |
| Lateral Movement | (varies) | — | Lateral movement vectors selected autonomously by AI planner based on discovered network topology |
| Command and Control | Application Layer Protocol | T1071 | Outbound API calls to external AI model inference endpoints (DeepSeek API, Zhipu GLM API) used as C2 coordination channel |
| Command and Control | Multi-Stage Channels | T1104 | "Blackboard" shared state architecture: compromised hosts communicate through a shared in-memory coordination layer, allowing multiple Cairn agents to collaborate on a single operation |
| Collection | Automated Collection | T1119 | Cairn framework autonomously identifies and stages high-value data for exfiltration without operator instruction |

## 3. Malware & Tools

| Name | Type | Description |
|------|------|-------------|
| Cairn framework | Open-source AI pentesting framework | Multi-agent autonomous penetration testing framework; modified and weaponized by CL-STA-1238 for offensive operations. Integrates with external AI model APIs for action planning. |
| DeepSeek (AI model) | External AI inference service | CL-STA-1238 uses DeepSeek's API as the action-planning "brain" for Cairn agents; requests to api.deepseek.com from compromised hosts indicate active Cairn operations |
| Zhipu GLM / BigModel | External AI inference service | Alternate AI backend used for certain task types; API calls to open.bigmodel.cn from internal hosts are anomalous |
| Blackboard coordination layer | C2 architecture component | Shared in-memory state store allowing multiple Cairn sub-agents to coordinate actions on a single target; enables parallel attack paths without operator involvement |

## 4. Attribution

| Actor | Confidence | Notes |
|-------|------------|-------|
| CL-STA-1238 | High | Unit 42 designation for this China-nexus cluster |
| China-nexus (state-sponsored) | High | Targeting profile (US semiconductor, US defense policy, civil society) and use of Chinese-developed AI infrastructure (DeepSeek, Zhipu GLM) consistent with PRC state interests |

**Campaign context:** Unit 42 published research on November 12, 2026 documenting CL-STA-1238's use of the Cairn autonomous AI pentesting framework for offensive cyber operations. Between August and September 2026, CL-STA-1238 conducted 25 discrete operations against 19 organizations, confirming compromise of 10 targets. The actor weaponized the open-source Cairn framework — integrating DeepSeek and Zhipu GLM AI model APIs as autonomous action planners — enabling operations with minimal human operator involvement after initial target selection. The "blackboard" shared architecture allows multiple Cairn agents to collaborate on a single target, dramatically increasing operational tempo. Targeting focused on US semiconductor manufacturers, US defense policy think tanks, and civil society organizations. This represents a significant evolution: AI-driven cyber operations no longer require highly skilled operators for routine exploitation tasks.

## 5. Splunk Detection Searches

### Outbound connections to AI model APIs from internal workstations/servers

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where (All_Traffic.dest_host="api.deepseek.com" OR All_Traffic.dest_host="open.bigmodel.cn"
         OR All_Traffic.dest_host="*.bigmodel.cn" OR All_Traffic.dest_host="api.zhipuai.cn")
  AND All_Traffic.src_category!="proxy" AND All_Traffic.src_category!="approved_ai_workstation"
  by All_Traffic.src All_Traffic.dest_host All_Traffic.dest_port All_Traffic.bytes_out All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    bytes_out > 50000, 90,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime src dest_host dest_port bytes_out user risk_score
```

### High-velocity automated scanning from a single internal source

```spl
| tstats `security_content_summariesonly` count dc(All_Traffic.dest) as dest_count
  min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.action="allowed"
  by All_Traffic.src _time span=5m
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| where dest_count > 200
| eval risk_score=case(
    dest_count > 500, 85,
    dest_count > 200, 70,
    1=1, 50)
| where risk_score >= 70
| table firstTime lastTime src dest_count risk_score
```

### Cairn-related process execution (open-source framework artifacts)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process="*cairn*" OR Processes.process="*cairn-agent*" OR Processes.process_name="cairn")
  by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## 6. Executive Summary

Unit 42 documented CL-STA-1238, a China-nexus threat actor, conducting 25 autonomous AI-driven cyber operations between August and September 2026, compromising 10 of 19 targeted organizations in the US semiconductor, defense policy, and civil society sectors. The actor weaponized the open-source Cairn autonomous pentesting framework, integrating DeepSeek and Zhipu GLM AI model APIs as action-planning backends, enabling end-to-end exploitation with minimal human operator involvement. A "blackboard" shared-state coordination architecture allows multiple Cairn agents to collaborate in parallel against a single target, significantly increasing operational tempo and reducing dwell time. The reliance on external AI inference APIs (api.deepseek.com, open.bigmodel.cn) is a detectable operational signature: unexplained outbound API calls to these endpoints from servers or workstations that do not perform authorized AI development work are a high-fidelity indicator of Cairn framework activity. Organizations in targeted sectors should monitor for unexpected outbound connections to Chinese AI model inference APIs, enforce egress filtering, and treat anomalous network scanning velocity as a possible indicator of autonomous AI-driven reconnaissance.

## References

- [Unit 42 - CL-STA-1238: Autonomous AI Cyber Operations Using Cairn Framework](https://unit42.paloaltonetworks.com/cl-sta-1238-cairn-framework-autonomous-ai-attacks/)
- [MITRE ATT&CK - T1595 Active Scanning](https://attack.mitre.org/techniques/T1595/)
- [MITRE ATT&CK - T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK - T1071 Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [Cairn Framework (GitHub - open source)](https://github.com/cairn-ai/cairn)
- [DeepSeek API Documentation](https://platform.deepseek.com/api-docs/)
- [Zhipu AI GLM / BigModel API](https://open.bigmodel.cn/dev/api)
