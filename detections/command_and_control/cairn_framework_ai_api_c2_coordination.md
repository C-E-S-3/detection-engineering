# Cairn Framework Autonomous AI API C2 Coordination

## Description

Detects outbound connections from internal hosts to external AI model inference APIs — specifically DeepSeek (api.deepseek.com) and Zhipu GLM/BigModel (open.bigmodel.cn, api.zhipuai.cn) — that are not attributable to authorized AI development workloads. These endpoints are the action-planning backends used by CL-STA-1238's weaponized Cairn autonomous pentesting framework. When Cairn agents run on compromised hosts, they issue HTTP requests to these inference APIs to obtain the next attack action, using them as a de-facto C2 channel. Unexpected outbound API calls to these endpoints from servers, standard workstations, or hosts outside approved AI development environments are a high-fidelity indicator of Cairn framework activity.

False positives include authorized AI development or research workstations that legitimately use DeepSeek or Zhipu APIs. Allowlist these by source IP or host tag.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Application Layer Protocol: Web Protocols |
| Technique ID | T1071.001 |
| Secondary Technique | Multi-Stage Channels |
| Secondary Technique ID | T1104 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count sum(All_Traffic.bytes_out) as bytes_out
  min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where (All_Traffic.dest_host="api.deepseek.com"
         OR All_Traffic.dest_host="open.bigmodel.cn"
         OR All_Traffic.dest_host="api.zhipuai.cn"
         OR All_Traffic.dest_host IN ("*.bigmodel.cn","*.zhipuai.cn"))
  AND All_Traffic.dest_port=443
  by All_Traffic.src All_Traffic.dest_host All_Traffic.dest_port
     All_Traffic.user All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    bytes_out > 100000, 90,
    bytes_out > 10000, 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime src dest_host dest_port user app bytes_out risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| >100KB outbound to AI inference API (unexpected host) | 90 | Significant data to AI API strongly suggests active Cairn planning loop |
| 10KB–100KB outbound to AI inference API (unexpected host) | 85 | Moderate payload consistent with iterative AI action requests |
| Any outbound to AI inference API (unexpected host) | 75 | Any connection warrants investigation if the host has no AI development justification |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| CL-STA-1238 | [Unit 42 - CL-STA-1238 Cairn Framework](https://unit42.paloaltonetworks.com/cl-sta-1238-cairn-framework-autonomous-ai-attacks/) |

## References

- [Unit 42 - CL-STA-1238: Autonomous AI Cyber Operations Using Cairn Framework (Nov 12, 2026)](https://unit42.paloaltonetworks.com/cl-sta-1238-cairn-framework-autonomous-ai-attacks/)
- [MITRE ATT&CK T1071.001 - Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK T1104 - Multi-Stage Channels](https://attack.mitre.org/techniques/T1104/)
- [Cairn Framework - Open Source AI Pentesting Tool](https://github.com/cairn-ai/cairn)
- [DeepSeek API Reference](https://platform.deepseek.com/api-docs/)
- [Zhipu AI BigModel API Reference](https://open.bigmodel.cn/dev/api)
