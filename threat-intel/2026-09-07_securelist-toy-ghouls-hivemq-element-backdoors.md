---
title: "Toy Ghouls: New Windows Backdoors Abuse HiveMQ MQTT and Element Messenger for C2"
source: Kaspersky / Securelist
source_url: https://securelist.com/toy-ghouls-new-hivemq-and-element-backdoors/121270/
date: 2026-09-07
scraped_at: 2026-09-07T00:00:00Z
report_type: threat-intel
severity: high
tags: [toy-ghouls, mqtt, hivemq, element, matrix, c2, windows-backdoor, russia, winrm, chacha20]
mitre_tactics: [TA0003, TA0011, TA0008]
---

# Toy Ghouls: New Windows Backdoors Abuse HiveMQ MQTT and Element Messenger for C2

## Executive Summary

Kaspersky's Securelist published research on 2026-09-05 documenting two novel Windows backdoors attributed to the **Toy Ghouls** threat actor. The backdoors—**mqtt-bird-agent 0.1.0** and **matrix-bird-agent 0.1.0**—use publicly available messaging infrastructure (HiveMQ's public MQTT broker and an attacker-controlled Element/Matrix server) as command-and-control channels, a technique that blends C2 traffic with legitimate messaging traffic and bypasses conventional domain- and IP-based blocking. First observed in July 2026, the implants target Russian organizations and are deployed post-compromise following acquisition of valid administrator credentials via WinRM.

## IOCs

### Domains

| Indicator | Role |
|-----------|------|
| `broker[.]hivemq[.]com` | Legitimate public MQTT broker abused by mqtt-bird-agent 0.1.0 (`cplsupport.exe`) for C2 traffic |
| `meet[.]element[.]tw` | Attacker-controlled Matrix/Element server used by matrix-bird-agent 0.1.0 (`wtass.exe`) for C2 |

### IP Addresses

| Indicator | Role |
|-----------|------|
| No specific IPs recovered at time of report | — |

### File Hashes

| Hash | Type | File | Description |
|------|------|------|-------------|
| `BFADBEEE63A4F0BF19EC9DEB8FA58F58` | MD5 | `cplsupport.exe` | Toy Ghouls MQTT backdoor (mqtt-bird-agent 0.1.0); C2 via broker.hivemq.com; ChaCha20-Poly1305 encrypted config |
| `7916C33688385525078BEE504C90F359` | MD5 | `wtass.exe` | Toy Ghouls Element/Matrix backdoor (matrix-bird-agent 0.1.0); C2 via meet.element.tw; encrypted config in registry key `SealedConfig` |

## TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Description |
|--------|-----------|----|-------------|
| Lateral Movement | Remote Services: Windows Remote Management | T1021.006 | Initial implant deployment via Evil-WinRM / WinRM-fs after valid admin credential acquisition |
| Persistence | Create or Modify System Process: Windows Service | T1543.003 | Backdoors can run as a Windows service; `cplsupport.exe` and `wtass.exe` register as services |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | MQTT over TCP/8883 (TLS) to broker.hivemq.com; blends with legitimate MQTT traffic |
| Command and Control | Web Service | T1102 | Matrix/Element messaging service (`meet.element.tw`) used as C2 relay |
| Defense Evasion | Obfuscated Files or Information: Encrypted/Encoded File | T1027.002 | ChaCha20-Poly1305 encrypted configuration for mqtt-bird-agent; `SealedConfig` registry key for matrix-bird-agent |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 | Binary names `cplsupport.exe` (mimics CPL support) and `wtass.exe` (mimics Windows TASS service) |

### Kill Chain Phase
**Installation → Command & Control → Actions on Objectives**

## Malware & Tools

| Name | Version | Binary | Description |
|------|---------|--------|-------------|
| mqtt-bird-agent | 0.1.0 | `cplsupport.exe` | Windows backdoor; MQTT C2 via HiveMQ public broker; ChaCha20-Poly1305 config encryption; deployable as Windows service |
| matrix-bird-agent | 0.1.0 | `wtass.exe` | Windows backdoor; Matrix/Element C2 via attacker-controlled `meet.element.tw`; encrypted config stored in `SealedConfig` registry key; deployable as Windows service |
| Evil-WinRM / WinRM-fs | — | — | Open-source WinRM tooling used for post-credential-acquisition lateral movement and implant staging |

## Threat Actor / Campaign Attribution

- **Threat Actor**: Toy Ghouls (no established public alias beyond Securelist attribution)
- **Motivation**: Unknown — Securelist describes the targeting as post-compromise persistence; potential espionage or financially motivated
- **Targeting**: Russian organizations (government, enterprise)
- **First observed**: July 2026 (mqtt-bird-agent and matrix-bird-agent builds dated July 2026)
- **Disclosure**: 2026-09-05 (Securelist / Kaspersky)
- **Novel TTPs**: Use of public MQTT broker (HiveMQ) and self-hosted Matrix server as C2 channels to evade network-based blocking; ChaCha20-Poly1305 config encryption

## Splunk Detection Searches

### 1 — MQTT Traffic to broker.hivemq.com (Network)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_host="broker.hivemq.com"
     OR (All_Traffic.dest_port IN ("1883","8883") AND All_Traffic.app!="mqtt")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port
     All_Traffic.app All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    dest_host="broker.hivemq.com", 85,
    dest_port IN ("1883","8883"), 60,
    true(), 40)
| where risk_score >= 60
| table firstTime lastTime src dest dest_host dest_port app bytes_out risk_score
```

**Risk Score**: 60–85 (High) — MQTT to HiveMQ public broker from endpoint is unusual and warrants investigation.

### 2 — Matrix/Element C2 Network Connections (Network)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_host="meet.element.tw"
     OR All_Traffic.dest_host IN ("matrix.element.tw","element.tw")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src dest dest_host dest_port bytes_out
```

**Risk Score**: 90 (Critical) — `meet.element.tw` is an attacker-controlled infrastructure; any connection is a high-confidence IOC hit.

### 3 — Toy Ghouls Backdoor Process Execution (Endpoint)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("cplsupport.exe","wtass.exe")
  by Processes.dest Processes.user Processes.process_name Processes.process_path
     Processes.process Processes.process_id Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user process_name process_path parent_process_name process_id
```

**Risk Score**: 95 (Critical) — File name IOC match for known Toy Ghouls backdoor binaries.

### 4 — Suspicious Registry Key SealedConfig (Endpoint Registry)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Registry
  where Registry.registry_key_name="*SealedConfig*"
  by Registry.dest Registry.user Registry.registry_key_name Registry.registry_value_name
     Registry.registry_value_data Registry.process_name
| `drop_dm_object_name(Registry)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user registry_key_name registry_value_name process_name
```

**Risk Score**: 80 (High) — `SealedConfig` is a Toy Ghouls–specific registry artifact for encrypted matrix-bird-agent configuration.

### 5 — WinRM Lateral Movement Followed by Suspicious Service Creation (Endpoint / Correlation)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Services
  where Services.process_name IN ("cplsupport.exe","wtass.exe")
     OR Services.service_description="*bird*agent*"
  by Services.dest Services.user Services.process_name Services.service_name Services.service_description
| `drop_dm_object_name(Services)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user process_name service_name service_description
```

**Risk Score**: 90 (Critical) — Toy Ghouls–specific service names or binary matches.

## References

- [Securelist: New backdoors from Toy Ghouls](https://securelist.com/toy-ghouls-new-hivemq-and-element-backdoors/121270/)
- [GBHackers: Hackers Turn HiveMQ and Element Messenger Into Control Channels](https://gbhackers.com/hivemq-powers-backdoor/)
- [SecurityOnline: Toy Ghouls Backdoor Uses HiveMQ and Element for C2](https://securityonline.info/toy-ghouls-backdoor-hivemq-element/)
- [MITRE ATT&CK T1102 — Web Service](https://attack.mitre.org/techniques/T1102/)
- [MITRE ATT&CK T1071.001 — Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK T1021.006 — Remote Services: Windows Remote Management](https://attack.mitre.org/techniques/T1021/006/)
