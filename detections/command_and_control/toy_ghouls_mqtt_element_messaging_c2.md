# Toy Ghouls: MQTT and Element/Matrix Messaging Service C2

## Description

Detects Windows backdoor C2 activity associated with the **Toy Ghouls** threat actor, which deploys two novel implants that abuse public messaging infrastructure to blend C2 traffic with legitimate service communications:

- **mqtt-bird-agent 0.1.0** (`cplsupport.exe`): Uses the public HiveMQ MQTT broker (`broker.hivemq.com`) over TLS (port 8883) for command-and-control. Configuration encrypted with ChaCha20-Poly1305.
- **matrix-bird-agent 0.1.0** (`wtass.exe`): Uses an attacker-controlled Matrix/Element server (`meet.element.tw`) for C2. Stores encrypted configuration in a registry key named `SealedConfig`.

Both implants are deployed post-compromise via WinRM/Evil-WinRM following valid administrator credential acquisition, and can run as Windows services. Targets Russian organizations.

**False positive sources:**
- Legitimate MQTT clients in IoT or industrial environments connecting to `broker.hivemq.com`
- Legitimate Matrix/Element desktop clients (note: `meet.element.tw` is an attacker-controlled domain, not the canonical `element.io` service)
- Network security scanning tools connecting to MQTT ports

## MITRE ATT&CK Mapping

- **Tactic:** Command and Control (TA0011)
- **Technique:** Web Service (T1102) — Element/Matrix C2 via attacker-controlled server
- **Technique:** Application Layer Protocol: Web Protocols (T1071.001) — MQTT over TLS to HiveMQ broker
- **Sub-technique:** Web Service: Bidirectional Communication (T1102.002) — two-way C2 via messaging platform
- **Secondary Tactic:** Persistence (TA0003)
- **Secondary Technique:** Create or Modify System Process: Windows Service (T1543.003) — backdoors register as Windows services

## Lockheed Martin Kill Chain Phase

**Installation** (service persistence), **Command & Control** (MQTT/Matrix C2 channels)

## Splunk SPL Query

### Rule 1 — MQTT Connections to HiveMQ Public Broker (Network)

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
    dest_host="broker.hivemq.com" AND dest_port="8883", 85,
    dest_host="broker.hivemq.com", 75,
    dest_port IN ("1883","8883"), 60,
    true(), 40)
| where risk_score >= 60
| table firstTime lastTime src dest dest_host dest_port app bytes_out risk_score
```

### Rule 2 — Toy Ghouls meet.element.tw C2 (Network IOC)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_host="meet.element.tw"
     OR All_Traffic.dest_host="element.tw"
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src dest dest_host dest_port bytes_out
```

### Rule 3 — Toy Ghouls Backdoor Binary Execution (Endpoint)

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

### Rule 4 — SealedConfig Registry Key (Endpoint Registry)

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

## Risk Score Logic

| Score | Condition |
|-------|-----------|
| 95 | Process name IOC match (`cplsupport.exe` or `wtass.exe`) |
| 90 | `SealedConfig` registry key created or modified |
| 90 | Network connection to `meet.element.tw` |
| 85 | MQTT TLS (port 8883) connection to `broker.hivemq.com` |
| 75 | MQTT cleartext (port 1883) connection to `broker.hivemq.com` |
| 60 | Any outbound MQTT traffic on port 1883/8883 from a non-IoT host |

## Associated Threat Actors

| Actor | Role |
|-------|------|
| Toy Ghouls | Threat actor deploying mqtt-bird-agent and matrix-bird-agent; targets Russian organizations; post-compromise persistence focus; WinRM deployment after valid credential acquisition |

## References

- [Securelist: New backdoors from Toy Ghouls](https://securelist.com/toy-ghouls-new-hivemq-and-element-backdoors/121270/)
- [GBHackers: Hackers Turn HiveMQ and Element Messenger Into Control Channels](https://gbhackers.com/hivemq-powers-backdoor/)
- [MITRE ATT&CK T1102 — Web Service](https://attack.mitre.org/techniques/T1102/)
- [MITRE ATT&CK T1071.001 — Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK T1543.003 — Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/)
- [MITRE ATT&CK T1021.006 — Remote Services: Windows Remote Management](https://attack.mitre.org/techniques/T1021/006/)
