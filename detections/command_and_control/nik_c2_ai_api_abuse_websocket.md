# NIK C2 AI API Abuse and WebSocket C2 Beaconing

## Description

Detects the NIK C2 framework, a Go-based Windows RAT that establishes a primary WebSocket-over-TLS C2 channel on port 443 and abuses the victim host's `OPENAI_API_KEY` environment variable to authenticate AI API requests on behalf of the attacker. The attacker-controlled server presents a TLS certificate with CN `nik-panel`. A secondary HTTP polling channel operates at 250ms intervals.

Detection layers:
1. **IOC-based**: DNS query or network connection to the known C2 domain `total-sitevv[.]lol` and IP `87.120.196[.]120`
2. **TLS CN anomaly**: TLS connections from non-browser processes to servers presenting CN `nik-panel`
3. **Behavioral**: Non-browser, non-AI-client process accessing OpenAI API with an API key from the host environment (indicating the RAT is piggybacking on the victim's credentials)

False positive sources for the behavioral detection: legitimate developer tools (e.g., `cursor.exe`, `code.exe`, Python scripts) that make authorized calls to `api.openai.com` using a locally configured API key. The IOC-based and TLS CN detections have negligible false-positive rates.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Application Layer Protocol: Web Protocols |
| Technique ID | T1071.001 |
| Sub-technique | — |
| Secondary Technique | Web Service |
| Secondary Technique ID | T1102 |
| Secondary Technique | Fallback Channels |
| Secondary Technique ID | T1008 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("total-sitevv.lol","total-sitevv[.]lol","www.total-sitevv.lol")
  by DNS.src DNS.query DNS.record_type
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95, detection_layer="IOC: known NIK C2 domain"
| table firstTime lastTime src query record_type detection_layer risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest="87.120.196.120"
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95, detection_layer="IOC: known NIK C2 server IP"
| table firstTime lastTime src dest dest_port app detection_layer risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process IN ("*api.openai.com*","*OPENAI_API_KEY*")
  NOT Processes.process_name IN ("cursor.exe","code.exe","code-insiders.exe","python.exe","python3",
                                  "node.exe","node","jupyter.exe","ipython","uvicorn","gunicorn")
  NOT Processes.parent_process_name IN ("cursor.exe","code.exe","code-insiders.exe","cursor-helper")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
     Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75, detection_layer="Behavioral: non-IDE process accessing OpenAI API"
| table firstTime lastTime dest user parent_process_name process_name process detection_layer risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| DNS query or network connection to `total-sitevv[.]lol` | 95 (Critical) | Known NIK C2 IOC; no benign use |
| Network connection to `87.120.196[.]120` | 95 (Critical) | Known NIK C2 server IP; no benign use |
| Non-IDE/non-developer process accessing OpenAI API | 75 (High) | Strong behavioral signal; some false positives from custom scripts |
| TLS connection to server with CN `nik-panel` (if TLS inspection available) | 90 (Critical) | Near-zero false-positive rate for this specific CN |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (NIK C2 operator) | [Cisco Talos — NIK C2 Analysis](https://blog.talosintelligence.com/nik-c2-ai-integrated-command-and-control/) |

## References

- [Cisco Talos — NIK C2: AI-Integrated Windows Command-and-Control Framework (2026-10-29)](https://blog.talosintelligence.com/nik-c2-ai-integrated-command-and-control/)
- [MITRE ATT&CK — T1071.001 Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK — T1102 Web Service](https://attack.mitre.org/techniques/T1102/)
- [MITRE ATT&CK — T1008 Fallback Channels](https://attack.mitre.org/techniques/T1008/)
- [MITRE ATT&CK — T1003.001 OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
