# CylindricalCanine Golden Gh0st RAT WebSocket C2

## Description

Detects Golden Gh0st RAT command-and-control communications attributed to CylindricalCanine, a subgroup of the Chinese cybercrime and espionage collective GoldenEyeDog (APT-Q-27 / Dragon Breath / Miuuti Group). The RAT uses a dual-port WebSocket C2 architecture: an unencrypted command channel on TCP 5188 and an encrypted data exfiltration channel on TCP 5198.

The group stole 60 code-signing certificates from DigiCert in April 2026 by compromising a support employee via a malicious file in the ticketing system. At least 27 certificates were used to sign Golden Gh0st Loader and Golden Gh0st RAT binaries, defeating signature-based AV detection at time of deployment.

False positive sources: legitimate applications using custom WebSocket ports 5188 or 5198 (uncommon); verify by checking the connecting process name and reviewing for additional post-exploitation indicators.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control (TA0011) |
| Technique | T1071.001 — Application Layer Protocol: Web Protocols |
| Additional Technique | T1573 — Encrypted Channel |
| Additional Technique | T1553.002 — Code Signing (defense evasion vector for initial delivery) |

## Lockheed Martin Kill Chain Phase

Command & Control (C2)

## Splunk SPL Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where (All_Traffic.dest_port IN ("5188", "5198")
      OR All_Traffic.dest IN ("uu.goldeyeuu.io", "api.keensie.com"))
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
     All_Traffic.transport All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    dest IN ("uu.goldeyeuu.io", "api.keensie.com"), 95,
    dest_port IN ("5188", "5198") AND bytes_out > 10000, 80,
    dest_port IN ("5188", "5198"), 65
  )
| where risk_score >= 65
| table firstTime lastTime src dest dest_port app transport bytes_out risk_score
```

**Process-correlated detection (if host-network correlation is available):**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port IN ("5188", "5198")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| join src
    [ | tstats `security_content_summariesonly` count
        from datamodel=Endpoint.Processes
        where NOT Processes.process_name IN ("chrome.exe", "firefox.exe", "msedge.exe",
                                              "safari", "opera.exe", "brave.exe",
                                              "iexplore.exe", "Electron.exe")
        by Processes.dest Processes.process_name Processes.process_id
      | `drop_dm_object_name(Processes)`
      | rename dest as src ]
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src dest dest_port process_name risk_score
```

**File hash IOC hunt:**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_hash="81e276aaa3eb9b3f595663c316b3c6414cc3dde5e6cc3a82856b7276acabb7de"
  by Processes.dest Processes.user Processes.process_name Processes.process_hash
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime dest user process_name process_hash risk_score
```

## Risk Score Logic

| Score | Condition |
|-------|-----------|
| 100 | Process hash matches Golden Gh0st IOC exactly |
| 95 | Outbound connection to known C2 domain (`uu.goldeyeuu.io` or `api.keensie.com`) |
| 90 | Non-browser process connecting to TCP 5188 or 5198 externally |
| 80 | Any host connecting to TCP 5188 or 5198 with significant data transfer (>10KB) |
| 65 | Any outbound connection to TCP 5188 or 5198 (low-confidence, needs triage) |

## Associated Threat Actors

- **CylindricalCanine** — subgroup of GoldenEyeDog (APT-Q-27 / Dragon Breath / Miuuti Group); Chinese cybercrime and espionage collective; targeted DigiCert April 2026 to steal code-signing certificates for malware signing
- **GoldenEyeDog** — broader collective previously targeting online gambling platforms and VPN users in Southeast Asia

## References

- Expel (2026-07-20): https://expel.com/blog/introducing-cylindricalcanine/
- The Hacker News (2026-07): https://thehackernews.com/2026/07/goldeneyedog-subgroup-linked-to.html
- MITRE ATT&CK — Dragon Breath (APT-Q-27 / G1071): https://attack.mitre.org/groups/G1071/
- MITRE ATT&CK T1071.001: https://attack.mitre.org/techniques/T1071/001/
- MITRE ATT&CK T1553.002: https://attack.mitre.org/techniques/T1553/002/
