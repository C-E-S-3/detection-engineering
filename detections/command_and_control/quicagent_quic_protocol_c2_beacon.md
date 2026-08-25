# QUICAgent QUIC Protocol C2 Beacon

## Description

Detects non-browser processes establishing outbound QUIC (UDP/443) connections, consistent with the QUICAgent Go backdoor used in Operation QUICSILVER. QUICAgent communicates with its C2 server using the QUIC protocol over UDP port 443 to blend with legitimate HTTPS/3 traffic. Before initiating C2, the implant queries a Cloudflare Workers domain (`register[.]mediumser[.]com`) to dynamically resolve the current C2 server IP, avoiding hardcoded infrastructure.

QUIC over UDP/443 is a significant detection gap because most network monitoring focuses on TCP-based HTTPS (port 443/TCP). Legitimate QUIC traffic originates from browsers (Chrome, Edge, Firefox) and well-known applications (Zoom, Teams, Google Meet). Any non-browser process generating sustained UDP/443 traffic is highly anomalous.

**False positive sources:** Video conferencing clients (Zoom, Webex, Teams), browsers with QUIC enabled, CDN health checks on endpoints with custom software. Tune the exclusion list for your environment's known QUIC-using applications.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Application Layer Protocol: Web Protocols |
| Technique ID | T1071.001 |
| Secondary Technique | Dynamic Resolution |
| Secondary Technique ID | T1568 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    sum(All_Traffic.bytes_out) as total_bytes_out
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port=443
    AND All_Traffic.transport="udp"
    AND NOT All_Traffic.app IN (
      "quic","zoom","teams","meet","webex","skype","slack",
      "chrome","msedge","firefox","safari","opera","brave",
      "google-chrome","microsoft-edge"
    )
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port
     All_Traffic.transport All_Traffic.app All_Traffic.src_ip
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    dest IN ("104.64.211.22"), 95,
    total_bytes_out > 100000, 80,
    total_bytes_out > 10000, 70,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src dest dest_port transport app total_bytes_out risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Destination matches known QUICAgent C2 IP (`104.64.211.22`) | 95 | Direct IOC match; near-certain true positive |
| Non-browser/non-conferencing process; > 100 KB sent via UDP/443 | 80 | Sustained non-browser QUIC C2 beaconing pattern |
| Non-browser/non-conferencing process; 10–100 KB sent via UDP/443 | 70 | Anomalous QUIC egress; likely C2 establishment phase |
| Non-browser/non-conferencing process; any UDP/443 traffic | 60 | Baseline anomaly; requires analyst review and process correlation |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Operation QUICSILVER (China-nexus) | [Seqrite — Operation QUICSILVER](https://www.seqrite.com/blog/operation-quicsilver-china-nexus-actor-targets-myanmar-diplomats-via-vhd-delivered-go-backdoor/) |
| DragonForce (Backdoor.Turn, QUIC via Teams TURN relay) | [Symantec — Backdoor.Turn (2026-06-16)](https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor) |

## References

- [Seqrite — Operation QUICSILVER (2026-08)](https://www.seqrite.com/blog/operation-quicsilver-china-nexus-actor-targets-myanmar-diplomats-via-vhd-delivered-go-backdoor/)
- [MITRE ATT&CK T1071.001 — Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK T1568 — Dynamic Resolution](https://attack.mitre.org/techniques/T1568/)
- [IETF RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000)
