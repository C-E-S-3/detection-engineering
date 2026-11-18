# TGR-STA-0049 HTTP/3 over QUIC RAT C2 Beaconing

## Description

Detects command-and-control communications using HTTP/3 over QUIC (UDP/443), the C2 transport used by TGR-STA-0049 (also tracked as REF7707, Earth Alux, Ink Dragon) in campaigns targeting Southeast Asian government ministries. The PerfectPioneer and KUKURAT RAT families implement HTTP/3 natively to blend with legitimate browser QUIC traffic and evade TCP-focused DPI and IDS inspection.

Three complementary detection surfaces:

1. **Server-sourced QUIC (high confidence):** Server-class hosts generating outbound UDP/443 — servers don't run browsers and should not produce QUIC traffic.
2. **Low-and-slow QUIC beaconing (statistical):** Regular-interval, low-volume UDP/443 sessions consistent with periodic RAT check-in rather than bulk data transfer.
3. **Non-browser process initiating UDP/443 (endpoint telemetry):** Process-level network events where the initiating process is not a browser — the definitive signal when endpoint telemetry is available.

False positive sources for the statistical detection: legitimate QUIC-using background services (some update mechanisms, cloud sync agents); tune by allowlisting known-good source processes. The server-sourced detection produces very few false positives since servers legitimately running browsers are rare.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Application Layer Protocol: Web Protocols |
| Technique ID | T1071.001 |

Secondary techniques: T1095 (Non-Application Layer Protocol — QUIC/UDP transport), T1573.002 (Encrypted Channel: Asymmetric Cryptography — TLS 1.3 within QUIC), T1008 (Fallback Channels — HTTP/1.1 fallback when QUIC is blocked).

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) |

## Splunk Detection Query

### Detection 1: Server-Class Hosts Generating Outbound UDP/443

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  dc(All_Traffic.dest_ip) as unique_dests
  sum(All_Traffic.bytes_out) as bytes_out
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.transport=udp AND All_Traffic.dest_port=443
    AND All_Traffic.src_category IN ("server", "dc", "domain-controller",
      "web-server", "app-server", "database-server")
  by All_Traffic.src_ip All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    app IN ("unknown", "unknown-udp") OR isnull(app), 85,
    NOT match(app, "(?i)(chrome|firefox|safari|edge|quic|http3|h3|google)"), 80,
    1=1, 55)
| where risk_score >= 55
| table firstTime lastTime src_ip app unique_dests bytes_out count risk_score
```

### Detection 2: Low-and-Slow QUIC Beaconing (Statistical Pattern)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  sum(All_Traffic.bytes_out) as bytes_out
  sum(All_Traffic.bytes_in) as bytes_in
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.transport=udp AND All_Traffic.dest_port=443
  by All_Traffic.src_ip All_Traffic.dest_ip _time span=1h
| `drop_dm_object_name(All_Traffic)`
| eval avg_bytes_per_flow=round((bytes_out + bytes_in) / count, 0)
| where count > 10 AND avg_bytes_per_flow < 4096
| stats stdev(count) as count_stdev avg(count) as avg_count
  min(firstTime) as firstTime max(lastTime) as lastTime
  values(dest_ip) as dest_ips
  by src_ip
| eval beacon_score=round((avg_count / (count_stdev + 0.1)) * 10, 2)
| where beacon_score > 25
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    beacon_score > 50, 85,
    beacon_score > 25, 70,
    1=1, 55)
| where risk_score >= 55
| table firstTime lastTime src_ip dest_ips avg_count count_stdev beacon_score risk_score
```

### Detection 3: Non-Browser Process UDP/443 (Endpoint Telemetry)

```spl
index=endpoint sourcetype IN ("crowdstrike:events:json", "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational")
  EventID IN (3, 22) Protocol=UDP DestinationPort=443
| where NOT match(Image, "(?i)(chrome\.exe|firefox\.exe|msedge\.exe|safari|opera|brave|iexplore\.exe|chromium\.exe)")
| stats count min(_time) as firstTime max(_time) as lastTime
  values(DestinationIp) as dest_ips
  by Computer User Image DestinationPort Protocol
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(Image, "(?i)(svchost|lsass|services|winlogon|explorer|rundll32|regsvr32)"), 90,
    match(Image, "(?i)(cmd\.exe|powershell|wscript|cscript|mshta)"), 85,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime Computer User Image DestinationPort Protocol dest_ips count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Server-class host, unknown app, UDP/443 | 85 | Servers don't run browsers; unknown QUIC from server = high suspicion |
| Server-class host, non-browser app, UDP/443 | 80 | Known non-browser process generating QUIC from server |
| Statistical beacon score > 50 (very regular) | 85 | Highly periodic QUIC beaconing — strong RAT check-in indicator |
| Statistical beacon score 25–50 | 70 | Moderately periodic; warrants investigation |
| System process (svchost/lsass) UDP/443 (endpoint) | 90 | Critical Windows processes should never generate QUIC |
| Shell/script interpreter UDP/443 (endpoint) | 85 | Unusual interpreter process generating QUIC traffic |
| Arbitrary non-browser process UDP/443 (endpoint) | 65 | Unknown process making QUIC connection — investigate |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| TGR-STA-0049 (Unit 42) / REF7707 (Elastic) / Earth Alux (Trend Micro) / Ink Dragon (CrowdStrike) | [Unit 42: Custom RATs Target SEA Governments](https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/) |

## References

- [Unit 42: Custom RATs Target Southeast Asia Governments (TGR-STA-0049)](https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/)
- [Elastic Security: REF7707 Threat Profile](https://www.elastic.co/security-labs/ref7707)
- [MITRE ATT&CK T1071.001 — Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK T1095 — Non-Application Layer Protocol](https://attack.mitre.org/techniques/T1095/)
- [MITRE ATT&CK T1573.002 — Encrypted Channel: Asymmetric Cryptography](https://attack.mitre.org/techniques/T1573/002/)
- [IETF RFC 9114: HTTP/3](https://www.rfc-editor.org/rfc/rfc9114)
- [Threat Intel Report: TGR-STA-0049](../threat-intel/2026-11-16_unit42-paloaltonetworks-com-tgr-sta-0049-perfectpioneer-kukurat-http3-c2.md)
