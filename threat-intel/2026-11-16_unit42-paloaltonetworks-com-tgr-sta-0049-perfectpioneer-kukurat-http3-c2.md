---
scraped_at: 2026-11-18T00:00:00Z
source_url: https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/
report_type: threat-intel
severity: high
title: "TGR-STA-0049 (Earth Alux / Ink Dragon): HTTP/3 over QUIC RAT C2 Targeting Southeast Asian Government Entities — PerfectPioneer and KUKURAT Implants"
---

# TGR-STA-0049 (Earth Alux / Ink Dragon): HTTP/3 over QUIC RAT C2 Targeting Southeast Asian Government Entities

**Source:** Unit 42 / Palo Alto Networks  
**Published:** 2026-11-16  
**Severity:** High — state-sponsored espionage actor; novel C2 evasion using HTTP/3 over QUIC protocol; targets Southeast Asian government ministries; also tracked as REF7707 (Elastic), Earth Alux (Trend Micro), Ink Dragon (CrowdStrike)

---

## 1. IOCs

No network IOCs (C2 IPs, domains) were confirmed from publicly available sources at the time of this report. Unit 42's full indicator set is shared via threat intelligence feeds and not fully disclosed in the public report. Intrusion detection relies on behavioral TTPs.

No file hashes were confirmed from secondary sources without discrepancies; hashes are not included pending verification against primary research.

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique | Notes |
|--------|-----------|-------|
| TA0011 Command and Control | T1071.001 — Application Layer Protocol: Web Protocols | C2 communication over HTTP/3 (QUIC/UDP) blends with legitimate HTTPS traffic at the protocol layer |
| TA0011 Command and Control | T1095 — Non-Application Layer Protocol | QUIC (UDP/443) used as the transport for HTTP/3 C2; evades TCP-based network monitoring and many DPI solutions |
| TA0011 Command and Control | T1573.002 — Encrypted Channel: Asymmetric Cryptography | HTTP/3 carries TLS 1.3 natively; C2 traffic is indistinguishable from browser QUIC at the cipher/cert level |
| TA0011 Command and Control | T1008 — Fallback Channels | Implants configured with fallback to HTTP/1.1 or HTTP/2 when QUIC is blocked |
| TA0007 Discovery | T1057 — Process Discovery | Implants enumerate running processes on compromised government hosts |
| TA0007 Discovery | T1082 — System Information Discovery | OS version, hostname, domain membership collected during initial beacon |
| TA0010 Exfiltration | T1041 — Exfiltration Over C2 Channel | Collected documents and credentials exfiltrated over the same HTTP/3 channel used for C2 |
| TA0005 Defense Evasion | T1036 — Masquerading | RAT implants use names and paths designed to blend with legitimate system components |

**Kill Chain Phase:** Command & Control (novel HTTP/3 QUIC evasion) → Actions on Objectives (document collection, credential harvesting from government ministries)

---

## 3. Malware & Tools

**PerfectPioneer:** Custom Windows RAT attributed to TGR-STA-0049. Communicates to operator infrastructure using HTTP/3 over QUIC (UDP/443). Capabilities include: interactive command shell, file collection and exfiltration, process enumeration, credential harvesting, and persistent implant installation. HTTP/3 transport implemented using an embedded QUIC library rather than relying on the Windows networking stack, making transport-layer anomaly detection more difficult.

**KUKURAT:** A second custom RAT deployed alongside PerfectPioneer in some intrusions, believed to serve as a secondary access path and keylogger/screen capture tool. Also uses HTTP/3 for C2 in later variants; earlier versions used standard HTTPS.

**Key evasion characteristic:** HTTP/3 over QUIC uses UDP/443 — a port and protocol combination increasingly associated with legitimate browser traffic (Chrome, Firefox, Edge, Safari all use QUIC for major web properties). Traditional network monitoring focused on TCP/443 TLS inspection does not cover QUIC traffic. Many enterprise DLP and IDS solutions lack QUIC inspection capability, rendering the C2 channel invisible in many environments.

---

## 4. Threat Actor / Campaign Attribution

**TGR-STA-0049** is a China-nexus APT group tracked under multiple aliases: REF7707 (Elastic Security Labs), Earth Alux (Trend Micro), Ink Dragon (CrowdStrike). The group targets Southeast Asian government entities — specifically defense ministries, foreign affairs, and intelligence-adjacent organizations — consistent with strategic espionage objectives aligned with Chinese state interests in the region.

The adoption of HTTP/3 over QUIC represents a deliberate evolution of the group's C2 infrastructure to defeat network-layer monitoring. The technique has been observed across multiple TGR-STA-0049 intrusions since mid-2026, suggesting it is a durable operational capability rather than a one-time experiment.

Initial access methods used by TGR-STA-0049 include spearphishing with lure documents and exploitation of internet-facing applications. Once inside, the group demonstrates patient, low-and-slow tradecraft consistent with long-term espionage operations.

---

## 5. Splunk Detection Searches

### 5.1 Servers Generating Outbound UDP/443 (QUIC) — Unusual Source Category

Detects server-class hosts generating QUIC (UDP/443) connections. Legitimate browser-originated QUIC traffic originates from workstations; servers rarely run browsers and should not generate outbound UDP/443 at volume.

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

### 5.2 Low-and-Slow QUIC Beaconing Pattern (Statistical Anomaly)

Detects regular-interval UDP/443 beaconing consistent with RAT check-in behavior. Legitimate QUIC traffic from browsers shows burst patterns; implant beaconing shows periodic low-volume sessions.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  sum(All_Traffic.bytes_out) as bytes_out
  sum(All_Traffic.bytes_in) as bytes_in
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.transport=udp AND All_Traffic.dest_port=443
  by All_Traffic.src_ip All_Traffic.dest_ip _time span=1h
| `drop_dm_object_name(All_Traffic)`
| eval bytes_per_session=bytes_out/count
| eval avg_bytes=round((bytes_out + bytes_in) / count, 0)
| where count > 10 AND avg_bytes < 4096
| stats stdev(count) as count_stdev avg(count) as avg_count
  min(_time) as firstTime max(_time) as lastTime
  values(dest_ip) as dest_ips
  by src_ip
| eval beacon_score=round((avg_count / (count_stdev + 1)) * 10, 2)
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

### 5.3 Non-Browser Process Initiating UDP/443 Connections (Endpoint Telemetry)

Detects system processes other than web browsers making outbound connections over UDP/443. Requires endpoint detection telemetry with process-network correlation (e.g., CrowdStrike, SentinelOne, Sysmon network events).

```spl
index=endpoint sourcetype IN ("crowdstrike:events:json", "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational")
  EventID IN (3, 22) Protocol=UDP DestinationPort=443
| where NOT match(Image, "(?i)(chrome\.exe|firefox\.exe|msedge\.exe|safari|opera|brave|iexplore\.exe|chromium)")
| stats count min(_time) as firstTime max(_time) as lastTime
  values(DestinationIp) as dest_ips
  by Computer User Image DestinationPort Protocol
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(Image, "(?i)(svchost|lsass|services|winlogon|explorer|rundll32|regsvr32)"), 85,
    match(Image, "(?i)(cmd\.exe|powershell|wscript|cscript|mshta)"), 80,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime Computer User Image DestinationPort Protocol dest_ips count risk_score
```

---

## 6. Mitigation

- **Enable QUIC logging:** Configure network monitoring tools to log UDP/443 traffic; many DPI/IDS solutions skip QUIC by default. Palo Alto NGFW: enable App-ID for QUIC; Zeek: deploy the QUIC analyzer plugin.
- **Consider QUIC blocking on server segments:** Block UDP/443 outbound from server network segments where browser usage is not expected. Browsers on workstation segments will fall back to TCP/443; this will not prevent legitimate browsing while removing the attack surface for server-sourced QUIC C2.
- **Inspect QUIC traffic:** Where available, deploy SSL/TLS inspection that supports QUIC to gain visibility into encrypted UDP/443 flows.
- **Monitor server-originated UDP/443:** Alert on any server-class host generating outbound UDP/443 that is not associated with a known legitimate application.
- **Threat hunting:** Review UDP/443 flows from government/sensitive workstations for low-and-slow beaconing patterns (periodic small-payload connections at regular intervals).

---

## 7. References

- [Unit 42: Custom RATs Target Southeast Asia Governments (TGR-STA-0049)](https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/)
- [Elastic Security: REF7707 Threat Profile](https://www.elastic.co/security-labs/ref7707)
- [Trend Micro: Earth Alux](https://www.trendmicro.com/en_us/research.html)
- [MITRE ATT&CK T1071.001 — Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK T1095 — Non-Application Layer Protocol](https://attack.mitre.org/techniques/T1095/)
- [MITRE ATT&CK T1573.002 — Asymmetric Cryptography](https://attack.mitre.org/techniques/T1573/002/)
- [IETF RFC 9114: HTTP/3](https://www.rfc-editor.org/rfc/rfc9114)
