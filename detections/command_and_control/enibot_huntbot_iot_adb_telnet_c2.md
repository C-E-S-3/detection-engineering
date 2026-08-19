# ENIBot/HuntBot IoT Botnet C2 Beaconing and ADB Exploitation

## Description

Detects IoT and Android devices compromised by the ENIBot/HuntBot DDoS-for-hire botnet, which enrolls victims via unauthenticated Android Debug Bridge (ADB) on TCP/5555, Telnet brute-force on TCP/23 and TCP/2323, and OpenSSH CVE exploitation (CVE-2023-28531, CVE-2024-6387, CVE-2024-41996). Enrolled bots beacon to C2 servers on non-standard TCP ports 1337 and 1338 to receive DDoS tasking (HTTP GET flood, HTTP POST flood, Slowloris, RUDY attacks).

Rule 1 detects outbound connections to confirmed ENIBot C2 IPs or to the characteristic non-standard ports 1337/1338. Rule 2 detects inbound ADB connection attempts, which indicate either active botnet scanning for new recruits or an already-infected device being commanded via ADB.

False positives for Rule 1 are minimal; TCP 1337/1338 have no legitimate business use. False positives for Rule 2 may include authorized Android device management in BYOD environments — scope with known Android MDM source IPs.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Application Layer Protocol: Web Protocols |
| Technique ID | T1071.001 |
| Technique | Non-Standard Port |
| Technique ID | T1571 |
| Technique | Network Denial of Service: Direct Network Flood |
| Technique ID | T1498.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) |
| Actions on Objectives |

## Splunk Detection Query

**Rule 1 — ENIBot C2 Beaconing (Known IPs + Non-Standard Ports)**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where ((All_Traffic.dest_ip IN ("216.167.26.154","192.204.41.160","176.65.139.99",
    "176.65.139.7","176.65.139.11","176.65.139.69","176.65.139.59"))
    OR (All_Traffic.dest_port IN (1337,1338) AND All_Traffic.transport="tcp"))
by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.transport
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    dest_ip IN ("216.167.26.154","192.204.41.160","176.65.139.99","176.65.139.7",
        "176.65.139.11","176.65.139.69","176.65.139.59"), 95,
    dest_port IN (1337,1338), 75,
    true(), 50)
| where risk_score >= 75
| table firstTime lastTime src_ip dest_ip dest_port transport risk_score
```

**Rule 2 — Inbound ADB (TCP/5555) Exploitation Scanning**

```spl
| tstats `security_content_summariesonly` count dc(All_Traffic.dest_ip) as unique_targets
    min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_port=5555 AND All_Traffic.transport="tcp"
by All_Traffic.src_ip All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    unique_targets > 50, 85,
    unique_targets > 10, 70,
    true(), 50)
| where risk_score >= 50
| table firstTime lastTime src_ip dest_port unique_targets count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Outbound connection to confirmed ENIBot C2 IP | 95 | Direct IOC match; Critical; nearly certain true positive |
| Outbound TCP to port 1337 or 1338 | 75 | No legitimate service uses these ports; high confidence C2 beaconing |
| ADB scan: >50 unique targets in window | 85 | Mass scanning indicative of botnet propagation |
| ADB scan: 10–50 unique targets in window | 70 | Targeted ADB sweep; suspicious even at low volume |
| ADB connection attempt (any count) | 50 | Context enrichment; correlate with other botnet indicators |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| ENIBot / HuntBot (DDoS-for-hire botnet operator) | [Unit 42 — ENIBot/HuntBot IoT Botnet Campaign (2026-08-14)](https://unit42.paloaltonetworks.com/enibot-huntbot-iot-botnet-campaign/) |

## References

- [Unit 42 — ENIBot/HuntBot IoT Botnet Campaign (2026-08-14)](https://unit42.paloaltonetworks.com/enibot-huntbot-iot-botnet-campaign/)
- [MITRE ATT&CK — T1571: Non-Standard Port](https://attack.mitre.org/techniques/T1571/)
- [MITRE ATT&CK — T1498.001: Network DoS: Direct Network Flood](https://attack.mitre.org/techniques/T1498/001/)
- [NVD — CVE-2024-6387 (OpenSSH regreSSHion)](https://nvd.nist.gov/vuln/detail/CVE-2024-6387)
- [NVD — CVE-2024-41996 (OpenSSH DH key exchange DoS)](https://nvd.nist.gov/vuln/detail/CVE-2024-41996)
