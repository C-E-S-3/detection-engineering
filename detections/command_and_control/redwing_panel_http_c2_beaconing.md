# RedWing Panel / SXRat HTTP C2 Beaconing

## Description

Detects outbound network connections and DNS queries to known RedWing Panel / SXRat C2 infrastructure. RedWing Panel is a Windows RAT with VNC remote-access capability, distributed through Russian-speaking cybercrime channels. HTTP C2 operates primarily on non-standard TCP port 8080. A dedicated `vnc.redwing.top` subdomain confirms VNC-based interactive access. 32 confirmed C2 IP addresses and 22 C2/panel domains were added to open-source threat intelligence on July 25, 2026 (maltrail commit a0a0554).

False positive sources: applications legitimately using TCP 8080 (dev servers, Jenkins, Tomcat) — use the domain-match query to reduce noise, or scope by internal network segments where production traffic is not expected.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Application Layer Protocol: Web Protocols |
| Technique ID | T1071.001 |
| Secondary Technique | Remote Access Software |
| Secondary Technique ID | T1219 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where (All_Traffic.dest_ip IN (
    "103.27.156.192","104.207.80.215","104.244.90.94","144.225.240.132",
    "144.31.106.200","144.31.48.144","151.243.218.132","18.229.133.101",
    "185.112.59.214","185.199.197.58","185.69.122.108","185.69.122.72",
    "191.44.113.16","194.87.52.254","195.226.92.50","2.26.83.70",
    "200.9.155.236","31.77.168.220","37.77.150.21","45.130.147.194",
    "45.144.65.6","54.233.52.162","72.61.249.143","77.91.100.102",
    "77.91.100.81","77.91.100.83","78.46.23.30","81.29.146.96",
    "87.120.84.133","89.34.219.49","93.152.223.39","69.164.252.150")
  OR All_Traffic.dest IN (
    "redwing.top","redwingqq.top","redwing.ink","redwing-hub.top",
    "vnc.redwing.top","s8k2x.redwing-hub.top","s8k2x.redwingqq.top",
    "webmaxauth.com","arbuziki-shluszki.shop","ebem-mamontov.shop",
    "pushka-sosushka.top","sly-time.sbs","krusty-crabs.sbs","pidryzoski.sbs",
    "shlushka-potaskushka.shop","shnejne-watafa.top","sloniki-cartela.shop",
    "fixte.claytop.sbs","chill-dlapidril.shop","vpn.delt4.de"))
by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port
   All_Traffic.transport All_Traffic.action
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(dest,"redwing\.(top|ink)") OR match(dest,"redwing-hub\.top") OR match(dest,"redwingqq\.top"), 90,
    dest_ip IN ("77.91.100.102","77.91.100.81","77.91.100.83","185.69.122.108","185.69.122.72"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime src dest dest_ip dest_port transport action risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Connection to primary redwing.\* panel domains | 90 | Branded C2 panel infrastructure; no legitimate use case |
| Connection to high-confidence C2 IP cluster (77.91.100.x, 185.69.122.x) | 85 | These /24 blocks host multiple confirmed RedWing C2 nodes |
| Any other known RedWing IP or domain | 75 | Confirmed IOC but lower specificity |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| RedWing Panel / SXRat operators (Russian-speaking cybercrime) | [maltrail commit a0a0554](https://github.com/stamparm/maltrail/commit/a0a0554) |

## References

- [stamparm/maltrail — sxrat.txt (2026-07-25)](https://github.com/stamparm/maltrail/commit/a0a0554)
- [MITRE ATT&CK T1071.001 — Application Layer Protocol: Web](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK T1219 — Remote Access Software](https://attack.mitre.org/techniques/T1219/)
