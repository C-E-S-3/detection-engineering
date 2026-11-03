# XCPE Botnet MQTT C2 — DNS and Network IOC Detection

## Description

Detects DNS queries to known XCPE botnet command-and-control domains and outbound TCP connections on the non-standard MQTT ports (3885–3887) used by the XCPE C2 infrastructure. XCPE is a firmware-level backdoor pre-installed by Videostrong Technology Co. in Android set-top boxes. Infected devices communicate via MQTT to `szbboys.com` on ports 3885–3887 for tasking, then receive and execute affiliate modules (residential proxy, ad fraud).

False positive rate is very low for the domain IOC list. TCP 3885–3887 may see false positives from non-MQTT industrial or custom applications; correlate with the domain IOC list for highest confidence.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Non-Application Layer Protocol |
| Technique ID | T1095 |
| Secondary Technique | Application Layer Protocol: Web Protocols |
| Secondary Technique ID | T1071.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN (
  "szbboys.com", "mqtt.szbboys.com", "ott.szbboys.com",
  "anyevonline.com", "intermedia-arts.tv", "yokatvonline.com",
  "linkfog.cn", "cloudbrokerapi.xyz", "dddlink.link",
  "smrtai.cc", "bkdomain.cn", "columbus2024.com",
  "bd-devmetrics.net", "tx-devmetrics.net",
  "bestipip.com", "fecebbbk.xyz", "guangzhouroot.com",
  "amhib.com", "disview.com", "prataw.com",
  "auqee.com", "alptk.com", "mfiny.com", "leisurepuz.com",
  "earn.fm", "geo-loadbalanced.com",
  "collection.shixunsuda.com", "analysis.shixunsuda.com",
  "gtxvdqvuweqs.com", "hiddeninplainsight.top",
  "dgjm.online", "drgdj.top", "spiritlib.cyou",
  "dmurdce.xyz", "edisajalsjfdfh.shop", "ty4523.space"
)
by DNS.src DNS.query DNS.record_type
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    query IN ("szbboys.com","mqtt.szbboys.com","ott.szbboys.com"), 95,
    query IN ("anyevonline.com","intermedia-arts.tv","yokatvonline.com"), 90,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime src query record_type risk_score
```

**Supplemental — Network connection to XCPE MQTT infrastructure:**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where (All_Traffic.dest_port=3885 OR All_Traffic.dest_port=3886 OR All_Traffic.dest_port=3887)
by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.action
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    dest IN ("219.134.163.210","219.134.163.211","23.94.49.57","38.145.197.135"), 100,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime src dest dest_port action risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| DNS query to primary MQTT C2 (szbboys.com variants) | 95 | Direct C2 contact; near-certain XCPE infection |
| DNS query to bootstrap / fallback C2 | 90 | Device registration or fallback; high confidence |
| DNS query to affiliate module domain | 75 | Affiliate module enrollment; strong indicator |
| TCP 3885–3887 to known XCPE IPs | 100 | C2 confirmed by IP+port combination |
| TCP 3885–3887 to unknown dest | 65 | Non-standard MQTT port; needs investigation |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Videostrong Technology Co. (XCPE Botnet operator) | [Google GTIG — Shutting the Door on the XCPE Botnet (2026-11-02)](https://cloud.google.com/blog/topics/threat-intelligence/shutting-the-door-on-the-xcpe-botnet) |

## References

- [Google GTIG — Shutting the Door on the XCPE Botnet (2026-11-02)](https://cloud.google.com/blog/topics/threat-intelligence/shutting-the-door-on-the-xcpe-botnet)
- [MITRE ATT&CK — T1095: Non-Application Layer Protocol](https://attack.mitre.org/techniques/T1095/)
- [MITRE ATT&CK — T1195.003: Supply Chain Compromise: Compromise Hardware Supply Chain](https://attack.mitre.org/techniques/T1195/003/)
