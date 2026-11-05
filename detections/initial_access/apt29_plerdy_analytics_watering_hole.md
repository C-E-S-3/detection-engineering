# APT29 Poisoned Source — Plerdy Analytics Supply Chain Watering Hole

## Description

Detects network activity consistent with the APT29 "Poisoned Source" campaign, in which the Plerdy SEO Tracker analytics JavaScript (served from `a.plerdy[.]com`) was backdoored to deliver mobile exploit chains. The injected JavaScript fingerprinted visiting mobile devices and silently routed iOS visitors to the DarkSword exploit kit and Android visitors to the AndroSnitch infostealer via a Chrome exploit chain.

Detections cover three vectors:
1. DNS resolution of known watering-hole delivery domains
2. Outbound network connections to known Poisoned Source infrastructure
3. AndroSnitch payload hash match (via EDR/MDM filesystem telemetry)

False positives are extremely unlikely for the domain and hash detections. The Plerdy-script-on-non-Plerdy-domain proxy search may produce false positives if internal proxy caches or analytics aggregators legitimately re-serve Plerdy script content.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Drive-by Compromise |
| Technique ID | T1189 |
| Secondary Technique | Supply Chain Compromise: Software Supply Chain |
| Secondary Technique ID | T1195.002 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("theowo.club","*.theowo.club",
                      "america250.holiday","*.america250.holiday",
                      "static.flux-telemetry.com","*.flux-telemetry.com",
                      "adsprism-stat.com","*.adsprism-stat.com")
  by DNS.src DNS.query DNS.record_type DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| where risk_score >= 75
| table firstTime lastTime src query record_type answer risk_score
```

### Alternate: Network Connection Detection

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_host IN ("theowo.club","america250.holiday",
                                   "static.flux-telemetry.com","adsprism-stat.com")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port
     All_Traffic.app All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| where risk_score >= 75
| table firstTime lastTime src dest dest_host dest_port app user risk_score
```

### Alternate: AndroSnitch Hash (EDR/MDM)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Endpoint.Filesystem.file_hash="387a7fb768db1350a9788d9704e7a72abe07152734e0ff026af72b417e36268c"
  by Endpoint.Filesystem.dest Endpoint.Filesystem.user Endpoint.Filesystem.file_name
     Endpoint.Filesystem.file_path Endpoint.Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| where risk_score >= 75
| table firstTime lastTime dest user file_name file_path file_hash risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| DNS query or connection to any of the four Poisoned Source domains | 90 | High-confidence IOC match; no legitimate services use these domains |
| AndroSnitch SHA256 hash match | 100 | Exact malware hash; near-certain true positive |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| APT29 (SVR, Cozy Bear, Midnight Blizzard, IRON RITUAL) | [MITRE ATT&CK — APT29 (G0016)](https://attack.mitre.org/groups/G0016/) |
| PARS Defense / UNC6748 / UNC6353 (DarkSword kit supplier) | [BleepingComputer — Apple iOS 18 DarkSword](https://www.bleepingcomputer.com/news/security/apple-expands-ios-18-updates-to-more-ipho/) |

## References

- [Sekoia — Poisoned Source: APT29 Watering Holes Target Mobile Devices with N-Day Exploits (2026-11-04)](https://www.sekoia.com/blog/poisoned-source-apt29-watering-holes-targets-mobile-devices-with-n-day-exploits)
- [The Hacker News — APT29-Linked Hackers Hijack Web Analytics Script (2026-11-04)](https://thehackernews.com/2026/11/apt29-linked-hackers-hijack-web.html)
- [Help Net Security — APT29 watering hole targeting mobile devices (2026-11-04)](https://www.helpnetsecurity.com/2026/11/04/apt29-watering-hole-mobile-devices-n-day-exploits/)
- [MITRE ATT&CK — T1189: Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- [MITRE ATT&CK — T1195.002: Supply Chain Compromise: Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)
