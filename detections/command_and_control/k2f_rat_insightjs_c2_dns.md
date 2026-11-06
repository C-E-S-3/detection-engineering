# K2F RAT insightjs.com C2 DNS and Network Detection

## Description

Detects DNS queries and outbound network connections to `insightjs[.]com`, `analytics.insightjs[.]com`,
and `insightjs[.]org` — the command-and-control infrastructure used by the K2F remote access trojan
distributed via a supply chain compromise of the NIKKE: Goddess of Victory PC game launcher CDN in
November 2026.

K2F is a LuaJIT 2.0 bytecode RAT with a 19-command C2 protocol. It uses DLL side-loading via the Chrome
component path and exfiltrates credentials, screenshots, SSH keys, cloud provider configs, and data from
28 cryptocurrency wallet browser extensions via Slack webhooks. The C2 uses TLS with a self-signed
certificate bearing `CN=k2f operator CA`.

False positive rate is expected to be very low — `insightjs.com` has no legitimate software or CDN use
case; any resolution is high-confidence malicious.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Application Layer Protocol: Web Protocols |
| Technique ID | T1071.001 |
| Sub-technique note | Also covers T1195.002 (Supply Chain), T1574.002 (DLL Side-Load) as delivery chain |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("insightjs.com","*.insightjs.com","insightjs.org","*.insightjs.org",
                      "analytics.insightjs.com")
  by DNS.src DNS.query DNS.record_type DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(query,"analytics\.insightjs\.com"), 95,
    match(query,"insightjs\.(com|org)"), 90,
    1=1, 85)
| where risk_score >= 85
| table firstTime lastTime src query record_type answer risk_score
```

### Alternate: Network Traffic (firewall / proxy logs)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_ip IN ("89.127.233.127","89.126.250.172")
     OR All_Traffic.dest IN ("insightjs.com","analytics.insightjs.com","insightjs.org")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port
     All_Traffic.transport All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    dest_ip IN ("89.127.233.127","89.126.250.172"), 95,
    1=1, 90)
| where risk_score >= 90
| table firstTime lastTime src dest dest_ip dest_port transport app risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| DNS query to `analytics.insightjs.com` | 95 | Direct C2 beacon subdomain with no legitimate use |
| DNS query to `insightjs.com` or `insightjs.org` | 90 | K2F operator apex domains; no legitimate use |
| IP connection to `89.127.233.127` or `89.126.250.172` | 95 | Confirmed K2F C2 and staging server IPs |
| Wildcard match on `*.insightjs.*` | 85 | Catch-all for DGA-style subdomains under K2F operator domains |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| K2F Operator (unattributed) | [WormW GitHub Analysis](https://github.com/WormW/nikke_malware_analysis/blob/main/README.en.md) |

## References

- [BleepingComputer — NIKKE PC game launcher hacked to spread remote access, data-stealing malware](https://www.bleepingcomputer.com/news/security/nikke-pc-game-launcher-hacked-to-spread-remote-access-data-stealing-malware/)
- [WormW nikke_malware_analysis](https://github.com/WormW/nikke_malware_analysis/blob/main/README.en.md)
- [Threat Intel Report](../../threat-intel/2026-11-04_bleepingcomputer-com-nikke-launcher-k2f-rat-supply-chain.md)
- [MITRE ATT&CK — T1071.001](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK — T1195.002](https://attack.mitre.org/techniques/T1195/002/)
