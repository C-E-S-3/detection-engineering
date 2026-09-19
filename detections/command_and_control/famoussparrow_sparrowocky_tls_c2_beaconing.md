# FamousSparrow SparroWocky TLS C2 Beaconing to Known Infrastructure

## Description

Detects outbound network connections from internal hosts to known SparroWocky command-and-control server IP addresses on ports 443 or 8080, and DNS resolution of known FamousSparrow infrastructure domains. SparroWocky is a modular C++ backdoor deployed by China-aligned espionage group FamousSparrow against government organizations, primarily in Latin America. C2 traffic is encrypted over TLS on port 443 or 8080 with payload additionally RC4-encrypted; HTTP and SOCKS5 proxies are used to relay traffic through intermediate nodes.

Any connection to these specific IPs on ports 443/8080 from a non-expected host is high-confidence malicious — these IPs have no known legitimate use. False positives are extremely unlikely; the only expected false positive would be a security researcher or threat intelligence platform explicitly scanning these IPs.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Application Layer Protocol: Web Protocols |
| Technique ID | T1071.001 |
| Sub-technique | — |
| Secondary Tactic | Command and Control |
| Secondary Technique | Encrypted Channel: Symmetric Cryptography |
| Secondary Technique ID | T1573.001 |
| Tertiary Technique | Proxy |
| Tertiary Technique ID | T1090 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_ip IN (
    "38.54.57.17","38.60.197.55","38.60.209.106","38.60.224.51","38.60.224.235",
    "38.60.241.65","38.60.241.127","38.60.241.193","77.111.101.40","91.148.134.115",
    "130.94.101.82","140.99.164.199","149.104.87.228","149.104.90.203","216.238.92.2",
    "216.238.105.53","216.238.106.150","216.238.110.120","216.238.121.164",
    "43.254.216.195","103.85.25.166","45.131.179.24","27.102.113.240")
    AND All_Traffic.dest_port IN ("443","8080")
by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port
   All_Traffic.bytes_in All_Traffic.bytes_out All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src dest dest_ip dest_port bytes_in bytes_out app risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN ("amelicen.com","credits.offices-analytics.com")
by DNS.src DNS.query DNS.answer DNS.record_type
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=92
| table firstTime lastTime src query answer record_type risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Connection to known SparroWocky C2 IP on port 443 or 8080 | 90 | High-confidence malicious — these IPs have no known legitimate use; direct indicator match |
| DNS resolution of `amelicen.com` or `credits.offices-analytics.com` | 92 | High-confidence malicious — known FamousSparrow infrastructure domains; any resolution indicates either active beaconing or prior compromise |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| FamousSparrow | [MITRE ATT&CK G0093](https://attack.mitre.org/groups/G0093/) / [ESET WeLiveSecurity (Sep 2026)](https://www.welivesecurity.com/en/eset-research/beware-sparrowock-backdoor-bites-commands-catch/) |

## References

- [ESET WeLiveSecurity — FamousSparrow / SparroWocky (September 17, 2026)](https://www.welivesecurity.com/en/eset-research/beware-sparrowock-backdoor-bites-commands-catch/)
- [ESET GitHub malware-ioc — FamousSparrow](https://github.com/eset/malware-ioc/tree/master/famoussparrow)
- [MITRE ATT&CK — T1071.001 Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK — T1573.001 Encrypted Channel: Symmetric Cryptography](https://attack.mitre.org/techniques/T1573/001/)
- [MITRE ATT&CK — T1090 Proxy](https://attack.mitre.org/techniques/T1090/)
- [MITRE ATT&CK — FamousSparrow (G0093)](https://attack.mitre.org/groups/G0093/)
