# DNS TXT Record Data Exfiltration (DNS Tunneling)

## Description

Detects suspicious DNS TXT record queries consistent with DNS tunneling used to exfiltrate data out of a network. DNS TXT records are normally used for domain validation (SPF, DKIM, DMARC) and occasional service discovery; high-volume TXT queries with long, high-entropy labels — particularly from non-DNS-management processes — are a strong indicator of data exfiltration via DNS tunneling.

This technique was concretely observed in the May 2026 `node-ipc` npm supply chain attack, where a malicious payload harvested developer credentials and exfiltrated them as gzip-compressed archives encoded into DNS TXT query names under the zone `bt[.]node[.]js`, using `sh[.]azurestaticprovider[.]net:443` as a typosquatted bootstrap resolver.

**False positives:** Legitimate CDN health checks or zone-transfer tooling may produce short-lived TXT query bursts. Certificate issuance processes (ACME/Let's Encrypt DNS-01 challenges) produce `_acme-challenge.*` TXT queries that are benign. Tune the query length threshold and label character distribution for your environment.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Application Layer Protocol: DNS |
| Technique ID | T1071.004 |
| Secondary Tactic | Exfiltration |
| Secondary Technique | Exfiltration Over Alternative Protocol |
| Secondary ID | T1048 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control |
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.record_type="TXT"
by DNS.src DNS.query DNS.record_type
| `drop_dm_object_name(DNS)`
| eval query_len=len(query)
| eval subdomain=mvindex(split(query, "."), 0)
| eval subdomain_len=len(subdomain)
| eval label_prefix=substr(subdomain, 1, 2)
| eval is_known_exfil=if(
    match(query, "(?i)\.bt\.node\.js$") OR
    match(query, "(?i)sh\.azurestaticprovider\.net"), 1, 0)
| eval is_acme=if(match(query, "(?i)_acme-challenge"), 1, 0)
| eval is_dkim=if(match(query, "(?i)_domainkey"), 1, 0)
| eval is_dmarc=if(match(query, "(?i)_dmarc"), 1, 0)
| eval is_spf=if(match(query, "(?i)^v=spf"), 1, 0)
| where is_acme=0 AND is_dkim=0 AND is_dmarc=0 AND is_spf=0
| where is_known_exfil=1 OR (query_len > 50 AND subdomain_len > 30)
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    is_known_exfil=1, 95,
    query_len > 80 AND label_prefix IN ("xh","xd","xf"), 80,
    query_len > 60 AND subdomain_len > 40, 70,
    1=1, 55)
| where risk_score >= 55
| table firstTime lastTime src query record_type query_len subdomain_len risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Query matches known node-ipc exfil zone (`bt.node.js`) or resolver (`sh.azurestaticprovider.net`) | 95 | Direct IOC match — confirmed malicious |
| Query length > 80 chars AND label starts with `xh`, `xd`, or `xf` | 80 | Matches node-ipc exfil label pattern with high confidence |
| Query length > 60 chars AND subdomain > 40 chars | 70 | Strong indicator of base64/hex-encoded data chunk |
| Any TXT query with very long subdomain | 55 | Suspicious but needs analyst review |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (node-ipc supply chain, May 2026) | [Socket.dev — node-ipc compromise](https://socket.dev/blog/node-ipc-package-compromised) |
| Various APT groups (DNS tunneling is widely used) | [MITRE ATT&CK — T1071.004](https://attack.mitre.org/techniques/T1071/004/) |

## References

- [Socket.dev — Popular node-ipc npm Package Infected with Credential Stealer](https://socket.dev/blog/node-ipc-package-compromised)
- [Datadog Security Labs — Backdoored node-ipc npm releases steal credentials via DNS queries](https://securitylabs.datadoghq.com/articles/node-ipc-npm-malware-analysis/)
- [MITRE ATT&CK — T1071.004 Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/)
- [MITRE ATT&CK — T1048 Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
