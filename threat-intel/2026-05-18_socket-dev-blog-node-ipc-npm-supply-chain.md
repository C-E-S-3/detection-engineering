---
scraped_at: 2026-05-18T00:00:00Z
source_url: https://socket.dev/blog/node-ipc-package-compromised
report_type: threat-intel
severity: high
title: "node-ipc npm Package Supply Chain Compromise — Maintainer Account Takeover and DNS-Tunneled Credential Exfiltration"
---

# node-ipc npm Supply Chain Compromise — DNS-Tunneled Credential Exfiltration

## 1. IOCs

### File Hashes

| Hash | Type | Description |
|------|------|-------------|
| `3427a90c8cb9af764445448648176e120ebc6af0a538158340cf6220de4d01b7` | SHA-256 | Malicious payload appended to `node-ipc.cjs` — byte-identical across all three compromised versions |

### Domains / Network Indicators

| Indicator | Context |
|-----------|---------|
| `sh[.]azurestaticprovider[.]net` | Bootstrap DNS resolver contacted on port 443; masquerades as Microsoft Azure Static Web Apps infrastructure |
| `bt[.]node[.]js` | DNS TXT exfiltration zone — malware builds query names under this suffix to tunnel gzip-compressed credential archives |
| `atlantis-software[.]net` | Expired maintainer email domain re-registered by threat actor on May 7, 2026 via Namecheap; used to hijack the `atiertant` npm account via password reset |

### Affected Package Versions

| Package | Malicious Versions | Published |
|---------|--------------------|-----------|
| `node-ipc` | 9.1.6, 9.2.3, 12.0.1 | 2026-05-14 14:25–14:26 UTC |

### Detection Patterns

- Temporary directories matching `nt-<pid>` on disk after interrupted payload run (gzip archive artifact)
- DNS TXT queries where the label begins with `xh`, `xd`, or `xf`

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Usage |
|--------|-----------|-----|-------|
| Initial Access | Supply Chain Compromise: Compromise Software Supply Chain | T1195.002 | Injected malicious payload into `node-ipc.cjs` by taking over a dormant npm maintainer account; three simultaneous malicious versions published |
| Credential Access | Unsecured Credentials | T1552 | Harvested SSH keys, cloud provider credentials (AWS, GCP, Azure), Kubernetes configs, `.env` files, AI tool configuration files, and other secrets from the developer environment |
| Command and Control | Application Layer Protocol: DNS | T1071.004 | DNS TXT record queries used as C2 channel; encoded data tunneled under `bt[.]node[.]js` zone |
| Exfiltration | Exfiltration Over Alternative Protocol | T1048 | Gzip-compressed tar archives exfiltrated via DNS TXT queries to avoid endpoint and network DLP controls |
| Defense Evasion | Obfuscated Files or Information | T1027 | 80 KB obfuscated IIFE appended to `node-ipc.cjs`; no npm lifecycle hooks used, payload fires on every `require('node-ipc')` call |
| Resource Development | Acquire Infrastructure: Web Services | T1583.006 | Re-registered expired email domain `atlantis-software[.]net` (originally expired Jan 10, 2025) to hijack npm maintainer account via password reset |

---

## 3. Malware & Tools

| Component | Description |
|-----------|-------------|
| Malicious `node-ipc.cjs` payload | 80 KB obfuscated JavaScript IIFE appended to the CommonJS bundle of `node-ipc`; fires unconditionally on every `require('node-ipc')` call; fingerprints the host, collects over 100 categories of sensitive files, compresses them into a gzip tar archive, and exfiltrates via DNS TXT tunneling |
| DNS tunnel encoder | Encodes gzip-compressed archive chunks as DNS TXT query names under `bt[.]node[.]js`, using `sh[.]azurestaticprovider[.]net:443` as the bootstrap resolver |

**Data categories targeted:** SSH private keys, AWS/GCP/Azure credentials and tokens, Kubernetes `~/.kube/config`, `.env` files, `~/.npmrc` (npm auth tokens), `~/.gitconfig`, AI tool configs (OpenAI, Anthropic API keys), and Terraform/Pulumi state files.

---

## 4. Threat Actor / Campaign Attribution

| Field | Detail |
|-------|--------|
| Attribution | Unknown; account `atiertant` (a.tiertant@atlantis-software.net) used to publish malicious versions |
| Method | Expired email domain hijack — `atlantis-software[.]net` re-registered May 7, 2026 via Namecheap, one week before malicious publication |
| Impact | `node-ipc` has ~10 million weekly downloads; malicious versions were live for approximately two hours before detection and removal by npm |
| Detection | Socket.dev AI scanner flagged malicious versions within ~3 minutes of publication |
| Motive | Credential and secret theft targeting developer environments (CI/CD pipelines, cloud infrastructure) |

---

## 5. Splunk Detection Searches

### 5.1 DNS TXT Tunneling — node-ipc Exfiltration Pattern

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.record_type="TXT"
by DNS.src DNS.query DNS.record_type
| `drop_dm_object_name(DNS)`
| eval query_len=len(query)
| eval label_prefix=substr(query, 1, 2)
| eval is_known_exfil=if(match(query, "\.bt\.node\.js$") OR match(query, "sh\.azurestaticprovider\.net"), 1, 0)
| eval is_suspicious_prefix=if(label_prefix IN ("xh", "xd", "xf") AND query_len > 30, 1, 0)
| where is_known_exfil=1 OR is_suspicious_prefix=1
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    is_known_exfil=1, 95,
    is_suspicious_prefix=1 AND query_len > 60, 75,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime src query record_type query_len risk_score
```

### 5.2 Node Process Making Unusual DNS TXT Queries

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.record_type="TXT" AND DNS.process_name IN ("node", "node.exe", "npm", "npm.exe", "npx", "npx.exe")
by DNS.src DNS.process_name DNS.query DNS.record_type
| `drop_dm_object_name(DNS)`
| eval query_len=len(query)
| where query_len > 40
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=60
| table firstTime lastTime src process_name query query_len risk_score
```

### 5.3 Bootstrap DNS Resolver Contacted — Typosquatted Azure Domain

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query="sh.azurestaticprovider.net"
by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src query answer risk_score
```

### 5.4 Suspicious npm Publish from Expired/Recently Re-registered Domain Account (CI/CD Audit)

```spl
index=cicd_audit OR index=npm_registry_events
| search event_type="publish" AND publisher_email_domain IN ("atlantis-software.net")
| stats count by publisher_account, package_name, package_version, publish_time, publisher_email_domain
| eval risk_score=90
| table publish_time publisher_account package_name package_version publisher_email_domain risk_score
```

---

## 6. Executive Summary

On May 14, 2026, an unknown threat actor published three malicious versions of `node-ipc` (9.1.6, 9.2.3, and 12.0.1) to the npm registry, a package with approximately 10 million weekly downloads widely used in Node.js projects for inter-process communication. The attack exploited a dormant maintainer account (`atiertant`) by re-registering its expired email domain `atlantis-software[.]net` one week prior, then using a standard npm password reset to gain publish rights without any interaction from the original maintainer.

All three malicious versions contain an identical 80 KB obfuscated JavaScript payload appended to `node-ipc.cjs` that fires on every `require('node-ipc')` call. The malware harvests over 100 categories of secrets from developer environments — including SSH keys, cloud credentials, Kubernetes configs, `.env` files, and AI API keys — and exfiltrates them via DNS TXT tunneling to `bt[.]node[.]js` using a typosquatted Azure domain (`sh[.]azurestaticprovider[.]net`) as the bootstrap resolver. This DNS-over-HTTPS approach bypasses many traditional network exfiltration controls.

The malicious versions were live for approximately two hours before removal. Any organization or developer whose Node.js CI/CD pipeline or application loaded `node-ipc` at versions 9.1.6, 9.2.3, or 12.0.1 should treat the environment as fully compromised and rotate all credentials.

---

## References

- [Socket.dev — Popular node-ipc npm Package Infected with Credential Stealer](https://socket.dev/blog/node-ipc-package-compromised)
- [BleepingComputer — Popular node-ipc npm Package Compromised to Steal Credentials](https://www.bleepingcomputer.com/news/security/popular-node-ipc-npm-package-compromised-to-steal-credentials/)
- [StepSecurity — Active Supply Chain Attack: Malicious node-ipc Versions Published to npm](https://www.stepsecurity.io/blog/node-ipc-npm-supply-chain-attack)
- [Datadog Security Labs — Backdoored node-ipc npm releases steal developer credentials through DNS queries](https://securitylabs.datadoghq.com/articles/node-ipc-npm-malware-analysis/)
- [Snyk — Malicious node-ipc Versions Published to npm](https://snyk.io/blog/malicious-node-ipc-versions-published-npm/)
- [MITRE ATT&CK — T1195.002 Supply Chain Compromise: Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)
- [MITRE ATT&CK — T1071.004 Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/)
