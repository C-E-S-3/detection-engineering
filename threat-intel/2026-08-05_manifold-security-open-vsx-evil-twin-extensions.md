---
scraped_at: "2026-08-06T00:00:00Z"
source_url: "https://www.manifold.security/blog/open-vsx-evil-twin-extensions"
report_type: threat-intel
severity: high
title: "Open VSX Evil Twin Extensions — 77 Malicious IDE Extensions Exfiltrating to mangorbit[.]com"
---

# Open VSX Evil Twin Extensions — 77 Malicious IDE Extensions Exfiltrating to mangorbit[.]com

## 1. IOCs

### Domains
| Indicator | Type | Context |
|-----------|------|---------|
| `mangorbit[.]com` | C2 / Exfiltration domain | Primary C2 and data exfiltration endpoint for all 77 malicious extensions; registered July 15, 2026; receives system info, environment variable dumps, and (for 19 extensions) Git repo metadata, GitHub Actions secrets, Azure DevOps PATs, and cloud credentials |

### File / Extension Artifacts
| Indicator | Type | Context |
|-----------|------|---------|
| Version `0.0.1` from accounts unrelated to the impersonated publisher | Behavioral | All 77 extensions published at artificially low version numbers to appear as early releases |
| Extensions published July 26 – August 1, 2026 on unrelated accounts | Behavioral | Account mismatch between publisher identity and impersonated tool is a key detection signal |

### Infrastructure
- DNS TXT record fallback C2 used for resilience if primary `mangorbit[.]com` is blocked
- 7-day retry loop: extensions re-attempt exfiltration if initial connection fails

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Notes |
|--------|-----------|-----|-------|
| Initial Access | Supply Chain Compromise: Compromise Software Supply Chain | T1195.001 | 77 malicious extensions impersonating legitimate developer tools on Open VSX marketplace |
| Collection | Automated Collection | T1119 | Extensions automatically harvest system info and environment variables on activation |
| Exfiltration | Automated Exfiltration | T1020 | Immediate exfiltration to `mangorbit[.]com` on install; 7-day retry loop |
| Discovery | System Information Discovery | T1082 | OS, hostname, username, IDE version fingerprinted by all 77 extensions |
| Discovery | File and Directory Discovery | T1083 | Git repository metadata enumerated by credential-stealing variant |
| Credential Access | Unsecured Credentials: Private Keys | T1552.004 | 19 of 77 extensions steal SSH private keys, Git signing keys from developer environments |
| Credential Access | Unsecured Credentials: Credentials in Files | T1552.001 | CI/CD secret files, .env files, cloud credential files harvested by 19 extensions |
| Command and Control | Application Layer Protocol: DNS | T1071.004 | DNS TXT record used as fallback C2 channel for domain-blocked environments |

---

## 3. Malware & Tools

**Evil Twin Extension Loader (unnamed)**
- Embedded in all 77 malicious Open VSX extensions
- Activates on IDE startup (VSCode/VSCodium extension activation event)
- Stage 1 (all 77 extensions): system fingerprint → HTTP POST to `mangorbit[.]com`
- Stage 2 (19 of 77 extensions): environment variable dump → Git credential files → CI/CD secret files → cloud credential files → exfil to `mangorbit[.]com`
- Retry mechanism: 7-day loop with DNS TXT fallback
- No persistence mechanism beyond the extension itself remaining installed

---

## 4. Threat Actor / Campaign Attribution

**Campaign:** Open VSX Evil Twin Extensions  
**Actor:** Unknown — no public attribution to a named threat actor or group  
**Discovery:** Manifold Security, reported August 5, 2026  
**Timeline:**
- July 15, 2026: `mangorbit[.]com` registered
- July 26 – August 1, 2026: 77 malicious extensions published to Open VSX marketplace
- August 3, 2026: Extensions removed from Open VSX by marketplace administrators
- August 5, 2026: Manifold Security public disclosure

**Targeting:** Developers using the Open VSX marketplace (primarily VSCodium users and Linux/open-source developer environments that use Open VSX instead of the Microsoft VS Code Marketplace)

**Motivation:** Credential and secret theft — targeted data (Git credentials, GitHub Actions secrets, Azure DevOps PATs, cloud credentials) is consistent with financially motivated access brokerage or supply chain compromise staging.

---

## 5. Splunk Detection Searches

### 5a. Network connection to mangorbit[.]com (Web proxy / DNS)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.dest="mangorbit.com" OR Web.dest="*.mangorbit.com"
  by Web.src Web.dest Web.http_method Web.uri_path Web.status Web.http_user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(1=1, 90)
| table firstTime lastTime src dest http_method uri_path status http_user_agent risk_score
```

### 5b. DNS resolution of mangorbit[.]com

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query="mangorbit.com" OR DNS.query="*.mangorbit.com"
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src query answer risk_score
```

### 5c. Open VSX extension activation with outbound POST (endpoint behavioral — raw)

```spl
index=* sourcetype=osquery
  (query_name="process_open_sockets" OR query_name="process_events")
  (cmdline="*extensionHostProcess*" OR name="extensionHost*" OR parent_cmdline="*extensionHost*")
  (remote_address="*mangorbit*" OR remote_port IN (80,443))
| eval risk_score=90
| table _time host cmdline remote_address remote_port pid ppid
| sort -_time
```

---

## 6. Executive Summary

Between July 26 and August 1, 2026, an unidentified threat actor published 77 malicious IDE extensions to the Open VSX marketplace — the primary extension source for VSCodium and Linux developer environments. Each extension impersonated a legitimate, popular developer tool using near-identical names and icons (an "evil twin" pattern), but was published from unrelated accounts at artificially low version numbers (0.0.1).

All 77 extensions activated on IDE startup and immediately exfiltrated system fingerprint data (OS, hostname, username, IDE version) to `mangorbit[.]com`, a domain registered July 15, 2026. A subset of 19 extensions went further, harvesting Git repository metadata, GitHub Actions secrets, Azure DevOps personal access tokens, SSH private keys, and cloud credential files before exfiltrating to the same endpoint. A DNS TXT record fallback C2 and 7-day retry loop provide resilience against network-level blocking.

Open VSX administrators removed all 77 extensions by August 3, 2026, following discovery by Manifold Security. Any developer who had these extensions installed between July 26 and August 3 should rotate all secrets present in their development environment, including Git credentials, CI/CD secrets, SSH keys, and cloud credentials.

**Severity: High** — Wide developer targeting, credential and secret theft, supply chain compromise potential.

---

## References

- [Manifold Security — Open VSX Evil Twin Extensions](https://www.manifold.security/blog/open-vsx-evil-twin-extensions)
- [MITRE ATT&CK — T1195.001 Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/001/)
- [MITRE ATT&CK — T1552.004 Unsecured Credentials: Private Keys](https://attack.mitre.org/techniques/T1552/004/)
- [Open VSX Registry](https://open-vsx.org/)
