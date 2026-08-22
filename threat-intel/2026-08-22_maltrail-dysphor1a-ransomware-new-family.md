---
scraped_at: 2026-08-22T00:00:00Z
source_url: https://github.com/stamparm/maltrail/blob/master/trails/static/malware/dysphor1a_ransomware.txt
report_type: threat-intel
severity: medium
title: "Dysphor1a Ransomware — New Family Identified (Maltrail IOC Addition)"
---

# Dysphor1a Ransomware — New Family Identified

**Source:** Maltrail (stamparm/maltrail) — community threat intelligence trail  
**Published:** 2026-08-21 (maltrail commit)  
**Severity:** Medium  
**Threat Actor:** Unknown / Unattributed  

---

## 1. IOCs

### Domains

| Indicator | Context |
|-----------|---------|
| dysphor1a.zya.me | Dysphor1a ransomware infrastructure (clearnet) |
| normalhunters0x.surge.sh | Dysphor1a ransomware infrastructure (clearnet) |

### Onion / Tor

| Indicator | Context |
|-----------|---------|
| y3maveiwszbnrziufbbberx74cvrdcsf72nxzuqxzv7ppdmmqzffazid.onion | Dysphor1a ransomware Tor hidden service (likely payment/negotiation portal) |

### File Hashes

None identified at this time.

---

## 2. TTPs (MITRE ATT&CK)

> **Note:** TTPs are inferred from infrastructure patterns only. No detailed technical analysis is available yet. This section will be updated as more information becomes available.

| Tactic | Technique | ID | Description |
|--------|-----------|-----|-------------|
| Command and Control | Web Service | T1102 | Clearnet C2/exfil infrastructure (dysphor1a.zya.me, normalhunters0x.surge.sh) |
| Command and Control | Proxy: Multi-hop Proxy | T1090.003 | Tor hidden service used for payment/communication anonymization |
| Impact | Data Encrypted for Impact | T1486 | Ransomware family — encrypts victim data for extortion |

---

## 3. Threat Actor / Campaign Attribution

**Unknown.** Dysphor1a is a newly identified ransomware family added to the Maltrail threat intelligence trail on 2026-08-21. No attribution to a known threat actor or ransomware group has been established. The name may derive from "dysphoria," potentially a deliberate branding choice by the operators.

Infrastructure notes:
- `dysphor1a.zya.me` uses the `zya.me` dynamic DNS provider (historically abused by commodity malware)
- `normalhunters0x.surge.sh` uses Surge.sh, a static web hosting platform, suggesting possible payload hosting or exfiltration staging
- Tor hidden service pattern is consistent with ransomware-as-a-service (RaaS) payment portals

---

## 4. Splunk Detection Searches

### 4a. Dysphor1a — Known Infrastructure DNS Lookup Detection

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Network_Resolution.DNS
    where DNS.query IN (
        "dysphor1a.zya.me",
        "normalhunters0x.surge.sh"
    )
    by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src query answer count
```

---

## 5. Executive Summary

On 2026-08-21, the Maltrail open-source threat intelligence project added a new trail entry for **Dysphor1a**, a previously untracked ransomware family. Three indicators of compromise were published: two clearnet domains (`dysphor1a.zya.me` and `normalhunters0x.surge.sh`) and one Tor hidden service address.

Intelligence on this family is sparse — no ransomware samples, ransom notes, victim disclosures, or technical write-ups have been identified at this time. The infrastructure pattern (dynamic DNS + static hosting platform + Tor) is consistent with commodity or emerging ransomware operations.

**Recommended actions:** Block identified domains at DNS and proxy; monitor for DNS queries to `*.zya.me` or `*.surge.sh` from non-development endpoints as a broader detection layer. Continue monitoring for additional reporting on this family.
