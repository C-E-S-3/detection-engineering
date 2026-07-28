---
scraped_at: "2026-07-27T00:00:00Z"
source_url: https://github.com/stamparm/maltrail/commit/a23920d
report_type: threat-intel
severity: medium
title: "Shiba Ransomware: New Family with Three Tor Onion C2 Addresses"
---

# Shiba Ransomware: New Family with Three Tor Onion C2 Addresses

The Maltrail project created a new tracking file for **Shiba ransomware** on July 27, 2026 (commit `a23920d`), sourced from a disclosure by researcher @DarkJstr on X/Twitter. The family is newly named and only three Tor hidden service (onion) addresses have been confirmed. Limited TTP data is available at this time; this report documents the known IOCs and marks the family for tracking.

## 1. IOCs

### Tor Onion Addresses (3)

| Indicator | Role |
|-----------|------|
| exfil5gqmbxrg6yky5aeitkdj7kfwxxjh3wxzrtlewjqi2x67o634iyd[.]onion | Shiba ransomware — suspected data exfiltration or victim portal |
| o5lsqyar7ox25z734k6zaxt2vf7bsyi4q5rturi5iyxzqo3ica7bjsad[.]onion | Shiba ransomware — C2 or negotiation portal |
| shibaitobajtr6yctvrijfitnugfulkmprrqbmu2ysk3zyzx2ufe3yqd[.]onion | Shiba ransomware — primary C2 (name "shibaitoba" embedded in onion address) |

**Note:** No standard domains, IP addresses, or file hashes are currently confirmed. All known C2 infrastructure routes through the Tor network, consistent with modern ransomware operational security practices.

## 2. TTPs

Limited TTP data is available. Based on the infrastructure pattern (Tor-only C2), the following are assessed with low confidence:

| Tactic | Technique ID | Technique | Usage |
|--------|-------------|-----------|-------|
| Command and Control | T1090.003 | Proxy: Multi-hop Proxy (Tor) | All known C2 routes through Tor hidden services |
| Impact | T1486 | Data Encrypted for Impact | Assessed ransomware behavior based on family classification |
| Exfiltration | T1048 | Exfiltration Over Alternative Protocol | Suspected double-extortion exfiltration via onion exfil endpoint |

## 3. Malware & Tools

**Shiba Ransomware**

A newly identified ransomware family named "Shiba" (referencing the Shiba Inu dog breed, potentially as branding). The only confirmed infrastructure is three Tor hidden services. The naming convention of the primary onion address ("shibaitobajtr6...") embeds "shibaitoba" (Japanese: "柴犬", Shiba Inu dog). The family uses separate onion addresses for exfiltration (prefix "exfil5") and C2/negotiation, consistent with double-extortion ransomware operational patterns.

At the time of this report, no ransom notes, encrypted file extensions, victim disclosures, or technical malware analysis are publicly available.

## 4. Threat Actor / Campaign Attribution

| Actor | Assessment | Notes |
|-------|-----------|-------|
| Unknown | Low confidence | Insufficient data for attribution; Tor-only C2 infrastructure limits passive attribution |

## 5. Splunk Detection Searches

```spl
`-- Detect Tor traffic that may indicate Shiba ransomware C2 communication`
`-- (Tor hidden services are not resolvable via standard DNS; detect Tor client activity instead)`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where (All_Traffic.dest_port=9001 OR All_Traffic.dest_port=9030
  OR All_Traffic.dest_port=9050 OR All_Traffic.dest_port=9150)
  AND All_Traffic.app!="tor"
by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.transport
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=60
| table firstTime lastTime src dest dest_port transport risk_score
```

```spl
`-- Detect potential ransomware file encryption activity (generic — pending Shiba-specific IOCs)`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.action=modified OR Filesystem.action=created
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name _time span=1m
| `drop_dm_object_name(Filesystem)`
| stats count as file_changes by dest user _time
| where file_changes > 200
| eval risk_score=75
| `security_content_ctime(firstTime)`
| table _time dest user file_changes risk_score
```

## 6. Executive Summary

On July 27, 2026, the Maltrail project added initial tracking for **Shiba ransomware**, a newly identified ransomware family. The only confirmed IOCs are three Tor hidden service (.onion) addresses used for C2, negotiations, and suspected data exfiltration. No file hashes, ransom note filenames, encrypted file extensions, or victim disclosures have been confirmed publicly. Severity is rated **Medium** pending further analysis — the Tor-only infrastructure and double-extortion pattern (separate exfil and negotiation onion addresses) are consistent with active ransomware operations, but the threat cannot be fully assessed without additional technical data. Organizations should monitor for Tor client activity on endpoints and update this entry when further analysis becomes available.

## References

- https://github.com/stamparm/maltrail/commit/a23920d — maltrail creation of shiba_ransomware.txt (July 27, 2026)
- https://github.com/stamparm/maltrail — stamparm/maltrail repository
