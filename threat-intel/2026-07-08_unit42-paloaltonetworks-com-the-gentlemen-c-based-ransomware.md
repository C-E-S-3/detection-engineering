---
scraped_at: "2026-07-10T09:30:00Z"
source_url: "https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-07-08-The-Gentlemen-C-Based-Ransomware-samples.txt"
report_type: threat-intel
severity: high
title: "The Gentlemen C-Based Ransomware: New PE64 Variant (Storm-2697) — 580 Victims / 77 Countries, 90% Affiliate Payout"
---

## 1. IOCs

### File Hashes (C-Based PE64 Variant)

| Type | Indicator | Date First Seen | Context |
|------|-----------|-----------------|---------|
| SHA256 | `086bdbaa9ae8ea7e9f7f22901ea8f06cd5613595fb70f64da63cf78134b21b1d` | 2026-04-02 | The Gentlemen C-based PE64 ransomware encryptor; XOR-decrypts ransom note at runtime |
| SHA256 | `c95f0172563259ffa8cafb687cfecfce7c0255cf3ec6b50fa71c54bef868efaf` | 2026-04-01 | The Gentlemen C-based PE64 ransomware encryptor |
| SHA256 | `402818dac47dbfd05570b5e741acb76052bb14d61e7e12362560cbcd68cd81fb` | 2026-03-31 | The Gentlemen C-based PE64 ransomware encryptor (earliest observed sample) |

### Network / Infrastructure IOCs

| Type | Indicator | Context |
|------|-----------|---------|
| Onion domain | `tezwsse5czllksjb7cwp65rvnk4oobmzti2znn42i43bjdfd2prqqkad[.]onion` | The Gentlemen RaaS victim leak site and negotiation portal |
| Contact email | `thegentlemen@onionmail[.]org` | Victim contact for ransom negotiation (ransom note) |
| Contact email | `thegentlemen@2mail[.]co` | Alternate victim contact for ransom negotiation |

### File System Artifacts

| Type | Indicator | Context |
|------|-----------|---------|
| Ransom note | `!-READ-ME---GEN-TLE-MEN-!.txt` | XOR-decrypted at runtime and dropped in each traversed directory; distinct from Go-variant's `README-GENTLEMEN.txt` |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|--------------|----------------|-------|
| Impact | TA0040 / T1486 | Data Encrypted for Impact | C-based PE64 ransomware encrypts victim files |
| Defense Evasion | TA0005 / T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | Ransom note text is XOR-encoded in the binary and decrypted at runtime, reducing static string detection |

*Note: Initial access, lateral movement, and C2 TTPs carry forward from the Go-encryptor variant (CVE-2024-55591 FortiOS auth bypass; wormable PsExec/WMIC/WinRM spreading; G-BOT C2; SystemBC proxy) as the RaaS operational playbook is common across variants.*

---

## 3. Malware & Tools

| Item | Type | Notes |
|------|------|-------|
| Gentlemen C-based ransomware (PE64) | Ransomware payload | C-language Windows PE64 binary; XOR-decodes ransom note at runtime; drops `!-READ-ME---GEN-TLE-MEN-!.txt` in each traversed directory; distinct from the previously documented Go/Garble-obfuscated encryptor; samples detected March 31 – April 2, 2026 |

---

## 4. Threat Actor / Campaign Attribution

- **Actor:** Storm-2697 / The Gentlemen (RaaS operator)
- **Original launch:** July 2025 as The Gentlemen RaaS; prior affiliation as ArmCorp under Qilin RaaS
- **Scale (as of July 7, 2026):** 580 claimed victims across 77 countries; victim count increased ~6x comparing H2 2025 to H1 2026
- **Affiliate model:** 90% payout to affiliates (vs. industry standard 70–80%) — primary recruitment differentiator
- **Victim countdown:** 239-hour timer referenced in ransom note communications
- **Discovery context:** Unit 42 (Matt Brady) identified these samples while investigating a Kaspersky Securelist report on the group; samples predate the July 2026 publication

---

## 5. Splunk Detection Searches

```spl
| comment "Detect The Gentlemen C-based ransomware by hash — PE64 variant (March–April 2026 samples)"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_hash IN (
    "086bdbaa9ae8ea7e9f7f22901ea8f06cd5613595fb70f64da63cf78134b21b1d",
    "c95f0172563259ffa8cafb687cfecfce7c0255cf3ec6b50fa71c54bef868efaf",
    "402818dac47dbfd05570b5e741acb76052bb14d61e7e12362560cbcd68cd81fb")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id Processes.process_hash
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime dest user parent_process_name process_name process_hash risk_score
```

```spl
| comment "Detect The Gentlemen C-based variant ransom note creation (distinct from Go variant note)"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_name="!-READ-ME---GEN-TLE-MEN-!.txt"
  by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=99
| table firstTime lastTime dest user file_name file_path risk_score
```

---

## 6. Executive Summary

Unit 42 researcher Matt Brady identified a C-based PE64 ransomware variant associated with The Gentlemen (Storm-2697) RaaS operation, distinct from the previously documented Go/Garble-obfuscated encryptor. Three samples were detected between March 31 and April 2, 2026. The C-based variant uses a different ransom note filename (`!-READ-ME---GEN-TLE-MEN-!.txt` vs. the Go variant's `README-GENTLEMEN.txt`) and XOR-decodes the note text at runtime to reduce static detection.

The Gentlemen RaaS has grown rapidly since launching in July 2025, claiming 580 victims across 77 countries as of July 7, 2026 — a roughly 6x increase in victim count comparing H2 2025 to H1 2026. The group's 90% affiliate payout rate distinguishes it from the industry norm of 70–80% and has driven aggressive affiliate recruitment. The operational playbook (CVE-2024-55591 FortiOS initial access, wormable lateral movement, G-BOT C2) is shared across variants.

**Severity: High.** The C-based variant demonstrates continued development investment in the Gentlemen toolkit. Existing Go-encryptor detections keyed on `README-GENTLEMEN.txt` or `.umc16h` extensions will not fire on C-variant infections; the new ransom note filename requires a separate detection rule.

---

## References

- [Unit 42 Timely Threat Intel — The Gentlemen C-Based Ransomware samples (July 8, 2026)](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-07-08-The-Gentlemen-C-Based-Ransomware-samples.txt)
- [Kaspersky Securelist — The Gentlemen RaaS analysis](https://securelist.com)
- [Microsoft Security Blog — The Gentlemen ransomware: Dissecting a self-propagating Go encryptor (May 28, 2026)](https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/)
- [MITRE ATT&CK T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK T1027.013 — Obfuscated Files or Information: Encrypted/Encoded File](https://attack.mitre.org/techniques/T1027/013/)
