---
scraped_at: "2026-10-13T00:00:00Z"
source_url: "https://research.checkpoint.com/2026/12th-october-threat-intelligence-report"
report_type: threat-intel
severity: high
title: "Check Point October 12 2026: DataSuckers Claims 7.9M ATB Ukraine Records; Osaka Metropolitan University Ransomware (~500 Servers, 130K Individuals)"
---

## 1. IOCs

### Domains

No domains published in secondary reporting.

### IPs

No IPs published in secondary reporting.

### Hashes

No hashes published in secondary reporting.

---

## 2. TTPs (MITRE ATT&CK)

### DataSuckers / ATB Ukraine

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Exfiltration | T1537 | Transfer Data to Cloud Account | DataSuckers posted alleged exfiltration of 7.9 million customer records from ATB Ukraine, Ukraine's largest grocery retailer |
| Impact | T1495 | Firmware Corruption / Service Disruption | ATB online services disrupted; extortion demand posted on ATB website |

### Osaka Metropolitan University Ransomware

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Impact | T1486 | Data Encrypted for Impact | Approximately 500 servers encrypted; personal data of at least 130,000 individuals potentially exposed |
| Lateral Movement | T1021 | Remote Services | Lateral movement implied by scale (~500 servers) of the encryption event |

---

## 3. Incident Summaries

### DataSuckers — ATB Ukraine Data Breach (Disclosed October 12, 2026)

- **Victim:** ATB (Ukraine's largest grocery retail chain)
- **Claimed impact:** 7.9 million customer records exfiltrated
- **Attacker claim:** DataSuckers extortion group posted demand on ATB's website; disrupted online services
- **Attribution:** DataSuckers (extortion group; prior attributions unknown from public reporting)
- **Status:** Online services disrupted at time of reporting; no confirmation of ransom payment

### Osaka Metropolitan University Ransomware Attack (Disclosed October 12, 2026)

- **Victim:** Osaka Metropolitan University (Japan)
- **Impact:** Approximately 500 servers affected; personal information of at least 130,000 individuals potentially exposed
- **Attack type:** Ransomware (specific family not attributed in public reporting)
- **Attribution:** Unknown ransomware group
- **Status:** University investigating scope of data exposure

---

## 4. Threat Actors

| Actor | Description |
|-------|-------------|
| DataSuckers | Data extortion group; claimed responsibility for ATB Ukraine breach targeting customer PII; no prior large-scale public attributions confirmed |

---

## 5. Executive Summary

Check Point's October 12, 2026 threat intelligence report highlights two significant incidents. First, the DataSuckers extortion group claimed to have stolen approximately 7.9 million customer records from ATB, Ukraine's largest grocery chain, posting an extortion demand on the ATB website and disrupting online services. This follows a pattern of extortion targeting Ukrainian civilian infrastructure during the ongoing conflict.

Second, Osaka Metropolitan University in Japan disclosed a ransomware attack affecting approximately 500 servers, with personal information belonging to at least 130,000 individuals potentially exposed. The specific ransomware family and threat actor have not been publicly attributed.

Neither incident has yielded specific IOCs suitable for network-level or endpoint detections in public reporting. Monitor threat intel feeds for technical indicators should they be released.

---

## 6. References

- [Check Point Research — 12th October Threat Intelligence Report](https://research.checkpoint.com/2026/12th-october-threat-intelligence-report)
