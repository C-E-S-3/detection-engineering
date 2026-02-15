# Impact Detections

**MITRE ATT&CK Tactic:** [Impact (TA0040)](https://attack.mitre.org/tactics/TA0040/)
**Kill Chain Phase:** Actions on Objectives

Detections for techniques adversaries use to disrupt availability or compromise integrity, including data encryption (ransomware), data destruction, and service disruption.

---

## Detections

No detections in this category yet. Use `detections/_template.md` to add new detections.

---

## Threat Actors

| Actor | Type | TTPs | References |
|-------|------|------|-----------|
| Medusa Ransomware | Ransomware Operator | Data encryption for extortion, double extortion (data leak + encryption) | [MITRE - Medusa (S1131)](https://attack.mitre.org/software/S1131/), [CISA - StopRansomware: Medusa](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a) |
| REvil / Sodinokibi | Ransomware (RaaS) | Data encryption, often delivered via Gootloader initial access | [MITRE - REvil (S0496)](https://attack.mitre.org/software/S0496/) |
