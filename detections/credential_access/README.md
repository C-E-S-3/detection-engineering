# Credential Access Detections

**MITRE ATT&CK Tactic:** [Credential Access (TA0006)](https://attack.mitre.org/tactics/TA0006/)
**Kill Chain Phase:** Actions on Objectives

Detections for techniques adversaries use to steal credentials, including credential dumping, brute force, and keylogging.

---

## Detections

No detections in this category yet. Use `detections/_template.md` to add new detections.

---

## Threat Actors

| Actor | Type | TTPs | References |
|-------|------|------|-----------|
| Lazarus Group (HIDDEN COBRA) | Nation-State APT (DPRK) | Credential dumping, Mimikatz, pass-the-hash | [MITRE - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/) |
| Medusa Ransomware | Ransomware Operator | comsvcs.dll MiniDump for LSASS credential extraction | [CISA - StopRansomware: Medusa](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a) |
