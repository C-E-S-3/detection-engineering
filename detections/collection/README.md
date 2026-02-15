# Collection Detections

**MITRE ATT&CK Tactic:** [Collection (TA0009)](https://attack.mitre.org/tactics/TA0009/)
**Kill Chain Phase:** Actions on Objectives

Detections for techniques adversaries use to gather data of interest from target systems, including cryptocurrency wallet access, data staging, and automated collection.

---

## Detections

| Detection | MITRE Technique | Description |
|-----------|----------------|-------------|
| [Lazarus Cryptocurrency Access](lazarus_cryptocurrency_access.md) | T1005, T1119 | DNS queries and process activity targeting cryptocurrency wallets and exchanges |

---

## Threat Actors

| Actor | Type | TTPs | References |
|-------|------|------|-----------|
| Lazarus Group (HIDDEN COBRA) | Nation-State APT (DPRK) | Cryptocurrency theft from exchanges and individual wallets, AppleJeus campaign | [MITRE - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/), [CISA - AppleJeus](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-048a), [FBI - TraderTraitor](https://www.ic3.gov/Media/News/2022/220418.pdf) |
