# Persistence Detections

**MITRE ATT&CK Tactic:** [Persistence (TA0003)](https://attack.mitre.org/tactics/TA0003/)
**Kill Chain Phase:** Installation

Detections for techniques adversaries use to maintain access across restarts, credential changes, or other disruptions, including scheduled tasks, registry modifications, and service installation.

---

## Detections

| Detection | MITRE Technique | Description |
|-----------|----------------|-------------|
| [Gootloader Registry Stuffing](gootloader_registry_stuffing.md) | T1112 | Script interpreters writing large encoded payloads to HKCU registry |
| [Gootloader Scheduled Task Persistence](gootloader_scheduled_task.md) | T1053.005 | Scheduled task creation referencing wscript, cscript, or PowerShell |

---

## Threat Actors

| Actor | Type | TTPs | References |
|-------|------|------|-----------|
| Gootloader / UNC2565 | Malware Loader | Registry stuffing (large encoded blobs in HKCU\SOFTWARE), scheduled tasks invoking wscript/PowerShell | [MITRE - Gootloader (S1138)](https://attack.mitre.org/software/S1138/), [Mandiant - UNC2565](https://www.mandiant.com/resources/tracking-and-disrupting-gootloader-operations) |
