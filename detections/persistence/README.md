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
| [Malicious Service Installation](malicious_service_installation.md) | T1543.003 | Kernel driver and user-mode service installation via sc.exe from interpreter parents, binaries in temp/appdata paths, or direct registry ServiceDll/ImagePath modification |
| [Cloud Privileged Role Assignment](cloud_privileged_role_assignment.md) | T1098.003, T1136.003 | Unauthorized Global Administrator or Privileged Role Administrator assignment in Azure AD/Entra ID; new account created and promoted to Global Admin within minutes (Handala/Scattered Spider/Lapsus$ pattern) |

---

## Threat Actors

| Actor | Type | TTPs | References |
|-------|------|------|-----------|
| Gootloader / UNC2565 | Malware Loader | Registry stuffing (large encoded blobs in HKCU\SOFTWARE), scheduled tasks invoking wscript/PowerShell | [MITRE - Gootloader (S1138)](https://attack.mitre.org/software/S1138/), [Mandiant - UNC2565](https://www.mandiant.com/resources/tracking-and-disrupting-gootloader-operations) |
| Scattered Spider (UNC3944) | Cybercrime / ALPHV Affiliate | Installs RMM tools as persistent services for re-entry after initial eviction | [MITRE - Scattered Spider (G1015)](https://attack.mitre.org/groups/G1015/) |
| LockBit Affiliates | RaaS Affiliates | Deploy ransomware loaders as services for pre-execution staging | [MITRE - LockBit (S1091)](https://attack.mitre.org/software/S1091/) |
| Lazarus Group (HIDDEN COBRA) | Nation-State APT (DPRK) | Malicious services used to maintain long-term persistence on high-value targets | [MITRE - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/) |
| Handala (Hatef / Hamsa) | Iranian MOIS-linked Hacktivist | Compromises domain admin → immediately creates Azure AD Global Administrator account for persistent wiper deployment; responsible for Stryker 2026 attack (~80,000 devices wiped) | [BleepingComputer - Handala Stryker](https://www.bleepingcomputer.com/news/security/medtech-giant-stryker-fully-operational-after-data-wiping-attack/) |
| Scattered Spider (UNC3944) | Cybercrime / ALPHV Affiliate | Creates Global Admin accounts after helpdesk social engineering for persistent tenant access before ransomware deployment | [MITRE - Scattered Spider (G1015)](https://attack.mitre.org/groups/G1015/) |
| North Korea IT Workers | Nation-State (DPRK) | Fraudulently obtain employment and create admin cloud accounts for cryptocurrency theft and data exfiltration | [CISA - North Korean IT Workers](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-240a) |
