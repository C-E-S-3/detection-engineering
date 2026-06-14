# Impact Detections

**MITRE ATT&CK Tactic:** [Impact (TA0040)](https://attack.mitre.org/tactics/TA0040/)
**Kill Chain Phase:** Actions on Objectives

Detections for techniques adversaries use to disrupt availability or compromise integrity, including data encryption (ransomware), data destruction, and service disruption.

---

## Detections

| [Ransomware Mass File Encryption](ransomware_mass_file_encryption.md) | T1486 | Statistical detection of rapid file modification volume (>200/min), ransom note creation, and VSS deletion |
| [Ransomware Backup Infrastructure Targeting](ransomware_backup_infrastructure_targeting.md) | T1490, T1485 | Backup agent termination, wbadmin/bcdedit anti-recovery, Veeam/ESXi snapshot destruction |
| [Unauthorized GPU Cryptominer Execution](gpu_cryptomining_unauthorized_miner_execution.md) | T1496 | Detection of gminer, lolMiner, SRBMiner-MULTI, and XMRig execution; covers May–June 2026 SEO-poisoning/ScreenConnect cryptojacking campaign and WeedHack MaaS; pool connection CLI argument detection; campaign IP IOCs |
| [Disk Space Exhaustion](disk_space_exhaustion.md) | T1499, T1485 | ENOSPC kernel errors, Docker overlay filesystem exhaustion, and disk usage warnings ≥90% from monitoring scripts; covers adversarial disk-fill and operational capacity failures |

---

## Threat Actors

| Actor | Type | TTPs | References |
|-------|------|------|-----------|
| Medusa Ransomware | Ransomware Operator | Data encryption for extortion, double extortion (data leak + encryption) | [MITRE - Medusa (S1131)](https://attack.mitre.org/software/S1131/), [CISA - StopRansomware: Medusa](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a) |
| REvil / Sodinokibi | Ransomware (RaaS) | Data encryption, often delivered via Gootloader initial access | [MITRE - REvil (S0496)](https://attack.mitre.org/software/S0496/) |
| Qilin (AGENDA) | Ransomware Operator | #1 most active ransomware 2025; EDR killer before encryption; targets VMware ESXi; backup infrastructure destruction | [Cisco Talos - Qilin Japan 2025](https://blog.talosintelligence.com/an-overview-of-ransomware-threats-in-japan-in-2025-and-early-detection-insights-from-qilin-cases/) |
| Akira (REDBIKE) | Ransomware Operator | Targets backup infrastructure and virtualization management planes; absorbs affiliates from defunct RaaS groups | [Google TI - M-Trends 2026](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/) |
| LockBit (Gold Mystic) | Ransomware Operator (RaaS) | Self-spreading encryption; Veeam exploitation; VSS and wbadmin deletion | [MITRE - LockBit (S1091)](https://attack.mitre.org/software/S1091/) |
| Unknown (GPU cryptojacking, March–June 2026) | Financially Motivated Cryptojacking | SEO-poisoned fake utility download portals (CrystalDiskInfo, HWMonitor, FurMark) deliver ScreenConnect + GPU miners (gminer, lolMiner, SRBMiner-MULTI); AI chatbot manipulation supplements SEO poisoning; DLL sideloading via autorun.dll; 150+ domains; 4 IPs; 12 samples | [Microsoft Security Blog (2026-05-26)](https://www.microsoft.com/en-us/security/blog/2026/05/26/poisoned-search-results-gpu-mining-cryptojacking-campaign-abusing-screenconnect-microsoft-net-utilities/) |
| WeedHack MaaS Operator | Minecraft-Focused Cryptojacking (MaaS) | 116,000+ infections via SEO-poisoned Minecraft mod downloads; EtherHiding blockchain dead drop for C2 rotation; deploys Elevator.jar GPU miner; telemetrydata[.]to C2 | [McAfee Labs (2026-06-03)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/weedhack-minecraft-malware-as-a-service-campaign-research/) |
