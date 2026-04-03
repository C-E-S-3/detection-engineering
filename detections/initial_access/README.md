# Initial Access Detections

**MITRE ATT&CK Tactic:** [Initial Access (TA0001)](https://attack.mitre.org/tactics/TA0001/)
**Kill Chain Phase:** Delivery

Detections for techniques adversaries use to gain an initial foothold in a network, including phishing, drive-by compromise, SEO poisoning, and exploitation of public-facing applications.

---

## Detections

| Detection | MITRE Technique | Description |
|-----------|----------------|-------------|
| [Gootloader SEO ZIP Download](gootloader_seo_zip_download.md) | T1189, T1204.002 | Browser downloading ZIP archive followed by JS file extraction in user directories |
| [Gootloader JS File Creation](gootloader_js_file_creation.md) | T1204.002 | Obfuscated JavaScript file creation in user-writable directories |
| [Lazarus O365 Spearphishing](lazarus_o365_spearphishing.md) | T1566.001 | Spearphishing emails with suspicious attachments via Office 365 |
| [UAT-10608 Next.js React2Shell RCE Exploitation](uat10608_nextjs_rce_exploitation.md) | T1190 | CVE-2025-55182 exploitation of Next.js apps; NEXUS Listener C2 callbacks and staged shell dropper |

---

## Threat Actors

| Actor | Type | TTPs | References |
|-------|------|------|-----------|
| Gootloader / UNC2565 | Malware Loader | SEO poisoning to deliver malicious JS payloads via compromised WordPress sites | [MITRE - Gootloader (S1138)](https://attack.mitre.org/software/S1138/), [Mandiant - UNC2565](https://www.mandiant.com/resources/tracking-and-disrupting-gootloader-operations) |
| Godloader / GodLoader (Stargazer Goblin) | Malware Loader | Fake GitHub repositories distributing Godot Engine-based loaders via Stargazers Ghost Network (~200 repos, 225+ fake accounts) | [Check Point - Gaming Engines: An Undetected Playground](https://research.checkpoint.com/2024/gaming-engines-an-undetected-playground-for-malware-loaders/), [Check Point - Stargazers Ghost Network](https://research.checkpoint.com/2024/stargazers-ghost-network/) |
| Lazarus Group (HIDDEN COBRA) | Nation-State APT (DPRK) | Spearphishing with weaponized attachments targeting defense, finance, cryptocurrency | [MITRE - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/), [CISA - HIDDEN COBRA](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-106a) |
| UAT-10608 | Threat Cluster | Automated exploitation of CVE-2025-55182 in Next.js applications, NEXUS Listener credential harvesting affecting 766+ hosts | [Cisco Talos - UAT-10608](https://blog.talosintelligence.com/uat-10608-inside-a-large-scale-automated-credential-harvesting-operation-targeting-web-applications/) |
