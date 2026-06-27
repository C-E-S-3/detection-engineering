---
scraped_at: "2026-06-27T00:00:00Z"
source_url: "https://www.microsoft.com/en-us/security/blog/2026/06/24/stealc-and-amadey-breaking-down-infostealers-and-the-cybercrime-services-that-deliver-them/"
report_type: threat-intel
severity: high
title: "Operation Endgame Phase 2: Europol/Microsoft Disrupt Amadey, StealC, and SocGholish Infrastructure (June 2026)"
---

## 1. IOCs

### Amadey C2 Domains (disrupted — 5 confirmed, over 200 total taken down)

| Indicator | Context |
|-----------|---------|
| `goodpanelforgoodjob[.]com` | Amadey C2; victim fingerprint POST to `/hg8jjfSr5hy/index.php` |
| `rebustan[.]top` | Amadey C2; victim fingerprint POST to `/gd7djkDveE2/index.php` |
| `svclsc[.]com` | Amadey C2; victim registration POST to `/ms/index.php` |
| `microsoft-telemetry[.]at` | Amadey C2; impersonates Microsoft telemetry; POST to `/cvdfnaFJBmC0/index.php` |
| `spasopro[.]at` | Amadey C2; POST to `/Lsge63sd3/index.php` |

### StealC C2 Domains (disrupted — 7 confirmed, over 200 total taken down)

| Indicator | Context |
|-----------|---------|
| `polse[.]us` | StealC C2; RC4-encrypted data POST to `/62ea47cac2534aa18f74.php` |
| `roger99699[.]xyz` | StealC C2; POST to `/425f1faf4b214434b8a3.php` |
| `bluescry[.]com` | StealC C2; POST to `/01f96fd710e905ca2326.php` |
| `secure.controlpanel[.]asia` | StealC C2; POST to `/330311481fe14ab99814.php` |
| `neltron-geltron[.]shop` | StealC C2 (HTTPS); POST to `/e396586b99ee49d19cc3.php` |
| `cdntestconnect[.]com` | StealC C2; POST to `/ed54b97a570943999715.php` |
| `bartsen284[.]online` | StealC C2 (HTTPS); POST to `/39d9612df78e45b5a4bb.php` |

### Amadey File Hashes (SHA-256)

| Hash | Version |
|------|---------|
| `b7d1f172ff3feafe65d47fd1cbe0cc249316371ae0e1cbe3a7c741c738b3353d` | Amadey v5.87 |
| `9383572a30ae5b76fadd0700fbd7a1aa7b05d0b6c8f9cdaef9b30a3e1f65d57d` | Amadey v5.86 |
| `5f5b25b2e35d404034d0d60975cf1ffbc6f141761ec3f4f15d6f7c6213a056f6` | Amadey v5.80 |
| `98e504cc7125b79eda5491f40b998605a05f4cd968b961aab4cce7beb074fefe` | Amadey v5.78 |
| `30cef3d3d956e83e2c50579cfbe57a49159cccbcc8b0b0422f27d55e1c401ad9` | Amadey v5.77 |
| `8cef760d11d24fc2e9bbd9f770dca5105854f7ece3b0e6948d7c8b7fdd1765ea` | Amadey v5.73 |
| `99507f18c4e61fdb109805404bf6a79ea8ce2fddc590ce48d717e97516ab7e8d` | Amadey v5.70 |
| `1246c5b89ab668c1137f377507bc3e266a98e93248382aa026610ae1e764a497` | Amadey v5.65 |
| `d43c988d6f9cb355497696b580621fb1bdb7b6ed6d90f97520ecf6da5a1a41ff` | Amadey v5.64 |
| `ca4d4c4fc3e5d5cfa922b898f2d7411f03a446dddb139ba45dfd4f8f0018b64f` | Amadey v5.63 |
| `43455f1ff4a623b783da670d052eb77eaaacb0c66a9f1e8508f802bf22e8129e` | Amadey v5.60 |

### StealC File Hashes (SHA-256)

| Hash | Description |
|------|-------------|
| `8f32456359f209a63adfd24b94235e1727382ac7f7bb7f2bcaf754e721925b64` | StealC infostealer sample |
| `0215f734867bd71c57ff5c524d8cc670be5b4f1861b2c390cf46d18784a53624` | StealC infostealer sample |
| `2a0f053855da59b3b56812e580d7baeba59fc9493694722aa9e3f121ee3363f1` | StealC infostealer sample |
| `977b33a9b481cf714946b7d386865cd5d284312aa5ecfa0546c197b1003e1bde` | StealC infostealer sample |

---

## 2. TTPs

### StealC

| Tactic | Technique | ID | Usage |
|--------|-----------|-----|-------|
| Credential Access | Credential Dumping from Web Browsers | T1555.003 | Harvests saved passwords from 20+ browser profiles |
| Discovery | System Information Discovery | T1082 | Fingerprints hardware, OS, processes; sends HWID+build ID in first C2 POST |
| Defense Evasion | Process Injection | T1055 | Injects ~165 KB payload into suspended process via APC; writes cleartext to `C:\ProgramData\<HWID>.txt` (IPC file) |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | RC4-encrypted HTTP POST; one POST per data category |
| Persistence | Scheduled Task | T1053.005 | Creates scheduled task using victim HWID as identifier |
| Collection | Screen Capture | T1113 | JPEG screenshots at 90% quality sent to C2 |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTP POST with RC4 encryption + Base64 |
| Defense Evasion | System Language Check | T1614.001 | Terminates if locale = Russian, Ukrainian, Belarusian, Kazakh, or Uzbek |

### Amadey

| Tactic | Technique | ID | Usage |
|--------|-----------|-----|-------|
| Persistence | Scheduled Task | T1053.005 | Persistence via Windows Task Scheduler |
| Execution | Process Injection | T1055 | Injects credential-stealing plugin (cred.dll) and clipboard stealer (clip.dll) |
| Credential Access | Credentials from Password Stores | T1555 | cred.dll plugin scrapes browser credentials |
| Collection | Clipboard Data | T1115 | clip.dll monitors clipboard for financial data |
| Lateral Movement | Remote Desktop Protocol | T1021.001 | Enables RDP via registry; VNC plugin for operator access |
| Persistence | Create Account | T1136.001 | Creates hidden local admin account with elevated privileges |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | RC4 + hex-encoded HTTP; first beacon is "st=s" for sleep multiplier |
| Defense Evasion | System Language Check | T1614.001 | Russian locale check before credential theft execution |
| Staging | Data Staged | T1074.001 | Stages exfiltration in `C:\ProgramData\` before C2 upload |

---

## 3. Malware & Tools

**StealC** — Windows infostealer MaaS. RC4 with hard-coded keys, Base64 encoding. Receives JSON config (browser targets, file-grabbing rules, access tokens) from C2 on first contact. Exfiltrates credentials, cookies, system data, and screenshots. Latest samples analyzed by Microsoft DCU via Copilot-assisted binary analysis.

**Amadey** — Windows loader/dropper MaaS. Modular plugin architecture (cred.dll, clip.dll, VNC). Persistence in `C:\Users\<user>\e079729711` (Win 10/11) or `%TEMP%\e079729711`. Supports EXE, DLL, PowerShell, MSI, and process injection payload delivery. First observed ~2018, active through June 2026.

**SocGholish (FAKEUPDATES)** — JavaScript-based fake browser update dropper. Precursor loader that downloads Amadey and StealC on compromised victim hosts. Infrastructure also disrupted in Operation Endgame Phase 2 action.

---

## 4. Threat Actor / Campaign Attribution

Operation Endgame is a multi-phase Europol-coordinated law enforcement action. Phase 1 (May 2024) targeted IcedID, SystemBC, Pikabot, Smokeloader, and Bumblebee botnets. Phase 2 (June 15–19, 2026) targeted SocGholish, Amadey, and StealC infrastructure.

These malware families operate as MaaS commodities with no single attributed operator. Distribution is through:
- SocGholish fake browser update injection on thousands of compromised websites
- Phishing email campaigns
- Malvertising and pay-per-install (PPI) networks

In the first two weeks of May 2026, Amadey and StealC were linked to over **140,000 infected computers** globally.

**Phase 2 Disruption Scope:**
- 326 servers and 142 domains disrupted/seized/sinkholed
- €41 million ($47 million) in criminal cryptocurrency identified
- ~27 million credentials recovered from ~385,000 compromised systems
- Participating agencies: Europol, Canada, Denmark, Germany, Netherlands, UK, US (FBI, DOJ, Secret Service)
- Private partners: Microsoft DCU, Bitdefender, IBM X-Force, Proofpoint, Infoblox, Shadowserver, Orange Cyberdefense, Bitsight, and others

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where (All_Traffic.dest_host IN ("goodpanelforgoodjob.com","rebustan.top","svclsc.com",
  "microsoft-telemetry.at","spasopro.at","polse.us","roger99699.xyz","bluescry.com",
  "secure.controlpanel.asia","neltron-geltron.shop","cdntestconnect.com","bartsen284.online"))
by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src dest dest_host dest_port app risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where (Processes.process IN ("*e079729711*") OR Processes.process_path IN ("*e079729711*"))
   OR (Processes.parent_process IN ("*e079729711*"))
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| where risk_score >= 90
| table firstTime lastTime dest user parent_process_name process_name process process_path risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Endpoint.Filesystem.file_path IN ("*\\ProgramData\\*.txt") AND
  Endpoint.Filesystem.process_name IN ("*e079729711*","rundll32.exe")
by Endpoint.Filesystem.dest Endpoint.Filesystem.user Endpoint.Filesystem.file_name
   Endpoint.Filesystem.file_path Endpoint.Filesystem.process_name
| rename Endpoint.Filesystem.* as *
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| table firstTime lastTime dest user file_name file_path process_name risk_score
```

---

## 6. Executive Summary

On June 24, 2026, Microsoft, Europol, and international law enforcement partners announced the disruption of criminal infrastructure supporting three major malware families: **Amadey**, **StealC**, and **SocGholish (FakeUpdates)**. The coordinated action — the second phase of Operation Endgame — occurred June 15–19, 2026, and resulted in 326 servers and 142 domains being taken down, €41M in cryptocurrency seized, and approximately 27 million stolen credentials recovered.

Amadey (loader/dropper MaaS, ~2018–present) and StealC (infostealer MaaS) are frequently used in tandem: Amadey establishes initial access and delivers StealC as a plugin, which then harvests browser credentials, cookies, and financial data. SocGholish drives victim traffic to the malware through fake browser update overlays on thousands of compromised websites.

**Analyst note:** While the C2 infrastructure listed here has been seized or sinkholed, new infrastructure may emerge as operators reconstitute. Endpoint-based detections (Amadey persistence path `e079729711`, StealC IPC file in `%PROGRAMDATA%`) are more durable. Any endpoint still communicating with the listed C2 domains requires immediate forensic investigation as the activity predates the June 15–19 takedown.

---

## References

- [Microsoft Security Blog — StealC and Amadey Analysis (2026-06-24)](https://www.microsoft.com/en-us/security/blog/2026/06/24/stealc-and-amadey-breaking-down-infostealers-and-the-cybercrime-services-that-deliver-them/)
- [Europol — Operation Endgame Phase 2 Press Release](https://www.europol.europa.eu/media-press/newsroom/news/global-cyber-strike-disrupts-socgholish-amadey-and-stealc-malware-networks)
- [BleepingComputer — Operation Endgame Amadey/StealC Disruption](https://www.bleepingcomputer.com/news/security/amadey-stealc-malware-operations-disrupted-in-operation-endgame-action/)
- [The Hacker News — Amadey and StealC: 27M Credentials Recovered](https://thehackernews.com/2026/06/amadey-and-stealc-malware-network.html)
- [Bitsight — Disruption Efforts on Amadey and StealC](https://www.bitsight.com/blog/bitsight-aids-disruption-efforts-on-amadey-malware-and-stealc-malware)
- [MITRE ATT&CK — Amadey (S1027)](https://attack.mitre.org/software/S1027/)
