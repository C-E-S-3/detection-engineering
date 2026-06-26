---
scraped_at: "2026-06-26T00:00:00Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering"
report_type: threat-intel
severity: critical
title: "STOCKSTAY: Turla (FSB Center 16) Multi-Component .NET WebSocket Backdoor Ecosystem"
---

## 1. IOCs

### Attacker-Controlled C2 Domains (WebSocket Endpoints)

| Indicator | Context |
|-----------|---------|
| `wool-basalt-clock.glitch.me` | STOCKSTAY.STOCKBROKER WebSocket C2 (wss://wool-basalt-clock.glitch.me/ws) |
| `weatherdataai.theworkpc.com` | STOCKSTAY.STOCKBROKER WebSocket C2 (wss://weatherdataai.theworkpc.com/ws) |
| `canal1zac1a.onrender.com` | STOCKSTAY.STOCKBROKER WebSocket C2 (wss://canal1zac1a.onrender.com/ws) |
| `driverx86-adobe.onrender.com` | STOCKSTAY.STOCKBROKER WebSocket C2 (wss://driverx86-adobe.onrender.com/ws) |
| `google-ai-labs-it.onrender.com` | STOCKSTAY.STOCKBROKER WebSocket C2 (wss://google-ai-labs-it.onrender.com/ws); GitHub ChikenFresh account also hosted controller server code here |

### Compromised Legitimate Sites Used for Payload Staging (NOT attacker-owned)

| URL | Context |
|-----|---------|
| `https://circoloesteri.elezioni.idnet.it/admin-election/riepilogo.php` | Compromised Italian elections site used to host STOCKSTAY stage |
| `https://www.drs.gov.ua/wp-content/themes/twentytwentyfive/docs.zip` | Compromised Ukrainian government site (State Property Fund) staging payload (May 2025) |
| `https://basecon.com.ua/calculator.rar` | Compromised Ukrainian IT company staging military calculator lure (Jul–Aug 2025) |
| `https://online.zp.ua/wp-content/uploads/Tools/EditorToolsPdf.zip` | Compromised Ukrainian site staging EditorToolsPdf.zip |

### File Hashes (SHA-256) — 2023 Samples

| Hash | Filename | Description |
|------|----------|-------------|
| `e6d8192960a89d5480868b94088cccdaa1560f9c8a0b0282ced2b7c1f72341b6` | DriversPrinterGraphic.rar | Early STOCKSTAY archive lure |
| `1fc23ec18a94a599a34c74ef5f49a1e27acd37a07d5846661702b5e7e81a6a24` | StockMarketNews.exe | Single-component STOCKSTAY sample (Sep 2023) |
| `1a2ca8b8e0344fe3d80da7352206a470245443e2349a237bc093df934ddc011f` | sample.conf | STOCKSTAY configuration file |
| `81aabf646619ea5f4a72457cd3aa17c5988003d67e6454f45e7cb33613021bac` | apps_libwallets_v1.3.rar | STOCKSTAY archive lure |
| `9164054d0bf0b7c8820da4f742860940998984555e65820e4fa8dd07b6bd67ec` | StockMarketView.exe | STOCKSTAY.STOCKTRADER (2023) |
| `34fcbe7e90fc87a4f3766469c19a64f24672d7adb99e0198f5ba10d58911368b` | StockMarketNet.exe | STOCKSTAY.STOCKBROKER (2023) |
| `0a545dd1b703cddfb3d582c8c70f65f556bbd580bfa836a387121eb837bda61b` | StockMarketSystem.exe | STOCKSTAY.STOCKMARKET (2023) |

### File Hashes (SHA-256) — 2024 Samples

| Hash | Filename | Description |
|------|----------|-------------|
| `b064a3efb04ed77e6c57955089ce639e193d166c8ea2216c98c3e9b701ea2cff` | Copia.msi | Italian-language MSI installer targeting Ministry of Foreign Affairs lures (Feb 2024) |
| `82707cfdf24dcb762f4615f01e1ba4d3dfdec4abe9cd588558d2634d7e6a5eeb` | StockMarketView.exe | STOCKSTAY.STOCKTRADER with K1MORPHER obfuscation (2024) |
| `249a4c7cacdd8e99a2a089a5c0ce904f2eff22e0e40fcfb10f7824dca6c51ecb` | StockMarketNet.exe | STOCKSTAY.STOCKBROKER with K1MORPHER obfuscation (2024) |
| `b728eba4f0d6d16602fbad05a591f14391594262d3584b2e249e97f86e4dcc5a` | StockMarketSystem.exe | STOCKSTAY.STOCKMARKET with K1MORPHER obfuscation (2024) |
| `40b1208dda0cd5dd95c6b57764b2cfe7145b3ed9457f498408b4aaa05bf3ef50` | default.conf | STOCKSTAY configuration (2024) |

### File Hashes (SHA-256) — 2025 Samples (Most Recent)

| Hash | Filename | Description |
|------|----------|-------------|
| `da8a96bc74e265f945f1cc6992c6dc0f9ea36ed1991f7b8d312db79d9bf78c40` | MicrosoftUpdateOneDrive.exe | STOCKSTAY 2025 dropper masquerading as Microsoft OneDrive update |
| `9fe944147c15a87963b06baf6473288d64c23655a0ba9369c35566272d8efc73` | docs.zip | STOCKSTAY payload archive hosted on compromised drs.gov.ua (May 2025) |
| `e1d16fb635060d23e889b0617d77f0cf06d00cc19b43a2c8b5ac53ac027ac722` | SMEditor.exe | STOCKSTAY.STOCKTRADER 2025 variant (SMEditor naming) |
| `dfd5cb91d06b9649d4cab500343af80ad1144a9e46641cc406f43dd169003c22` | SMNet.exe | STOCKSTAY.STOCKBROKER 2025 variant |
| `2af7b513c05e76d7da5f75bb0a223c894a706c99ef2c2ddfe4eae542f95a08e0` | StockMarketView.exe | STOCKSTAY.STOCKTRADER latest 2025 variant with heavy K1MORPHER obfuscation |
| `d3fd32f915c239872c9e7ed9408b1f36dfcef03aa68f9a396d05c437667cdb43` | ClientMNGR2.exe | STOCKSTAY.STOCKMARKET 2025 controller |
| `98ce3c6e4dd05887ea619f2bbfeb2e2c2805ed07e85e119b79b828b7ef8be397` | GR3.exe | STOCKSTAY.MARKETMAKER 2025 downloader |
| `6da0b4c1a5d0d3fb6e6a2990a82ba51db1f68a3bba818baa46526a29731e2342` | calculator.rar | Military benefit calculator RAR lure hosted on basecon.com.ua (Jul 2025) |
| `0d6b083208097d5b3e189891338540f6c64faaaaf268b0bb0b085dd53d5857b4` | Калькулятор...2025.hta | HTA dropper with Ukrainian-language military lure (military personnel benefit calculator); CVE-2025-8088 WinRAR exploitation chain (Nov 2025) |
| `447f430b46fad5a3f8e8c5aad1f8f7f79af069489c3d9c29224bb9f14f0c7bf4` | EditorToolsPdf.zip | STOCKSTAY archive lure hosted on online.zp.ua |
| `19e6ed42248f9d03beb343a7c09a864dcd3cd671c29e1e5eac93579225224ac9` | DiplomacyEduAI.msi | STOCKSTAY diplomacy-lure MSI (GitHub Roberto1983-ai, Jul 2025, test v1) |
| `6298f3150ad94a242e649886d47c59c634a4d04b9af5ee15e3bf335c40b5e58e` | DiplomacyEduAI.msi | STOCKSTAY diplomacy-lure MSI (GitHub Roberto1983-ai, Jul 2025, test v2) |
| `a40bf9c75d1bfa6d66f1179f2321de6589f80d3089d992797a9cb0e84f6196ce` | MSViewer.exe | STOCKSTAY.STOCKTRADER Nov 2025 drone-lure campaign sample (v1) |
| `e316b1e13154dc6115e1e0c023f6fe3d17861cae839d4a4a81779b6aad9a24f8` | MSViewer.exe | STOCKSTAY.STOCKTRADER Nov 2025 drone-lure campaign sample (v2) |
| `c905cb512018cc55512c6a22677c3d6f389c47afd54d7c85797868fc4fcb90e9` | MSDriver.exe | STOCKSTAY.STOCKBROKER Nov 2025 drone-lure campaign |
| `667a8f568a611f2f3d84a366b7946b360e055bece9699c95aad619637ab72a38` | MSRender.exe | STOCKSTAY.STOCKMARKET Nov 2025 drone-lure campaign |
| `b287347a5bff8af360ce0e6500c336b6fe6d97920abc26202c9d843ffebc5f89` | ms-lib-math-core.dll | STOCKSTAY component DLL (Nov 2025) |
| `1682e8d82016b3f10434d2efac995fd3b6aa812f079bfd7888652e94a994d851` | ms-api-win-render.dll | STOCKSTAY component DLL (Nov 2025) |
| `e2a0f4440f67998a0215d49be31746ea192bfcb4dc4ee532a218f8cf13605714` | ms-api-wmcpdt.dll | STOCKSTAY component DLL (Nov 2025) |
| `3627f582420ad2782d452fe6d13fae42658d1484296351d3916703e25dcadd14` | MSViewer.lnk | Malicious LNK dropper — Nov 2025 drone/UAV lure campaign |
| `813c78b5b6ed28a9c0ed35f2c6cd88fc50880ab91f8777dfe7aaccb1c24b08d5` | MSDriver.lnk | Malicious LNK dropper — Nov 2025 drone/UAV lure campaign |

### File Hashes (SHA-256) — Server-Side Components

| Hash | Filename | Description |
|------|----------|-------------|
| `f04f43b6f7c2d86109c495179b497f7fb45fd95816623de1b77900f71b4f99ed` | server.py | STOCKSTAY.STOCKMARKET controller server (Python) — GitHub ChikenFresh/google-ai-labs-it (Aug 2025) |
| `7615140f78d9a0ce31cc9fe8c54c60028a7439cb32526fd97b10afef7145dd78` | models.py | STOCKSTAY server-side data models |
| `b55f3b8a7334af049ba3f70a9ad3fe78574b1e180c68baf9a7110d104387a636` | wtools.py | STOCKSTAY server-side utilities |
| `d1e54270433a94aa3d45d888e4c62299bee3480eb2cb4a5489c7dda69d476c3e` | websocket-sharp.dll | WebSocket library bundled with STOCKSTAY; compiled December 2022 (earliest implant dating) |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique | STOCKSTAY Usage |
|--------|-------------|-----------|-----------------|
| Initial Access | T1566.002 | Phishing: Spearphishing Attachment | Malicious RDP files, HTA files, RAR archives with military/diplomacy lures targeting Ukraine/Europe |
| Initial Access | T1598 | Phishing for Information | Email phishing with academic, diplomatic, and military lure themes |
| Execution | T1203 | Exploitation for Client Execution | CVE-2025-8088 WinRAR path traversal used in Nov 2025 drone-lure campaign |
| Execution | T1059.001 | PowerShell | iclsClient.ps1 PowerShell backdoor deployment |
| Execution | T1218.007 | Mshta | HTA execution wrapper for initial payload delivery |
| Execution | T1053.005 | Scheduled Task | Time-based operational windows (Mon–Fri 09:00–18:00) |
| Persistence | T1547.001 | Registry Run Keys | MSI installer writes STOCKSTAY components to Run keys |
| Persistence | T1547.004 | Winlogon Helper DLL | RDP-based post-exploitation persistence |
| Persistence | T1505 | Server Software Component | Compromise of WordPress sites for payload hosting |
| Defense Evasion | T1140 | Deobfuscate/Decode Files | K1MORPHER string obfuscation (Squirrel3 PRNG, GDC 2017 algorithm) first deployed Apr 2024; also used in Kazuar June 2025 |
| Defense Evasion | T1027 | Obfuscated Files or Information | Junk code insertion, string obfuscation across all components |
| Defense Evasion | T1497 | Virtualization/Sandbox Evasion | Environmental keying — configuration bound to machine environment |
| Defense Evasion | T1564.001 | Hidden Files and Directories | Configuration file concealment |
| Collection | T1005 | Data from Local System | File collection via `Get` command; ZIP archive creation |
| Collection | T1113 | Screen Capture | `Image` command for screen capture |
| Collection | T1119 | Automated Exfiltration | ZIP archive creation and Base64 encoding before exfil |
| Command and Control | T1071.001 | Web Protocols: WebSocket | WSS:// WebSocket C2 (STOCKSTAY.STOCKBROKER); cloud hosting via Render.com, Glitch.me |
| Command and Control | T1573.001 | Symmetric Encryption | AES encryption for C2 configuration |
| Command and Control | T1573.002 | Asymmetric Encryption | RSA 4096-bit key exchange for session establishment |
| Command and Control | T1008 | Fallback Channels | Multiple C2 endpoints configured; operational backup |
| Command and Control | T1102 | Web Service | C2 hosted on legitimate cloud platforms (Render.com, Glitch.me, theworkpc.com) |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Data exfiltrated via established WebSocket C2 channel |
| Discovery | T1057 | Process Discovery | `Sysinfo` command enumerates running processes |
| Discovery | T1012 | Query Registry | Registry read via `RegRead` command |
| Discovery | T1518.001 | Security Software Discovery | System reconnaissance before deployment |

---

## 3. Malware & Tools

### STOCKSTAY Ecosystem (Multi-Component .NET Backdoor)

**STOCKSTAY.STOCKBROKER** — WebSocket tunneler / C2 proxy
- Establishes encrypted WSS:// connection to controller
- Tunnels commands from STOCKSTAY.STOCKMARKET to STOCKSTAY.STOCKTRADER on the victim
- AES + RSA 4096-bit key exchange; Windows-1251 encoding (Cyrillic-indicative)

**STOCKSTAY.STOCKMARKET** — C2 orchestrator / controller (server-side)
- Python-based server receiving connections from implanted STOCKBROKER instances
- Hosted on attacker GitHub accounts (ChikenFresh, Roberto1983-ai) and cloud platforms

**STOCKSTAY.STOCKTRADER** — Backdoor command executor (victim-side)
- Full remote access capability via 14 commands: `Del`, `Dir`, `Get`, `Image`, `MkDir`, `MultyTask`, `Put`, `RegDelete`, `RegRead`, `RegWrite`, `RmDir`, `Run` (60-sec timeout), `Sysinfo`, `UnpackArchive`
- IPC via Windows `WM_COPYDATA` messages between components

**STOCKSTAY.MARKETMAKER** — Downloader / installer
- Fetches and deploys remaining STOCKSTAY components
- Configuration embedded as encrypted JSON blob

**K1MORPHER** — String obfuscator (shared with KAZUAR from June 2025)
- Uses Squirrel3 PRNG-based algorithm (GDC 2017 implementation)
- Applied to all STOCKSTAY components from April 2024 onward

### Configuration Format (Decrypted Sample)
```json
{
  "internal_id": "<server_identifier>",
  "internal_key": "<server_public_key>",
  "interval_engine": "600000",
  "span_min": "9",
  "span_max": "18",
  "days_not_work": "Saturday;Sunday;",
  "service": "<wss://c2_endpoint/ws>"
}
```
Operational windows limited to business hours (09:00–18:00, Mon–Fri) to blend with legitimate traffic.

### CVE Exploited

| CVE | Product | Context |
|-----|---------|---------|
| CVE-2025-8088 | WinRAR | Path traversal used in November 2025 drone-lure campaign targeting Ukrainian military |

---

## 4. Threat Actor / Campaign Attribution

**Turla** (aka Secret Blizzard, VENOMOUS BEAR, SUMMIT, UAC-0194, Uroburos)
- **Attribution:** Russia's Federal Security Service (FSB) Center 16
- **Confidence:** High — code overlaps with KAZUAR, shared K1MORPHER obfuscation, same deployment patterns and operational targets
- **MITRE ATT&CK Group:** [G0010](https://attack.mitre.org/groups/G0010/)
- **Active since STOCKSTAY:** December 2022 (websocket-sharp.dll compilation date)

**Primary Targets:**
- Ukraine (government, military, foreign affairs entities) — primary focus, especially active during ongoing conflict
- European foreign affairs ministries (Italy, Netherlands, Poland, Germany)
- Academic and diplomatic organizations

**Lure Themes:** Academic/university institutions, diplomatic/foreign affairs content, military equipment and personnel benefits, drone/UAV operations, election systems

**GitHub Infrastructure:**
- Account `Roberto1983-ai` (created Jul 23, 2025): Hosted DiplomacyEduAI.msi payload
- Account `ChikenFresh` (created Aug 14, 2025): Hosted STOCKSTAY.STOCKMARKET controller server code

**Relationship to KAZUAR:**
STOCKSTAY is a parallel toolkit distinct from Kazuar. Both share K1MORPHER obfuscation starting June 2025, are deployed against the same Ukrainian targets alongside WILDDAY and DIAMONDBACK, but use different C2 mechanisms (WebSocket cloud hosting vs. P2P HTTP/EWS/Exchange).

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN (
  "wool-basalt-clock.glitch.me",
  "weatherdataai.theworkpc.com",
  "canal1zac1a.onrender.com",
  "driverx86-adobe.onrender.com",
  "google-ai-labs-it.onrender.com"
)
by DNS.src DNS.query DNS.record_type
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src query record_type risk_score
```
*Detects DNS resolution of known STOCKSTAY WebSocket C2 endpoints.*

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_port IN (443)
  AND (All_Traffic.dest_dns IN ("*.onrender.com","*.glitch.me","*.theworkpc.com"))
  AND All_Traffic.app NOT IN ("chrome","firefox","msedge","safari","opera","iexplore")
by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.dest_dns All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name, "(?i)mshta|wscript|cscript|powershell|cmd|rundll32"), 90,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime src dest dest_dns dest_port process_name risk_score
```
*Detects non-browser processes establishing WebSocket connections to cloud hosting platforms used as STOCKSTAY C2.*

```spl
index=* sourcetype=* (
  "StockMarketNews.exe" OR "StockMarketView.exe" OR "StockMarketNet.exe" OR "StockMarketSystem.exe"
  OR "SMEditor.exe" OR "SMNet.exe" OR "MSViewer.exe" OR "MSDriver.exe" OR "MSRender.exe"
  OR "ClientMNGR2.exe" OR "GR3.exe" OR "DiplomacyEduAI.msi" OR "MicrosoftUpdateOneDrive.exe"
)
| stats count min(_time) as firstTime max(_time) as lastTime by host source sourcetype
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime host source sourcetype risk_score
```
*Hunts for known STOCKSTAY component filenames across all log sources.*

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="mshta.exe"
  AND Processes.parent_process_name NOT IN ("explorer.exe","svchost.exe","msiexec.exe")
by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(parent_process_name, "(?i)winrar|7z|mshta"), 90,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```
*Detects mshta.exe launched by unusual parents — STOCKSTAY delivery vector (HTA execution wrapper, T1218.007).*

---

## 6. Executive Summary

Google Threat Intelligence Group (GTIG) published a detailed analysis on June 25, 2026 of **STOCKSTAY**, a previously undisclosed multi-component .NET backdoor ecosystem attributed to Turla (FSB Center 16). STOCKSTAY has been under active development since at least December 2022 and represents a significant new addition to Turla's toolset running in parallel with the Kazuar P2P botnet.

The malware consists of four components: **STOCKBROKER** (WebSocket C2 tunneler), **STOCKMARKET** (server-side controller), **STOCKTRADER** (victim-side backdoor executor with 14 commands), and **MARKETMAKER** (downloader/installer). A distinguishing feature is C2 infrastructure abuse of legitimate cloud hosting platforms — specifically Render.com and Glitch.me — for WebSocket-based C2, making outbound traffic difficult to distinguish from legitimate SaaS usage.

The campaign has targeted Ukrainian government, military, and foreign affairs entities as its primary focus, alongside European foreign ministries (Italy, Netherlands, Poland, Germany). Lure themes exploit current events — Ukrainian military personnel benefit calculators, drone/UAV documentation, diplomatic educational content, and university materials. From November 2025, Turla began exploiting CVE-2025-8088 (WinRAR) in the delivery chain alongside malicious LNK files.

Both STOCKSTAY and Kazuar now share the **K1MORPHER** string obfuscator (first adopted by STOCKSTAY in April 2024, adopted by Kazuar in June 2025), suggesting a centralized obfuscation toolkit managed by a common Turla development team. Organizations in Ukraine and European government/diplomatic sectors should hunt for STOCKSTAY component filenames and WebSocket connections to Render.com/Glitch.me from non-browser processes.

**Severity: Critical** — Active Russia-state espionage against European defense and government targets.

---

## References

- [Google GTIG — STOCKSTAY Another Day: The Latest Addition to Turla's Intelligence Gathering Apparatus (2026-06-25)](https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering)
- [MITRE ATT&CK — Turla (G0010)](https://attack.mitre.org/groups/G0010/)
- [Microsoft — Kazuar Anatomy of a Nation-State Botnet (2026-05-14)](https://www.microsoft.com/en-us/security/blog/2026/05/14/kazuar-anatomy-of-a-nation-state-botnet/)
- [NVD — CVE-2025-8088 (WinRAR path traversal)](https://nvd.nist.gov/vuln/detail/CVE-2025-8088)
