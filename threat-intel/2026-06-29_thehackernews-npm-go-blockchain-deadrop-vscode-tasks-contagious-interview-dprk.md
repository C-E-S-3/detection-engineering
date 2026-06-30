---
scraped_at: 2026-06-29T00:00:00Z
source_url: https://thehackernews.com/2026/06/hijacked-npm-and-go-packages-use-vs.html
report_type: threat-intel
severity: high
title: "DPRK Contagious Interview: Hijacked npm/Go Packages Deploy Blockchain Dead-Drop C2 via VS Code Tasks Auto-Execution and InvisibleFerret Python Stealer (JFrog Security / The Hacker News June 29 2026)"
---

## 1. IOCs

### IP Addresses

| Indicator | Type | Context |
|-----------|------|---------|
| 166.88.134.62 | IPv4 | Contagious Interview Socket.io C2 server; html-to-gutenberg/fetch-page-assets npm campaign; InvisibleFerret Python stealer exfiltration; June 2026 |
| 198.105.127.210 | IPv4 | Contagious Interview Socket.io C2 server; html-to-gutenberg/fetch-page-assets npm campaign; June 2026 |
| 23.27.202.27 | IPv4 | Contagious Interview Socket.io C2 server; html-to-gutenberg/fetch-page-assets npm campaign; June 2026 |

### Domains / Infrastructure

| Indicator | Type | Context |
|-----------|------|---------|
| 260120[.]vercel.app | Domain | PolinRider/Contagious Interview C2; attacker-controlled Vercel subdomain used as loader stage C2 |
| default-configuration[.]vercel.app | Domain | PolinRider/Contagious Interview C2; attacker-controlled Vercel subdomain |
| vscode-settings-bootstrap[.]vercel.app | Domain | PolinRider/Contagious Interview C2; attacker-controlled Vercel subdomain used for VS Code workspace poisoning delivery |
| vscode-settings-config[.]vercel.app | Domain | PolinRider/Contagious Interview C2; attacker-controlled Vercel subdomain |
| vscode-bootstrapper[.]vercel.app | Domain | PolinRider/Contagious Interview C2; attacker-controlled Vercel subdomain |
| vscode-load-config[.]vercel.app | Domain | PolinRider/Contagious Interview C2; attacker-controlled Vercel subdomain |
| api.trongrid[.]io | Domain | TronGrid public blockchain API; abused by Contagious Interview for dead-drop C2 payload delivery (attacker embeds XOR-encrypted payload in TRON transaction input data) — not attacker-controlled, but attacker-abused |
| fullnode.mainnet.aptoslabs[.]com | Domain | Aptos public blockchain API; fallback dead-drop resolver; same abuse pattern as TronGrid |
| bsc-dataseed.binance[.]org | Domain | BSC (Binance Smart Chain) public JSON-RPC; second fallback dead-drop resolver |

### File Artifacts

| Indicator | Type | Context |
|-----------|------|---------|
| `public/fonts/fa-solid-400.woff2` | Filename | Fake font file containing obfuscated JavaScript; disguised as FontAwesome Solid 400 weight webfont; executed via VS Code tasks.json |
| `.vscode/tasks.json` | Filename | Malicious VS Code workspace task configuration; includes `eslint-check` task with `runOn: folderOpen` that auto-executes the fake font file payload when the project is opened |
| `html-to-gutenberg@4.2.11` | npm package+version | Hijacked legitimate npm package (DiogoAngelim's WordPress Gutenberg converter); malicious version uploaded May 25, 2026; removed from registry |
| `fetch-page-assets@1.2.9` | npm package+version | Malicious npm package listing html-to-gutenberg as dependency; independently malicious; uploaded May 25, 2026; removed from registry |

### File Hashes

| Indicator | Type | Context |
|-----------|------|---------|
| 9a541dffb7fc18dc71dbc8523ec6c3a71c224ffeb518ae3a8d7d16377aebee58 | SHA256 | Contagious Interview npm campaign malicious payload; specific file-to-hash mapping in JFrog primary report (source-confirmed via search snippet; full mapping requires direct JFrog post access) |
| bb2a89001410fa5a11dea6477d4f5573130261badc67fe952cfad1174c2f0edd | SHA256 | Contagious Interview npm campaign malicious payload; Contagious Interview / PolinRider campaign |
| 7c5adef4b5aee7a4aa6e795a86f8b7d601618c3bc003f1326ca57d03ec7d6524 | SHA256 | Contagious Interview npm campaign malicious payload; Contagious Interview / PolinRider campaign |

### Blockchain Addresses (Novel IOC Type — Attacker-Controlled Dead-Drop Staging)

| Indicator | Type | Context |
|-----------|------|---------|
| TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP | TRON address | PolinRider/Contagious Interview dead-drop address; XOR-encrypted next-stage payload embedded in transaction input data |
| TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG | TRON address | PolinRider/Contagious Interview dead-drop address |
| 0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e | Aptos address | PolinRider/Contagious Interview Aptos fallback dead-drop address |
| 0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3 | Aptos address | PolinRider/Contagious Interview Aptos fallback dead-drop address |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1195.001 | Supply Chain Compromise: Compromise Software Dependencies | Hijacked legitimate npm packages (html-to-gutenberg, fetch-page-assets) and 16 Go packages by uploading trojanized versions; developers who install or update the package receive the malware |
| Execution | T1059.007 | Command and Scripting Interpreter: JavaScript | Fake font file (`fa-solid-400.woff2`) contains obfuscated JavaScript; executed via `node public/fonts/fa-solid-400.woff2` in VS Code task; subsequent stages also JS-based |
| Execution | T1204.001 | User Execution: Malicious Link | VS Code `tasks.json` with `runOn: folderOpen` executes automatically when developer opens project workspace — no explicit user action required beyond opening the project folder |
| Command and Control | T1102.001 | Web Service: Dead Drop Resolver | XOR-encrypted next-stage payload embedded in TRON/Aptos/BSC blockchain transaction input data; loader queries public blockchain APIs (TronGrid, Aptos, BSC JSON-RPC) to retrieve payload; C2 address cannot be sinkhled or blocked without blocking entire blockchain network |
| Defense Evasion | T1027 | Obfuscated Files or Information | Payload XOR-encrypted (key: `2[gWfGj;<:-93Z^C` in PolinRider variant); disguised as font file with `.woff2` extension; security scanners routinely skip binary-looking asset files |
| Defense Evasion | T1036 | Masquerading | Payload filename `fa-solid-400.woff2` mimics a legitimate FontAwesome web font; VS Code task labeled `eslint-check` mimics a legitimate linting task |
| Persistence | T1176 | Browser Extensions | Socket.io C2 backdoor provides persistent remote shell, clipboard harvesting, file system operations, file upload to C2, process management |
| Ingress Tool Transfer | T1105 | Ingress Tool Transfer | Python infostealer downloaded from C2 as ZIP or 7z archive (`/d/python.zip`, `/d/python.7z`); `7zr.exe` also fetched for Windows extraction |
| Credential Access | T1555 | Credentials from Password Stores | InvisibleFerret Python stealer harvests browser credentials (Chromium/Firefox), password managers, authenticator apps, cryptocurrency wallets |
| Credential Access | T1552 | Unsecured Credentials | Harvests Git credentials, GitHub CLI `hosts.yml`, cloud API keys, environment secrets, SSH private keys |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Harvested credentials packaged as ZIP archives and exfiltrated to C2 server; optional Telegram bot exfiltration channel if bot token provided at runtime |

---

## 3. Malware & Tools

### Malicious npm/Go Package Delivery Chain

- **Hijacked npm packages:** `html-to-gutenberg@4.2.11` (legitimate package, trojanized), `fetch-page-assets@1.2.9`; uploaded May 25, 2026; removed from registry
- **Hijacked Go packages:** 16 packages identified by Nextron Systems; all using same fake font structure; specific module paths in JFrog primary report
- **Infection vector:** `.vscode/tasks.json` injected into package with task labeled `eslint-check` and `"runOn": "folderOpen"`
- **Payload masquerade:** Task executes `node public/fonts/fa-solid-400.woff2` — a JS payload disguised as a webfont file

### Stage 1 — Blockchain Dead-Drop Loader (`fa-solid-400.woff2`)

- Obfuscated JavaScript; queries TRON → Aptos → BSC JSON-RPC in order
- Extracts XOR-encrypted payload embedded after `?.?` marker in blockchain transaction input data
- Decrypts with hardcoded XOR key; executes via `eval()` or detached `node -e` child process

### Stage 2 — Socket.io JavaScript C2 Backdoor

- Downloaded via blockchain dead-drop
- Connects to Socket.io C2 server (IPs: 166.88.134.62, 198.105.127.210, 23.27.202.27)
- Capabilities: remote shell, clipboard capture, file system read/write, process management, file upload to C2, arbitrary JS execution

### Stage 3 — InvisibleFerret Python Infostealer

- Downloaded from C2 as `/d/python.zip` or `/d/python.7z`
- **Attribution:** InvisibleFerret family; DPRK-linked
- **Targets:**
  - Browser credentials and cookies (Chromium, Firefox)
  - Password managers and authenticator apps
  - Cryptocurrency wallets
  - Git credentials, GitHub CLI `hosts.yml`
  - Cloud API keys and environment variables
- **Exfiltration:** ZIP archives to C2; optional Telegram bot channel

---

## 4. Threat Actor / Campaign Attribution

| Field | Value |
|-------|-------|
| Campaign | "Fake Font" sub-campaign (Contagious Interview, third wave); also tracked as PolinRider |
| Nation-state | North Korea (DPRK) — attributed by multiple vendors |
| MITRE ATT&CK Group | Contagious Interview / G1052 |
| Aliases | DeceptiveDevelopment, DEV#POPPER, PurpleBravo, TAG-121 |
| Final payload | InvisibleFerret Python backdoor (DPRK-attributed) |
| GitHub presence | `fsaldev` account running compromised forks (e.g., `fsaldev/superset`); fake interview project names: `ShoeVista` (MERN), `StakingGame` (Web3/blockchain) |
| Scale | 1,951 compromised GitHub repositories across 1,047 unique owners as of April 2026 (OpenSourceMalware PolinRider dossier) |
| Targeting | Software developers; approached via fake technical job interviews; blockchain and full-stack developers specifically targeted with sector-relevant fake projects |

---

## 5. Splunk Detection Searches

### 5a. VS Code Spawning Node Process from Suspicious Font or Asset File Path

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("code.exe","code","cursor.exe","cursor","Code - OSS")
  AND Processes.process_name IN ("node.exe","node","python.exe","python","python3")
  AND (Processes.process LIKE "%woff%"
       OR Processes.process LIKE "%\.woff2%"
       OR Processes.process LIKE "%fonts%"
       OR Processes.process LIKE "%fa-solid%"
       OR Processes.process LIKE "%fa-regular%")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)woff2|fonts.*\\.js"), 95,
    match(process, "(?i)fa-solid|fa-regular|fontawesome"), 90,
    1=1, 80)
| where risk_score >= 80
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### 5b. Network Requests to Public Blockchain APIs from Developer Workstations (Dead-Drop Resolver)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN ("api.trongrid.io","fullnode.mainnet.aptoslabs.com",
    "bsc-dataseed.binance.org","bsc-rpc.publicnode.com")
  AND DNS.src_category IN ("workstation","developer","endpoint")
by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(query, "trongrid|aptoslabs"), 85,
    match(query, "bsc-dataseed|publicnode"), 80,
    1=1, 70)
| where risk_score >= 80
| table firstTime lastTime src query answer risk_score
```

### 5c. Known Contagious Interview C2 IP Communication

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_ip IN ("166.88.134.62","198.105.127.210","23.27.202.27")
by All_Traffic.src All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src dest_ip dest_port process_name risk_score
```

### 5d. Python ZIP Download from C2 Path Pattern (InvisibleFerret Stage)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where (Web.url LIKE "%/d/python.zip%"
       OR Web.url LIKE "%/d/python.7z%"
       OR Web.url LIKE "%/d/7zr.exe%"
       OR Web.url LIKE "%/$/boot%"
       OR Web.url LIKE "%/snv%"
       OR Web.url LIKE "%/verify-human/%")
by Web.src Web.dest Web.url Web.http_method Web.status
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(url, "(?i)/d/python\\.zip|/d/python\\.7z|/d/7zr\\.exe"), 95,
    match(url, "(?i)/\\$/boot|/snv|/verify-human"), 80,
    1=1, 70)
| where risk_score >= 80
| table firstTime lastTime src dest url http_method status risk_score
```

---

## 6. Executive Summary

On June 29, 2026, JFrog Security Research and The Hacker News disclosed a new sub-campaign of the DPRK-linked **Contagious Interview** operation (also tracked as PolinRider, DeceptiveDevelopment, G1052), targeting software developers via hijacked npm and Go packages. Two npm packages — `html-to-gutenberg@4.2.11` (a legitimate package by DiogoAngelim) and `fetch-page-assets@1.2.9` — were uploaded to the npm registry on May 25, 2026 with embedded malware; Nextron Systems identified an additional 16 maliciously-modified Go packages using the same delivery mechanism.

The attack introduces two novel techniques. First, the malware injects a `.vscode/tasks.json` file into the package that configures a VS Code workspace task labeled `eslint-check` with `"runOn": "folderOpen"` — **automatically executing the payload when a developer opens the project folder**, with no other user interaction. The payload is disguised as a FontAwesome web font (`public/fonts/fa-solid-400.woff2`) containing obfuscated JavaScript that security scanners routinely skip as a binary asset.

Second, instead of hardcoded C2 infrastructure, the loader uses **public blockchain APIs as C2 dead-drops**: querying TronGrid (TRON), Aptos, and BSC JSON-RPC endpoints in sequence and extracting XOR-encrypted next-stage payloads embedded in blockchain transaction input data. This makes the C2 resolver effectively uncensorable — no domain can be sinkholed without blocking an entire blockchain network.

The final payload is **InvisibleFerret**, a DPRK-attributed Python infostealer targeting browser credentials, cryptocurrency wallets, Git/GitHub credentials, cloud API keys, and environment secrets, with exfiltration to Socket.io C2 servers and optional Telegram bot channels.

**Recommended actions:**
- Audit all developer workstations for presence of `html-to-gutenberg@4.2.11` or `fetch-page-assets@1.2.9` in any `node_modules` directory; remove and rotate all credentials on affected systems.
- Block DNS resolution and outbound HTTP to the known C2 IPs (166.88.134.62, 198.105.127.210, 23.27.202.27).
- Alert on VS Code or Cursor spawning Node.js or Python from font/asset file paths (`.woff2`, `fonts/` directory).
- Alert on developer workstations querying TronGrid, Aptos, or BSC JSON-RPC APIs (legitimate developer use is rare from corporate endpoints).
- Enforce VS Code workspace trust and disable automatic task execution (`task.allowAutomaticTasks: off` in VS Code settings) on managed developer systems.
- Audit for the attacker-controlled Vercel C2 subdomains in proxy/DNS logs.

---

## References

- [The Hacker News — npm/Go Blockchain Dead-Drop Campaign](https://thehackernews.com/2026/06/hijacked-npm-and-go-packages-use-vs.html)
- [JFrog Security Research — Hijacked npm VSCode Tasks Blockchain](https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/)
- [OpenSourceMalware — PolinRider Rides Again](https://opensourcemalware.com/blog/polinrider-rides-again)
- [PolinRider GitHub Dossier](https://github.com/OpenSourceMalware/PolinRider/blob/main/README.md)
- [Security Alliance Radar — VS Code Tasks Abuse by Contagious Interview (DPRK)](https://radar.securityalliance.org/vs-code-tasks-abuse-by-contagious-interview-dprk/)
- [SafeDep — astro.config.mjs Supply Chain Attack via Blockchain C2](https://safedep.io/astro-config-blockchain-c2-supply-chain/)
- [Socket.dev — Contagious Interview Campaign Spreads Across 5 Ecosystems](https://socket.dev/blog/contagious-interview-campaign-spreads-across-5-ecosystems)
- [Apache Superset GitHub Issue #39299 — PolinRider Supply Chain](https://github.com/apache/superset/issues/39299)
- [MITRE ATT&CK — Contagious Interview G1052](https://attack.mitre.org/groups/G1052/)
- [MITRE ATT&CK — T1195.001](https://attack.mitre.org/techniques/T1195/001/)
- [MITRE ATT&CK — T1102.001](https://attack.mitre.org/techniques/T1102/001/)
