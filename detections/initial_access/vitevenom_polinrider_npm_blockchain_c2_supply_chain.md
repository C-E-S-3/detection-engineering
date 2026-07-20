# ViteVenom / PolinRider npm Supply Chain - TRON/Aptos Blockchain C2, DEV#POPPER RAT and OmniStealer

## Description

Detects the ViteVenom npm supply chain campaign (PolinRider / Contagious Interview, DPRK-attributed), active June 29 - July 17, 2026. Seven malicious npm packages typosquatting Tailwind CSS animation and typography libraries delivered DEV#POPPER RAT or OmniStealer via a multi-chain blockchain dead-drop mechanism. Each package's `postinstall` hook queried the TRON blockchain API (`api.trongrid.io`) to retrieve an XOR decryption key from wallet `TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP`, decrypted an embedded payload blob, and executed it via `eval()`. Aptos and Binance Smart Chain (BSC) served as fallback dead-drop channels if TRON was unreachable. The decryption key's residence on a public blockchain makes it impossible to sinkhole or remove without blocking the entire TRON network.

**DEV#POPPER RAT** is a Node.js backdoor providing remote shell access, file system enumeration, and secondary payload delivery. It establishes persistence via LaunchAgent (macOS), crontab (Linux), or scheduled task (Windows). It connects to PolinRider Socket.io C2 servers (166.88.134.62, 198.105.127.210, 23.27.202.27) previously documented in the June 2026 PolinRider campaign.

**OmniStealer** is a credential harvester targeting browser-stored passwords and cookies (Chrome, Edge, Firefox, Brave), SSH private keys, AWS/GCP/Azure credentials, `.npmrc` authentication tokens, kubeconfig files, Docker registry credentials, and `.env` files.

False positives for blockchain connection rules: TRON or Aptos DApp developers; BSC portfolio trackers. Scope with asset group filters to exclude designated blockchain developer workstations. All seven malicious packages have been removed from the npm registry; the rule for known package names (104033) flags historical installs or cached packages.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Primary Tactic | Initial Access |
| Primary Tactic ID | TA0001 |
| Primary Technique | Compromise Software Dependencies and Development Tools |
| Primary Technique ID | T1195.001 |
| Secondary Tactic | Command and Control |
| Secondary Technique | Web Service: One-Way Communication |
| Secondary Technique ID | T1102.003 |
| Tertiary Technique | Fallback Channels (Aptos / BSC fallback) |
| Tertiary Technique ID | T1008 |
| Credential Access | Credentials from Web Browsers (OmniStealer) |
| Credential Access ID | T1555.003 |
| Credential Access (2) | Credentials in Files (SSH/cloud/npmrc) |
| Credential Access ID (2) | T1552.001 |
| Persistence (macOS) | Plist Modification - LaunchAgent |
| Persistence ID (macOS) | T1547.011 |
| Persistence (Linux) | Scheduled Task/Job: Cron |
| Persistence ID (Linux) | T1053.005 |
| Defense Evasion | Obfuscated Files - XOR-encrypted in-memory payload |
| Defense Evasion ID | T1027 |
| Execution | JavaScript postinstall hook via eval() |
| Execution ID | T1059.007 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery (malicious npm package install) |
| Exploitation (postinstall hook TRON blockchain key retrieval + eval()) |
| Command & Control (TRON/Aptos/BSC dead-drop; Socket.io C2) |
| Actions on Objectives (OmniStealer credential harvest) |
| Installation (DEV#POPPER LaunchAgent / crontab persistence) |

## Wazuh Detection Rules

**Rule file:** `wazuh/rules/staged/vitevenom_polinrider_tron_aptos_supply_chain.xml`
**Rule IDs:** 104033-104043

| Rule ID | Level | Description |
|---------|-------|-------------|
| 104033 | 14 | Known ViteVenom malicious npm package name in npm command (Windows) |
| 104034 | 14 | TRON blockchain RPC connection (api.trongrid.io and variants) |
| 104035 | 14 | Aptos or BSC blockchain RPC connection (fallback dead-drop channels) |
| 104036 | 15 | TRON wallet dead-drop address IOC in network or FIM log |
| 104037 | 14 | PolinRider Socket.io C2 server IP connection |
| 104038 | 13 | node.exe with inline eval / Buffer.from / atob decode pattern |
| 104039 | 14 | OmniStealer: node.exe accessing browser credential database (Windows) |
| 104040 | 14 | OmniStealer: npm/node opening SSH/cloud credentials on Linux (auditd) |
| 104041 | 14 | DEV#POPPER: LaunchAgent plist created by npm/node on macOS (who-data) |
| 104042 | 13 | DEV#POPPER: crontab or shell profile modified by npm/node on Linux |
| 104043 | 15 | Sustained TRON C2 beaconing - active DEV#POPPER RAT confirmed |

## Splunk Detection Queries

### Query 1: npm Install of Known ViteVenom Malicious Package Names

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("npm", "npm.cmd", "npx", "npx.cmd")
  AND (Processes.process IN (
    "*tailwindcss-style-animate*", "*tailwind-mainanimation*",
    "*tailwind-autoanimation*", "*tailwind-animationbased*",
    "*tailwindcss-typography-style*", "*tailwindcss-style-modify*",
    "*tailwindcss-animate-style*"))
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100, note="Known ViteVenom malicious Tailwind npm package -- rotate all dev credentials on this host"
| table firstTime lastTime dest user process_name process risk_score note
```

### Query 2: TRON or Aptos Blockchain RPC Connection from Developer Workstations

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_host IN (
    "api.trongrid.io", "fullnode.tron.network", "api.tronstack.io",
    "rpc.trongrid.io", "fullnode.shasta.trongrid.io",
    "fullnode.mainnet.aptoslabs.com", "api.mainnet.aptoslabs.com",
    "rpc.mainnet.aptos.dev", "rpc.aptos.network",
    "bsc-dataseed.binance.org", "bsc-dataseed1.binance.org",
    "bsc-rpc.publicnode.com")
  AND NOT All_Traffic.app IN ("chrome", "firefox", "msedge", "brave", "safari")
by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(app, "(?i)node|npm|npx|node\.exe"), 90,
    match(dest_host, "trongrid|aptoslabs|aptos\.network"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime src dest_host dest_port app risk_score
```

### Query 3: TRON Wallet Dead-Drop Address in DNS or Network Traffic

```spl
(index=dns OR index=proxy OR index=netflow)
  ("TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP" OR "TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG")
| eval risk_score=100, note="ViteVenom TRON wallet dead-drop address IOC -- confirmed supply chain compromise"
| table _time host src dest query url risk_score note
```

### Query 4: PolinRider Socket.io C2 Server Connection

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_ip IN ("166.88.134.62", "198.105.127.210", "23.27.202.27")
by All_Traffic.src All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95, note="PolinRider DEV#POPPER RAT Socket.io C2 -- isolate host immediately"
| table firstTime lastTime src dest_ip dest_port app risk_score note
```

### Query 5: OmniStealer - node.exe Accessing Browser Credential Database

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.process_name IN ("node.exe", "node")
  AND (Filesystem.file_path LIKE "%\\Login Data%"
       OR Filesystem.file_path LIKE "%\\Cookies%"
       OR Filesystem.file_path LIKE "%logins.json%"
       OR Filesystem.file_path LIKE "%key4.db%"
       OR Filesystem.file_path LIKE "%Local State%")
  AND (Filesystem.file_path LIKE "%Chrome%"
       OR Filesystem.file_path LIKE "%Edge%"
       OR Filesystem.file_path LIKE "%Firefox%"
       OR Filesystem.file_path LIKE "%Brave%")
by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user process_name file_path action risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Known ViteVenom malicious package name in npm command | 100 | Confirmed IOC; this package name has no legitimate use |
| TRON wallet dead-drop address in any log | 100 | Unique campaign IOC; confirmed supply chain compromise |
| PolinRider Socket.io C2 IP connection | 95 | Confirmed C2; DEV#POPPER RAT is running; isolate immediately |
| Sustained TRON/Aptos C2 beaconing (2+ hits / 120s) | 95 | Active RAT check-in confirmed; full IR response warranted |
| OmniStealer browser credential file access from node | 90 | Near-certain credential theft; rotate browser passwords |
| OmniStealer SSH/cloud credential file access on Linux | 85 | Strong indicator; rotate SSH keys and cloud credentials |
| TRON blockchain RPC connection from npm/node | 85 | High-confidence dead-drop resolver query |
| Aptos or BSC blockchain RPC connection | 80 | Fallback dead-drop; higher FP rate but still suspicious |
| DEV#POPPER LaunchAgent created by npm/node | 85 | Confirmed persistence mechanism |
| DEV#POPPER crontab/profile modified by npm/node | 75 | Persistence; rare FP from legitimate package install scripts |
| node.exe with inline eval/decode pattern | 70 | In-memory payload execution; correlate with blockchain C2 connections |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| PolinRider / Contagious Interview (G1052, DPRK) | [MITRE ATT&CK G1052](https://attack.mitre.org/groups/G1052/), [opensourcemalware.com ViteVenom (2026-07-19)](https://opensourcemalware.com/) |
| DEV#POPPER (DPRK threat cluster alias) | [JFrog — Hijacked npm Blockchain C2 (2026-06-29)](https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/) |

## References

- [opensourcemalware.com — ViteVenom Campaign Analysis (2026-07-19)](https://opensourcemalware.com/)
- [The Hacker News — PolinRider npm/Go Blockchain Dead-Drop (2026-06-29)](https://thehackernews.com/2026/06/hijacked-npm-and-go-packages-use-vs.html)
- [JFrog Security Research — Hijacked npm VSCode Tasks Blockchain](https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/)
- [MITRE ATT&CK — G1052: Contagious Interview](https://attack.mitre.org/groups/G1052/)
- [MITRE ATT&CK — T1195.001: Compromise Software Dependencies](https://attack.mitre.org/techniques/T1195/001/)
- [MITRE ATT&CK — T1102.003: Web Service: One-Way Communication](https://attack.mitre.org/techniques/T1102/003/)
- [MITRE ATT&CK — T1555.003: Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
- [Prior campaign threat intel (2026-06-29)](../../threat-intel/2026-06-29_thehackernews-npm-go-blockchain-deadrop-vscode-tasks-contagious-interview-dprk.md)
- [ViteVenom threat intel (2026-07-19)](../../threat-intel/2026-07-19_opensourcemalware-polinrider-vitevenom-vite-npm-expansion.md)
