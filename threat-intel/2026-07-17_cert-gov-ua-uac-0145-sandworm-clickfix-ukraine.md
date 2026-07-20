---
scraped_at: 2026-07-17T00:00:00Z
source_url: https://cert.gov.ua/article/6318437
report_type: threat-intel
severity: critical
title: "UAC-0145 (Sandworm/GRU): ClickFix CAPTCHA Lure Campaign Against Ukraine Using GHETTOVIBE, SCOUTCURL, and EtherHiding C2"
---

## 1. IOCs

*Specific network IOCs (domains, IPs, hashes) were not publicly disclosed in CERT-UA's advisory and the portal requires authentication for the full indicator set. The behavioral and file artifact IOCs below are extracted from the public advisory.*

### File Artifacts (Behavioral IOCs)

| Artifact | Description |
|----------|-------------|
| `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\*.vbs` | GHETTOVIBE persistence: VBS script written to Windows Startup folder for auto-execution at logon |
| Ethereum smart contract address (actor-controlled) | EtherHiding C2: Ethereum contract stores current C2 domain; SCOUTCURL/FluidLeech resolves domain by calling `eth_call` against the contract |

### Infrastructure Pattern

| Pattern | Description |
|---------|-------------|
| Ethereum RPC endpoints (`eth_call` to Cloudflare/public nodes) | EtherHiding technique: malware queries public Ethereum RPC to retrieve C2 domain from smart contract state; endpoints include `cloudflare-eth.com`, `mainnet.infura.io`, and community public RPC nodes |
| Compromised Ukrainian web infrastructure | UAC-0145 injected fake CAPTCHA verification JavaScript into 10+ legitimate Ukrainian websites; victims are redirected through these sites to ClickFix lures |

## 2. TTPs

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1189 | Drive-by Compromise | Victims are directed to compromised legitimate Ukrainian websites that display a fake CAPTCHA verification page |
| Initial Access | T1204.003 | User Execution: Malicious Image | ClickFix lure instructs victim to press Win+R, paste a PowerShell command from clipboard, and press Enter; command is copied to clipboard automatically by malicious JavaScript on the compromised page |
| Defense Evasion | T1036 | Masquerading | SMARTAXE cloaking component presents legitimate web content to automated scanners and security researchers while delivering ClickFix payload to targeted human visitors based on browser fingerprinting |
| Execution | T1059.001 | Command and Script Interpreter: PowerShell | Initial ClickFix command is a PowerShell one-liner that downloads and executes the GHETTOVIBE VBS dropper |
| Persistence | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | GHETTOVIBE VBS script is dropped into the Windows Startup folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`) to execute on every logon |
| Execution | T1059.005 | Command and Script Interpreter: Visual Basic | GHETTOVIBE is implemented as a VBS script; executes SCOUTCURL for system reconnaissance after establishing persistence |
| Discovery | T1082 | System Information Discovery | SCOUTCURL (PowerShell reconnaissance script) collects hostname, OS version, installed software, running processes, network configuration, and user/group membership; transmits results to C2 |
| Discovery | T1016 | System Network Configuration Discovery | SCOUTCURL enumerates network adapters, IP addresses, and routing tables |
| Discovery | T1057 | Process Discovery | SCOUTCURL enumerates running processes and services |
| Command and Control | T1102.002 | Web Service: Bidirectional Communication | EtherHiding: FluidLeech and LoadLoop query a public Ethereum RPC endpoint (`eth_call`) to retrieve the current C2 domain from an actor-controlled smart contract's storage slot; provides C2 resilience because the contract cannot be sinkholed |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | FluidLeech / LoadLoop beacon to the actor-controlled domain resolved via EtherHiding; use standard HTTP/HTTPS to blend with normal web traffic |

## 3. Malware & Tools

### SMARTAXE (Cloaking Layer)

A JavaScript-based web cloaking framework injected into compromised Ukrainian websites. SMARTAXE fingerprints incoming requests: automated scanners, crawlers, and known security research infrastructure receive legitimate page content, while targeted human visitors from Ukraine see a fake CAPTCHA verification page. The CAPTCHA is designed to display a CLOUDFLARE-branded verification prompt. When the victim clicks "I am not a robot," malicious JavaScript copies a PowerShell command to the clipboard and instructs the victim to paste and run it via Win+R. SMARTAXE is not stored on the compromised website in a persistent way — it is injected into page responses dynamically, making detection via static site scanning difficult.

### GHETTOVIBE (VBS Persistence / Dropper)

A Visual Basic Script dropped to the Windows Startup folder by the initial ClickFix PowerShell command. GHETTOVIBE is designed for persistence: it executes automatically at every logon without requiring registry modification. On execution, GHETTOVIBE invokes SCOUTCURL for initial reconnaissance and subsequently downloads FluidLeech or LoadLoop from the actor's C2. The choice of Startup folder (rather than Run keys) avoids common registry-based persistence detections.

### SCOUTCURL (PowerShell Reconnaissance)

A PowerShell reconnaissance module invoked by GHETTOVIBE. SCOUTCURL systematically collects system information (hostname, OS version, installed software, running processes, network configuration, domain membership, user accounts and groups) and transmits the results to the actor's C2 infrastructure. The module is named for its use of `curl`/`Invoke-WebRequest` for data exfiltration. Output is compressed and base64-encoded before transmission.

### FluidLeech / LoadLoop (C2 Loaders)

Two functionally similar loaders that provide ongoing access after GHETTOVIBE establishes persistence. Both tools implement the EtherHiding technique to resolve their C2 domain at runtime: they query a public Ethereum JSON-RPC endpoint with `eth_call` targeting an actor-controlled smart contract and read the current C2 domain from the contract's storage. This indirect C2 resolution means:
1. The malware binary contains no hardcoded C2 domain (only the Ethereum contract address and a public RPC endpoint).
2. Defenders cannot sinkhole the C2 by seizing the domain — the actor simply updates the contract's storage to point to a new domain.
3. The Ethereum contract address, once deployed, is permanent and can serve as a reliable C2 resolver for the lifetime of the malware.

FluidLeech and LoadLoop differ primarily in their persistence mechanism: FluidLeech runs via GHETTOVIBE's Startup invocation, while LoadLoop is injected into a legitimate system process context.

### SMARTAXE (Duplicate Role)

SMARTAXE also serves as a secondary cloaking layer within FluidLeech/LoadLoop to mask C2 traffic patterns from network monitoring: the loaders modulate their beacon timing and HTTP header profiles to match typical browser traffic.

## 4. Threat Actor / Campaign Attribution

**Actor:** UAC-0145, CERT-UA's designation for a Sandworm (GRU Unit 74455) sub-cluster

**Parent organization:** Russian GRU (Main Intelligence Directorate), Unit 74455; also tracked as ELECTRUM, Voodoo Bear, TeleBots, and Sandworm Team

**Motivation:** Espionage and sabotage targeting Ukrainian government, military, critical infrastructure, and defense industrial base

**Geography:** Ukraine (primary target); Ukrainian diaspora and allied government entities (secondary)

**Activity date:** CERT-UA advisory published July 17, 2026; campaign observed targeting 10+ compromised Ukrainian websites

**Technique evolution:** This campaign represents a significant TTP evolution for the Sandworm cluster:
- Adoption of ClickFix social engineering (previously associated with cybercrime groups) demonstrates operational borrowing from the criminal ecosystem
- EtherHiding blockchain C2 was previously observed in commodity malware (WeedHack MaaS in 2023); Sandworm's adoption indicates the technique's resilience advantages have attracted nation-state interest
- The SMARTAXE cloaking layer provides unusually sophisticated detection evasion for what is otherwise a relatively simple VBS/PowerShell chain

## 5. Splunk Detection Searches

### Query 1: GHETTOVIBE — VBS Written to Windows Startup Folder

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_path IN (
    "*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*.vbs",
    "*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*.vbe",
    "*\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\*.vbs",
    "*\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\*.vbe"
  )
  AND Filesystem.action IN ("created", "modified")
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
   Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime dest user file_path file_name process_name risk_score
```

### Query 2: SCOUTCURL — PowerShell Spawned by wscript.exe (GHETTOVIBE → SCOUTCURL Chain)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("wscript.exe", "cscript.exe")
  AND Processes.process_name IN ("powershell.exe", "pwsh.exe")
  AND (Processes.process IN ("*Invoke-WebRequest*", "*iwr *", "*curl*", "*DownloadString*",
    "*DownloadFile*", "*Get-WmiObject*", "*Get-CimInstance*", "*systeminfo*",
    "*ipconfig*", "*net user*", "*net group*", "*tasklist*"))
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)invoke-webrequest.*http|iwr.*http|downloadstring.*http"), 90,
    match(process, "(?i)get-wmiobject|get-ciminstance|systeminfo"), 80,
    1=1, 75)
| where risk_score >= 75
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Query 3: EtherHiding — Non-Browser Process Connecting to Ethereum JSON-RPC Endpoints

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_host IN (
    "cloudflare-eth.com", "mainnet.infura.io", "eth-mainnet.g.alchemy.com",
    "rpc.ankr.com", "ethereum.publicnode.com", "rpc.flashbots.net",
    "eth.llamarpc.com", "rpc.mevblocker.io", "api.mycryptoapi.com",
    "gateway.tenderly.co", "rpc-ethereum.g.allthatnode.com"
  )
  AND NOT All_Traffic.app IN ("chrome", "firefox", "msedge", "brave", "safari",
    "chromium", "opera", "vivaldi")
by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port
   All_Traffic.app All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(app, "(?i)powershell|wscript|cscript|mshta|rundll32|regsvr32"), 90,
    match(app, "(?i)python|node|curl|wget"), 75,
    1=1, 65)
| where risk_score >= 65
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src dest dest_host dest_port app process_name risk_score
```

## 6. Executive Summary

On July 17, 2026, CERT-UA published advisory #6318437 documenting a targeted ClickFix campaign against Ukrainian entities attributed to UAC-0145, a Sandworm (GRU) sub-cluster. The campaign injected fake CAPTCHA verification JavaScript (SMARTAXE) into 10 or more compromised legitimate Ukrainian websites. When a targeted visitor clicks the CAPTCHA, a PowerShell command is automatically copied to their clipboard; the victim is instructed to paste and run it using Win+R. The initial PowerShell command drops GHETTOVIBE, a VBS script persisted in the Windows Startup folder, which runs SCOUTCURL (PowerShell reconnaissance) and subsequently downloads FluidLeech or LoadLoop. Both loaders use EtherHiding — a technique where the current C2 domain is stored in an Ethereum smart contract's storage slot and retrieved at runtime via a public `eth_call` JSON-RPC query. This makes the C2 domain impossible to sinkhole: the actor can update the contract to a new domain instantly, and the old contract address remains functional as a resolver indefinitely. No specific hashes or network IOCs were released publicly; CERT-UA's full indicator set requires portal authentication. The EtherHiding C2 mechanism is a high-priority detection target because it is novel at the nation-state level, durable across campaign lifetimes, and directly observable as an anomalous network connection from a non-browser process to a public Ethereum RPC endpoint. Detections for the GHETTOVIBE Startup VBS pattern and EtherHiding non-browser Ethereum RPC connections are added to this repository.

## References

- [CERT-UA — Advisory #6318437: UAC-0145 ClickFix Campaign (2026-07-17)](https://cert.gov.ua/article/6318437)
- [MITRE ATT&CK — T1189: Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- [MITRE ATT&CK — T1547.001: Startup Folder Persistence](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE ATT&CK — T1102.002: Web Service: Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002/)
- [MITRE ATT&CK — T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK — T1059.005: Visual Basic](https://attack.mitre.org/techniques/T1059/005/)
- [MITRE ATT&CK Group — Sandworm Team (G0034)](https://attack.mitre.org/groups/G0034/)
- [EtherHiding Technique Reference — GuardioLabs (2023)](https://labs.guard.io/etherhiding-hiding-web2-malicious-code-in-web3-smart-contracts-65ea78efad16)
- [Unit 42 — ClickFix Social Engineering Overview](https://unit42.paloaltonetworks.com/clickfix-social-engineering/)
