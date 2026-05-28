---
scraped_at: 2026-05-27T14:00:00Z
source_url: https://www.crowdstrike.com/en-us/blog/inside-crowdstrike-takedown-of-a-developer-targeting-botnet/
report_type: threat-intel
severity: high
title: "Disrupting Glassworm: CrowdStrike, Google, and Shadowserver Take Down Developer-Targeting Supply Chain Botnet"
---

## 1. IOCs

### IP Addresses (Sinkhole Detection Indicator)

| Indicator | Type | Context |
|-----------|------|---------|
| 164.92.88[.]210 | IPv4 | CrowdStrike-operated Glassworm sinkhole IP (post-takedown May 26, 2026); Glassworm-infected hosts beacon here after C2 disruption — any endpoint connection to this IP indicates active Glassworm infection requiring immediate remediation |

### Domains

No dedicated C2 domains identified. Glassworm used exclusively decentralized infrastructure:
- **Solana blockchain** transaction memo fields (immutable public dead drop for C2 server addresses)
- **BitTorrent DHT** (configuration data stored against hardcoded public keys)
- **Google Calendar** event titles (Base64-encoded C2 path dead drops)

### File Hashes

No specific file hashes confirmed in publicly available reporting at time of ingestion. Full IOC list available to CrowdStrike Falcon Intelligence customers.

### Malicious Packages and Extensions

| Artifact | Platform | Publisher Account | Notes |
|----------|----------|-------------------|-------|
| code-wakatime-activity-tracker | OpenVSX / VS Code / Cursor / Windsurf | specstudio | Trojanized Zig-compiled native dropper; ships win.node (PE32+ DLL) on Windows and mac.node (universal Mach-O) on macOS; loaded directly into Node.js runtime bypassing extension sandbox protections |
| 21 additional malicious VS Code extensions | OpenVSX / VS Marketplace | Various | Identified by Aikido, Socket, Step Security, and OpenSourceMalware community |
| 4 malicious npm packages | npm | Various | Deliver GlasswormRAT via postinstall hooks; use invisible Unicode character obfuscation to evade static analysis |
| 300+ poisoned GitHub repositories | GitHub | Various (compromised developer accounts) | Malicious code force-pushed to default branches using credentials harvested from earlier Glassworm infections |

**Total attributed compromised components: 433** across GitHub, npm, PyPI, OpenVSX, and VS Code Marketplace.

---

## 2. TTPs

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Trojanized VSCode extensions on OpenVSX/VS Marketplace; backdoored npm/PyPI packages with malicious postinstall hooks; force-pushed malicious commits to 300+ GitHub repositories using stolen developer credentials |
| Execution | T1059.007 | Command and Scripting Interpreter: JavaScript | GlasswormRAT is a full-featured Node.js RAT; postinstall hooks execute obfuscated JavaScript downloaders |
| Execution | T1204.002 | User Execution: Malicious File | Developers install and run trojanized packages during normal development workflows |
| Defense Evasion | T1027 | Obfuscated Files or Information | Invisible Unicode characters embedded in npm package source to evade static analysis and code review |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location | Extensions disguised as popular developer tools (WakaTime time tracker, Google Docs Offline) |
| Defense Evasion | T1548 | Abuse Elevation Control Mechanism | Zig-compiled native Node.js add-on (win.node/mac.node) loaded directly into the runtime with full OS access outside standard sandbox |
| Persistence | T1176 | Browser Extensions | Malicious Chrome extension (Stage 3) force-installed; poses as Google Docs Offline; persists across browser sessions |
| Command and Control | T1102 | Web Service | C2 channel 1: Solana blockchain transaction memo fields as immutable, censorship-resistant dead drop for C2 server IPs |
| Command and Control | T1102 | Web Service | C2 channel 2: BitTorrent DHT configuration data stored against hardcoded public keys |
| Command and Control | T1102 | Web Service | C2 channel 3: Google Calendar event titles containing Base64-encoded C2 paths |
| Command and Control | T1095 | Non-Application Layer Protocol | C2 channel 4: Direct TCP/WebSocket connections to commercial VPS providers for payload delivery |
| Credential Access | T1555 | Credentials from Password Stores | GlasswormRAT browser credential stealer modules extract saved passwords |
| Credential Access | T1539 | Steal Web Session Cookie | Chrome extension harvests cookies and active session tokens |
| Credential Access | T1528 | Steal Application Access Token | Targets developer OAuth tokens, npm credentials, GitHub PATs, cloud API keys |
| Collection | T1113 | Screen Capture | Chrome extension captures screenshots from compromised developer workstations |
| Collection | T1056.001 | Input Capture: Keylogging | Chrome extension logs keystrokes |
| Impact | T1657 | Financial Theft | Ledger/Trezor hardware wallet phishing component deployed when hardware wallet is detected on victim system |

---

## 3. Malware & Tools

| Malware/Tool | Type | Platform | Description |
|-------------|------|----------|-------------|
| GlasswormRAT | RAT | Windows, macOS, Linux | Full-featured Node.js remote access tool; modules include browser credential stealer, WebSocket C2 client, Chrome extension force-installer, screenshot capture, and keylogging relay |
| Zig dropper (win.node / mac.node) | Dropper | Windows / macOS | Zig-compiled native Node.js add-on; loads with full OS-level access outside Node.js sandbox; delivers GlasswormRAT; also targets Cursor and Windsurf IDEs in addition to VS Code |
| Glassworm Chrome extension | Browser Extension | Chrome (all Chromium-based) | Stage 3 force-installed extension disguised as Google Docs Offline; keylogger, cookie/session token harvester, screenshot capture; C2 via Solana blockchain memo fields |

---

## 4. Threat Actor / Campaign Attribution

| Field | Details |
|-------|---------|
| Tracking Name | Glassworm |
| Alternate Name | GlassWorm Group |
| Country Nexus | Russia-assessed — malware performs runtime CIS country/locale/timezone check and exits silently if victim is in a CIS-member country |
| Activity Start | Early 2025 (earliest identified malicious packages; possibly late 2024 per Truesec) |
| Primary Target | Software developers and DevOps engineers globally (CIS region excluded) |
| Secondary Impact | Downstream software consumers of poisoned packages and repositories |
| Scale | 433 compromised components; 300+ GitHub repositories; cross-platform (Windows, macOS, Linux) |
| Takedown | May 26, 2026, 14:00 UTC — CrowdStrike Counter Adversary Operations, Google, and Shadowserver Foundation simultaneously disrupted all four C2 channels |
| Campaign Objective | Gain persistent access to developer workstations to harvest credentials and inject malicious code into supply chain artifacts consumed by downstream organizations |

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.parent_process_name IN ("node.exe","node","npm","npm.cmd","pip","pip3","pip.exe",
      "python.exe","python3","python","code.exe","code","extensionHost.exe")
    AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","bash","sh","curl","curl.exe",
      "wget","wget.exe","python.exe","python3","mshta.exe","wscript.exe","cscript.exe","certutil.exe",
      "bitsadmin.exe","regsvr32.exe","rundll32.exe"))
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)(-enc|-encodedcommand|IEX|Invoke-Expression|FromBase64String)"), 90,
    match(process,"(?i)(DownloadString|DownloadFile|WebClient|Invoke-WebRequest)"), 87,
    match(process,"(?i)(curl|wget).+http"), 80,
    match(process,"(?i)(mshta|cscript|wscript|regsvr32|rundll32|certutil|bitsadmin)"), 82,
    match(process_name,"(?i)(bash|sh)") AND match(process,".*http.*"), 75,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_hostname IN (
      "api.mainnet-beta.solana.com","api.devnet.solana.com","api.testnet.solana.com",
      "rpc.ankr.com","solana-mainnet.rpc.extrnode.com","mainnet.rpc.triton.one")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_hostname All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(app,"(?i)(node|npm|pip|python)"), 80,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime src dest dest_hostname dest_port app risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest="164.92.88.210"
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95, note="Glassworm sinkhole (CrowdStrike-operated) — endpoint is infected with GlasswormRAT and requires immediate remediation"
| table firstTime lastTime src dest dest_port app risk_score note
```

---

## 6. Executive Summary

On May 26, 2026, CrowdStrike Counter Adversary Operations, in collaboration with Google and the Shadowserver Foundation, executed a coordinated simultaneous takedown of all four C2 channels used by the Glassworm botnet — a sophisticated developer-targeting supply chain threat active since early 2025. The botnet compromised 433 developer ecosystem components across npm, PyPI, OpenVSX, VS Code Marketplace, and GitHub by deploying trojanized extensions (disguised as popular tools like WakaTime), injecting malicious postinstall hooks into packages, and force-pushing malicious commits to over 300 GitHub repositories using credentials harvested from previously compromised developer accounts.

The primary payload, GlasswormRAT, is a cross-platform Node.js remote access tool with credential stealing, keylogging, screenshot capture, and cryptocurrency hardware wallet phishing capabilities. A Zig-compiled native dropper loaded directly into the Node.js runtime to bypass extension sandbox protections, affecting VS Code, Cursor, and Windsurf IDEs. Critically, Glassworm's C2 infrastructure used four decentralized channels — Solana blockchain transaction memo fields, BitTorrent DHT, Google Calendar event titles, and direct VPS connections — making conventional domain-based takedown impossible without simultaneous disruption of all channels.

CIS country exclusion logic in the malware strongly suggests Russia-based operators. Post-takedown, all infected hosts now beacon to CrowdStrike's sinkhole at 164.92.88[.]210 — organizations should immediately hunt for connections to this IP in network logs as a high-fidelity indicator of active Glassworm infection.
