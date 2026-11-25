---
scraped_at: 2026-11-25T04:00:00Z
source_url: https://engage.morphisec.com/hubfs/2026-PDFs/RevStealer_ThreatAnalysis_5.pdf
report_type: threat-intel
severity: high
title: "RevStealer Fake Claude Opus 5 Electron App: Trojanized Desktop Infostealer Targeting Crypto Wallets and Browser Credentials (Morphisec, Nov 2026)"
---

## 1. IOCs

### File Hashes

| Hash (SHA-256) | Filename | Description |
|---|---|---|
| `551a7a0c63e6d716fbe41c45923d623ea8d86e34fd4212fbe3e758a98cde0970` | `app.asar` | Trojanized Electron app package — fake "Claude Opus 5 Free Desktop"; AES-256-CBC encrypted payload concealed in resources; ~101 MB ZIP |
| `e21d6c433cf0168b24b1a0a46f56ca23799378fd21ada2b17240934e9887c058` | `app-ri9icle2.res` | AES-256-CBC encrypted RevStealer native payload embedded in Electron resources; decrypted and written to `%USERPROFILE%\AppData.9qdz1mlg\tk6pm8x57t.exe` at runtime |

### Domains

| Domain | Role |
|---|---|
| `elitecheatsx[.]live` | RevStealer C2 / fake cheat/game-tool distribution hub delivering the trojanized Claude Opus 5 app |
| `elitemods[.]shop` | RevStealer distribution domain — fake game modification portal |
| `satano[.]xyz` | RevStealer distribution hub — fake premium software / "free AI tools" lure |
| `cheatseller[.]com` | RevStealer distribution hub — game account tool / cheat delivery lure |

### GitHub Lure Repositories (now removed)

- `github[.]com/claude5opus/Claude-Opus-5-Free-Desktop`
- `github[.]com/claudeopus5/Claude-Opus-5-Free-Desktop`

---

## 2. TTPs

| MITRE Tactic | Technique ID | Technique Name | Usage |
|---|---|---|---|
| Initial Access | T1204.002 | User Execution: Malicious File | Victim downloads and launches trojanized Electron ZIP from fake Claude Opus 5 GitHub repo or lure site |
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | Loader adds `%AppData%\.9qdz1mlg\` to Windows Defender exclusion list via `Add-MpPreference -ExclusionPath` before payload decryption |
| Defense Evasion | T1027.002 | Obfuscated Files or Information: Software Packing | Payload encrypted with AES-256-CBC; key derived from victim system fingerprint; encrypted file named with random characters (`app-ri9icle2.res`) |
| Defense Evasion | T1480 | Execution Guardrails | CAPTCHA-style prompt and language/locale filter executed before payload decryption to avoid researcher sandbox analysis; anti-CN geofence also observed |
| Credential Access | T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Steals saved passwords, cookies, and session tokens from Chrome, Firefox, Edge, and 50+ Chromium-based browsers |
| Credential Access | T1555.005 | Credentials from Password Stores: Password Managers | Targets KeePass, Bitwarden, and 1Password browser extensions |
| Collection | T1005 | Data from Local System | Exfiltrates browser databases, Telegram session files, Steam account data, and game authentication tokens |
| Collection | T1115 | Clipboard Data | Monitors clipboard for cryptocurrency wallet addresses and replaces with attacker-controlled wallets |
| Impact | T1657 | Financial Theft | Captured card data, stolen credentials, crypto wallet address swapping |
| Command and Control | T1041 | Exfiltration Over C2 Channel | Stolen data POSTed to C2 endpoint via HTTPS |

---

## 3. Malware & Tools

### RevStealer (new Electron-based delivery variant)

**Overview:** RevStealer is a Windows infostealer first observed in July 2026. This November 2026 campaign introduces a new delivery vector: a ~101 MB trojanized Electron application masquerading as a free desktop client for Anthropic's Claude Opus 5. The Electron wrapper is not functional as an AI client; it serves solely as a loader.

**Execution chain:**
1. Victim downloads `Claude-Opus-5-Free-Desktop.zip` (~101 MB) from a GitHub lure repo or distribution site
2. Electron app launches and runs environment checks (locale filter, CAPTCHA lure, process/VM detection)
3. Loader calls `Add-MpPreference -ExclusionPath %USERPROFILE%\AppData.9qdz1mlg\` via PowerShell
4. Encrypted payload `app-ri9icle2.res` decrypted with AES-256-CBC; plaintext written to `%USERPROFILE%\AppData.9qdz1mlg\tk6pm8x57t.exe`
5. `tk6pm8x57t.exe` launched as a hidden child process
6. Stealer harvests browser credentials, crypto wallets, session tokens, game auth data
7. Data exfiltrated via HTTPS POST to C2

**Key artifacts:**
- Electron parent process spawning PowerShell with `Add-MpPreference`
- Path pattern: `%USERPROFILE%\AppData\.<random8char>\<random12char>.exe`
- Registry run key persistence: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

**Note:** Anthropic was not compromised. This campaign impersonates Anthropic branding but has no connection to Anthropic or the legitimate Claude product.

---

## 4. Threat Actor / Campaign Attribution

| Attribute | Value |
|---|---|
| Actor | Unattributed; RevStealer operator consistent with financially motivated threat actor |
| Motivation | Financial — cryptocurrency theft, credential resale, gaming account theft |
| Targeting | Windows users seeking "free" premium AI tools, game cheats, or software; broad targeting via GitHub and SEO-poisoned lure sites |
| Distribution | GitHub (lure repos now removed); lure sites (`elitecheatsx[.]live`, `satano[.]xyz`, `cheatseller[.]com`, `elitemods[.]shop`) and 100+ linked domains identified by Morphisec |
| Prior coverage | Base RevStealer C2 domains tracked from July 31, 2026 — see `2026-08-01_maltrail-win-revstealer-windows-infostealer.md` and `iocs/domain.csv` |

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("electron.exe","claude-opus-5.exe","claude.exe","*Electron*")
    AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe")
    AND Processes.process IN ("*Add-MpPreference*","*ExclusionPath*","*MpPreference*")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
     Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| where risk_score >= 90
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("powershell.exe","pwsh.exe")
    AND Processes.process IN ("*Add-MpPreference*","*ExclusionPath*","*AppData*")
    AND NOT Processes.parent_process_name IN ("msiexec.exe","setup.exe","install.exe","Update.exe","Squirrel.exe")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
     Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)appdata\.[a-z0-9]{6,12}"), 95,
    match(process,"(?i)appdata"), 80,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path IN ("*\\AppData\\.*\\*.exe","*\\AppData\\*\\*.exe")
    AND Filesystem.file_name="*.exe"
    AND (Filesystem.action="created" OR Filesystem.action="modified")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path,"(?i)appdata\.[a-z0-9]{6,12}"), 95,
    match(file_name,"(?i)[a-z0-9]{8,14}\.exe") AND match(file_path,"(?i)appdata"), 80,
    1=1, 60)
| where risk_score >= 80
| table firstTime lastTime dest user file_path file_name process_name risk_score
```

---

## 6. Executive Summary

Morphisec published technical analysis in November 2026 of a new RevStealer distribution campaign using a trojanized Electron application posing as a free desktop version of Anthropic's Claude Opus 5. The ~101 MB app package is distributed via GitHub lure repositories (now removed) and a network of fake game-cheat and "free AI tools" websites. It targets 50+ cryptocurrency wallets, browser credentials across all major browsers, gaming account tokens, and payment card data.

The campaign is notable for its **Defender exclusion bypass** pattern: the Electron loader uses PowerShell `Add-MpPreference` to whitelist an obfuscated AppData subdirectory (`AppData\.<random8>`) before decrypting and executing the native stealer payload (`<random12>.exe`). This path pattern is highly anomalous for legitimate Electron applications and is a reliable detection opportunity.

**Immediate actions:** Block the four distribution domains (`elitecheatsx[.]live`, `elitemods[.]shop`, `satano[.]xyz`, `cheatseller[.]com`) at DNS and proxy. Alert on PowerShell spawned by Electron processes executing `Add-MpPreference` with `AppData` path arguments. Existing RevStealer C2 domain detections (`revstealer_dns_c2_lookup.md`) remain valid; this report adds the new lure-distribution IOCs.

---

## 7. References

- [Morphisec: RevStealer Threat Analysis v5 (PDF)](https://engage.morphisec.com/hubfs/2026-PDFs/RevStealer_ThreatAnalysis_5.pdf)
- [CyberInsider: New RevStealer malware spreads as fake Claude Opus 5 desktop app](https://cyberinsider.com/new-revstealer-malware-spreads-as-fake-claude-opus-5-desktop-app/)
- [SC World: RevStealer malware spread through fake Claude Opus 5 download](https://www.scworld.com/news/revstealer-malware-spread-through-fake-claude-opus-5-download)
- [GBHackers: Fake Claude Opus 5 App Deploys RevStealer](https://gbhackers.com/fake-claude-app/)
- [CyberPress: Hackers Disguise RevStealer as Claude Opus 5 AI App](https://cyberpress.org/revstealer-masquerades-as-claude/)
- Prior RevStealer coverage: `2026-08-01_maltrail-win-revstealer-windows-infostealer.md`
- MITRE ATT&CK: [T1204.002](https://attack.mitre.org/techniques/T1204/002/), [T1562.001](https://attack.mitre.org/techniques/T1562/001/), [T1555.003](https://attack.mitre.org/techniques/T1555/003/)
