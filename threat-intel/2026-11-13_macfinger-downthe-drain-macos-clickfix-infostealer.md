---
title: "Macfinger ClickFix Campaign Delivers DownTheDRAIN macOS Go-Based Infostealer"
date: 2026-11-13
source: "https://isc.sans.edu/diary/Macfinger+ClickFix+DownTheDRAIN+macOS+Infostealer"
tlp: WHITE
severity: MEDIUM
tags: [macos, clickfix, infostealer, downthe-drain, go-based, macfinger, crypto-drainer, xattr-bypass, trustd-masquerade]
iocs_added: ["45.150.32[.]130"]
---

# Macfinger ClickFix Campaign Delivers DownTheDRAIN macOS Infostealer

## Summary

The SANS Internet Storm Center documented a macOS ClickFix campaign (internally named "Macfinger") on November 13, 2026 delivering a Go-based infostealer named **DownTheDRAIN**. The malware harvests credentials and crypto wallet data, and redirects a share of outbound cryptocurrency transactions via clipboard hijacking. Huntress confirmed the analysis.

---

## Infection Chain

1. **Delivery:** Victim encounters a fake CAPTCHA page designed for macOS users.
2. **Social Engineering (ClickFix):** The fake CAPTCHA instructs the user to open Terminal and paste a shell command to "verify" they are human.
3. **Stage 1 Execution:** The pasted command contacts the delivery server (`45.150.32[.]130`, path `37339606cba4522a`) and retrieves a shell script.
4. **Stage 2 Binary:** The shell script downloads the DownTheDRAIN Go binary. macOS Gatekeeper blocked execution and quarantined the binary (moved to Trash), but the attack chain strips the quarantine extended attribute to bypass this control.
5. **Persistence & Masquerade:** The loader creates a directory named to impersonate the macOS system trust daemon (`trustd`) and copies the payload as `com.apple.verified`, removing the `com.apple.quarantine` xattr to defeat Gatekeeper.

---

## Capabilities

DownTheDRAIN is a Go-based multi-function infostealer:
- **Browser credential harvesting:** Targets Chromium and Firefox credential stores.
- **Crypto wallet theft:** Targets macOS-based wallet applications.
- **Clipboard hijacking:** Monitors clipboard for cryptocurrency address patterns and substitutes attacker-controlled addresses (crypto drainer functionality).
- **Keychain targeting:** Attempts access to macOS Keychain entries.

---

## MITRE ATT&CK

| Tactic | Technique | Description |
|--------|-----------|-------------|
| TA0001 Initial Access | T1566.002 | Spearphishing via link (ClickFix fake CAPTCHA page) |
| TA0002 Execution | T1204.002 | User Execution: Malicious File / Terminal command |
| TA0005 Defense Evasion | T1553.001 | Subvert Trust Controls: Gatekeeper Bypass (xattr quarantine removal) |
| TA0005 Defense Evasion | T1036.004 | Masquerading: Masquerade Task or Service (`trustd` directory, `com.apple.verified` name) |
| TA0006 Credential Access | T1555.001 | Credentials from Password Stores: Keychain |
| TA0006 Credential Access | T1555.003 | Credentials from Web Browsers |
| TA0009 Collection | T1115 | Clipboard Data (crypto address hijacking) |
| TA0011 C2 | T1071.001 | Application Layer Protocol: Web Protocols |

## Lockheed Martin Kill Chain

Delivery → Exploitation (user execution) → Installation (xattr bypass + trustd masquerade) → Actions on Objectives (credential/crypto theft)

---

## IOCs

### IP Addresses

| Indicator | Type | Context |
|-----------|------|---------|
| `45.150.32[.]130` | IP | DownTheDRAIN delivery server; Macfinger ClickFix campaign; observed path `37339606cba4522a` |

### Hashes

No confirmed hashes publicly released at time of writing.

### Domains

No confirmed C2 domains publicly released at time of writing.

---

## Hunting Notes

Key on-host indicators to hunt for:
- `xattr -d com.apple.quarantine` execution by a user-initiated shell
- Directory creation with name `trustd` in non-system paths (e.g., `~/Library/`, `/tmp/`)
- File named `com.apple.verified` created in non-Apple paths
- Terminal.app or `zsh`/`bash` spawning `curl`/`wget` to non-Apple domains followed by binary execution
- macOS Gatekeeper quarantine removal events (Unified Log: `com.apple.quarantine`)

**Note:** Do NOT confuse this campaign's IOCs with a separate AMOS/MacSync campaign using `svs-verificationdate[.]beer` and `196.251.107[.]171` — those belong to a different ClickFix delivery chain reported by Palo Alto Unit 42.

---

## References

- [SANS ISC — Macfinger ClickFix DownTheDRAIN macOS Infostealer (Nov 13, 2026)](https://isc.sans.edu/diaryarchive.html)
- [BleepingComputer — New macOS ClickFix attack silently mounts DMGs to push infostealer](https://www.bleepingcomputer.com/news/security/new-macos-clickfix-attack-silently-mounts-dmgs-to-push-infostealer/)
- [Daily Security Review — ClickFix Campaign Pushes Go-Based macOS Crypto Drainer](https://dailysecurityreview.com/phishing/clickfix-campaign-pushes-go-based-macos-crypto-drainer/)
- [ThreatPulse — ClickFix macOS Infostealer (Go-based Crypto/Credential Theft Campaign)](https://threatpulse.dev/threats/clickfix-macos-infostealer-go-based-crypto-credential-theft-campaign)
