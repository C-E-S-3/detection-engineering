---
scraped_at: 2026-06-28T12:00:00Z
source_url: https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/
report_type: threat-intel
severity: high
title: "macOS.Gaslight: DPRK-Linked Rust Backdoor Embeds Prompt Injection Payload to Defeat AI-Assisted Malware Analysis"
---

## 1. IOCs

### File Artifacts

| Indicator | Type | Context |
|-----------|------|---------|
| `com.apple.system.services.activity` | LaunchAgent label | Persistence plist label used by macOS.Gaslight; impersonates legitimate Apple system service naming convention |
| `cpython-3.10.18-macos-*-none-install_only.tar.gz` | File download | Python runtime fetched at runtime from `github.com/astral-sh/python-build-standalone`; used to execute embedded 6.6 KB Base64-encoded stealer module |
| macOS.Gaslight Mach-O binary | ELF/Mach-O | Rust-compiled universal binary; first uploaded to VirusTotal May 22, 2026; XProtect rule MACOS_BONZAI_COBUCH targets this hash; 0 detections by static engines at time of disclosure |

### Network / Behavioral

| Indicator | Type | Context |
|-----------|------|---------|
| `api.telegram.org` | Domain (Telegram CDN) | Command and control channel; Gaslight polls Telegram Bot API in a persistent loop; all C2 payloads AES-GCM encrypted with fresh nonces; key supplied at runtime via operator config (not hardcoded in binary) |
| Telegram file upload API | Behavioral | Exfiltration vector; collected files (browser credential DBs, Keychain, terminal histories) delivered to attacker via Telegram file upload rather than direct C2 server |

### XProtect

| Rule | Context |
|------|---------|
| `MACOS_BONZAI_COBUCH` | Apple XProtect hash-based rule added in early June 2026 update; SentinelLABS associates the BONZAI family with North Korean threat activity; rule surfaced the initial Gaslight sample from VirusTotal |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Persistence | T1543.001 | Create or Modify System Process: Launch Agent | LaunchAgent plist with label `com.apple.system.services.activity` deployed to `~/Library/LaunchAgents/`; survives user logout/reboot |
| Credential Access | T1555.001 | Credentials from Password Stores: Keychain | Copies macOS login Keychain database (`~/Library/Keychains/login.keychain-db`) for exfiltration |
| Credential Access | T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Collects Chrome, Brave, Firefox, and Safari credential/session databases |
| Collection | T1119 | Automated Collection | Embedded 6.6 KB Python stealer module harvests: terminal command histories, installed application listing, running process snapshot, system hardware/software profile, browser credentials, macOS Keychain |
| Exfiltration | T1567 | Exfiltration Over Web Service | Collected archives uploaded via Telegram Bot file-upload API to attacker-controlled bot |
| Command and Control | T1102.002 | Web Service: Bidirectional Communication | Telegram Bot API polling loop used as interactive shell C2; AES-GCM payload encryption; certificate-pinned TLS; bot token self-redacted from runtime output (forensic resistance) |
| Defense Evasion | T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | 6.6 KB Python stealer Base64-encoded within Rust binary; decoded and staged at runtime |
| Defense Evasion | T1036.004 | Masquerade: Masquerade Task or Service | LaunchAgent label `com.apple.system.services.activity` impersonates legitimate Apple system daemon naming |
| Defense Evasion | T1027.016 | Obfuscated Files or Information: Junk Code Insertion | 3.5 KB Markdown-fenced block of 38 fabricated "system" messages embedded in binary to manipulate LLM-based malware triage agents (prompt injection against AI analysts) |
| Defense Evasion | T1553 | Subvert Trust Controls | Sample had 0 static AV detections at time of disclosure despite XProtect hash match |
| Resource Development | T1587.001 | Develop Capabilities: Malware | Custom Rust binary; unique among DPRK macOS cluster for adding prompt injection anti-analysis technique |

---

## 3. Malware & Tools

| Name | Type | Notes |
|------|------|-------|
| macOS.Gaslight | Rust backdoor + infostealer | DPRK-aligned BONZAI family; interactive shell + file upload C2 over Telegram Bot API; embeds Python stealer chain + 38-message prompt injection payload targeting LLM triage agents |
| Embedded Python stealer | Python (Base64-encoded, 6.6 KB) | Staged at runtime; downloads cpython-3.10.18 from astral-sh/python-build-standalone to execute; harvests Keychain, browser credentials, terminal histories, installed apps, process list |
| BONZAI cluster (unnamed prior samples) | macOS implants | Previous single-message prompt injection variant; Gaslight stacks 38 messages indicating active iteration/testing against production AI analysis tools |

### Prompt Injection Technique Details

The 3.5 KB embedded payload is formatted as a Markdown-fenced block containing 38 fabricated "system"-role LLM messages designed to abort or truncate AI-assisted triage:

- Fake token expiry notifications
- False memory overflow warnings
- Fabricated disk space depletion alerts
- False injection vulnerability alerts from the "sandbox"
- Fake static analysis failure messages

The technique targets the **summary/recommendation stage** of LLM-assisted pipelines — the step where an AI tool decides whether to flag a file as malicious. SentinelLABS confirmed the current version did not bypass any production AI analysis platform in testing, but the 38-message escalation (vs. a single message in prior BONZAI samples) indicates the operators are testing refinements against real tools.

---

## 4. Threat Actor / Campaign Attribution

| Field | Value |
|-------|-------|
| Actor | Unnamed DPRK-aligned cluster (BONZAI family) |
| Attribution confidence | High — XProtect BONZAI rule family; consistent with Lazarus/BlueNoroff macOS targeting patterns |
| Researcher | Phil Stokes, SentinelLABS (published June 23, 2026) |
| Discovery | Apple XProtect update (early June 2026) flagged a Mach-O uploaded to VirusTotal on May 22, 2026 |
| Targeting | macOS users; consistent with prior DPRK targeting of cryptocurrency, finance, and developer ecosystems |
| Prior BONZAI samples | Used single prompt injection message; Gaslight escalation to 38 messages shows active operational testing |

---

## 5. Splunk Detection Searches

### 5a. LaunchAgent Plist Created with System-Impersonating Label

```spl
`mac_os` source="/var/log/unified_logging/*" OR source="osquery:*"
| where (EventMessage LIKE "%com.apple.system.services.activity%"
  AND (EventMessage LIKE "%LaunchAgents%"))
| stats count min(_time) as firstTime max(_time) as lastTime by host user EventMessage
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime host user EventMessage risk_score
```

### 5b. LaunchAgent Plist Written Outside Standard System Paths (macOS Filesystem)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_path="*/Library/LaunchAgents/*.plist"
  AND NOT Filesystem.process_name IN ("installer", "pkgutil", "launchctl", "softwareupdate")
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_name, "(?i)com\.apple\.system\."), 95,
    match(process_name, "(?i)curl|wget|python|node|ruby|perl"), 85,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user file_path file_name process_name risk_score
```

### 5c. Python Runtime Fetched from astral-sh GitHub at Runtime (Staged Stealer Download)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query="objects.githubusercontent.com"
  OR DNS.query="github.com"
by DNS.src DNS.query DNS.answer DNS.process_name
| `drop_dm_object_name(DNS)`
| search process_name IN ("*Rust*","*cargo*") OR NOT process_name IN ("git","brew","mas","com.apple.dt.Xcode","softwareupdate")
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name, "(?i)python-build-standalone|astral-sh"), 90,
    NOT match(process_name, "(?i)git|brew|xcode|cursor|vscode|npm|yarn|pip"), 70,
    1=1, 45)
| where risk_score >= 70
| table firstTime lastTime src query answer process_name risk_score
```

### 5d. Non-Browser Process Connecting to Telegram Bot API (macOS C2 Beacon)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query="api.telegram.org"
by DNS.src DNS.query DNS.process_name
| `drop_dm_object_name(DNS)`
| search NOT process_name IN ("Telegram","telegram","TelegramDesktop")
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name, "(?i)launchd|systemd|cron|cfprefsd"), 90,
    NOT match(process_name, "(?i)telegram|signal|slack|discord"), 80,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime src query process_name risk_score
```

---

## 6. Executive Summary

On June 23, 2026, SentinelLABS researcher Phil Stokes disclosed **macOS.Gaslight**, a Rust-based macOS backdoor attributed with high confidence to a DPRK-aligned threat cluster (the BONZAI family). The sample was first uploaded to VirusTotal on May 22, 2026 and surfaced via an Apple XProtect update in early June 2026 under rule **MACOS_BONZAI_COBUCH**.

Gaslight combines three capabilities into a single Mach-O binary:

1. **Interactive shell C2** over the Telegram Bot API with AES-GCM encrypted payloads; the bot token is self-redacted from runtime logs to frustrate forensic recovery.
2. **Infostealer** using a staged Python 3.10 module (downloaded from `astral-sh/python-build-standalone` at runtime) that collects macOS Keychain, browser credentials (Chrome, Brave, Firefox, Safari), terminal command histories, installed applications, and system information, then exfiltrates via Telegram file upload.
3. **Prompt injection payload** — a 3.5 KB block of 38 fabricated LLM "system" messages embedded directly in the binary to confuse AI-assisted triage pipelines into aborting analysis. While not yet effective against production tools in testing, the escalation from 1 message (prior BONZAI samples) to 38 signals active iteration by DPRK operators against real-world AI security tooling.

Persistence is established via a LaunchAgent plist using the label `com.apple.system.services.activity`, which impersonates the Apple system service naming convention.

**Recommended actions:**
- Alert on LaunchAgent plist creation containing `com.apple.system.services.activity` or other `com.apple.system.*` patterns written by non-Apple processes.
- Alert on non-Telegram processes resolving `api.telegram.org`.
- Alert on processes fetching archives from `astral-sh/python-build-standalone` on GitHub outside of developer IDE workflows.
- Apply XProtect updates and ensure XProtect Remediator is enabled on all macOS endpoints.
- Review macOS endpoint telemetry for Keychain file access (`~/Library/Keychains/login.keychain-db`) by non-Apple processes.
