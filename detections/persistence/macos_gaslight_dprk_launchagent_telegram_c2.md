# macOS.Gaslight DPRK LaunchAgent Persistence and Telegram C2

## Description

Detects macOS.Gaslight, a Rust-compiled backdoor attributed with high confidence to a DPRK-aligned threat cluster (BONZAI family), via two primary detection angles:

1. **LaunchAgent persistence**: A plist file containing the label `com.apple.system.services.activity` — or any `com.apple.system.*`-prefixed label — written to `~/Library/LaunchAgents/` by a process other than Apple installers or `launchctl`. The label impersonates the Apple system service naming convention to blend in with legitimate LaunchDaemon labels.

2. **Telegram Bot API C2**: A non-Telegram application process resolving `api.telegram.org` via DNS. Gaslight polls the Telegram Bot API in a persistent loop to receive operator commands and upload collected files (macOS Keychain, browser credential databases, terminal histories) via the Telegram file-upload API. AES-GCM encrypted payloads with per-session nonces prevent passive decryption of traffic.

**False positives (LaunchAgent):** Legitimate developer tools or package managers (Homebrew, npm) occasionally write LaunchAgent plists, but they will not use `com.apple.system.*` labels. Other `com.apple.system.*`-labelled plists written by non-Apple processes should be treated as high-fidelity signals.

**False positives (Telegram C2):** Any macOS application that legitimately embeds Telegram Bot API calls (some notification/alerting tools) will trigger the non-Telegram C2 query. Enrich with the resolving process name and tune exclusions as needed for the environment.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Persistence |
| Tactic ID | TA0003 |
| Technique | Create or Modify System Process: Launch Agent |
| Technique ID | T1543.001 |
| Secondary Tactic | Command and Control |
| Secondary Technique | Web Service: Bidirectional Communication |
| Secondary Technique ID | T1102.002 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |
| Command & Control (C2) |

## Splunk Detection Query

### Query 1 — LaunchAgent Plist Written Outside Standard System Paths

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_path="*/Library/LaunchAgents/*.plist"
  AND NOT Filesystem.process_name IN ("installer", "pkgutil", "launchctl", "softwareupdate",
    "System Preferences", "SystemPreferences")
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
   Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_name, "(?i)com\.apple\.system\."), 95,
    match(process_name, "(?i)curl|wget|python|node|ruby|perl|bash|zsh|sh"), 85,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user file_path file_name process_name risk_score
```

### Query 2 — Specific Gaslight LaunchAgent Label (Unified Logging / osquery)

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

### Query 3 — Non-Browser Process Resolving Telegram Bot API (macOS C2 Beacon)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query="api.telegram.org"
by DNS.src DNS.query DNS.process_name
| `drop_dm_object_name(DNS)`
| search NOT process_name IN ("Telegram", "telegram", "TelegramDesktop")
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name, "(?i)launchd|cfprefsd|cron|bash|zsh|sh|python|ruby|perl|node"), 90,
    NOT match(process_name, "(?i)telegram|signal|slack|discord|electron"), 80,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime src query process_name risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| LaunchAgent plist named `com.apple.system.*` by non-Apple process | 95 | Gaslight-specific label; no legitimate software uses this pattern |
| LaunchAgent plist written by interpreter (curl, wget, python, bash, zsh) | 85 | Strong signal; package managers use their own binary names, not shell interpreters |
| Any LaunchAgent plist written by unlisted non-system process | 65 | Moderate baseline; catches novel variants with different labels |
| Non-Telegram process resolving api.telegram.org, system/interpreter process name | 90 | Highly suspicious; system daemons have no legitimate use for Telegram Bot API |
| Non-Telegram process resolving api.telegram.org, other non-messaging process | 80 | Suspicious; requires analyst review to rule out legitimate integrations |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| DPRK BONZAI cluster (macOS.Gaslight) | [SentinelLABS — macOS.Gaslight (2026-06-23)](https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/) |
| Lazarus Group (HIDDEN COBRA) | [MITRE ATT&CK G0032](https://attack.mitre.org/groups/G0032/) |
| BlueNoroff (DPRK financial sub-cluster) | [MITRE ATT&CK G0098](https://attack.mitre.org/groups/G0098/) |

## References

- [SentinelLABS — macOS.Gaslight: DPRK-Linked Rust Backdoor Embeds Prompt Injection Payload (2026-06-23)](https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/)
- [Apple XProtect MACOS_BONZAI_COBUCH rule — early June 2026 update]
- [MITRE ATT&CK T1543.001 — Create or Modify System Process: Launch Agent](https://attack.mitre.org/techniques/T1543/001/)
- [MITRE ATT&CK T1102.002 — Web Service: Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002/)
- [MITRE ATT&CK T1555.001 — Credentials from Password Stores: Keychain](https://attack.mitre.org/techniques/T1555/001/)
