# ClickLock macOS GUI Input Capture via Browser Kill-Loop

## Description

Detects ClickLock, a macOS infostealer that uses a novel **process kill-loop** to coerce credential entry. After delivery via ClickFix social engineering (victim pastes a `curl | bash` command into Terminal), ClickLock installs two LaunchAgents: a watchdog daemon (`com.authirity.plist`) that continuously kills Safari, Chrome, Firefox, and other browsers until the user enters their login password into a fake macOS authentication dialog, and an exfiltration agent (`com.chromer.plist`) that sends harvested Keychain secrets and browser credentials to an attacker-controlled Telegram bot.

Primary false positive sources: legitimate software packaging scripts that briefly kill browsers during updates; MDM tools that push browser configuration changes. The combination of LaunchAgent creation from a shell process AND browser kill-loop activity together is very high confidence for ClickLock.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Input Capture: GUI Input Capture |
| Technique ID | T1056.002 |

**Secondary Techniques:**
- T1543.001 — Persistence: Launch Agent
- T1489 — Defense Evasion / Impact: Service Stop (browser kill-loop)
- T1555.001 — Credential Access: Keychain
- T1567 — Exfiltration: Exfiltration Over Web Service (Telegram Bot API)
- T1204.002 — Initial Access / Execution: User Execution (ClickFix delivery)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |
| Installation |
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path="*/Library/LaunchAgents/*.plist"
    AND (Filesystem.file_name IN ("com.authirity.plist","com.chromer.plist")
         OR Filesystem.process_name IN ("bash","sh","zsh","curl","python","python3","ruby","perl"))
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    file_name IN ("com.authirity.plist","com.chromer.plist"), 95,
    process_name IN ("bash","sh","zsh","curl") AND match(file_path,"LaunchAgents"), 80,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user file_path file_name process_name risk_score
```

**Supplemental — Browser Kill-Loop Detection:**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("kill","pkill","killall")
    AND (Processes.process IN ("*Safari*","*Chrome*","*Firefox*","*Chromium*","*Brave*","*Opera*"))
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process _time
| `drop_dm_object_name(Processes)`
| bucket _time span=2m
| stats count by dest user parent_process_name process_name _time
| where count >= 5
| eval risk_score=case(count >= 20, 90, count >= 10, 75, count >= 5, 60)
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table _time dest user parent_process_name process_name count risk_score
```

**Supplemental — Telegram Exfiltration from Non-Telegram Process:**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_host="api.telegram.org" AND All_Traffic.app!="Telegram"
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port
     All_Traffic.app All_Traffic.user All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(process_name IN ("bash","sh","zsh","curl","python","python3"), 90, 1=1, 70)
| where risk_score >= 70
| table firstTime lastTime src dest dest_host dest_port app process_name user risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Known ClickLock LaunchAgent filenames (`com.authirity.plist`, `com.chromer.plist`) | 95 | Exact IOC match — near-certain true positive |
| Shell/curl process writing any LaunchAgent plist | 80 | ClickFix delivery pattern; no legitimate installer delivers LaunchAgents via bare shell |
| 20+ browser kill commands in 2-minute window | 90 | Kill-loop rate indistinguishable from ClickLock's watchdog behavior |
| 10–19 browser kill commands in 2-minute window | 75 | High-rate kill pattern with few benign explanations |
| 5–9 browser kill commands in 2-minute window | 60 | Elevated kill rate; review for kill-loop context |
| Telegram API traffic from shell/curl/python process | 90 | Non-Telegram process reaching `api.telegram.org` — high-confidence exfil signal |
| Telegram API traffic from unrecognized process | 70 | Unrecognized process using Telegram Bot API for outbound communications |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| ClickLock Operators (Unknown) | [Group-IB — ClickLock macOS Stealer (2026-07-16)](https://www.group-ib.com/blog/clicklock-stealer-macos-malware/) |

## References

- [Group-IB — ClickLock macOS Stealer (2026-07-16)](https://www.group-ib.com/blog/clicklock-stealer-macos-malware/)
- [MITRE ATT&CK — T1056.002: GUI Input Capture](https://attack.mitre.org/techniques/T1056/002/)
- [MITRE ATT&CK — T1543.001: Launch Agent](https://attack.mitre.org/techniques/T1543/001/)
- [MITRE ATT&CK — T1489: Service Stop](https://attack.mitre.org/techniques/T1489/)
- [MITRE ATT&CK — T1555.001: Keychain](https://attack.mitre.org/techniques/T1555/001/)
- [MITRE ATT&CK — T1567: Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)
- [MITRE ATT&CK — T1204.002: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
