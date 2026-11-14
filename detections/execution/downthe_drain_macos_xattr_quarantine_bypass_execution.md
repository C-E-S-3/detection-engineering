# DownTheDRAIN macOS Infostealer — Gatekeeper Bypass via xattr Quarantine Removal and trustd Masquerade

## Description

Detects the DownTheDRAIN macOS Go-based infostealer delivered by the Macfinger ClickFix campaign (SANS ISC, November 13, 2026). The malware is delivered via a fake CAPTCHA that lures users into Terminal to run a shell command fetching the payload from `45.150.32[.]130`. Key detection opportunities include: xattr quarantine attribute removal (Gatekeeper bypass), creation of a directory named to impersonate the macOS `trustd` system daemon, and writing a file named `com.apple.verified` to that directory. The malware also harvests browser credentials, Keychain data, and crypto wallet contents, and hijacks clipboard cryptocurrency addresses.

Distinct from earlier macOS ClickFix campaigns delivering AMOS/MacSync (which use SVS-based delivery domains and DMG mount chains). Do not conflate `45.150.32[.]130` with AMOS-linked infrastructure.

False positives: `xattr -d com.apple.quarantine` is legitimately run by developers testing apps and by some software installers. Tune by context: execution from Terminal.app after a web browsing session by a non-developer user is high-confidence.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | User Execution: Malicious File |
| Technique ID | T1204.002 |

Secondary techniques: T1553.001 (Subvert Trust Controls: Gatekeeper Bypass), T1036.004 (Masquerade Task or Service — `trustd` impersonation), T1555.001 (Keychain credential access), T1555.003 (Browser credential access), T1115 (Clipboard Data — crypto address hijacking).

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

**Rule 1 — xattr Quarantine Removal Executed from Shell in User Context**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="xattr"
  AND Processes.process="*-d com.apple.quarantine*"
  AND Processes.parent_process_name IN ("bash", "zsh", "sh", "Terminal", "osascript", "python3", "python")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(lower(parent_process_name), "terminal"), 85,
    match(lower(parent_process_name), "(bash|zsh|sh)"), 75,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

**Rule 2 — Directory or File Creation Masquerading as Apple System Components in Non-System Paths**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where (Filesystem.file_name="com.apple.verified" OR Filesystem.file_path="*/trustd/*")
  AND NOT (Filesystem.file_path="/usr/libexec/trustd*" OR Filesystem.file_path="/System/*")
by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    file_name="com.apple.verified" AND match(file_path, "(Library|tmp|var)"), 95,
    match(file_path, "*/trustd/*") AND NOT match(file_path, "/(usr|System)/"), 90,
    1=1, 80)
| where risk_score >= 80
| table firstTime lastTime dest user process_name file_name file_path risk_score
```

**Rule 3 — Network IOC: Connection to Known DownTheDRAIN Delivery Server**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_ip="45.150.32.130"
by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src_ip dest_ip dest_port app risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| xattr quarantine removal from Terminal parent | 85 | ClickFix social engineering lures target non-technical macOS users via Terminal |
| xattr quarantine removal from shell parent | 75 | May be scripted delivery; warrants investigation |
| `com.apple.verified` file created outside system paths | 95 | No legitimate Apple software creates this filename outside system directories |
| `trustd`-named directory created outside `/usr/libexec` | 90 | Direct impersonation of macOS system trust daemon |
| Connection to 45.150.32[.]130 | 95 | Confirmed DownTheDRAIN delivery server; Macfinger campaign Nov 2026 |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Macfinger ClickFix campaign operators (unattributed) | [SANS ISC — Macfinger ClickFix DownTheDRAIN (Nov 13, 2026)](https://isc.sans.edu/diaryarchive.html) |

## References

- [SANS ISC — Macfinger ClickFix DownTheDRAIN macOS Infostealer (Nov 13, 2026)](https://isc.sans.edu/diaryarchive.html)
- [Daily Security Review — ClickFix Campaign Pushes Go-Based macOS Crypto Drainer](https://dailysecurityreview.com/phishing/clickfix-campaign-pushes-go-based-macos-crypto-drainer/)
- [ThreatPulse — ClickFix macOS Infostealer Campaign](https://threatpulse.dev/threats/clickfix-macos-infostealer-go-based-crypto-credential-theft-campaign)
- [MITRE ATT&CK — T1553.001 Gatekeeper Bypass](https://attack.mitre.org/techniques/T1553/001/)
- [MITRE ATT&CK — T1036.004 Masquerade Task or Service](https://attack.mitre.org/techniques/T1036/004/)
