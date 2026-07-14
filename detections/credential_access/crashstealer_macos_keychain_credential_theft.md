# CrashStealer macOS Keychain Credential Theft

## Description

Detects CrashStealer, a native C++ macOS infostealer that targets the macOS Keychain and browser credentials. CrashStealer is distinguished by its Apple Developer notarization (bypassing Gatekeeper), PIN-gated delivery via `werkbit[.]io`, and a masquerade as Apple's CrashReporter framework. After installation it writes a LaunchAgent plist for persistence and exfiltrates AES-GCM encrypted data to `endpoint-api-v1[.]com` via libcurl HTTP POST.

Three detection surfaces are covered:

1. **DNS/network connections to delivery or C2 domains** — `werkbit[.]io` (delivery) and `endpoint-api-v1[.]com` (exfiltration). No legitimate macOS software uses either domain.
2. **`codesign` execution touching CrashReporter or LaunchAgents paths** — the malware re-signs itself after copying to a CrashReporter-mimicking path; `codesign` invocations involving these paths from non-system parent processes are highly suspicious.
3. **LaunchAgent plist creation by unexpected processes** — CrashStealer installs persistence via `~/Library/LaunchAgents/`; plist writes by processes other than known Apple management tools warrant investigation, particularly when the file path contains `CrashReporter`.

False positives for the LaunchAgent detection: legitimate developer tools (Homebrew, some IDEs) can write LaunchAgents; tune the process exclusion list per environment. The domain detections have no expected false positives.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| **Tactic** | Credential Access (TA0006) |
| **Primary Technique** | T1555.001 — Credentials from Password Stores: Keychain |
| **Secondary Techniques** | T1005 — Data from Local System; T1041 — Exfiltration Over C2 Channel |
| **Supporting Techniques** | T1547.011 — Boot or Logon Autostart Execution: Plist Modification; T1553.002 — Subvert Trust Controls: Code Signing; T1036.005 — Masquerading: Match Legitimate Name or Location |

## Lockheed Martin Kill Chain Phase

**Actions on Objectives** (Keychain credential theft, data exfiltration)
**Installation** (LaunchAgent plist persistence)
**Command & Control (C2)** (libcurl POST to `endpoint-api-v1[.]com`)

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN ("werkbit.io","endpoint-api-v1.com")
by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src query answer risk_score
```

```spl
index=* (dest="werkbit.io" OR dest="endpoint-api-v1.com")
| stats count min(_time) as firstTime max(_time) as lastTime by src dest dest_port
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src dest dest_port risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="codesign"
  AND (Processes.process="*CrashReporter*" OR Processes.process="*LaunchAgents*")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_path="*/Library/LaunchAgents/*"
  AND (Filesystem.process_name!="launchctl" AND Filesystem.process_name!="installer"
       AND Filesystem.process_name!="softwareupdate" AND Filesystem.process_name!="mdmclient")
by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path,"CrashReporter"), 90,
    1=1, 50
  )
| where risk_score >= 50
| table firstTime lastTime dest user file_name file_path process_name risk_score
```

## Risk Score Logic

| Score | Condition |
|-------|-----------|
| 95 | DNS resolution or network connection to `werkbit[.]io` or `endpoint-api-v1[.]com` |
| 90 | LaunchAgent plist written by non-system process with `CrashReporter` in the path |
| 75 | `codesign` execution with `CrashReporter` or `LaunchAgents` in the command arguments from a non-Apple parent |
| 50 | LaunchAgent plist written by any unexpected process (no CrashReporter path match) |

## Associated Threat Actors

| Actor | Notes |
|-------|-------|
| Unknown | CrashStealer has not been attributed to a known threat group as of July 2026. The PIN-gated delivery mechanism suggests targeted distribution rather than mass deployment. The Developer ID `Emil Grigorov (WWB7JA7AQV)` may be a fraudulently obtained or compromised Apple Developer certificate. |

## References

- [Jamf Threat Labs — CrashStealer macOS Infostealer (2026-07-13)](https://www.jamf.com/blog/crashstealer-macos-infostealer/)
- [BleepingComputer — CrashStealer (2026-07-13)](https://www.bleepingcomputer.com/news/security/new-crashstealer-macos-malware-steals-passwords-using-fake-crashreporter/)
- [The Hacker News — CrashStealer (2026-07-13)](https://thehackernews.com/2026/07/crashstealer-macos-malware-impersonates.html)
- [MITRE ATT&CK T1555.001 — Credentials from Password Stores: Keychain](https://attack.mitre.org/techniques/T1555/001/)
- [MITRE ATT&CK T1547.011 — Boot or Logon Autostart Execution: Plist Modification](https://attack.mitre.org/techniques/T1547/011/)
- [MITRE ATT&CK T1036.005 — Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)
- [MITRE ATT&CK T1553.002 — Subvert Trust Controls: Code Signing](https://attack.mitre.org/techniques/T1553/002/)
