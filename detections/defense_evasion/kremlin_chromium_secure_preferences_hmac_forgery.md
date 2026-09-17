# KREMLIN Chromium Secure Preferences HMAC Forgery for Forced Extension Install

## Description

Detects PowerShell manipulating Chromium browser profile Secure Preferences files or recomputing HMAC-SHA256 integrity values, consistent with the KREMLIN banking malware technique (Elastic REF9334) that force-installs a malicious Chrome/Edge browser extension without user consent.

Chromium-based browsers compute an HMAC-SHA256 integrity check over the `Secure Preferences` file (which stores extension allow-list settings) using a machine-specific key. When an extension is added externally — bypassing normal browser extension installation flows — the browser detects tampering and alerts the user or disables the extension. KREMLIN includes a PowerShell component that recomputes this HMAC with the correct key after injecting the malicious extension ID, preventing the alert. This technique had not been publicly documented in active malware prior to the September 2026 Elastic report.

Also detects the associated DLL side-loading component: `SentinelMemoryScanner.exe` executing from non-standard paths or with unusual parents, indicating the attacker planted a malicious `SentinelAgentCore.dll` adjacent to the legitimate SentinelOne binary.

**Expected false positives:** Enterprise browser management tools (Google Admin, Intune) may legitimately manage extension policy via registry Group Policy rather than directly modifying `Secure Preferences`. Review the parent process and deployment context. Direct HMAC manipulation of `Secure Preferences` by a script process has essentially no legitimate use case.

## MITRE ATT&CK Mapping

- **Tactic:** Defense Evasion (TA0005)
- **Technique:** T1176 — Browser Extensions
- **Secondary Tactic:** Defense Evasion (TA0005)
- **Secondary Technique:** T1574.002 — Hijack Execution Flow: DLL Side-Loading
- **Secondary Tactic:** Persistence (TA0003)
- **Secondary Technique:** T1176 — Browser Extensions

## Lockheed Martin Kill Chain Phase

- Installation (persistence via browser extension)
- Exploitation (defense evasion via HMAC forgery and DLL side-loading)

## Splunk SPL Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("powershell.exe","pwsh.exe")
    AND (Processes.process="*Secure Preferences*"
         OR Processes.process="*secure_preferences*"
         OR Processes.process="*ChromeExtension*"
         OR Processes.process="*extension_settings*"
         OR Processes.process="*hmac*sha256*"
         OR Processes.process="*ForceInstall*"
         OR Processes.process="*ExtensionInstallForceList*")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)(hmac|sha256|integrity)"), 95,
    match(process,"(?i)(SecurePreferences|secure_preferences)"), 90,
    match(process,"(?i)(ForceInstall|ExtensionInstallForceList)"), 80,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="SentinelMemoryScanner.exe"
    AND NOT Processes.parent_process_name IN ("SentinelAgent.exe","SentinelServiceHost.exe","SentinelUI.exe","msiexec.exe","services.exe")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_name="SentinelAgentCore.dll"
    AND NOT Filesystem.file_path IN ("*\\Program Files\\SentinelOne\\*","*\\ProgramData\\Sentinel\\*")
by Filesystem.dest Filesystem.user Filesystem.process_name
   Filesystem.file_name Filesystem.file_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path,"(?i)(\\\\AppData\\\\|\\\\Temp\\\\|\\\\ProgramData\\\\(?!Sentinel))"), 95,
    match(file_path,"(?i)\\\\Users\\\\"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user process_name file_name file_path action risk_score
```

## Risk Score Logic

| Score | Condition |
|-------|-----------|
| 95 | PowerShell referencing HMAC/SHA256/integrity in context of browser preferences — very high specificity for KREMLIN installer |
| 90 | PowerShell referencing `Secure Preferences` or `secure_preferences` file — no legitimate script use case |
| 85 | `SentinelMemoryScanner.exe` with anomalous parent — DLL side-loading indicator |
| 80 | PowerShell referencing Chrome `ForceInstallList` or similar extension policy terms |

## Associated Threat Actors

| Actor | Malware | Campaign | Reference |
|-------|---------|----------|-----------|
| REF9334 (unnamed Brazilian financial threat cluster) | KREMLIN | Brazilian banking trojan targeting 12 banks; 1,515 hosts; active May 2025–present | [Elastic Security Labs REF9334](https://www.elastic.co/security-labs/kremlin-browser-extension-banking-malware) |

## References

- [Elastic Security Labs — KREMLIN / REF9334 Analysis](https://www.elastic.co/security-labs/kremlin-browser-extension-banking-malware)
- [MITRE ATT&CK — T1176 Browser Extensions](https://attack.mitre.org/techniques/T1176/)
- [MITRE ATT&CK — T1574.002 DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- [Chromium Source — Secure Preferences integrity check implementation](https://source.chromium.org/chromium/chromium/src/+/main:chrome/browser/prefs/chrome_pref_service_factory.cc)
