# Malicious Browser Extension Native Messaging Host Registration (Edgecution / Payouts Kings)

## Description

Detects adversaries abusing the Chrome/Edge Native Messaging protocol to bridge a sandboxed browser extension to a host-level backdoor process, bypassing the browser sandbox without exploiting any vulnerability. Edgecution (discovered by Zscaler ThreatLabz, June 2026) uses this technique: a malicious Microsoft Edge extension registers a Python script as a Chrome Native Messaging host under `SOFTWARE\Microsoft\NativeMessagingHosts\` in the Windows registry, then relays commands from an attacker-controlled WebSocket C2 through the extension to the Python process for host OS execution.

Normal Chrome Native Messaging hosts are installed by legitimate applications (e.g., password managers, remote desktop tools) to user-writable profile directories (`%APPDATA%\...`) or to `%ProgramFiles%`. The key detection signals are:
1. Native Messaging host registry keys referencing user-writable paths (AppData, Temp, Downloads) rather than Program Files — characteristic of attacker-deployed hosts
2. `msedge.exe` or `chrome.exe` spawning Python or other interpreter child processes via the native messaging subprocess mechanism
3. New Native Messaging host manifests written by processes other than the browser itself

False positives: Legitimate Chrome Native Messaging hosts are installed by enterprise software (1Password, Bitwarden, Remote Desktop clients, print drivers). Focus suppression on manifests written by `msiexec.exe`, `setup.exe`, or signed vendor installers pointing to `%ProgramFiles%`. Alert on unsigned hosts or hosts pointing to `%APPDATA%`, `%TEMP%`, or `%USERPROFILE%\Downloads`.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Persistence |
| Tactic ID | TA0003 |
| Technique | Browser Extensions |
| Technique ID | T1176 |
| Secondary Tactic | Execution |
| Secondary Tactic ID | TA0002 |
| Secondary Technique | Inter-Process Communication |
| Secondary Technique ID | T1559 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Registry
  where Registry.registry_path IN (
      "*\\SOFTWARE\\Google\\Chrome\\NativeMessagingHosts\\*",
      "*\\SOFTWARE\\Microsoft\\Edge\\NativeMessagingHosts\\*",
      "*\\SOFTWARE\\Chromium\\NativeMessagingHosts\\*",
      "*\\SOFTWARE\\Mozilla\\NativeMessagingHosts\\*")
    AND (Registry.registry_value_data="*AppData*"
      OR Registry.registry_value_data="*\\Temp\\*"
      OR Registry.registry_value_data="*\\Downloads\\*"
      OR Registry.registry_value_data="*\\Desktop\\*"
      OR Registry.registry_value_data="*python*"
      OR Registry.registry_value_data="*\\Users\\*\\Documents\\*"
      OR Registry.registry_value_data="*\\ProgramData\\*")
  by Registry.dest Registry.user Registry.registry_path Registry.registry_value_data Registry.process_name
| `drop_dm_object_name(Registry)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(registry_value_data, "(?i)python"), 90,
    match(registry_value_data, "(?i)(\\\\Temp\\\\|\\\\AppData\\\\Local\\\\Temp\\\\)"), 90,
    match(registry_value_data, "(?i)(\\\\Downloads\\\\|\\\\Desktop\\\\)"), 80,
    match(registry_value_data, "(?i)(AppData|ProgramData)"), 75,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user registry_path registry_value_data process_name risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("msedge.exe","chrome.exe","msedgewebview2.exe","chromium.exe")
    AND Processes.process_name IN ("python.exe","python3.exe","pythonw.exe","cmd.exe","powershell.exe","wscript.exe","cscript.exe","node.exe","bun.exe","deno.exe")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name, "(?i)(python|bun|deno)"), 90,
    match(process_name, "(?i)(powershell|wscript|cscript)"), 80,
    match(process_name, "(?i)(cmd|node)"), 70,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Native Messaging host path references python executable | 90 | Edgecution IoC; no legitimate app registers Python as a native messaging host |
| Native Messaging host path points to %TEMP% | 90 | High-confidence malicious; legitimate installs never use Temp directories |
| Native Messaging host path points to Downloads or Desktop | 80 | Very suspicious; indicates manual/attacker drop |
| Native Messaging host path in AppData or ProgramData | 75 | Elevated; legitimate apps may use AppData, but warrants review |
| msedge.exe spawning python.exe | 90 | Direct Edgecution IoC; browsers do not normally spawn Python |
| msedge.exe spawning PowerShell or wscript | 80 | Suspicious; could indicate native messaging host execution of attacker commands |
| msedge.exe spawning cmd.exe or node.exe | 70 | Less specific; development tooling may produce this, but warrants investigation |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Payouts Kings | [Zscaler ThreatLabz: Edgecution Research (2026-06)](https://www.zscaler.com/blogs/security-research/payouts-king-ransomware-initial-access-broker-deploys-new-edgecution) |
| Generic IAB activity | [MITRE ATT&CK T1176 - Browser Extensions](https://attack.mitre.org/techniques/T1176/) |

## References

- [Zscaler ThreatLabz: Payouts King IAB Deploys Edgecution via Malicious Edge Extension (2026-06)](https://www.zscaler.com/blogs/security-research/payouts-king-ransomware-initial-access-broker-deploys-new-edgecution)
- [BleepingComputer: Malicious Edge Extension Abuses Native Messaging as Bridge to Malware](https://www.bleepingcomputer.com/news/security/malicious-edge-extension-abuses-native-messaging-as-bridge-to-malware/)
- [MITRE ATT&CK T1176 - Browser Extensions](https://attack.mitre.org/techniques/T1176/)
- [MITRE ATT&CK T1559 - Inter-Process Communication](https://attack.mitre.org/techniques/T1559/)
- [Google Chrome Native Messaging Protocol](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
- [Threat Intel Report: 2026-06-24_zscaler-threatlabz-edgecution-payouts-king-edge-extension-backdoor.md](../threat-intel/2026-06-24_zscaler-threatlabz-edgecution-payouts-king-edge-extension-backdoor.md)
