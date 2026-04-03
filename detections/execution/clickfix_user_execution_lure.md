# ClickFix / Fake CAPTCHA User Execution Lure

## Description

Detects ClickFix and fake CAPTCHA social engineering attacks that trick users into pasting and executing PowerShell or mshta commands directly from the Windows Run dialog (Win+R) or browser address bar. These attacks display a fake CAPTCHA verification, browser update notice, or document preview page that instructs the user to copy a command to their clipboard and run it. This technique bypasses email security gateways because no malicious attachment or link is delivered — the user types or pastes the payload themselves. According to Blackpoint Cyber's 2026 Annual Threat Report, social engineering lures of this type appear in 57.5% of intrusions. The resulting process tree is distinctive: PowerShell or mshta spawned directly from explorer.exe (Windows Run dialog), a browser process (Chrome/Edge/Firefox), or cmd.exe with a minimal command line. Common false positive sources: IT helpdesk scripts shared via internal wikis that admins paste into Run; power users testing PowerShell one-liners; software installers using Run dialog.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | User Execution: Malicious File |
| Technique ID | T1204.002 |

Secondary techniques: T1059.001 (PowerShell), T1218.005 (mshta), T1566.002 (Spearphishing Link — ClickFix delivered via malicious website or watering hole)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("explorer.exe","chrome.exe","msedge.exe",
      "firefox.exe","iexplore.exe","opera.exe","brave.exe","vivaldi.exe")
    AND Processes.process_name IN ("powershell.exe","pwsh.exe","mshta.exe","wscript.exe",
        "cscript.exe","cmd.exe","rundll32.exe","regsvr32.exe","msiexec.exe",
        "certutil.exe","bitsadmin.exe","curl.exe","wget.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| eval risk_score=case(
    match(process_name, "(?i)mshta") AND match(parent_process_name, "(?i)chrome|edge|firefox"), 95,
    match(process_name, "(?i)powershell|pwsh") AND match(process, "(?i)-enc|-encodedcommand"), 92,
    match(process_name, "(?i)powershell|pwsh") AND match(process, "(?i)-w hidden|-windowstyle h|-nop|-exec bypass"), 90,
    match(process_name, "(?i)powershell|pwsh") AND match(parent_process_name, "(?i)chrome|edge|firefox|explorer"), 85,
    match(process_name, "(?i)certutil|bitsadmin") AND match(process, "(?i)http"), 85,
    match(process_name, "(?i)mshta") AND match(parent_process_name, "(?i)explorer"), 88,
    match(process_name, "(?i)wscript|cscript") AND match(parent_process_name, "(?i)chrome|edge|firefox|explorer"), 80,
    1=1, 60)
| where risk_score >= 80
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

**Supplemental: PowerShell downloading content immediately after Run dialog execution (stage 2 beacon)**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("powershell.exe","pwsh.exe","cmd.exe")
    AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","curl.exe","wget.exe",
        "certutil.exe","bitsadmin.exe","mshta.exe","rundll32.exe","regsvr32.exe")
    AND (match(Processes.process, "(?i)invoke-webrequest|iwr|invoke-expression|iex|downloadstring|downloadfile|webclient|net\.http|start-bitstransfer")
         OR match(Processes.process, "(?i)-enc|-encodedcommand|-w hidden|-windowstyle"))
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| eval risk_score=case(
    match(process, "(?i)iex.*downloadstring|invoke-expression.*downloadstring"), 97,
    match(process, "(?i)-enc.*[A-Za-z0-9+/]{100,}"), 92,
    match(process, "(?i)invoke-webrequest.*http|iwr.*http"), 88,
    match(process, "(?i)downloadfile|downloadstring"), 88,
    1=1, 75)
| where risk_score >= 88
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

**Supplemental: Clipboard content execution pattern — short-dwell mshta/PowerShell with no ancestor chain**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("powershell.exe","pwsh.exe","mshta.exe")
    AND Processes.parent_process_name="explorer.exe"
  by Processes.dest Processes.user Processes.process_name Processes.process
     Processes.process_id
| `drop_dm_object_name(Processes)`
| eval cmd_length=len(process)
| where cmd_length > 200
| eval risk_score=case(
    match(process, "(?i)-enc") AND cmd_length > 500, 95,
    match(process, "(?i)http") AND cmd_length > 100, 90,
    match(process, "(?i)-nop|-noprofile|-w hidden|-exec bypass"), 88,
    cmd_length > 300, 82,
    1=1, 75)
| where risk_score >= 82
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user process_name process cmd_length risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| mshta spawned by browser process | 95 | Near-certain ClickFix execution; no legitimate web browsing generates mshta child processes |
| PowerShell IEX DownloadString in command line | 97 | Canonical fileless payload execution; used in virtually every ClickFix stage-2 download |
| PowerShell -encoded with 100+ char B64 blob | 92 | Obfuscated payload; combined with browser/explorer parent = high confidence ClickFix |
| PowerShell/mshta spawned by explorer.exe with long command | 88-90 | Windows Run dialog execution; ClickFix copies the full command to clipboard for Win+R paste |
| Encoded/download PowerShell from cmd parent | 75-88 | Stage-2 of ClickFix chain; cmd.exe sometimes acts as intermediate for obfuscation |

## Associated Threat Actors

| Actor | Relationship to Detection |
|-------|--------------------------|
| Various cybercrime groups (Scattered Spider, EvilCorp affiliates) | ClickFix and fake CAPTCHA widely adopted across threat landscape; 57.5% of intrusions (Blackpoint 2026) |
| Qilin Ransomware Affiliates | Use ClickFix-style browser lures for initial access before ransomware deployment |
| Scattered Spider (UNC3944) | Combine ClickFix with help desk social engineering for credential theft and RMM deployment |
| EvilTokens / Storm-237 | Pairing ClickFix lures with OAuth device code phishing for combined web session and cloud token theft |

## References

- [Blackpoint Cyber - 2026 Annual Threat Report](https://blackpointcyber.com/resources/reports/2026-annual-threat-report/)
- [BleepingComputer - ClickFix Social Engineering Coverage](https://www.bleepingcomputer.com/news/security/routine-access-is-powering-modern-intrusions-a-new-threat-report-finds/)
- [MITRE ATT&CK - T1204.002 User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK - T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK - T1218.005 System Binary Proxy Execution: Mshta](https://attack.mitre.org/techniques/T1218/005/)
