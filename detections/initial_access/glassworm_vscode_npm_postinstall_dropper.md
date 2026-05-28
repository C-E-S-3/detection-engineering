# Glassworm-Style Developer Supply Chain: VSCode Extension and npm/pip Postinstall Dropper Execution

## Description

Detects package manager processes (npm, pip, pip3) or VS Code extension host processes spawning child processes that download or execute additional payloads — the primary delivery mechanism used by the Glassworm supply chain campaign (2025–2026) and the TeamPCP node-ipc compromise (May 2026). Legitimate package postinstall scripts rarely spawn curl, wget, PowerShell, or LOLBins during installation. When they do, it is a strong indicator of a malicious postinstall hook fetching and executing a stage-2 implant.

False positives: Build tools that compile native addons (node-gyp invoking make or msbuild), packages that fetch pre-built binaries on install (Puppeteer downloading Chromium, esbuild fetching its binary). Reduce false positives by maintaining an allowlist of known-good parent process command lines containing allowlisted package paths or build tool signatures.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Supply Chain Compromise: Compromise Software Dependencies and Development Tools |
| Technique ID | T1195.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.parent_process_name IN ("node.exe","node","npm","npm.cmd","pip","pip3","pip.exe",
      "python.exe","python3","python","code.exe","code","extensionHost.exe","extensionHost")
    AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","bash","sh","curl","curl.exe",
      "wget","wget.exe","mshta.exe","wscript.exe","cscript.exe","certutil.exe","bitsadmin.exe",
      "regsvr32.exe","rundll32.exe"))
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)(-enc|-encodedcommand|IEX|Invoke-Expression|FromBase64String)"), 90,
    match(process,"(?i)(DownloadString|DownloadFile|WebClient|Invoke-WebRequest)"), 87,
    match(process,"(?i)(curl|wget).+http"), 80,
    match(process_name,"(?i)(mshta|cscript|wscript|regsvr32|rundll32|certutil|bitsadmin)"), 82,
    match(process_name,"(?i)(bash|sh)") AND match(process,".*http.*"), 75,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Encoded PowerShell / IEX / FromBase64String in postinstall context | 90 | High-confidence malicious — legitimate build scripts never invoke encoded PS commands |
| .NET download cradle (WebClient, Invoke-WebRequest, DownloadString) | 87 | Strong indicator of stage-2 payload fetch; not used by legitimate install scripts |
| curl or wget fetching a URL | 80 | Common malicious postinstall pattern; node-gyp does not use curl in this way |
| LOLBin execution (mshta, cscript, regsvr32, certutil, bitsadmin) | 82 | Living-off-the-land; inconsistent with any legitimate package install script |
| Shell (bash/sh) spawning HTTP request | 75 | Suspicious; some legitimate packages use this for binary download but is infrequent |
| Any other match | 60 | Anomalous process lineage; warrants analyst review |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Glassworm | [CrowdStrike — Disrupting Glassworm (2026-05-26)](https://www.crowdstrike.com/en-us/blog/inside-crowdstrike-takedown-of-a-developer-targeting-botnet/) |
| TeamPCP (UNC6780) | [Socket.dev — node-ipc Compromise (2026-05-14)](https://socket.dev/blog/node-ipc-package-compromised), [Wiz — durabletask Wave 3 (2026-05-20)](https://www.wiz.io/blog/durabletask-teampcp-supply-chain-attack) |
| Unknown (Dohdoor/UAT-10027) | [Cisco Talos — Dohdoor Backdoor Campaign (2026-02)](https://blog.talosintelligence.com/new-dohdoor-malware-campaign/) |

## References

- [CrowdStrike — Disrupting Glassworm: Inside CrowdStrike's Takedown of a Developer-Targeting Botnet](https://www.crowdstrike.com/en-us/blog/inside-crowdstrike-takedown-of-a-developer-targeting-botnet/)
- [Aikido — GlassWorm Goes Native: New Zig Dropper Infects Every IDE on Your Machine](https://www.aikido.dev/blog/glassworm-zig-dropper-infects-every-ide-on-your-machine)
- [Socket.dev — node-ipc npm Package Compromised (2026-05-14)](https://socket.dev/blog/node-ipc-package-compromised)
- [MITRE ATT&CK — T1195.001 Supply Chain Compromise: Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001/)
- [CISA KEV — CVE-2026-48027 Nx Console Embedded Malicious Code (2026-05-27)](https://www.cisa.gov/news-events/alerts/2026/05/27/cisa-adds-three-known-exploited-vulnerabilities-catalog)
