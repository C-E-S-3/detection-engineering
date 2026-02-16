# Godloader Legitimate Web Service Payload Delivery

## Description

Godloader uses legitimate web services -- specifically Bitbucket, GitHub, and Pastebin -- to host and deliver second-stage payloads and configuration files, avoiding the need for dedicated attacker-controlled C2 infrastructure. After initial execution via the Godot Engine loader, PowerShell downloads executables from Bitbucket repositories and retrieves XMRig mining configurations from Pastebin.

This detection identifies non-browser processes making HTTP/HTTPS requests to code hosting and paste services to download executable content. While developers and automation tools legitimately access these services, direct binary downloads initiated by PowerShell, cmd.exe, or unsigned executables from user-writable paths are strong indicators of malicious payload retrieval.

The Stargazers Ghost Network (operated by Stargazer Goblin) uses approximately 200 GitHub repositories and 225+ fake accounts to distribute malicious archives, and stages follow-on payloads on Bitbucket.

False positive sources: Developer tooling, package managers (pip, npm, cargo), CI/CD pipelines, and legitimate automation scripts that download from GitHub/Bitbucket. Tuning: whitelist known build service accounts, developer workstations, and established automation user-agents.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Web Service: Bidirectional Communication |
| Technique ID | T1102.002 |
| Secondary Technique | Ingress Tool Transfer (T1105) |
| Secondary Tactic | Initial Access (TA0001) - User Execution: Malicious File (T1204.002) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) |
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where Web.url IN ("*bitbucket.org*", "*raw.githubusercontent.com*", "*github.com*", "*pastebin.com/raw*", "*paste.ee/r/*")
    AND NOT Web.process_name IN ("chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "brave.exe", "opera.exe",
        "git.exe", "git-remote-https.exe", "gh.exe",
        "pip.exe", "pip3.exe", "npm.exe", "node.exe", "cargo.exe", "go.exe",
        "Code.exe", "devenv.exe")
by Web.dest Web.user Web.process_name Web.url Web.http_method Web.status
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(url, "(?i)\.(exe|dll|scr|bat|ps1|msi)(\?|$)"), 90,
    match(process_name, "(?i)(powershell|pwsh|cmd|wscript|cscript|mshta)\.exe$"), 85,
    match(url, "(?i)pastebin\.com/raw"), 80,
    match(url, "(?i)bitbucket\.org.*/downloads/"), 75,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user process_name url http_method status risk_score
```

### Supplemental Query: PowerShell Download Cradle to Code Hosting

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("powershell.exe", "pwsh.exe")
    AND (Processes.process="*bitbucket.org*"
         OR Processes.process="*raw.githubusercontent.com*"
         OR Processes.process="*pastebin.com*")
    AND (Processes.process="*Invoke-WebRequest*"
         OR Processes.process="*DownloadFile*"
         OR Processes.process="*DownloadString*"
         OR Processes.process="*Start-BitsTransfer*"
         OR Processes.process="*Net.WebClient*"
         OR Processes.process="*iwr *"
         OR Processes.process="*curl *"
         OR Processes.process="*wget *")
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)\.(exe|dll|scr)") AND match(process, "(?i)bitbucket\.org"), 95,
    match(process, "(?i)pastebin\.com"), 90,
    match(process, "(?i)raw\.githubusercontent\.com"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| PowerShell downloading .exe/.dll from Bitbucket | 95 | Exact Godloader payload delivery pattern |
| PowerShell fetching content from Pastebin | 90 | Godloader retrieves XMRig mining config from Pastebin |
| PowerShell downloading from raw.githubusercontent.com | 85 | GitHub-hosted payloads associated with Stargazers Ghost Network |
| Non-browser process requesting executable files from code hosting | 90 | Binary downloads from web services by system processes are anomalous |
| Script interpreter (PowerShell/cmd/wscript) accessing code hosting | 85 | Script-based downloads from these services warrant investigation |
| Pastebin raw content access by non-browser | 80 | Pastebin raw endpoint commonly used for config/payload retrieval |
| Bitbucket downloads path access by non-browser | 75 | Less specific but still unusual for non-development processes |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Stargazer Goblin (Stargazers Ghost Network) | [Check Point - Stargazers Ghost Network](https://research.checkpoint.com/2024/stargazers-ghost-network/) |
| Godloader / GodLoader | [Check Point - Gaming Engines: An Undetected Playground for Malware Loaders](https://research.checkpoint.com/2024/gaming-engines-an-undetected-playground-for-malware-loaders/) |

## References

- [Check Point Research - Gaming Engines: An Undetected Playground for Malware Loaders](https://research.checkpoint.com/2024/gaming-engines-an-undetected-playground-for-malware-loaders/)
- [Check Point Research - Stargazers Ghost Network](https://research.checkpoint.com/2024/stargazers-ghost-network/)
- [The Hacker News - Stargazer Goblin Creates 3,000 Fake GitHub Accounts for Malware Spread](https://thehackernews.com/2024/07/stargazer-goblin-creates-3000-fake.html)
- [BleepingComputer - Hackers Abuse Popular Godot Game Engine to Infect Thousands of PCs](https://www.bleepingcomputer.com/news/security/new-godloader-malware-infects-thousands-of-gamers-using-godot-scripts/)
