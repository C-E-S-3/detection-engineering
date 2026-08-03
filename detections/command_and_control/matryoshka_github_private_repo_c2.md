# Matryoshka — Private GitHub Repository C2 Dead Drop

## Description

Detects command-and-control traffic routed through private GitHub repositories, consistent with the Matryoshka Rust backdoor (HollowFrame campaign, Group-IB 2026-07-31) and other malware families that abuse GitHub's API as a C2 dead drop. Matryoshka issues commands by committing content to a private repository; the implant polls `api.github.com` for new commits and exfiltrates results back via repository file writes.

This detection identifies non-browser, non-developer processes establishing HTTPS connections to `api.github.com` or reading from `raw.githubusercontent.com`. In most enterprise environments, especially professional services and legal firms (primary Matryoshka targets), GitHub API calls from non-developer workstations are rare and high-fidelity indicators.

False positives include CI/CD agents, developer tools (git.exe, GitHub Desktop, VS Code source control), security scanners that check GitHub advisories, and endpoint agents that download updates from GitHub Releases. Baseline and exclude known developer workstations, build servers, and software update processes. The `process_name` exclusion list below covers common legitimate cases; adjust per environment.

This detection also covers other malware families that have adopted GitHub as a C2 medium, including SmartLoader (GitHub release staging) and portions of the Glassworm botnet.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Web Service: Dead Drop Resolver |
| Technique ID | T1102.001 |

Secondary: T1105 (Ingress Tool Transfer — payload download from GitHub releases), T1074 (Data Staged), T1059 (Command and Scripting Interpreter — commands received via repo)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where
    (All_Traffic.dest_host="api.github.com"
     OR All_Traffic.dest_host="raw.githubusercontent.com"
     OR All_Traffic.dest_host="github.com")
    AND All_Traffic.dest_port=443
  by All_Traffic.src All_Traffic.user All_Traffic.process All_Traffic.dest_host
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval is_known_legitimate=case(
    match(process, "(?i)(git\.exe|GitHub Desktop|code\.exe|idea\.exe|pycharm|eclipse|intellij|gradle|maven|npm|node\.exe|python\.exe|curl\.exe|wget|gh\.exe|runner\.exe|actions-runner|jenkins|bamboo|teamcity|renovate|snyk|dependabot|chromium|chrome|firefox|msedge|iexplore)"), 1,
    true(), 0
  )
| where is_known_legitimate=0
| eval risk_score=case(
    match(process, "(?i)(powershell|cmd\.exe|wscript|cscript|mshta|regsvr32|rundll32|certutil)"), 95,
    match(process, "(?i)(python\.exe|pythonw\.exe|lua|luajit|perl|ruby|php)"), 90,
    match(process, "(?i)(word|excel|outlook|winword|powerpnt|acrobat|acrord32)"), 95,
    true(), 75
  )
| where risk_score >= 75
| table src user process dest_host firstTime lastTime risk_score count
```

## Risk Score Logic

| Score | Condition |
|-------|-----------|
| 95 | GitHub API connection from living-off-the-land binary (PowerShell, cmd, mshta, certutil, regsvr32) or Office application |
| 90 | GitHub API connection from script interpreter (Python, Lua, Perl) — consistent with HollowFrame Python-sideloaded Matryoshka |
| 75 | GitHub API connection from any unrecognized process not in developer/CI exclusion list |

## Associated Threat Actors

| Actor | Notes |
|-------|-------|
| HollowFrame / Matryoshka campaign (Unattributed) | Go loader + Rust backdoor targeting law firms via spear-phishing LNK; GitHub private repo variant of Matryoshka uses GitHub API for two-way C2; Group-IB July 2026 |
| SmartLoader Gang (FakeGit) | Abuses public GitHub repositories for payload staging; detected by Godloader and SmartLoader existing detections; GitHub private repo C2 is a newer and stealthier variant |

## References

- [Group-IB — HollowFrame & Matryoshka: Novel Malware Targeting Law Firms (2026-07-31)](https://www.group-ib.com/blog/hollowframe-matryoshka-law-firm-campaign/)
- [MITRE ATT&CK — T1102.001: Web Service: Dead Drop Resolver](https://attack.mitre.org/techniques/T1102/001/)
- [MITRE ATT&CK — T1574.002: DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- [MITRE ATT&CK — T1497: Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497/)
