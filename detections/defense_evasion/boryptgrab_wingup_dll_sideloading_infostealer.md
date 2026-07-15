# BoryptGrab WinGUP.exe DLL Sideloading Infostealer

## Description

Detects the DLL sideloading technique used by the BoryptGrab infostealer campaign, which abuses the legitimate Notepad++ auto-updater binary `WinGUP.exe` to load a malicious `libcurl.dll` from the same directory. The campaign distributes malicious archives via 292+ brand-impersonating GitHub repositories (active since June 26, 2026). When executed from user-writable directories (Temp, AppData, Downloads, Public, ProgramData), WinGUP.exe loads the attacker-controlled `libcurl.dll` due to DLL search order hijacking, which then uses COM/SafeArray-based reflective loading to deploy the infostealer entirely in memory.

BoryptGrab targets 41 cryptocurrency wallet types, 19+ browsers, and messaging applications. Related malware families include HeaconLoad, TunnesshClient, and Vidar. C2 exfiltration uses a Russian-hosted server receiving encrypted ZIP archives.

False positive sources: legitimate Notepad++ installations running auto-update from the default installation path. This detection explicitly excludes standard Notepad++ installation directories.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Hijack Execution Flow: DLL Side-Loading |
| Technique ID | T1574.002 |

Secondary tactics: Credential Access (TA0006 — T1555.003), Collection (TA0009 — T1005), Exfiltration (TA0010 — T1041)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="WinGUP.exe"
  AND NOT (Processes.process_path IN (
    "*\\Program Files\\Notepad++\\updater\\*",
    "*\\Program Files (x86)\\Notepad++\\updater\\*"))
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_path Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_path, "(?i)\\\\(temp|appdata|downloads|public|programdata)\\\\"), 95,
    match(process_path, "(?i)\\\\users\\\\"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process process_path risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| WinGUP.exe in Temp, AppData, Downloads, Public, or ProgramData | 95 | Canonical BoryptGrab execution path; WinGUP.exe has no legitimate reason to run from these locations |
| WinGUP.exe in any Users directory (not the above) | 85 | High confidence; WinGUP.exe should only run from Notepad++ installation directory |
| WinGUP.exe from any non-standard path | 75 | Catch-all for unexpected paths; requires analyst triage |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (BoryptGrab campaign, June–July 2026) | [Arctic Wolf — BoryptGrab Fake GitHub Repositories (2026-07-14)](https://arcticwolf.com/resources/blog/fake-github-repositories-deliver-boryptgrab-lineage-infostealer/) |
| Unknown (Vidar MaaS ecosystem, overlapping infrastructure) | [MITRE ATT&CK S0673 — Vidar](https://attack.mitre.org/software/S0673/) |

## References

- [Arctic Wolf — Fake GitHub Repositories Deliver BoryptGrab Lineage Infostealer (2026-07-14)](https://arcticwolf.com/resources/blog/fake-github-repositories-deliver-boryptgrab-lineage-infostealer/)
- [Trend Micro — BoryptGrab Infostealer Analysis (2026-07-14)](https://www.trendmicro.com/en_us/research/)
- [MITRE ATT&CK T1574.002 — DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- [MITRE ATT&CK T1555.003 — Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
