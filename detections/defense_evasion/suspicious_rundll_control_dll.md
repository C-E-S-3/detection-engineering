# Suspicious RunDLL Control_RunDLL Use

## Description

Detects `rundll32.exe` invocations using the `Control_RunDLL` export function with non-standard DLLs or paths. `Control_RunDLL` is legitimately used to open Control Panel applets, but adversaries abuse it to proxy-execute arbitrary DLLs. This detection applies composite risk scoring based on DLL path, parent process, DLL name, and user privilege.

False positive sources: Legitimate Control Panel operations via control.exe or explorer.exe. Tuning: the scoring already accounts for expected parents (control.exe = 0 risk).

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | System Binary Proxy Execution: Rundll32 |
| Technique ID | T1218.011 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation / Installation |

## Splunk Detection Query

```spl
`crowdstrike`
process_name="rundll32.exe"
process="*Control_RunDLL*"
| rex field=process "Control_RunDLL\s+(?<dll_path>[^,]+)"
| eval dll_path=trim(dll_path)
| rex field=dll_path "(?<dll_name>[^\\]+\.(dll|cpl))$"
| rex field=user "(?<user_sid>S-\d+-\d+-\d+-.+)$"

| eval base_risk=10

| eval path_risk=case(
    match(dll_path, "(?i)C:\\\\Windows\\\\System32\\\\") OR match(dll_path, "(?i)C:\\\\Windows\\\\SysWOW64\\\\"), 0,
    match(dll_path, "(?i)C:\\\\Windows\\\\"), 20,
    match(dll_path, "(?i)C:\\\\Users\\\\"), 40,
    match(dll_path, "(?i)C:\\\\ProgramData\\\\"), 50,
    match(dll_path, "(?i)C:\\\\Temp\\\\") OR match(dll_path, "(?i)\\\\AppData\\\\"), 60,
    match(dll_path, "(?i)^\\\\\\\\") OR match(dll_path, "(?i)^[A-Z]:\\\\Temp"), 70,
    1=1, 50
)

| eval parent_risk=case(
    parent_process_name="control.exe", 0,
    parent_process_name="explorer.exe", 5,
    parent_process_name="sihost.exe", 5,
    match(parent_process_name, "(?i)cmd.exe|powershell.exe|wscript.exe|cscript.exe|mshta.exe"), 50,
    match(parent_process_name, "(?i)winword.exe|excel.exe|outlook.exe|acrord32.exe"), 40,
    match(parent_process_name, "(?i)chrome.exe|firefox.exe|msedge.exe|iexplore.exe"), 30,
    1=1, 15
)

| eval dll_risk=case(
    match(dll_name, "(?i)^(shell32\.dll|desk\.cpl|sysdm\.cpl|appwiz\.cpl|timedate\.cpl|intl\.cpl|inetcpl\.cpl|powercfg\.cpl|ncpa\.cpl|firewall\.cpl|main\.cpl|joy\.cpl|mmsys\.cpl)$"), 0,
    match(dll_name, "(?i)cryptext\.dll|zipfldr\.dll|control\.exe"), 20,
    match(dll_name, "(?i)\.cpl$"), 25,
    match(dll_name, "(?i)\.dll$"), 30,
    1=1, 40
)

| eval user_risk=case(
    match(user_sid, "-500$"), 30,
    match(user_sid, "-50[0-9]$"), 20,
    match(user, "(?i)SYSTEM|LOCAL SERVICE|NETWORK SERVICE"), -10,
    1=1, 0
)

| eval total_risk=base_risk + path_risk + parent_risk + dll_risk + user_risk

| eval risk_reason=mvappend(
    if(path_risk>0, "Non-standard DLL/CPL path (+" . path_risk . ")", null()),
    if(parent_risk>15, "Suspicious parent process: " . parent_process_name . " (+" . parent_risk . ")", null()),
    if(dll_risk>0, "Uncommon DLL/CPL: " . dll_name . " (+" . dll_risk . ")", null()),
    if(user_risk>0, "Privileged account usage (+" . user_risk . ")", null())
)

| where total_risk >= 50

| eval risk_level=case(
    total_risk >= 100, "critical",
    total_risk >= 80, "high",
    total_risk >= 60, "medium",
    1=1, "low"
)

| stats count, values(dll_path) as dll_paths, values(parent_process_name) as parents,
        values(risk_reason) as reasons, max(total_risk) as max_risk, values(risk_level) as risk_levels
  by src, user, dll_name

| sort - max_risk
```

## Risk Score Logic

| Component | Conditions | Score | Rationale |
|-----------|-----------|-------|-----------|
| path_risk | UNC or Temp paths | 60-70 | Non-standard DLL locations |
| parent_risk | Script hosts, Office apps | 40-50 | Suspicious process chains |
| dll_risk | Non-standard DLL/CPL names | 25-40 | Uncommon Control Panel items |
| user_risk | Local admin (RID 500) | 30 | Privileged execution |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Lazarus Group (HIDDEN COBRA) | [MITRE - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/) |

## References

- [MITRE ATT&CK - Rundll32 (T1218.011)](https://attack.mitre.org/techniques/T1218/011/)
- [LOLBAS Project - Rundll32](https://lolbas-project.github.io/lolbas/Binaries/Rundll32/)
