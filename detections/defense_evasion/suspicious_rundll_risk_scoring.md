# Suspicious RunDLL Composite Risk Scoring

## Description

Composite risk scoring rule for `rundll32.exe` execution. Evaluates multiple risk factors: DLL path (system vs. temp vs. user directories), parent process (expected vs. suspicious), DLL name (known-good vs. uncommon), command line arguments (JavaScript protocol, HTTP URLs, ordinal exports), and user privilege level. Individual factors are summed to produce a total risk score.

False positive sources: Legitimate Control Panel applets, shell extensions, and software that uses rundll32 as a launcher. Tuning: the known-good DLL list in dll_risk covers common legitimate DLLs.

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
| rex field=process "(?<dll_path>[A-Za-z]:\\\\[^,\s]+\.(dll|cpl))"
| eval dll_path=coalesce(dll_path, "unknown")
| rex field=dll_path "(?<dll_name>[^\\\\]+\.(dll|cpl))$"
| rex field=user "(?<user_sid>S-\d+-\d+-\d+-.+)$"

| eval base_risk=10

| eval path_risk=case(
    dll_path="unknown", 5,
    match(dll_path, "(?i)C:\\\\Windows\\\\System32\\\\") OR match(dll_path, "(?i)C:\\\\Windows\\\\SysWOW64\\\\"), 0,
    match(dll_path, "(?i)C:\\\\Windows\\\\"), 20,
    match(dll_path, "(?i)\\\\Local\\\\Temp\\\\") OR match(dll_path, "(?i)\\\\Windows\\\\Temp\\\\") OR match(dll_path, "(?i)C:\\\\Temp\\\\"), 70,
    match(dll_path, "(?i)\\\\AppData\\\\Local\\\\Temp\\\\"), 60,
    match(dll_path, "(?i)\\\\AppData\\\\Roaming\\\\"), 50,
    match(dll_path, "(?i)\\\\AppData\\\\"), 40,
    match(dll_path, "(?i)C:\\\\Users\\\\Public\\\\"), 60,
    match(dll_path, "(?i)C:\\\\Users\\\\"), 35,
    match(dll_path, "(?i)C:\\\\ProgramData\\\\"), 50,
    match(dll_path, "(?i)C:\\\\Intel\\\\") OR match(dll_path, "(?i)C:\\\\AMD\\\\"), 15,
    match(dll_path, "(?i)C:\\\\Program Files\\\\") OR match(dll_path, "(?i)C:\\\\Program Files \(x86\)\\\\"), 10,
    match(dll_path, "(?i)^\\\\\\\\"), 65,
    1=1, 55
)

| eval parent_risk=case(
    parent_process_name="control.exe", 0,
    parent_process_name="explorer.exe", 5,
    parent_process_name="sihost.exe", 5,
    parent_process_name="dllhost.exe", 5,
    parent_process_name="svchost.exe", 0,
    parent_process_name="services.exe", 0,
    match(parent_process_name, "(?i)cmd.exe|powershell.exe|wscript.exe|cscript.exe|mshta.exe"), 60,
    match(parent_process_name, "(?i)winword.exe|excel.exe|outlook.exe|acrord32.exe|acrobat.exe"), 45,
    match(parent_process_name, "(?i)chrome.exe|firefox.exe|msedge.exe|iexplore.exe"), 35,
    match(parent_process_name, "(?i)java.exe|javaw.exe"), 30,
    match(parent_process_name, "(?i)wmic.exe|certutil.exe|bitsadmin.exe|regsvr32.exe"), 70,
    1=1, 20
)

| eval dll_risk=case(
    match(dll_name, "(?i)^(shell32\.dll|desk\.cpl|sysdm\.cpl|appwiz\.cpl|timedate\.cpl|intl\.cpl|inetcpl\.cpl|powercfg\.cpl|ncpa\.cpl|firewall\.cpl|main\.cpl|joy\.cpl|mmsys\.cpl|ndfapi\.dll|davclnt\.dll|dfshim\.dll)$"), 0,
    match(dll_name, "(?i)^(cryptext\.dll|zipfldr\.dll|printui\.dll|pcwutl\.dll)$"), 15,
    match(dll_name, "(?i)^(mshtml\.dll|jscript\.dll|vbscript\.dll)$"), 40,
    match(dll_name, "(?i)^(comsvcs\.dll)$"), 50,
    match(dll_name, "(?i)\.cpl$"), 25,
    match(dll_name, "(?i)\.dll$"), 20,
    1=1, 45
)

| eval cmdline_risk=case(
    match(process, "(?i)javascript:|vbscript:|about:"), 70,
    match(process, "(?i)http://|https://|ftp://"), 60,
    match(process, "(?i)DllRegisterServer|DllUnregisterServer|DllInstall"), 30,
    match(process, "(?i)#[0-9]+"), 25,
    match(process, "(?i),a /p:"), 40,
    1=1, 0
)

| eval user_risk=case(
    match(user_sid, "-500$"), 35,
    match(user_sid, "-50[0-9]$"), 25,
    match(user, "(?i)SYSTEM|LOCAL SERVICE|NETWORK SERVICE"), -10,
    match(user, "(?i)Administrator"), 20,
    1=1, 0
)

| eval control_rundll_flag=if(match(process, "(?i)Control_RunDLL"), "yes", "no")

| eval total_risk=base_risk + path_risk + parent_risk + dll_risk + cmdline_risk + user_risk

| eval risk_reason=mvappend(
    if(path_risk>=60, "HIGH RISK: DLL in Temp/suspicious path (+" . path_risk . ")",
       if(path_risk>0, "Non-standard DLL path (+" . path_risk . ")", null())),
    if(parent_risk>=40, "HIGH RISK: Suspicious parent: " . parent_process_name . " (+" . parent_risk . ")",
       if(parent_risk>15, "Uncommon parent process: " . parent_process_name . " (+" . parent_risk . ")", null())),
    if(dll_risk>=40, "HIGH RISK: Dangerous DLL: " . dll_name . " (+" . dll_risk . ")",
       if(dll_risk>0, "Uncommon DLL: " . dll_name . " (+" . dll_risk . ")", null())),
    if(cmdline_risk>0, "Suspicious command line arguments (+" . cmdline_risk . ")", null()),
    if(user_risk>0, "Privileged/Admin account usage (+" . user_risk . ")", null())
)

| eval risk_level=case(
    total_risk >= 120, "critical",
    total_risk >= 90, "high",
    total_risk >= 60, "medium",
    total_risk >= 40, "low",
    1=1, "info"
)

| where total_risk >= 40

| stats count,
        values(dll_path) as dll_paths,
        values(parent_process_name) as parents,
        values(process) as command_lines,
        values(risk_reason) as reasons,
        max(total_risk) as max_risk,
        values(risk_level) as risk_levels,
        values(control_rundll_flag) as is_control_rundll
  by src, user, dll_name

| sort - max_risk
```

## Risk Score Logic

| Component | High-Risk Conditions | Score | Rationale |
|-----------|---------------------|-------|-----------|
| path_risk | Temp directories | 60-70 | Common malware staging locations |
| path_risk | UNC paths | 65 | Remote DLL loading |
| parent_risk | wmic, certutil, bitsadmin | 70 | LOLBAS parent chain |
| parent_risk | Script hosts (wscript, cmd, PS) | 60 | Malware delivery chain |
| dll_risk | comsvcs.dll | 50 | Credential dumping (MiniDump) |
| dll_risk | mshtml/jscript/vbscript | 40 | Script execution DLLs |
| cmdline_risk | javascript:/vbscript: protocol | 70 | Proxy execution |
| cmdline_risk | HTTP URLs | 60 | Remote payload retrieval |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Lazarus Group (HIDDEN COBRA) | [MITRE - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/) |
| Medusa Ransomware | [CISA - StopRansomware: Medusa](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a) |

## References

- [MITRE ATT&CK - Rundll32 (T1218.011)](https://attack.mitre.org/techniques/T1218/011/)
- [LOLBAS Project - Rundll32](https://lolbas-project.github.io/lolbas/Binaries/Rundll32/)
