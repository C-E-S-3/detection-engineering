# .NET AppDomain Manager Injection

## Description

Detects .NET AppDomain Manager Injection (T1574.014), a technique where an attacker places a trojanized XML `.config` file in the same directory as a legitimate .NET application. The config file specifies an attacker-controlled `AppDomainManager` subclass in a malicious DLL; when the legitimate application launches, the .NET runtime automatically loads the malicious DLL and executes the attacker's code before the application's own code runs. This bypasses application allowlisting because the host process is a trusted, signed binary.

Observed in the wild by **Nimbus Manticore** (IRGC-linked Iranian APT) starting February 2026, using the technique to deliver MiniJunk and MiniFast implants. The technique is also documented in the MITRE ATT&CK framework as applicable to any threat actor seeking to abuse .NET application trust.

Key detection signals:
- `.config` files created in standard program directories by unexpected writers (e.g., browsers, document viewers, scripting engines)
- A `.NET` application loading DLLs from the same directory as its `.config` file when those DLLs are not part of the application's expected set
- Child process anomalies from .NET applications that should not spawn shell utilities

False positive sources: legitimate software updates that deploy `.config` files alongside `.NET` executables; application frameworks that dynamically generate config files. Tune by whitelisting known-good software update processes and verifying config file signing.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Hijack Execution Flow: AppDomain Manager Injection |
| Technique ID | T1574.014 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_name="*.config"
    (Filesystem.file_path="*\\Program Files\\*" OR
     Filesystem.file_path="*\\Program Files (x86)\\*" OR
     Filesystem.file_path="*\\Windows\\*")
    Filesystem.process_name IN ("powershell.exe","wscript.exe","cscript.exe","cmd.exe",
                                "mshta.exe","regsvr32.exe","rundll32.exe","msiexec.exe",
                                "certutil.exe","bitsadmin.exe","curl.exe","wget.exe")
  by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path
     Filesystem.process_name Filesystem.process_id
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path,"(?i)\\\\Windows\\\\"), 90,
    process_name IN ("wscript.exe","cscript.exe","mshta.exe","regsvr32.exe"), 90,
    process_name IN ("powershell.exe","cmd.exe"), 80,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user file_name file_path process_name risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process IN ("*zoom.exe*","*teams.exe*","*outlook.exe*","*winword.exe*",
                               "*excel.exe*","*acrobat.exe*","*acrord32.exe*")
    Processes.process_name IN ("cmd.exe","powershell.exe","mshta.exe","wscript.exe",
                               "cscript.exe","rundll32.exe","regsvr32.exe")
    Processes.parent_process_name NOT IN ("explorer.exe","svchost.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)powershell.*-enc"), 95,
    process_name IN ("mshta.exe","wscript.exe","cscript.exe"), 90,
    process_name IN ("cmd.exe","powershell.exe"), 80,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `.config` file created in `\Windows\` path by scripting engine or LOLBin | 90 | High-privilege path; no legitimate reason for scripting engines to write `.config` files there |
| `.config` file created in Program Files by `wscript.exe`, `mshta.exe`, or `regsvr32.exe` | 90 | AppDomain hijacking delivery; these processes should not be writing application configs |
| `.config` file created in Program Files by `powershell.exe` or `cmd.exe` | 80 | Suspicious; may indicate post-exploitation staging |
| .NET application spawning `mshta.exe`, `wscript.exe`, or `cscript.exe` as child | 90 | Unexpected child processes from .NET applications indicate injected AppDomainManager code running |
| .NET application spawning `cmd.exe` or `powershell.exe` with encoded command | 95 | Obfuscated execution from injected DLL; near-certain true positive |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Nimbus Manticore (IRGC-linked Iranian APT) | [Check Point Research — Fast and Furious (2026-05-22)](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/) |

## References

- [Check Point Research — Nimbus Manticore (2026-05-22)](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [MITRE ATT&CK T1574.014 — AppDomain Manager Injection](https://attack.mitre.org/techniques/T1574/014/)
- [Unit 42 — MiniJunk V2 Disclosure](https://unit42.paloaltonetworks.com/)
- [THN — Iranian Hackers Deploy MiniFast and MiniJunk V2](https://thehackernews.com/2026/05/iranian-hackers-deploy-minifast-and.html)
