# Avalon Framework MSBuild CodeTaskFactory Inline C# Compilation

## Description

Detects MSBuild.exe executing inline C# code via the CodeTaskFactory UsingTask element, a technique used by the Avalon malware framework to compile and execute a .NET assembly entirely in memory without writing a compiled binary to disk. In the Avalon attack chain, a LNK shortcut inside a mounted ISO triggers cmd.exe to invoke MSBuild.exe against an embedded project file; MSBuild then compiles and executes the C# payload in-process with no disk artifact from the compiled output.

Legitimate uses of MSBuild.exe typically originate from Visual Studio (devenv.exe), MSBuild itself, or CI/CD systems (svchost.exe under a build agent service). MSBuild spawned by script interpreters (wscript.exe, cscript.exe, mshta.exe), LOLBins (rundll32.exe, regsvr32.exe), or a cmd.exe/powershell.exe whose own parent was a browser, mail client, or LNK-executing shell process is highly anomalous and warrants immediate investigation.

False positives can occur in environments where developers invoke MSBuild from terminal sessions (cmd.exe, powershell.exe). Tune by excluding parent cmd.exe or powershell.exe processes whose command lines contain known CI/CD paths or developer toolchain prefixes.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Trusted Developer Utilities Proxy Execution: MSBuild |
| Technique ID | T1127.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="MSBuild.exe"
  AND NOT Processes.parent_process_name IN ("devenv.exe","MSBuild.exe","xdesproc.exe","vstest.console.exe","testhost.exe","agent.exe","azp-agent.exe")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(parent_process_name,"(?i)(wscript|cscript|mshta|rundll32|regsvr32)\.exe"), 90,
    match(parent_process_name,"(?i)(explorer|lnkresolver)\.exe"), 75,
    match(parent_process_name,"(?i)(cmd|powershell|pwsh)\.exe"), 55,
    1=1, 40)
| where risk_score >= 40
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Parent is wscript.exe, cscript.exe, mshta.exe, rundll32.exe, or regsvr32.exe | 90 | Script interpreter or LOLBin spawning MSBuild is a near-certain proxy execution attempt |
| Parent is explorer.exe or lnkresolver.exe | 75 | LNK shortcut directly invoking MSBuild without a terminal intermediary strongly suggests ISO/LNK delivery chain |
| Parent is cmd.exe, powershell.exe, or pwsh.exe | 55 | Common in Avalon chain (LNK → cmd → MSBuild); also seen in some legitimate developer usage, requiring triage |
| Any other non-development parent | 40 | Low-confidence anomaly; useful for baselining |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Avalon Framework / CrownX (unknown threat actor, AI-assisted development suspected) | [The Hacker News — Avalon CrownX (2026-07-03)](https://thehackernews.com/2026/07/new-avalon-malware-framework-packs.html), [Blackpoint Cyber APG — Avalon Research (2026-07-03)](https://blackpointcyber.com/resources/blog/avalon-crownx-modular-ransomware-framework/) |
| Lazarus Group (HIDDEN COBRA) | [MITRE ATT&CK G0032](https://attack.mitre.org/groups/G0032/) |
| MuddyWater / Seedworm (historical MSBuild abuse) | [MITRE ATT&CK G0069](https://attack.mitre.org/groups/G0069/) |

## References

- [MITRE ATT&CK — T1127.001 Trusted Developer Utilities Proxy Execution: MSBuild](https://attack.mitre.org/techniques/T1127/001/)
- [The Hacker News — Avalon Malware Framework with CrownX Ransomware (2026-07-03)](https://thehackernews.com/2026/07/new-avalon-malware-framework-packs.html)
- [Blackpoint Cyber APG — Avalon/CrownX Modular Ransomware Framework (2026-07-03)](https://blackpointcyber.com/resources/blog/avalon-crownx-modular-ransomware-framework/)
- [LOLBAS Project — MSBuild](https://lolbas-project.github.io/lolbas/Binaries/Msbuild/)
- [Microsoft — UsingTask Element (MSBuild)](https://learn.microsoft.com/en-us/visualstudio/msbuild/usingtask-element-msbuild)
