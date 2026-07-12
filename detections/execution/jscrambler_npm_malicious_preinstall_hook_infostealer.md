# npm Malicious Preinstall Hook — Cross-Platform Rust Infostealer (jscrambler Supply Chain)

## Description

Detects `node.exe` or `npm` process trees spawning Windows system utilities that have no legitimate role in a JavaScript package install lifecycle — specifically `schtasks.exe` (Task Scheduler), `reg.exe`, PowerShell, or other LOLBins. This pattern is the primary behavioral signature of npm supply chain attacks that abuse the `preinstall`/`postinstall` lifecycle hook to drop and persist native binaries.

The jscrambler npm supply chain compromise (July 2026, versions 8.14.0–8.20.0) is a confirmed example: a malicious `dist/setup.js` preinstall hook fingerprinted the host OS and dropped a Rust-compiled cross-platform infostealer targeting Chrome/Brave/Edge credential stores, the Bitwarden browser extension vault, and Steam session tokens. On Windows, persistence was established via a Task Scheduler entry created by spawning `schtasks.exe` from the node.exe process tree.

False positives are rare but possible: some native npm addon packages (e.g., node-gyp builds) spawn `cmd.exe` to invoke MSBuild during installation. Legitimate `node-gyp` invocations are distinguishable by the presence of `node_gyp` in the command line and a known `python.exe` intermediate; exclude these patterns after validating in your environment. `schtasks.exe` spawned from `node.exe` has no known legitimate use case and should be treated as near-certain malicious activity.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | Command and Scripting Interpreter: JavaScript |
| Technique ID | T1059.007 |
| Secondary Tactic | Initial Access |
| Secondary Technique | Compromise Software Supply Chain: Compromise Software Dependencies and Development Tools |
| Secondary Technique ID | T1195.002 |
| Secondary Tactic | Persistence |
| Secondary Technique | Scheduled Task/Job: Scheduled Task (Windows persistence) |
| Secondary Technique ID | T1053.005 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.parent_process_name="node.exe" OR Processes.parent_process_name="npm.cmd" OR Processes.parent_process_name="npm")
    AND Processes.process_name IN ("schtasks.exe","reg.exe","powershell.exe","cmd.exe",
                                   "mshta.exe","wscript.exe","cscript.exe",
                                   "certutil.exe","curl.exe","bitsadmin.exe")
    AND NOT (Processes.process_name="cmd.exe"
             AND match(Processes.process, "(?i)node_gyp|node-gyp|python|msbuild|gyp-win-tool"))
  by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name="schtasks.exe", 95,
    match(process_name, "(?i)(mshta\.exe|wscript\.exe|cscript\.exe|certutil\.exe|bitsadmin\.exe)"), 85,
    process_name IN ("powershell.exe","reg.exe"), 80,
    match(process_name, "(?i)(cmd\.exe|curl\.exe)"), 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name parent_process process_name process process_id risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `node.exe` → `schtasks.exe` | 95 | npm package install has no legitimate reason to create a scheduled task; this is the primary persistence mechanism of the jscrambler infostealer |
| `node.exe` → `mshta.exe` / `wscript.exe` / `cscript.exe` / `certutil.exe` / `bitsadmin.exe` | 85 | Script engine or download-utility invocation from npm; classic payload staging / living-off-the-land pattern |
| `node.exe` → `powershell.exe` or `reg.exe` | 80 | PowerShell and registry manipulation are unusual from npm install context; high suspicion |
| `node.exe` → `cmd.exe` or `curl.exe` (without node-gyp indicators) | 65 | cmd.exe is used by node-gyp during native builds; exclude legitimate gyp invocations; remaining hits are suspicious |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (jscrambler npm supply chain compromise, July 2026) | [Socket.dev — jscrambler supply chain attack](https://socket.dev/blog/jscrambler-supply-chain-attack) |
| TeamPCP / UNC6780 (Miasma worm) | [The Hacker News — Miasma Worm (2026-06-06)](https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html) |
| TeamPCP / UNC6780 (Shai-Hulud Hades wave) | [BleepingComputer — Hades PyPI wave (2026-06-09)](https://www.bleepingcomputer.com/news/security/new-shai-hulud-attack-trojanizes-19-science-faced-pypi-packages/) |

## References

- [Socket.dev — jscrambler supply chain attack (2026-07-11)](https://socket.dev/blog/jscrambler-supply-chain-attack)
- [MITRE ATT&CK — T1195.002 Compromise Software Dependencies](https://attack.mitre.org/techniques/T1195/002/)
- [MITRE ATT&CK — T1059.007 JavaScript](https://attack.mitre.org/techniques/T1059/007/)
- [MITRE ATT&CK — T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- [Socket.dev — Injective Protocol SDK supply chain (2026-07-09)](https://socket.dev/blog/injective-sdk-npm-supply-chain-attack)
