# IDE Extension SSH Authorized Keys Modification

## Description

Detects IDE extensions or their spawned child processes modifying `~/.ssh/authorized_keys` (macOS/Linux) or the Windows OpenSSH equivalent (`%USERPROFILE%\.ssh\authorized_keys`), a technique used to establish persistent unauthorized remote access. This pattern was first observed in the wild in the October 2026 trojanized Claude Code VSIX v2.1.313 distributed via the Cursor IDE marketplace, which appended an attacker-controlled SSH public key labeled `svc-telemetry`.

Unlike traditional persistence via scheduled tasks or registry keys, SSH authorized_keys modification:
- Survives IDE/extension reinstallation and uninstallation
- Is not remediated by removing the offending extension
- Grants the attacker silent shell access with no malware on disk (post-persistence)

Detection layers:
1. **File write**: IDE process (or Extension Host child) writes to `authorized_keys`
2. **Key label IOC**: presence of `svc-telemetry` comment in `authorized_keys` (specific to the October 2026 campaign)
3. **Reverse tunnel**: IDE process spawning `ssh -R` for reverse tunneling
4. **Beacon**: IDE process making outbound connections on TCP/8099

False positive sources: legitimate development tools that automate SSH key provisioning (e.g., `ssh-keygen` called from a build script run inside VS Code integrated terminal). These are distinguished by the parent process; `ssh-keygen` run from an integrated terminal shell is expected. A direct write from the Extension Host process is anomalous.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Persistence |
| Tactic ID | TA0003 |
| Technique | Account Manipulation: SSH Authorized Keys |
| Technique ID | T1098.004 |
| Secondary Tactic | Command and Control |
| Secondary Tactic ID | TA0011 |
| Secondary Technique | Protocol Tunneling |
| Secondary Technique ID | T1572 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |
| Command & Control (C2) |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_name="authorized_keys"
    AND Filesystem.process_name IN ("cursor","cursor-helper","cursor-ext-host",
                                    "code","code-insiders","code-server",
                                    "extensionhost","vscodium","node","node.js")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name
     Filesystem.process_id
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name,"(?i)(cursor-ext|extensionhost)"), 90,
    match(process_name,"(?i)(cursor|code|vscodium)"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user file_path process_name process_id risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process IN ("*ssh*-R*","*ssh*--reverse*")
  AND Processes.parent_process_name IN ("cursor","cursor-helper","cursor-ext-host",
                                         "code","code-insiders","code-server",
                                         "extensionhost","vscodium")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90, detection_layer="Reverse SSH tunnel from IDE process"
| table firstTime lastTime dest user parent_process_name process_name process detection_layer risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port=8099 All_Traffic.transport=tcp
  by All_Traffic.src All_Traffic.dest All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    app IN ("cursor","cursor-helper","extensionhost","code","code-server"), 85,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src dest app risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Extension Host process writes to `authorized_keys` | 90 (Critical) | Extension Host should never write SSH keys; near-certain malicious |
| Cursor/VS Code main binary writes to `authorized_keys` | 85 (High) | Unexpected and strongly anomalous; IDE core has no SSH key management feature |
| Node/generic IDE child writes to `authorized_keys` | 75 (High) | Less specific but still very suspicious outside a provisioning context |
| Reverse SSH tunnel (`ssh -R`) spawned from IDE | 90 (Critical) | IDEs do not open reverse tunnels; clear attacker behavior |
| Outbound TCP/8099 from IDE process | 85 (High) | Non-standard port C2 beacon; IDEs have no legitimate use for TCP/8099 |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (Trojanized Claude Code VSIX campaign, Oct 2026) | [BleepingComputer — Trojanized Claude Code Extension](https://www.bleepingcomputer.com/news/security/trojanized-claude-code-extension-in-cursor-marketplace-installs-ssh-backdoor/) |

## References

- [BleepingComputer — Trojanized Claude Code Extension in Cursor Marketplace Installs SSH Backdoor (2026-10-29)](https://www.bleepingcomputer.com/news/security/trojanized-claude-code-extension-in-cursor-marketplace-installs-ssh-backdoor/)
- [StepSecurity — Analysis of Malicious Claude Code VSIX v2.1.313](https://www.stepsecurity.io/blog/analysis-malicious-claude-code-vsix-cursor-marketplace)
- [MITRE ATT&CK — T1098.004 Account Manipulation: SSH Authorized Keys](https://attack.mitre.org/techniques/T1098/004/)
- [MITRE ATT&CK — T1572 Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
- [MITRE ATT&CK — T1195.001 Supply Chain Compromise: Compromise Software Dependencies](https://attack.mitre.org/techniques/T1195/001/)
