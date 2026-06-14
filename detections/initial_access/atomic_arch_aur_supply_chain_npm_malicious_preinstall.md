# Atomic Arch AUR Supply Chain — Malicious npm Preinstall Hook Executing ELF Credential Stealer

## Description

Detects the Atomic Arch supply chain attack (June 2026) in which threat actors adopted orphaned Arch Linux AUR packages and modified their PKGBUILD scripts to install the malicious npm packages `atomic-lockfile`, `js-digest`, or `lockfile-js` during the build process. When an AUR helper (`yay`, `paru`, `pikaur`, `aurutils`, `trizen`) invokes the poisoned PKGBUILD, npm runs a preinstall lifecycle hook that executes a Rust-compiled ELF binary (`src/hooks/deps`) which steals SSH keys, browser credentials, GitHub/npm tokens, cloud credentials, and Slack/Discord sessions. On privileged hosts the binary also loads an eBPF rootkit that hides the process and its sockets from `ps`, `htop`, `lsof`, and `ss`.

**False positives:** Negligible. AUR build systems do not normally invoke npm to install these package names. A legitimate npm package named `atomic-lockfile` existed at versions prior to 1.4.2 but was an unmaintained utility with trivial download counts; its reappearance via an AUR package build should be treated as high-confidence malicious.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Supply Chain Compromise: Compromise Software Supply Chain |
| Technique ID | T1195.002 |

**Secondary Techniques:**

| Tactic | Technique ID | Technique Name |
|--------|-------------|----------------|
| Execution | T1059.004 | Command and Scripting Interpreter: Unix Shell |
| Execution | T1059.007 | Command and Scripting Interpreter: JavaScript |
| Defense Evasion | T1014 | Rootkit (eBPF) |
| Credential Access | T1552.001 | Unsecured Credentials: Credentials In Files |
| Exfiltration | T1048 | Exfiltration Over Alternative Protocol |
| Exfiltration | T1090.003 | Proxy: Multi-hop Proxy (Tor) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("makepkg","yay","paru","pikaur","trizen","aurutils","aura")
  AND Processes.process_name IN ("npm","node","bun")
  AND Processes.process IN ("*install*","*i *")
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| where match(process, "(?i)(atomic.lockfile|js.digest|lockfile.js)")
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name parent_process process_name process process_id risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("npm","node","bun")
  AND Processes.process_name="deps"
  AND Processes.process IN ("*/src/hooks/deps*","*node_modules*")
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_path IN ("*/node_modules/atomic-lockfile/*","*/node_modules/js-digest/*","*/node_modules/lockfile-js/*","*/src/hooks/deps")
  AND Filesystem.action="created"
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user file_path file_name process_name risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| AUR helper spawning npm to install `atomic-lockfile`, `js-digest`, or `lockfile-js` | 90 | Known-malicious package names; no legitimate use case in AUR builds; high-confidence Atomic Arch indicator |
| npm/node/bun spawning a child process named `deps` from `src/hooks/` path | 95 | Unique to Atomic Arch payload execution; near-certain true positive |
| Known-malicious node_modules directory created on filesystem | 90 | Filesystem artifact of successful installation of malicious packages |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Atomic Arch (unattributed supply chain threat actor, June 2026) | [Sonatype — Atomic Arch Campaign](https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency), [OSV.dev MAL-2026-2528](https://osv.dev/vulnerability/MAL-2026-2528) |

## References

- [Sonatype — Atomic Arch: npm Campaign Adds Malicious Dependency](https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency)
- [The Hacker News — Over 400 Arch Linux AUR Packages Hijacked to Deploy Infostealer and eBPF Rootkit](https://thehackernews.com/2026/06/over-400-arch-linux-aur-packages.html)
- [GitHub — lenucksi/aur-malware-check (community detection scripts)](https://github.com/lenucksi/aur-malware-check)
- [SafeDep — Atomic Arch Threat Intelligence](https://safedep.io/ti/campaigns/atomic-arch/)
- [MITRE ATT&CK — T1195.002 Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/002/)
- [MITRE ATT&CK — T1014 Rootkit](https://attack.mitre.org/techniques/T1014/)
